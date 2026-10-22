"""Import locally supplied vulnerability and ATT&CK data into SQLite.

This program deliberately does not download anything.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from typing import Any, Iterator

from ids.offline_intelligence import DEFAULT_DB_PATH, SCHEMA_SQL


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _source_files(
    paths: list[str | Path],
    *,
    allowed_suffixes: tuple[str, ...],
) -> list[Path]:
    """Find files whose formats are allowed for the requested source."""
    files: list[Path] = []
    allowed = tuple(suffix.lower() for suffix in allowed_suffixes)

    for value in paths:
        path = Path(value).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Input does not exist: {path}")

        if path.is_dir():
            candidates = [
                item for item in path.rglob("*")
                if item.is_file()
                and item.name.lower().endswith(allowed)
            ]
        elif path.is_file() and path.name.lower().endswith(allowed):
            candidates = [path]
        else:
            raise ValueError(
                f"Unsupported input format: {path}. "
                f"Expected one of: {', '.join(allowed)}"
            )

        files.extend(candidates)

    unique = sorted(set(files), key=lambda item: (
        "modified" in item.name.lower(),
        str(item),
    ))
    if not unique:
        raise ValueError(
            "No supported source files found. Expected: "
            + ", ".join(allowed)
        )
    return unique


def _sha256_files(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _read_json_payloads(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield JSON payloads from plain JSON, gzip, or ZIP files."""
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                if not name.lower().endswith(".json"):
                    continue
                with archive.open(name) as raw:
                    payload = json.load(io.TextIOWrapper(raw, encoding="utf-8"))
                if isinstance(payload, dict):
                    yield payload, name
        return

    opener = gzip.open if path.name.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        yield payload, path.name


def _nvd_cve_records(payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    entries = payload.get("vulnerabilities")

    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cve = entry.get("cve", entry)
            if isinstance(cve, dict) and cve.get("id"):
                yield cve
        return

    cve = payload.get("cve")
    if isinstance(cve, dict) and cve.get("id"):
        yield cve
    elif payload.get("id") and isinstance(payload.get("descriptions"), list):
        yield payload


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            return {
                "version": data.get("version"),
                "base_score": data.get("baseScore"),
                "base_severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "source": entry.get("source"),
                "type": entry.get("type"),
            }

    return None


def _nvd_summary(cve: dict[str, Any]) -> dict[str, Any]:
    description = ""
    descriptions = cve.get("descriptions", [])
    if isinstance(descriptions, list):
        for entry in descriptions:
            if isinstance(entry, dict) and entry.get("lang") == "en":
                description = str(entry.get("value") or "")
                break

    weaknesses: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []):
            if isinstance(desc, dict) and desc.get("value"):
                weaknesses.add(str(desc["value"]))

    references: list[dict[str, Any]] = []
    for reference in cve.get("references", []):
        if isinstance(reference, dict) and reference.get("url"):
            references.append({
                "url": reference["url"],
                "source": reference.get("source"),
                "tags": reference.get("tags", []),
            })

    cvss = _extract_cvss(cve) or {}

    return {
        "cve_id": str(cve["id"]).upper(),
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vulnerability_status": cve.get("vulnStatus"),
        "cvss": cvss,
        "cwe": sorted(weaknesses),
        "references": references,
        "configurations": cve.get("configurations", []),
    }




class _StreamingJSONReader:
    """Read JSON values incrementally without loading a whole feed into RAM."""

    def __init__(self, handle):
        self.handle = handle
        self.decoder = json.JSONDecoder()
        self.buffer = ""
        self.position = 0
        self.eof = False

    def _fill(self) -> None:
        if self.position:
            self.buffer = self.buffer[self.position:]
            self.position = 0
        chunk = self.handle.read(1024 * 1024)
        if chunk:
            self.buffer += chunk
        else:
            self.eof = True

    def peek(self) -> str:
        while True:
            while self.position < len(self.buffer):
                if not self.buffer[self.position].isspace():
                    return self.buffer[self.position]
                self.position += 1
            if self.eof:
                return ""
            self._fill()

    def expect(self, character: str) -> None:
        actual = self.peek()
        if actual != character:
            raise ValueError(
                f"Expected JSON character {character!r}, got {actual!r}"
            )
        self.position += 1

    def read_value(self):
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(
                    self.buffer, self.position
                )
                self.position = end
                return value
            except json.JSONDecodeError as exc:
                if self.eof:
                    raise ValueError(
                        f"Invalid or truncated JSON input: {exc}"
                    ) from exc
                self._fill()


def _iter_nvd_json_stream(handle):
    """Yield (feed_metadata, CVE record) pairs from an NVD JSON document."""
    reader = _StreamingJSONReader(handle)
    reader.expect("{")

    metadata: dict[str, Any] = {}
    saw_vulnerabilities = False
    first_key = True

    while True:
        character = reader.peek()
        if character == "}":
            reader.expect("}")
            break

        if not first_key:
            reader.expect(",")
        first_key = False

        key = reader.read_value()
        if not isinstance(key, str):
            raise ValueError("NVD JSON contains a non-string object key")
        reader.expect(":")

        if key != "vulnerabilities":
            metadata[key] = reader.read_value()
            continue

        saw_vulnerabilities = True
        reader.expect("[")
        first_item = True

        while True:
            character = reader.peek()
            if character == "]":
                reader.expect("]")
                break

            if not first_item:
                reader.expect(",")
            first_item = False

            item = reader.read_value()
            if not isinstance(item, dict):
                continue

            cve = item.get("cve", item)
            if isinstance(cve, dict) and cve.get("id"):
                yield metadata.copy(), cve

    if not saw_vulnerabilities:
        # Accept small, single-CVE NVD JSON records as well as bulk feeds.
        nested = metadata.get("cve")
        if isinstance(nested, dict) and nested.get("id"):
            yield metadata, nested
        elif CVE_RE.fullmatch(str(metadata.get("id") or "")):
            yield metadata, metadata
        else:
            raise ValueError(
                "Input is not a recognized NVD CVE feed or single-CVE record"
            )


def _iter_nvd_records(path: Path):
    """Stream NVD records from JSON, gzip-compressed JSON, or ZIP archives."""
    if path.name.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            names = sorted(
                name for name in archive.namelist()
                if name.lower().endswith(".json")
                and not name.startswith("__MACOSX/")
            )
            if not names:
                raise ValueError(f"No JSON feed found inside {path}")
            for name in names:
                with archive.open(name) as raw:
                    with io.TextIOWrapper(raw, encoding="utf-8") as handle:
                        yield from _iter_nvd_json_stream(handle)
    elif path.name.lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            yield from _iter_nvd_json_stream(handle)
    else:
        with path.open("r", encoding="utf-8") as handle:
            yield from _iter_nvd_json_stream(handle)

def _import_nvd(
    connection: sqlite3.Connection,
    paths: list[Path],
) -> tuple[int, str | None, str | None]:
    """Import NVD records incrementally, keeping memory use bounded."""
    count = 0
    latest_date: str | None = None
    latest_version: str | None = None

    for path in paths:
        for metadata, cve in _iter_nvd_records(path):
            candidates = (
                metadata.get("timestamp"),
                cve.get("lastModified"),
            )
            for value in candidates:
                if isinstance(value, str) and value:
                    if latest_date is None or value > latest_date:
                        latest_date = value

            version = metadata.get("version")
            if version is not None:
                latest_version = str(version)

            summary = _nvd_summary(cve)
            cve_id = summary["cve_id"]
            cvss = summary["cvss"]

            connection.execute(
                """
                INSERT OR REPLACE INTO cves (
                    cve_id, description, published, last_modified,
                    vulnerability_status, cvss_version, cvss_score,
                    cvss_severity, cvss_vector, cvss_source, cvss_type,
                    cwe_json, references_json, configurations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    summary["description"],
                    summary["published"],
                    summary["last_modified"],
                    summary["vulnerability_status"],
                    cvss.get("version"),
                    cvss.get("base_score"),
                    cvss.get("base_severity"),
                    cvss.get("vector"),
                    cvss.get("source"),
                    cvss.get("type"),
                    json.dumps(summary["cwe"], ensure_ascii=False),
                    json.dumps(summary["references"], ensure_ascii=False),
                    json.dumps(summary["configurations"], ensure_ascii=False),
                ),
            )
            count += 1

    return count, latest_date, latest_version


def _open_csv(path: Path):
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", newline="")
    return path.open("r", encoding="utf-8-sig", newline="")


def _import_epss(
    connection: sqlite3.Connection,
    paths: list[Path],
) -> tuple[int, str | None, str | None]:
    """Import EPSS CSVs and prefer their explicit score date over filename dates."""
    count = 0
    source_dates: list[str] = []
    version = None

    for path in paths:
        explicit_score_dates: list[str] = []
        comment_dates: list[str] = []
        filename_dates: list[str] = []

        filename_date = re.search(r"\d{4}-\d{2}-\d{2}", path.name)
        if filename_date:
            filename_dates.append(filename_date.group(0))

        with _open_csv(path) as handle:
            header = None

            for line in handle:
                if line.lstrip().startswith("#"):
                    comment = line.strip()

                    score_match = re.search(
                        r"\bscore_date\s*[:=]\s*(\d{4}-\d{2}-\d{2})",
                        comment,
                        re.IGNORECASE,
                    )
                    if score_match:
                        explicit_score_dates.append(score_match.group(1))
                    else:
                        date_match = re.search(r"\d{4}-\d{2}-\d{2}", comment)
                        if date_match:
                            comment_dates.append(date_match.group(0))

                    if "model_version" in comment.lower():
                        version = comment.lstrip("# ").strip()
                    continue

                if line.strip():
                    header = line
                    break

            if explicit_score_dates:
                file_score_date = max(explicit_score_dates)
            elif comment_dates:
                file_score_date = max(comment_dates)
            elif filename_dates:
                file_score_date = max(filename_dates)
            else:
                file_score_date = None

            if file_score_date:
                source_dates.append(file_score_date)

            if header is None:
                continue

            reader = csv.DictReader(chain([header], handle))
            fields = {
                str(field).strip().lower()
                for field in (reader.fieldnames or [])
            }
            if not {"cve", "epss", "percentile"}.issubset(fields):
                raise ValueError(
                    f"EPSS CSV must contain cve, epss, percentile columns: {path}"
                )

            for row in reader:
                normalized = {
                    str(key).strip().lower(): value
                    for key, value in row.items()
                    if key is not None
                }
                cve = str(normalized.get("cve") or "").strip().upper()
                if not CVE_RE.fullmatch(cve):
                    continue

                try:
                    score = float(normalized["epss"])
                    percentile = float(normalized["percentile"])
                except (KeyError, TypeError, ValueError):
                    continue

                connection.execute(
                    """
                    INSERT OR REPLACE INTO epss
                        (cve_id, score, percentile, score_date)
                    VALUES (?, ?, ?, ?)
                    """,
                    (cve, score, percentile, file_score_date),
                )
                count += 1

    return count, max(source_dates) if source_dates else None, version


def _load_one_json(path: Path) -> dict[str, Any]:
    payloads = list(_read_json_payloads(path))
    if len(payloads) != 1:
        raise ValueError(f"Expected one JSON payload in {path}")
    return payloads[0][0]


def _import_kev(connection: sqlite3.Connection, path: Path) -> tuple[int, str | None, str | None]:
    data = _load_one_json(path)
    entries = data.get("vulnerabilities", [])
    if not isinstance(entries, list):
        raise ValueError("CISA KEV JSON has no vulnerabilities list.")

    count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve = str(entry.get("cveID") or "").strip().upper()
        if not CVE_RE.fullmatch(cve):
            continue

        connection.execute(
            """
            INSERT OR REPLACE INTO kev (
                cve_id, vendor_project, product, vulnerability_name, date_added,
                short_description, required_action, due_date,
                known_ransomware_campaign_use, notes, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve,
                entry.get("vendorProject"),
                entry.get("product"),
                entry.get("vulnerabilityName"),
                entry.get("dateAdded"),
                entry.get("shortDescription"),
                entry.get("requiredAction"),
                entry.get("dueDate"),
                entry.get("knownRansomwareCampaignUse"),
                entry.get("notes"),
                json.dumps(entry, ensure_ascii=False),
            ),
        )
        count += 1

    return (
        count,
        str(data.get("dateReleased") or "") or None,
        str(data.get("catalogVersion") or "") or None,
    )


def _mitre_metadata(path: Path) -> dict[str, Any]:
    sidecar = path.with_suffix(".meta.json")
    if not sidecar.is_file():
        return {}
    try:
        with sidecar.open(encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _import_mitre(connection: sqlite3.Connection, path: Path) -> tuple[int, str | None, str | None]:
    data = _load_one_json(path)
    objects = data.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError("MITRE ATT&CK STIX JSON has no objects list.")

    count = 0
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        technique_url = None
        for reference in obj.get("external_references", []):
            if not isinstance(reference, dict):
                continue
            external_id = str(reference.get("external_id") or "").upper()
            if (
                TECHNIQUE_RE.fullmatch(external_id)
                and reference.get("source_name") in (None, "mitre-attack")
            ):
                technique_id = external_id
                technique_url = reference.get("url")
                if reference.get("source_name") == "mitre-attack":
                    break

        if not technique_id:
            continue

        tactics = sorted({
            str(phase.get("phase_name"))
            for phase in obj.get("kill_chain_phases", [])
            if isinstance(phase, dict)
            and phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name")
        })

        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])
        if not isinstance(platforms, list):
            platforms = []
        if not isinstance(data_sources, list):
            data_sources = []

        connection.execute(
            """
            INSERT OR REPLACE INTO attack_techniques (
                technique_id, stix_id, name, description, tactics_json,
                platforms_json, data_sources_json, url, is_subtechnique
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                technique_id,
                obj.get("id"),
                obj.get("name") or technique_id,
                obj.get("description") or "",
                json.dumps(tactics, ensure_ascii=False),
                json.dumps(platforms, ensure_ascii=False),
                json.dumps(data_sources, ensure_ascii=False),
                technique_url,
                int(bool(obj.get("x_mitre_is_subtechnique"))),
            ),
        )
        count += 1

    meta = _mitre_metadata(path)
    return (
        count,
        str(meta.get("retrieved_at") or "") or None,
        str(meta.get("dataset_version") or "") or None,
    )


def _write_source_metadata(
    connection: sqlite3.Connection,
    source: str,
    data_as_of: str | None,
    version: str | None,
    record_count: int,
    files: list[Path],
) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO source_metadata (
            source, data_as_of, imported_at, version,
            record_count, files_json, sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source,
            data_as_of,
            _now_iso(),
            version,
            record_count,
            json.dumps([path.name for path in files], ensure_ascii=False),
            _sha256_files(files),
        ),
    )


def import_sources(
    *,
    nvd_paths: list[str | Path],
    epss_paths: list[str | Path],
    kev_path: str | Path,
    mitre_path: str | Path,
    output_path: str | Path = DEFAULT_DB_PATH,
    replace: bool = False,
) -> dict[str, Any]:
    """Build a validated database from local files and atomically publish it."""
    target = Path(output_path).expanduser().resolve()

    if target.exists() and not replace:
        raise FileExistsError(
            f"Database already exists: {target}. "
            "Use replace=True/--replace only after backing it up."
        )

    nvd_files = _source_files(nvd_paths, allowed_suffixes=(".json", ".json.gz", ".zip"))
    epss_files = _source_files(epss_paths, allowed_suffixes=(".csv", ".csv.gz"))
    kev_file = Path(kev_path).expanduser().resolve()
    mitre_file = Path(mitre_path).expanduser().resolve()

    for path in (kev_file, mitre_file):
        if not path.is_file():
            raise FileNotFoundError(f"Input file does not exist: {path}")

    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)

    counts: dict[str, int] = {}

    try:
        connection = sqlite3.connect(temporary)
        try:
            connection.executescript(SCHEMA_SQL)

            count, date, version = _import_nvd(connection, nvd_files)
            counts["nvd"] = connection.execute(
                "SELECT COUNT(*) FROM cves"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "nvd", date, version, counts["nvd"], nvd_files
            )

            count, date, version = _import_epss(connection, epss_files)
            counts["epss"] = connection.execute(
                "SELECT COUNT(*) FROM epss"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "epss", date, version, counts["epss"], epss_files
            )

            count, date, version = _import_kev(connection, kev_file)
            counts["cisa_kev"] = connection.execute(
                "SELECT COUNT(*) FROM kev"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "cisa_kev", date, version, counts["cisa_kev"], [kev_file]
            )

            count, date, version = _import_mitre(connection, mitre_file)
            counts["mitre_attack"] = connection.execute(
                "SELECT COUNT(*) FROM attack_techniques"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "mitre_attack", date, version, counts["mitre_attack"], [mitre_file]
            )

            connection.execute("DELETE FROM cve_search")
            connection.execute(
                "INSERT INTO cve_search(cve_id, description) "
                "SELECT cve_id, description FROM cves"
            )
            connection.execute("DELETE FROM attack_search")
            connection.execute(
                "INSERT INTO attack_search(technique_id, name, description) "
                "SELECT technique_id, name, description FROM attack_techniques"
            )
            connection.commit()

            check = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                raise sqlite3.DatabaseError(
                    f"Staged database integrity check failed: {check}"
                )
        finally:
            connection.close()

        os.replace(temporary, target)

    finally:
        if temporary.exists():
            temporary.unlink()

    return {
        "database": str(target),
        "counts": counts,
        "size_bytes": target.stat().st_size,
        "integrity": "ok",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import local NVD, EPSS, CISA KEV and MITRE ATT&CK files. "
            "This script does not access the network."
        )
    )
    parser.add_argument(
        "--nvd-path",
        action="append",
        required=True,
        help="NVD JSON, JSON.GZ or ZIP file, or directory (repeatable).",
    )
    parser.add_argument(
        "--epss-csv",
        action="append",
        required=True,
        help="EPSS CSV or CSV.GZ file, or directory (repeatable).",
    )
    parser.add_argument("--kev-json", required=True, help="Local CISA KEV JSON file.")
    parser.add_argument("--mitre-json", required=True, help="Local ATT&CK STIX JSON file.")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_DB_PATH),
        help="Output database path (default: data/intel/intel.db).",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace an existing output database after successful import.",
    )
    args = parser.parse_args()

    result = import_sources(
        nvd_paths=args.nvd_path,
        epss_paths=args.epss_csv,
        kev_path=args.kev_json,
        mitre_path=args.mitre_json,
        output_path=args.output,
        replace=args.replace,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
