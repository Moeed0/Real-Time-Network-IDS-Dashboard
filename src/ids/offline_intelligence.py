"""Read-only access to the local, imported IDS intelligence database.

This module intentionally contains no network access.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "intel" / "intel.db"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS source_metadata (
    source TEXT PRIMARY KEY,
    data_as_of TEXT,
    imported_at TEXT NOT NULL,
    version TEXT,
    record_count INTEGER NOT NULL DEFAULT 0,
    files_json TEXT NOT NULL DEFAULT '[]',
    sha256 TEXT
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    published TEXT,
    last_modified TEXT,
    vulnerability_status TEXT,
    cvss_version TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    cvss_vector TEXT,
    cvss_source TEXT,
    cvss_type TEXT,
    cwe_json TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]',
    configurations_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_cves_cvss_score
    ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cves_last_modified
    ON cves(last_modified);

CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY COLLATE NOCASE,
    score REAL,
    percentile REAL,
    score_date TEXT
);

CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY COLLATE NOCASE,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added TEXT,
    short_description TEXT,
    required_action TEXT,
    due_date TEXT,
    known_ransomware_campaign_use TEXT,
    notes TEXT,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id TEXT PRIMARY KEY COLLATE NOCASE,
    stix_id TEXT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    tactics_json TEXT NOT NULL DEFAULT '[]',
    platforms_json TEXT NOT NULL DEFAULT '[]',
    data_sources_json TEXT NOT NULL DEFAULT '[]',
    url TEXT,
    is_subtechnique INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_attack_techniques_name
    ON attack_techniques(name);

CREATE VIRTUAL TABLE IF NOT EXISTS cve_search
    USING fts5(cve_id, description);

CREATE VIRTUAL TABLE IF NOT EXISTS attack_search
    USING fts5(technique_id, name, description);
"""


def _json_value(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    try:
        return json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return default


@contextmanager
def connect_offline_db(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> Iterator[sqlite3.Connection]:
    """Open an existing intelligence database read-only and always close it."""
    path = Path(db_path).expanduser().resolve()

    if not path.is_file():
        raise FileNotFoundError(
            f"Offline intelligence database not found: {path}"
        )

    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
        timeout=5.0,
    )
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        yield connection
    finally:
        connection.close()


def get_source_metadata(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, dict[str, Any]]:
    """Return import dates, versions, counts and provenance for each source."""
    with connect_offline_db(db_path) as connection:
        rows = connection.execute(
            """
            SELECT source, data_as_of, imported_at, version,
                   record_count, files_json, sha256
            FROM source_metadata
            ORDER BY source
            """
        ).fetchall()

    return {
        row["source"]: {
            "source": row["source"],
            "data_as_of": row["data_as_of"],
            "imported_at": row["imported_at"],
            "version": row["version"],
            "record_count": row["record_count"],
            "files": _json_value(row["files_json"], []),
            "sha256": row["sha256"],
        }
        for row in rows
    }


def get_cve_record(
    cve_id: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any] | None:
    """Return an NVD-style CVE summary compatible with Alert Explorer."""
    normalized = str(cve_id).strip().upper()
    if not normalized:
        return None

    with connect_offline_db(db_path) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM cves
            WHERE cve_id = ?
            """,
            (normalized,),
        ).fetchone()

    if row is None:
        return None

    cvss = None
    if row["cvss_score"] is not None:
        cvss = {
            "version": row["cvss_version"],
            "base_score": row["cvss_score"],
            "base_severity": row["cvss_severity"],
            "vector": row["cvss_vector"],
            "source": row["cvss_source"],
            "type": row["cvss_type"],
        }

    return {
        "id": row["cve_id"],
        "description": row["description"],
        "published": row["published"],
        "last_modified": row["last_modified"],
        "vulnerability_status": row["vulnerability_status"],
        "cvss": cvss,
        "cwe": _json_value(row["cwe_json"], []),
        "references": _json_value(row["references_json"], []),
        "configurations": _json_value(row["configurations_json"], []),
    }


def get_epss_record(
    cve_id: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any] | None:
    """Return the locally imported EPSS score and percentile."""
    with connect_offline_db(db_path) as connection:
        row = connection.execute(
            """
            SELECT cve_id, score, percentile, score_date
            FROM epss
            WHERE cve_id = ?
            """,
            (str(cve_id).strip().upper(),),
        ).fetchone()

    if row is None:
        return None

    return {
        "cve": row["cve_id"],
        "epss": row["score"],
        "percentile": row["percentile"],
        "date": row["score_date"],
    }


def get_kev_record(
    cve_id: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any] | None:
    """Return the matching CISA Known Exploited Vulnerabilities entry."""
    with connect_offline_db(db_path) as connection:
        row = connection.execute(
            """
            SELECT details_json
            FROM kev
            WHERE cve_id = ?
            """,
            (str(cve_id).strip().upper(),),
        ).fetchone()

    if row is None:
        return None

    return _json_value(row["details_json"], {})


def get_attack_technique(
    technique_id: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any] | None:
    """Return a locally indexed MITRE ATT&CK technique or sub-technique."""
    normalized = str(technique_id).strip().upper()

    with connect_offline_db(db_path) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM attack_techniques
            WHERE technique_id = ?
            """,
            (normalized,),
        ).fetchone()

    if row is None:
        return None

    return {
        "technique_id": row["technique_id"],
        "stix_id": row["stix_id"],
        "name": row["name"],
        "description": row["description"],
        "tactics": _json_value(row["tactics_json"], []),
        "platforms": _json_value(row["platforms_json"], []),
        "data_sources": _json_value(row["data_sources_json"], []),
        "url": row["url"],
        "is_subtechnique": bool(row["is_subtechnique"]),
    }


def _search_rows(
    table: str,
    query: str,
    limit: int,
    db_path: str | Path,
) -> list[dict[str, Any]]:
    """Search the appropriate FTS5 index using read-only SQL."""
    text = str(query).strip()
    if not text:
        return []

    limit = max(1, min(int(limit), 100))
    tokens = re.findall(r"[A-Za-z0-9]+", text)
    if not tokens:
        return []

    # Whitelist all SQL identifiers; never accept table names from user input.
    search_config = {
        "cve_search": (
            "cve_id, description",
            "cves",
            ("cve_id", "description"),
        ),
        "attack_search": (
            "technique_id, name, description",
            "attack_techniques",
            ("technique_id", "name", "description"),
        ),
    }
    if table not in search_config:
        raise ValueError(f"Unsupported search index: {table}")

    selected_columns, source_table, text_columns = search_config[table]
    match_expression = " AND ".join(f'"{token}"' for token in tokens)

    with connect_offline_db(db_path) as connection:
        try:
            rows = connection.execute(
                f"""
                SELECT {selected_columns}
                FROM {table}
                WHERE {table} MATCH ?
                LIMIT ?
                """,
                (match_expression, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            # Keep searching if this database lacks a working FTS index.
            # Require each term, but permit the terms to appear in any order.
            conditions = []
            params: list[Any] = []
            for token in tokens:
                conditions.append(
                    "(" + " OR ".join(
                        f"{column} LIKE ?" for column in text_columns
                    ) + ")"
                )
                params.extend([f"%{token}%"] * len(text_columns))

            rows = connection.execute(
                f"""
                SELECT {selected_columns}
                FROM {source_table}
                WHERE {" AND ".join(conditions)}
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()

    return [dict(row) for row in rows]


def search_cves(
    query: str,
    limit: int = 20,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    """Search indexed local CVE identifiers and descriptions."""
    text = str(query).strip()
    if not text:
        return []

    if re.match(r"^CVE-", text, re.IGNORECASE):
        with connect_offline_db(db_path) as connection:
            rows = connection.execute(
                """
                SELECT cve_id, description
                FROM cves
                WHERE cve_id LIKE ?
                ORDER BY cve_id
                LIMIT ?
                """,
                (f"{text.upper()}%", max(1, min(int(limit), 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    return _search_rows("cve_search", text, limit, db_path)


def search_attack_techniques(
    query: str,
    limit: int = 20,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    """Search indexed local ATT&CK IDs, technique names and descriptions."""
    text = str(query).strip()
    if not text:
        return []

    if re.match(r"^T\d", text, re.IGNORECASE):
        with connect_offline_db(db_path) as connection:
            rows = connection.execute(
                """
                SELECT technique_id, name, description
                FROM attack_techniques
                WHERE technique_id LIKE ?
                ORDER BY technique_id
                LIMIT ?
                """,
                (f"{text.upper()}%", max(1, min(int(limit), 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    return _search_rows("attack_search", text, limit, db_path)


def lookup_cve(
    cve_id: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    """Combine available local vulnerability sources without network calls."""
    cve = str(cve_id).strip().upper()

    return {
        "cve_id": cve,
        "nvd": get_cve_record(cve, db_path),
        "epss": get_epss_record(cve, db_path),
        "cisa_kev": get_kev_record(cve, db_path),
        "sources": get_source_metadata(db_path),
    }


def get_offline_live_intelligence(
    alert: dict[str, Any],
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> tuple[dict[str, Any], bool]:
    """Build Alert Explorer intelligence using local data only.

    The second return value keeps the existing dashboard callback contract.
    False means this result was built now rather than loaded from the old
    per-alert JSON cache. No network calls are made by this function.
    """
    from datetime import datetime, timezone

    from ids.alert_intelligence import build_alert_intelligence_context
    from ids.extended_alert_intelligence import (
        CVE_RE,
        MITRE_RE,
        _build_explanation,
        _priority_guidance,
        _recursive_ids,
        _rule_reference_cves,
    )

    base = build_alert_intelligence_context(alert)
    if not isinstance(base, dict):
        base = {}

    rule = base.get("rule")
    documentation = base.get("documentation")
    rule = rule if isinstance(rule, dict) else {}
    documentation = documentation if isinstance(documentation, dict) else {}

    cves = sorted(
        set(_rule_reference_cves(rule))
        | set(_recursive_ids(rule, CVE_RE))
        | set(_recursive_ids(documentation, CVE_RE))
        | set(_recursive_ids(alert, CVE_RE))
    )

    mitre_ids = sorted(
        set(_recursive_ids(rule, MITRE_RE))
        | set(_recursive_ids(documentation, MITRE_RE))
        | set(_recursive_ids(alert, MITRE_RE))
    )

    metadata = get_source_metadata(db_path)
    data_as_of = {
        source: record.get("data_as_of")
        for source, record in metadata.items()
    }

    vulnerabilities: dict[str, Any] = {}
    mitre_enrichment: dict[str, list[dict[str, Any]]] = {}
    references: list[dict[str, str]] = []

    max_cvss: float | None = None
    max_epss: float | None = None
    known_exploited = False

    for cve in cves:
        nvd = get_cve_record(cve, db_path) or {}
        epss_record = get_epss_record(cve, db_path) or {}
        kev = get_kev_record(cve, db_path)

        cvss = nvd.get("cvss")
        cvss = cvss if isinstance(cvss, dict) else {}

        try:
            cvss_score = (
                float(cvss["base_score"])
                if cvss.get("base_score") is not None
                else None
            )
        except (TypeError, ValueError):
            cvss_score = None

        try:
            epss_score = (
                float(epss_record["epss"])
                if epss_record.get("epss") is not None
                else None
            )
        except (TypeError, ValueError):
            epss_score = None

        try:
            epss_percentile = (
                float(epss_record["percentile"])
                if epss_record.get("percentile") is not None
                else None
            )
        except (TypeError, ValueError):
            epss_percentile = None

        if cvss_score is not None and (
            max_cvss is None or cvss_score > max_cvss
        ):
            max_cvss = cvss_score

        if epss_score is not None and (
            max_epss is None or epss_score > max_epss
        ):
            max_epss = epss_score

        if kev:
            known_exploited = True

        vulnerabilities[cve] = {
            "nvd": nvd,
            "cisa_kev": kev,
            "epss": {
                "score": epss_score,
                "percentile": epss_percentile,
                "raw": epss_record,
            },
            # CIRCL was intentionally excluded from the selected offline design.
            "circl": {},
        }

        references.append({
            "source": f"NVD {cve}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        })

        for reference in nvd.get("references", []):
            if isinstance(reference, dict) and reference.get("url"):
                references.append({
                    "source": str(reference.get("source") or f"NVD {cve}"),
                    "url": str(reference["url"]),
                })

    for technique_id in mitre_ids:
        details = get_attack_technique(technique_id, db_path)
        if details:
            mitre_enrichment[technique_id] = [details]
            if details.get("url"):
                references.append({
                    "source": f"MITRE ATT&CK {technique_id}",
                    "url": str(details["url"]),
                })

    priority = _priority_guidance(
        max_cvss,
        max_epss,
        known_exploited,
    )

    explanation = _build_explanation(
        alert,
        base,
        cves,
        mitre_ids,
        vulnerabilities,
    )

    source_urls = {
        "nvd": "Local NVD JSON 2.0 snapshot",
        "epss": "Local FIRST EPSS CSV snapshot",
        "cisa_kev": "Local CISA Known Exploited Vulnerabilities snapshot",
        "mitre_attack": "Local MITRE ATT&CK STIX snapshot",
        "rule_database": "data/lab/rules/ids_rules.db",
        "rule_documentation": "data/json/rule_docs_preprocessed_by_sid.json",
        "database": str(Path(db_path).resolve()),
    }

    source_urls.update({
        "nvd_reference": "https://nvd.nist.gov/",
        "epss_reference": "https://www.first.org/epss/",
        "cisa_kev_reference": (
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        ),
        "mitre_attack_reference": "https://attack.mitre.org/",
    })

    seen_urls: set[str] = set()
    deduped_references: list[dict[str, str]] = []
    for reference in references:
        url = reference.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        deduped_references.append(reference)

    context = {
        "alert": alert,
        "base_intelligence": base,
        "identifiers": {
            "cves": cves,
            "mitre_attack": mitre_ids,
        },
        "vulnerabilities": vulnerabilities,
        "mitre_enrichment": mitre_enrichment,
        "risk_context": {
            "priority_guidance": priority,
            "highest_cvss": max_cvss,
            "highest_epss": max_epss,
            "known_exploited": known_exploited,
            "known_exploited_cves": [
                cve
                for cve, details in vulnerabilities.items()
                if details.get("cisa_kev")
            ],
            "disclaimer": (
                "This is vulnerability-priority context, not proof that "
                "the alert is malicious or that exploitation succeeded."
            ),
        },
        "explanation": explanation,
        "references": deduped_references,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "sources": source_urls,
        "data_as_of": data_as_of,
        "lookup_mode": "offline_local",
    }

    return context, False
