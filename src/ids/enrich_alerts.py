#!/usr/bin/env python3

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data/lab/normalized/all_alerts_normalized.json"

OUTPUT_DIR = PROJECT_ROOT / "data/lab/enriched"

SNORT_OUTPUT = OUTPUT_DIR / "snort_enriched_alerts.json"
SURICATA_OUTPUT = OUTPUT_DIR / "suricata_enriched_alerts.json"
COMBINED_OUTPUT = OUTPUT_DIR / "all_alerts_enriched.json"
SUMMARY_OUTPUT = OUTPUT_DIR / "enrichment_summary.json"

NVD_DIR = PROJECT_ROOT / "data/lab/intelligence/nvd/cves"
NVD_BATCH_CACHE = PROJECT_ROOT / "data/lab/intelligence/nvd"

MITRE_DIR = PROJECT_ROOT / "data/lab/intelligence/mitre"
MITRE_FILE = MITRE_DIR / "enterprise-attack-19.2.json"
MITRE_META_FILE = MITRE_DIR / "enterprise-attack-19.2.meta.json"

CISA_DIR = PROJECT_ROOT / "data/lab/intelligence/cisa"
CISA_FILE = CISA_DIR / "known_exploited_vulnerabilities.json"
CISA_META_FILE = CISA_DIR / "kev.meta.json"


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/"
    "enterprise-attack-19.2.json"
)

CISA_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CISA_MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)

USER_AGENT = (
    "Real-Time-Network-IDS-Dashboard/1.0 "
    "(controlled IDS research enrichment)"
)

CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

MITRE_RE = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        return json.load(handle)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temporary.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    temporary.replace(path)


def http_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 60,
    retries: int = 4,
) -> Any:

    merged_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    if headers:
        merged_headers.update(headers)

    last_error = None

    for attempt in range(retries + 1):

        request = urllib.request.Request(
            url,
            headers=merged_headers,
            method="GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:

                raw = response.read()

                return json.loads(
                    raw.decode(
                        "utf-8",
                        errors="replace",
                    )
                )

        except urllib.error.HTTPError as exc:

            last_error = exc

            if exc.code in (429, 500, 502, 503, 504):

                if attempt < retries:

                    delay = 2 ** attempt

                    print(
                        f"HTTP {exc.code} from {url} "
                        f"- retrying in {delay}s..."
                    )

                    time.sleep(delay)
                    continue

            raise

        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:

            last_error = exc

            if attempt < retries:

                delay = 2 ** attempt

                print(
                    f"Request error for {url}: {exc} "
                    f"- retrying in {delay}s..."
                )

                time.sleep(delay)

                continue

            raise

    raise RuntimeError(
        f"Request failed: {url}: {last_error}"
    )


def download_json(
    url: str,
    destination: Path,
    timeout: int = 120,
) -> Any:

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
        method="GET",
    )

    print(f"Downloading: {url}")
    print(f"Saving to:  {destination}")

    with urllib.request.urlopen(
        request,
        timeout=timeout,
    ) as response:

        total = response.headers.get(
            "Content-Length"
        )

        total_size = (
            int(total)
            if total
            else None
        )

        downloaded = 0

        temporary = destination.with_suffix(
            destination.suffix + ".tmp"
        )

        with temporary.open("wb") as output:

            while True:

                chunk = response.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                output.write(chunk)
                downloaded += len(chunk)

                if total_size:

                    percent = (
                        downloaded
                        / total_size
                        * 100
                    )

                    print(
                        f"\r  {downloaded / 1024 / 1024:.1f} MB "
                        f"/ {total_size / 1024 / 1024:.1f} MB "
                        f"({percent:.1f}%)",
                        end="",
                        flush=True,
                    )

                else:

                    print(
                        f"\r  {downloaded / 1024 / 1024:.1f} MB",
                        end="",
                        flush=True,
                    )

        print()

        temporary.replace(destination)

    print("Download complete.")

    data = load_json(destination)

    if data is None:
        raise RuntimeError(
            f"Downloaded file is not valid JSON: {destination}"
        )

    return data


def refresh_required(
    path: Path,
    force: bool,
) -> bool:

    if force:
        return True

    return not path.exists()


def recursively_find_ids(
    value: Any,
    regex: re.Pattern[str],
    path: str = "$",
) -> dict[str, list[str]]:

    found: dict[str, list[str]] = {}

    def add(
        identifier: str,
        location: str,
    ) -> None:

        identifier = identifier.upper()

        found.setdefault(
            identifier,
            [],
        ).append(location)

    if isinstance(value, dict):

        for key, child in value.items():

            child_path = (
                f"{path}.{key}"
            )

            nested = recursively_find_ids(
                child,
                regex,
                child_path,
            )

            for identifier, locations in nested.items():

                for location in locations:

                    add(
                        identifier,
                        location,
                    )

    elif isinstance(value, list):

        for index, child in enumerate(value):

            child_path = (
                f"{path}[{index}]"
            )

            nested = recursively_find_ids(
                child,
                regex,
                child_path,
            )

            for identifier, locations in nested.items():

                for location in locations:

                    add(
                        identifier,
                        location,
                    )

    elif isinstance(value, str):

        for match in regex.finditer(value):

            add(
                match.group(0),
                path,
            )

    return found


def merge_identifier_maps(
    *maps: dict[str, list[str]]
) -> dict[str, list[str]]:

    result: dict[str, list[str]] = {}

    for mapping in maps:

        for identifier, locations in mapping.items():

            result.setdefault(
                identifier,
                [],
            )

            for location in locations:

                if location not in result[identifier]:

                    result[identifier].append(
                        location
                    )

    return result


def extract_alert_identifiers(
    record: dict[str, Any],
) -> dict[str, Any]:

    rule_part = record.get(
        "rule",
        {},
    )

    project_part = record.get(
        "project_enrichment",
        {},
    )

    native_part = record.get(
        "native_event",
        {},
    )

    rule_cves = recursively_find_ids(
        rule_part,
        CVE_RE,
    )

    project_cves = recursively_find_ids(
        project_part,
        CVE_RE,
    )

    native_cves = recursively_find_ids(
        native_part,
        CVE_RE,
    )

    rule_mitre = recursively_find_ids(
        rule_part,
        MITRE_RE,
    )

    project_mitre = recursively_find_ids(
        project_part,
        MITRE_RE,
    )

    native_mitre = recursively_find_ids(
        native_part,
        MITRE_RE,
    )

    cves = merge_identifier_maps(
        rule_cves,
        project_cves,
        native_cves,
    )

    mitre_ids = merge_identifier_maps(
        rule_mitre,
        project_mitre,
        native_mitre,
    )

    return {
        "cves": cves,
        "mitre": mitre_ids,
        "source_locations": {
            "rule": {
                "cves": rule_cves,
                "mitre": rule_mitre,
            },
            "project_documentation": {
                "cves": project_cves,
                "mitre": project_mitre,
            },
            "native_event": {
                "cves": native_cves,
                "mitre": native_mitre,
            },
        },
    }


def cache_is_valid(
    path: Path,
    force: bool,
) -> bool:

    if force:
        return False

    return path.exists()


def fetch_nvd_cves(
    cves: list[str],
    force: bool,
    api_key: str | None,
) -> tuple[dict[str, Any], dict[str, str]]:

    NVD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    results: dict[str, Any] = {}
    errors: dict[str, str] = {}

    missing = []

    for cve in cves:

        cache_file = NVD_DIR / f"{cve}.json"

        if cache_is_valid(
            cache_file,
            force,
        ):

            cached = load_json(
                cache_file,
                None,
            )

            if cached is not None:

                results[cve] = cached

                continue

        missing.append(cve)

    if not missing:

        return results, errors

    print()
    print(
        f"NVD: {len(missing)} CVE(s) need lookup."
    )

    batches = [
        missing[i:i + 100]
        for i in range(
            0,
            len(missing),
            100,
        )
    ]

    headers = {}

    if api_key:

        headers["apiKey"] = api_key

    for batch_number, batch in enumerate(
        batches,
        start=1,
    ):

        params = urllib.parse.urlencode(
            {
                "cveIds": ",".join(batch),
                "resultsPerPage": 100,
            }
        )

        url = f"{NVD_API}?{params}"

        print(
            f"NVD batch {batch_number}/{len(batches)} "
            f"({len(batch)} CVE(s))"
        )

        try:

            response = http_json(
                url,
                headers=headers,
                timeout=60,
            )

            vulnerabilities = response.get(
                "vulnerabilities",
                [],
            )

            found_this_batch = set()

            for item in vulnerabilities:

                cve_obj = item.get(
                    "cve",
                    {},
                )

                cve_id = (
                    cve_obj.get("id")
                    or ""
                ).upper()

                if not cve_id:
                    continue

                cache_file = (
                    NVD_DIR
                    / f"{cve_id}.json"
                )

                write_json(
                    cache_file,
                    item,
                )

                results[cve_id] = item

                found_this_batch.add(
                    cve_id
                )

            for requested in batch:

                if requested not in found_this_batch:

                    errors[requested] = (
                        "NVD returned no record"
                    )

        except Exception as exc:

            message = str(exc)

            for requested in batch:

                errors[requested] = message

        if batch_number < len(batches):

            # Keep requests polite when more than one batch is needed.
            time.sleep(2)

    return results, errors


def extract_metric_list(
    metrics: dict[str, Any],
    key: str,
) -> list[dict[str, Any]]:

    value = metrics.get(key, [])

    if isinstance(value, list):
        return value

    return []


def summarize_nvd(
    item: dict[str, Any],
) -> dict[str, Any]:

    cve = item.get(
        "cve",
        {},
    )

    metrics = cve.get(
        "metrics",
        {},
    )

    descriptions = cve.get(
        "descriptions",
        [],
    )

    weaknesses = cve.get(
        "weaknesses",
        [],
    )

    references = cve.get(
        "references",
        [],
    )

    return {
        "id": cve.get("id"),
        "source_identifier": cve.get(
            "sourceIdentifier"
        ),
        "published": cve.get(
            "published"
        ),
        "last_modified": cve.get(
            "lastModified"
        ),
        "vulnerability_status": cve.get(
            "vulnStatus"
        ),

        "descriptions": descriptions,

        "weaknesses": weaknesses,

        "cvss": {
            "v4": extract_metric_list(
                metrics,
                "cvssMetricV40",
            ),
            "v3_1": extract_metric_list(
                metrics,
                "cvssMetricV31",
            ),
            "v3_0": extract_metric_list(
                metrics,
                "cvssMetricV30",
            ),
            "v2": extract_metric_list(
                metrics,
                "cvssMetricV2",
            ),
        },

        "configurations": cve.get(
            "configurations",
            [],
        ),

        "references": references,

        "vendor_comments": cve.get(
            "vendorComments",
            [],
        ),

        "cisa": {
            "exploit_add": cve.get(
                "cisaExploitAdd"
            ),
            "action_due": cve.get(
                "cisaActionDue"
            ),
            "required_action": cve.get(
                "cisaRequiredAction"
            ),
        },

        "raw_nvd_record": item,
    }


def load_cisa_kev(
    force: bool,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:

    CISA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = None
    source_url = None

    if not refresh_required(
        CISA_FILE,
        force,
    ):

        data = load_json(
            CISA_FILE,
            None,
        )

        source_url = (
            CISA_MIRROR_URL
            if data is not None
            else None
        )

    if data is None:

        try:

            data = download_json(
                CISA_URL,
                CISA_FILE,
            )

            source_url = CISA_URL

        except Exception as exc:

            print(
                f"CISA canonical feed failed: {exc}"
            )

            print(
                "Trying the CISA-maintained GitHub mirror..."
            )

            data = download_json(
                CISA_MIRROR_URL,
                CISA_FILE,
            )

            source_url = CISA_MIRROR_URL

    vulnerabilities = data.get(
        "vulnerabilities",
        [],
    )

    kev_map = {}

    for entry in vulnerabilities:

        cve_id = (
            entry.get("cveID")
            or ""
        ).upper()

        if cve_id:

            kev_map[cve_id] = entry

    meta = {
        "retrieved_at": utc_now(),
        "source_url": source_url,
        "catalog_version": data.get(
            "catalogVersion"
        ),
        "date_released": data.get(
            "dateReleased"
        ),
        "count": data.get(
            "count",
            len(vulnerabilities),
        ),
    }

    write_json(
        CISA_META_FILE,
        meta,
    )

    return kev_map, meta


def download_mitre(
    force: bool,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:

    MITRE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = None

    if not refresh_required(
        MITRE_FILE,
        force,
    ):

        data = load_json(
            MITRE_FILE,
            None,
        )

    if data is None:

        data = download_json(
            MITRE_URL,
            MITRE_FILE,
            timeout=300,
        )

    objects = data.get(
        "objects",
        [],
    )

    meta = {
        "retrieved_at": utc_now(),
        "source_url": MITRE_URL,
        "dataset_version": "19.2",
        "object_count": len(objects),
    }

    write_json(
        MITRE_META_FILE,
        meta,
    )

    return data, meta


def build_mitre_index(
    bundle: dict[str, Any],
) -> dict[str, Any]:

    objects = bundle.get(
        "objects",
        [],
    )

    objects_by_id = {}
    techniques = {}
    relationships = []

    for obj in objects:

        object_id = obj.get(
            "id"
        )

        if object_id:

            objects_by_id[
                object_id
            ] = obj

        if obj.get(
            "type"
        ) == "attack-pattern":

            attack_id = None

            for reference in obj.get(
                "external_references",
                [],
            ):

                if (
                    reference.get(
                        "source_name"
                    ) == "mitre-attack"
                    and reference.get(
                        "external_id"
                    )
                ):

                    attack_id = (
                        reference.get(
                            "external_id"
                        )
                    ).upper()

                    break

            if attack_id:

                techniques[
                    attack_id
                ] = obj

        elif obj.get(
            "type"
        ) == "relationship":

            if (
                obj.get(
                    "relationship_type"
                ) == "uses"
            ):

                relationships.append(
                    obj
                )

    procedure_map: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for relationship in relationships:

        target_ref = relationship.get(
            "target_ref"
        )

        if target_ref not in objects_by_id:
            continue

        target = objects_by_id[
            target_ref
        ]

        if target.get(
            "type"
        ) != "attack-pattern":
            continue

        attack_id = None

        for reference in target.get(
            "external_references",
            [],
        ):

            if (
                reference.get(
                    "source_name"
                ) == "mitre-attack"
                and reference.get(
                    "external_id"
                )
            ):

                attack_id = (
                    reference.get(
                        "external_id"
                    )
                ).upper()

                break

        if not attack_id:
            continue

        source_ref = relationship.get(
            "source_ref"
        )

        source = objects_by_id.get(
            source_ref
        )

        if not source:
            continue

        procedure_map.setdefault(
            attack_id,
            [],
        ).append(
            {
                "relationship_id":
                    relationship.get("id"),
                "source_object_type":
                    source.get("type"),
                "source_object_id":
                    source.get("id"),
                "source_name":
                    source.get("name"),
                "source_description":
                    source.get("description"),
                "relationship_description":
                    relationship.get(
                        "description"
                    ),
                "created":
                    relationship.get(
                        "created"
                    ),
                "modified":
                    relationship.get(
                        "modified"
                    ),
            }
        )

    return {
        "objects_by_id": objects_by_id,
        "techniques": techniques,
        "procedures": procedure_map,
    }


def summarize_mitre_technique(
    technique_id: str,
    mitre_index: dict[str, Any],
) -> dict[str, Any]:

    technique = (
        mitre_index[
            "techniques"
        ].get(
            technique_id.upper()
        )
    )

    if technique is None:

        return {
            "found": False,
            "technique_id": technique_id,
            "source": "MITRE ATT&CK Enterprise v19.2",
        }

    external_references = []

    for reference in technique.get(
        "external_references",
        [],
    ):

        if (
            reference.get(
                "source_name"
            ) == "mitre-attack"
        ):

            external_references.append(
                {
                    "source_name":
                        reference.get(
                            "source_name"
                        ),
                    "external_id":
                        reference.get(
                            "external_id"
                        ),
                    "url":
                        reference.get(
                            "url"
                        ),
                }
            )

    procedures = (
        mitre_index[
            "procedures"
        ].get(
            technique_id.upper(),
            [],
        )
    )

    # Keep the alert useful without exploding the JSON.
    procedures = procedures[:25]

    return {
        "found": True,
        "technique_id": technique_id.upper(),
        "name": technique.get(
            "name"
        ),
        "description": technique.get(
            "description"
        ),
        "revoked": technique.get(
            "revoked",
            False,
        ),
        "deprecated": technique.get(
            "x_mitre_deprecated",
            False,
        ),
        "created": technique.get(
            "created"
        ),
        "modified": technique.get(
            "modified"
        ),
        "version": technique.get(
            "x_mitre_version"
        ),
        "domains": technique.get(
            "x_mitre_domains"
        ),
        "platforms": technique.get(
            "x_mitre_platforms"
        ),
        "permissions_required": technique.get(
            "x_mitre_permissions_required"
        ),
        "kill_chain_phases": technique.get(
            "kill_chain_phases",
            [],
        ),
        "external_references":
            external_references,
        "procedure_examples":
            procedures,
        "raw_attack_pattern":
            technique,
        "source":
            "MITRE ATT&CK Enterprise v19.2",
    }


def enrich_alert(
    record: dict[str, Any],
    identifier_info: dict[str, Any],
    nvd_records: dict[str, Any],
    nvd_errors: dict[str, str],
    kev_map: dict[str, Any],
    kev_meta: dict[str, Any],
    mitre_index: dict[str, Any],
) -> dict[str, Any]:

    enriched = dict(record)

    cve_ids = sorted(
        identifier_info[
            "cves"
        ].keys()
    )

    mitre_ids = sorted(
        identifier_info[
            "mitre"
        ].keys()
    )

    nvd_enrichment = []

    for cve_id in cve_ids:

        item = nvd_records.get(
            cve_id
        )

        kev_entry = kev_map.get(
            cve_id
        )

        if item is not None:

            nvd_data = summarize_nvd(
                item
            )

            nvd_data[
                "lookup_status"
            ] = "found"

        else:

            nvd_data = {
                "id": cve_id,
                "lookup_status":
                    "not_found_or_unavailable",
                "error":
                    nvd_errors.get(
                        cve_id
                    ),
            }

        nvd_data[
            "cisa_kev"
        ] = {
            "is_known_exploited": (
                kev_entry is not None
            ),
            "catalog_version":
                kev_meta.get(
                    "catalog_version"
                ),
            "entry":
                kev_entry,
        }

        nvd_enrichment.append(
            nvd_data
        )

    mitre_enrichment = []

    for technique_id in mitre_ids:

        mitre_enrichment.append(
            summarize_mitre_technique(
                technique_id,
                mitre_index,
            )
        )

    enriched[
        "external_enrichment"
    ] = {
        "enrichment_version": "1.0",

        "retrieved_at": utc_now(),

        "identifiers": {
            "cve_ids": cve_ids,
            "mitre_technique_ids": mitre_ids,
        },

        "identifier_locations":
            identifier_info[
                "source_locations"
            ],

        "nvd": {
            "lookup_performed":
                len(cve_ids) > 0,
            "records":
                nvd_enrichment,
        },

        "cisa_kev": {
            "lookup_performed":
                len(cve_ids) > 0,
            "catalog_version":
                kev_meta.get(
                    "catalog_version"
                ),
            "entries": [
                kev_map[cve]
                for cve in cve_ids
                if cve in kev_map
            ],
        },

        "mitre_attack": {
            "lookup_performed":
                len(mitre_ids) > 0,
            "dataset_version":
                "19.2",
            "techniques":
                mitre_enrichment,
        },

        "provenance": {
            "nvd":
                NVD_API,
            "cisa_kev":
                kev_meta.get(
                    "source_url"
                ),
            "mitre":
                MITRE_URL,
        },

        "status": (
            "enriched"
            if cve_ids
            or mitre_ids
            else "no_external_identifier"
        ),
    }

    return enriched


def build_summary(
    records: list[dict[str, Any]],
    nvd_errors: dict[str, str],
    kev_meta: dict[str, Any],
) -> dict[str, Any]:

    snort = [
        r
        for r in records
        if r.get("engine") == "Snort"
    ]

    suricata = [
        r
        for r in records
        if r.get("engine") == "Suricata"
    ]

    all_cves = set()
    all_mitre = set()

    kev_alerts = 0
    nvd_found_alerts = 0
    mitre_found_alerts = 0

    for record in records:

        external = record.get(
            "external_enrichment",
            {},
        )

        identifiers = external.get(
            "identifiers",
            {},
        )

        cves = identifiers.get(
            "cve_ids",
            [],
        )

        mitre_ids = identifiers.get(
            "mitre_technique_ids",
            [],
        )

        all_cves.update(cves)
        all_mitre.update(mitre_ids)

        if any(
            x.get(
                "lookup_status"
            ) == "found"
            for x in external.get(
                "nvd",
                {}
            ).get(
                "records",
                []
            )
        ):
            nvd_found_alerts += 1

        if any(
            x.get(
                "cisa_kev"
            ).get(
                "is_known_exploited"
            )
            for x in external.get(
                "nvd",
                {}
            ).get(
                "records",
                []
            )
            if isinstance(
                x.get(
                    "cisa_kev"
                ),
                dict,
            )
        ):
            kev_alerts += 1

        if any(
            x.get(
                "found"
            )
            for x in external.get(
                "mitre_attack",
                {}
            ).get(
                "techniques",
                []
            )
        ):
            mitre_found_alerts += 1

    return {
        "generated_at": utc_now(),
        "input_alerts": len(records),

        "snort_alerts": len(snort),
        "suricata_alerts": len(suricata),

        "combined_alerts": len(records),

        "unique_cves": sorted(
            all_cves
        ),

        "unique_mitre_techniques": sorted(
            all_mitre
        ),

        "unique_cve_count": len(
            all_cves
        ),

        "unique_mitre_technique_count": len(
            all_mitre
        ),

        "alerts_with_nvd_data":
            nvd_found_alerts,

        "alerts_with_cisa_kev":
            kev_alerts,

        "alerts_with_mitre_data":
            mitre_found_alerts,

        "nvd_lookup_errors":
            nvd_errors,

        "cisa_kev_catalog": kev_meta,

        "enrichment_sources": {
            "project_documentation":
                "data/json/rule_docs_preprocessed_by_sid.json",
            "rule_index":
                "data/lab/rules/ids_rules.db",
            "nvd":
                NVD_API,
            "cisa_kev":
                "CISA Known Exploited Vulnerabilities Catalog",
            "mitre":
                "MITRE ATT&CK Enterprise v19.2",
        },
    }


def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Enrich normalized Snort and Suricata alerts "
            "with NVD, CISA KEV and MITRE ATT&CK data."
        )
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Refresh cached NVD CVEs, CISA KEV and "
            "MITRE ATT&CK data."
        ),
    )

    args = parser.parse_args()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    records = load_json(
        INPUT_FILE,
        None,
    )

    if not isinstance(
        records,
        list,
    ):
        raise SystemExit(
            f"Input dataset not found or invalid: {INPUT_FILE}"
        )

    print(
        f"Loaded {len(records)} normalized alerts."
    )

    # ----------------------------------------
    # Extract identifiers
    # ----------------------------------------

    identifier_info_by_index = []

    all_cves = set()
    all_mitre = set()

    for record in records:

        info = extract_alert_identifiers(
            record
        )

        identifier_info_by_index.append(
            info
        )

        all_cves.update(
            info[
                "cves"
            ].keys()
        )

        all_mitre.update(
            info[
                "mitre"
            ].keys()
        )

    all_cves = sorted(
        all_cves
    )

    all_mitre = sorted(
        all_mitre
    )

    print()
    print(
        f"Unique CVEs found: {len(all_cves)}"
    )

    for cve in all_cves:
        print(
            f"  {cve}"
        )

    print()
    print(
        "Unique MITRE techniques found: "
        f"{len(all_mitre)}"
    )

    for technique in all_mitre:
        print(
            f"  {technique}"
        )

    # ----------------------------------------
    # NVD
    # ----------------------------------------

    api_key = None

    # Optional environment variable.
    import os

    api_key = os.environ.get(
        "NVD_API_KEY"
    )

    nvd_records, nvd_errors = (
        fetch_nvd_cves(
            all_cves,
            args.refresh,
            api_key,
        )
    )

    # ----------------------------------------
    # CISA KEV
    # ----------------------------------------

    kev_map, kev_meta = load_cisa_kev(
        args.refresh
    )

    # ----------------------------------------
    # MITRE ATT&CK
    # ----------------------------------------

    if all_mitre:

        mitre_bundle, mitre_meta = (
            download_mitre(
                args.refresh
            )
        )

        mitre_index = build_mitre_index(
            mitre_bundle
        )

        print()
        print(
            "MITRE ATT&CK techniques indexed: "
            f"{len(mitre_index['techniques'])}"
        )

    else:

        mitre_index = {
            "objects_by_id": {},
            "techniques": {},
            "procedures": {},
        }

        mitre_meta = {
            "dataset_version": "19.2",
            "object_count": 0,
        }

    # ----------------------------------------
    # Enrich
    # ----------------------------------------

    enriched_records = []

    for index, record in enumerate(
        records,
        start=1,
    ):

        enriched = enrich_alert(
            record,
            identifier_info_by_index[
                index - 1
            ],
            nvd_records,
            nvd_errors,
            kev_map,
            kev_meta,
            mitre_index,
        )

        enriched_records.append(
            enriched
        )

        if index % 25 == 0:

            print(
                f"Enriched {index}/{len(records)} alerts..."
            )

    # ----------------------------------------
    # Outputs
    # ----------------------------------------

    snort_records = [
        r
        for r in enriched_records
        if r.get("engine") == "Snort"
    ]

    suricata_records = [
        r
        for r in enriched_records
        if r.get("engine") == "Suricata"
    ]

    write_json(
        SNORT_OUTPUT,
        snort_records,
    )

    write_json(
        SURICATA_OUTPUT,
        suricata_records,
    )

    write_json(
        COMBINED_OUTPUT,
        enriched_records,
    )

    summary = build_summary(
        enriched_records,
        nvd_errors,
        kev_meta,
    )

    summary[
        "mitre_dataset"
    ] = mitre_meta

    write_json(
        SUMMARY_OUTPUT,
        summary,
    )

    print()
    print("=" * 70)
    print("EXTERNAL ENRICHMENT COMPLETE")
    print("=" * 70)

    print(
        f"Snort alerts:      {len(snort_records)}"
    )

    print(
        f"Suricata alerts:   {len(suricata_records)}"
    )

    print(
        f"Combined alerts:   {len(enriched_records)}"
    )

    print(
        f"Unique CVEs:       {len(all_cves)}"
    )

    print(
        f"Unique MITRE IDs:  {len(all_mitre)}"
    )

    print(
        "NVD records found: "
        f"{len(nvd_records)}"
    )

    print(
        "NVD lookup errors: "
        f"{len(nvd_errors)}"
    )

    print(
        "CISA KEV entries:  "
        f"{sum(1 for cve in all_cves if cve in kev_map)}"
    )

    print()
    print(
        f"Output: {COMBINED_OUTPUT}"
    )

    print(
        f"Summary: {SUMMARY_OUTPUT}"
    )


if __name__ == "__main__":
    main()
