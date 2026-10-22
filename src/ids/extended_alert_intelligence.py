#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from ids.alert_intelligence import (
    build_alert_intelligence_context,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

NVD_DIR = (
    PROJECT_ROOT
    / "data/lab/intelligence/nvd/cves"
)

CISA_FILE = (
    PROJECT_ROOT
    / "data/lab/intelligence/cisa"
    / "known_exploited_vulnerabilities.json"
)

EPSS_DIR = (
    PROJECT_ROOT
    / "data/lab/intelligence/epss"
)

CIRCL_DIR = (
    PROJECT_ROOT
    / "data/lab/intelligence/circl"
)

ENRICHED_ALERTS_FILE = (
    PROJECT_ROOT
    / "data/lab/enriched/all_alerts_enriched.json"
)

NVD_API = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

EPSS_API = (
    "https://api.first.org/data/v1/epss"
)

CIRCL_API = (
    "https://vulnerability.circl.lu/api/vulnerability"
)

CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

MITRE_RE = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)

CACHE_MAX_AGE_SECONDS = 24 * 60 * 60


def _now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _read_json(
    path: Path,
) -> Any:

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def _write_json(
    path: Path,
    value: Any,
) -> None:

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
            value,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    temporary.replace(path)


def _cache_is_fresh(
    path: Path,
    max_age_seconds: int = CACHE_MAX_AGE_SECONDS,
) -> bool:

    if not path.exists():
        return False

    age = (
        time.time()
        - path.stat().st_mtime
    )

    return age < max_age_seconds


def _load_project_env() -> None:

    env_file = (
        PROJECT_ROOT
        / ".env"
    )

    if not env_file.exists():
        return

    for raw_line in env_file.read_text(
        encoding="utf-8"
    ).splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split(
            "=",
            1,
        )

        key = key.strip()

        if not key:
            continue

        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {
                '"',
                "'",
            }
        ):
            value = value[1:-1]

        os.environ.setdefault(
            key,
            value,
        )


def _get_nvd_api_key() -> str | None:

    _load_project_env()

    value = os.environ.get(
        "NVD_API_KEY"
    )

    if value:
        return value.strip()

    return None


def _request_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> Any:

    request_headers = {
        "User-Agent": (
            "Real-Time-Network-IDS-Dashboard/"
            "extended-alert-intelligence"
        ),
        "Accept": "application/json",
    }

    if headers:
        request_headers.update(
            headers
        )

    request = urllib.request.Request(
        url,
        headers=request_headers,
        method="GET",
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout,
    ) as response:

        raw = response.read()

    return json.loads(
        raw.decode("utf-8")
    )


def _recursive_ids(
    value: Any,
    pattern: re.Pattern[str],
) -> list[str]:

    found: set[str] = set()

    def walk(item: Any) -> None:

        if isinstance(item, str):

            for match in pattern.findall(
                item
            ):
                found.add(
                    match.upper()
                )

            return

        if isinstance(item, dict):

            for child in item.values():
                walk(child)

            return

        if isinstance(item, list):

            for child in item:
                walk(child)

    walk(value)

    return sorted(found)


def _json_list(
    value: Any,
) -> list[Any]:

    if value is None:
        return []

    if isinstance(
        value,
        list,
    ):
        return value

    if isinstance(
        value,
        str,
    ):

        try:

            parsed = json.loads(
                value
            )

            if isinstance(
                parsed,
                list,
            ):
                return parsed

            if parsed:
                return [parsed]

        except json.JSONDecodeError:
            return [
                value
            ]

    return [
        value
    ]


def _load_cached_nvd(
    cve_id: str,
) -> dict[str, Any] | None:

    path = (
        NVD_DIR
        / f"{cve_id.upper()}.json"
    )

    if not path.exists():
        return None

    try:
        value = _read_json(path)
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None

    if not isinstance(
        value,
        dict,
    ):
        return None

    return value


def _fetch_nvd(
    cve_id: str,
    force: bool = False,
) -> dict[str, Any] | None:

    cache = _load_cached_nvd(
        cve_id
    )

    path = (
        NVD_DIR
        / f"{cve_id.upper()}.json"
    )

    if (
        cache is not None
        and not force
    ):
        return cache

    api_key = _get_nvd_api_key()

    if not api_key:
        return cache

    query = urllib.parse.urlencode(
        {
            "cveId": cve_id.upper(),
            "resultsPerPage": "20",
        }
    )

    try:

        data = _request_json(
            f"{NVD_API}?{query}",
            headers={
                "apiKey": api_key,
            },
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ):

        return cache

    _write_json(
        path,
        data,
    )

    return data


def _extract_nvd_item(
    data: dict[str, Any] | None,
) -> dict[str, Any] | None:

    if not data:
        return None

    vulnerabilities = data.get(
        "vulnerabilities"
    )

    if isinstance(
        vulnerabilities,
        list,
    ):

        if vulnerabilities:

            item = vulnerabilities[0]

            if isinstance(
                item,
                dict,
            ):
                return item

        return None

    if "cve" in data:
        return data

    return None


def _extract_cvss(
    cve: dict[str, Any],
) -> dict[str, Any] | None:

    metrics = cve.get(
        "metrics"
    )

    if not isinstance(
        metrics,
        dict,
    ):
        return None

    ordered_versions = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for version_key in ordered_versions:

        entries = metrics.get(
            version_key
        )

        if not isinstance(
            entries,
            list,
        ):
            continue

        for entry in entries:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            cvss_data = entry.get(
                "cvssData"
            )

            if not isinstance(
                cvss_data,
                dict,
            ):
                continue

            return {
                "version": cvss_data.get(
                    "version"
                ),
                "base_score": cvss_data.get(
                    "baseScore"
                ),
                "base_severity": (
                    cvss_data.get(
                        "baseSeverity"
                    )
                    or entry.get(
                        "baseSeverity"
                    )
                ),
                "vector": cvss_data.get(
                    "vectorString"
                ),
                "source": entry.get(
                    "source"
                ),
                "type": entry.get(
                    "type"
                ),
            }

    return None


def _extract_nvd_summary(
    data: dict[str, Any] | None,
) -> dict[str, Any]:

    item = _extract_nvd_item(
        data
    )

    if not item:
        return {}

    cve = item.get(
        "cve",
        {}
    )

    if not isinstance(
        cve,
        dict,
    ):
        return {}

    descriptions = cve.get(
        "descriptions",
        []
    )

    description = ""

    if isinstance(
        descriptions,
        list,
    ):

        for entry in descriptions:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            if entry.get(
                "lang"
            ) == "en":

                description = str(
                    entry.get(
                        "value",
                        ""
                    )
                )

                break

    weaknesses: list[str] = []

    for weakness in cve.get(
        "weaknesses",
        [],
    ):

        if not isinstance(
            weakness,
            dict,
        ):
            continue

        for desc in weakness.get(
            "description",
            [],
        ):

            if not isinstance(
                desc,
                dict,
            ):
                continue

            value = desc.get(
                "value"
            )

            if value:
                weaknesses.append(
                    str(value)
                )

    references: list[dict[str, Any]] = []

    for reference in cve.get(
        "references",
        [],
    ):

        if not isinstance(
            reference,
            dict,
        ):
            continue

        url = reference.get(
            "url"
        )

        if not url:
            continue

        references.append(
            {
                "url": url,
                "source": reference.get(
                    "source"
                ),
                "tags": reference.get(
                    "tags",
                    [],
                ),
            }
        )

    return {
        "id": cve.get(
            "id"
        ),
        "description": description,
        "published": cve.get(
            "published"
        ),
        "last_modified": cve.get(
            "lastModified"
        ),
        "vulnerability_status": cve.get(
            "vulnStatus"
        ),
        "cvss": _extract_cvss(
            cve
        ),
        "cwe": sorted(
            set(
                weaknesses
            )
        ),
        "references": references,
        "configurations": cve.get(
            "configurations",
            [],
        ),
    }


@lru_cache(maxsize=1)
def _load_kev_catalog() -> dict[str, Any]:

    if not CISA_FILE.exists():
        return {}

    try:
        data = _read_json(
            CISA_FILE
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return {}

    entries = data.get(
        "vulnerabilities",
        []
    )

    result: dict[str, Any] = {}

    if not isinstance(
        entries,
        list,
    ):
        return result

    for entry in entries:

        if not isinstance(
            entry,
            dict,
        ):
            continue

        cve = entry.get(
            "cveID"
        )

        if cve:
            result[str(cve).upper()] = entry

    return result


def _get_kev(
    cve_id: str,
) -> dict[str, Any] | None:

    return _load_kev_catalog().get(
        cve_id.upper()
    )


def _fetch_epss(
    cves: list[str],
    force: bool = False,
) -> dict[str, Any]:

    result: dict[str, Any] = {}

    missing: list[str] = []

    EPSS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for cve in cves:

        path = (
            EPSS_DIR
            / f"{cve.upper()}.json"
        )

        if (
            not force
            and _cache_is_fresh(path)
        ):

            try:
                value = _read_json(
                    path
                )
            except (
                OSError,
                json.JSONDecodeError,
            ):
                value = None

            if isinstance(
                value,
                dict,
            ):
                result[cve.upper()] = value
                continue

        missing.append(
            cve.upper()
        )

    if not missing:
        return result

    query = urllib.parse.urlencode(
        {
            "cve": ",".join(
                missing
            )
        }
    )

    try:

        response = _request_json(
            f"{EPSS_API}?{query}"
        )

        rows = response.get(
            "data",
            []
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ):

        rows = []

    if isinstance(
        rows,
        list,
    ):

        for row in rows:

            if not isinstance(
                row,
                dict,
            ):
                continue

            cve = row.get(
                "cve"
            )

            if not cve:
                continue

            cve = str(
                cve
            ).upper()

            payload = {
                "retrieved_at": _now_iso(),
                "source": EPSS_API,
                "data": row,
            }

            path = (
                EPSS_DIR
                / f"{cve}.json"
            )

            _write_json(
                path,
                payload,
            )

            result[cve] = payload

    return result


def _fetch_circl(
    cve_id: str,
    force: bool = False,
) -> dict[str, Any] | None:

    CIRCL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        CIRCL_DIR
        / f"{cve_id.upper()}.json"
    )

    if (
        not force
        and _cache_is_fresh(path)
    ):

        try:
            cached = _read_json(
                path
            )

            if isinstance(
                cached,
                dict,
            ):
                return cached

        except (
            OSError,
            json.JSONDecodeError,
        ):
            pass

    quoted_id = urllib.parse.quote(
        cve_id.upper(),
        safe="",
    )

    url = (
        f"{CIRCL_API}/{quoted_id}"
        "?with_meta=true"
        "&with_linked=true"
        "&with_sightings=true"
    )

    try:

        data = _request_json(
            url
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ):

        if path.exists():

            try:
                return _read_json(
                    path
                )
            except (
                OSError,
                json.JSONDecodeError,
            ):
                return None

        return None

    payload = {
        "retrieved_at": _now_iso(),
        "source": CIRCL_API,
        "data": data,
    }

    _write_json(
        path,
        payload,
    )

    return payload


def _collect_urls(
    value: Any,
) -> list[str]:

    urls: set[str] = set()

    def walk(item: Any) -> None:

        if isinstance(
            item,
            str,
        ):

            if item.startswith(
                "http://"
            ) or item.startswith(
                "https://"
            ):
                urls.add(item)

            return

        if isinstance(
            item,
            dict,
        ):

            for child in item.values():
                walk(child)

            return

        if isinstance(
            item,
            list,
        ):

            for child in item:
                walk(child)

    walk(value)

    return sorted(
        urls
    )


def _extract_circl_summary(
    payload: dict[str, Any] | None,
) -> dict[str, Any]:

    if not payload:
        return {}

    data = payload.get(
        "data",
        payload,
    )

    if not isinstance(
        data,
        dict,
    ):
        return {}

    summary = {
        "urls": _collect_urls(
            data
        ),
        "sighting_types": [],
        "sighting_sources": [],
    }

    sighting_types: set[str] = set()
    sighting_sources: set[str] = set()

    def walk(item: Any) -> None:

        if isinstance(
            item,
            dict,
        ):

            item_type = item.get(
                "type"
            )

            if (
                isinstance(
                    item_type,
                    str,
                )
                and item_type
            ):
                sighting_types.add(
                    item_type
                )

            source = item.get(
                "source"
            )

            if (
                isinstance(
                    source,
                    str,
                )
                and source
            ):
                sighting_sources.add(
                    source
                )

            for child in item.values():
                walk(child)

            return

        if isinstance(
            item,
            list,
        ):

            for child in item:
                walk(child)

    walk(data)

    summary[
        "sighting_types"
    ] = sorted(
        sighting_types
    )

    summary[
        "sighting_sources"
    ] = sorted(
        sighting_sources
    )

    return summary


@lru_cache(maxsize=1)
def _load_project_enriched() -> list[dict[str, Any]]:

    if not ENRICHED_ALERTS_FILE.exists():
        return []

    try:
        data = _read_json(
            ENRICHED_ALERTS_FILE
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return []

    if not isinstance(
        data,
        list,
    ):
        return []

    return [
        item
        for item in data
        if isinstance(
            item,
            dict,
        )
    ]


def _find_project_mitre_details(
    technique_id: str,
) -> list[dict[str, Any]]:

    matches: list[dict[str, Any]] = []

    for record in _load_project_enriched():

        external = record.get(
            "external_enrichment",
            {},
        )

        if not isinstance(
            external,
            dict,
        ):
            continue

        identifiers = external.get(
            "identifiers",
            {},
        )

        if not isinstance(
            identifiers,
            dict,
        ):
            continue

        techniques = identifiers.get(
            "mitre_technique_ids",
            [],
        )

        if technique_id.upper() not in {
            str(value).upper()
            for value in _json_list(
                techniques
            )
        }:
            continue

        mitre = external.get(
            "mitre_attack",
            {},
        )

        if not isinstance(
            mitre,
            dict,
        ):
            continue

        enrichment = mitre.get(
            "enrichment",
            [],
        )

        if not isinstance(
            enrichment,
            list,
        ):
            continue

        for entry in enrichment:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            entry_text = json.dumps(
                entry
            ).upper()

            if technique_id.upper() in entry_text:
                matches.append(
                    entry
                )

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()

    for entry in matches:

        key = json.dumps(
            entry,
            sort_keys=True,
            default=str,
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(entry)

    return deduped


def _priority_guidance(
    cvss_score: float | None,
    epss_score: float | None,
    known_exploited: bool,
) -> dict[str, str]:

    if known_exploited:

        return {
            "label": "High attention",
            "reason": (
                "At least one CVE associated with "
                "this rule is listed in the CISA Known "
                "Exploited Vulnerabilities catalog."
            ),
        }

    if (
        cvss_score is not None
        and cvss_score >= 9.0
    ):

        return {
            "label": "Critical vulnerability context",
            "reason": (
                "The highest associated CVE has a "
                "CVSS base score of 9.0 or higher."
            ),
        }

    if (
        epss_score is not None
        and epss_score >= 0.50
    ):

        return {
            "label": "Elevated attention",
            "reason": (
                "The highest associated EPSS score "
                "is 0.50 or higher."
            ),
        }

    if (
        cvss_score is not None
        and cvss_score >= 7.0
    ):

        return {
            "label": "Elevated attention",
            "reason": (
                "The highest associated CVE has a "
                "CVSS base score of 7.0 or higher."
            ),
        }

    return {
        "label": "Contextual",
        "reason": (
            "No high-priority vulnerability or active "
            "exploitation signal was found in the "
            "available enrichment."
        ),
    }


_REFERENCE_CVE_RE = re.compile(
    r"cve,\s*(\d{4}-\d{4,7})",
    re.IGNORECASE,
)

_QUOTED_CONTENT_RE = re.compile(
    r'"((?:[^"\\]|\\.)*)"'
)


def _rule_reference_cves(
    rule: Any,
) -> list[str]:
    """Normalise Snort-style 'cve,YYYY-NNNN' rule references to CVE IDs."""
    if not isinstance(rule, dict):
        return []

    found: set[str] = set()

    for reference in _json_list(rule.get("references_json")):
        match = _REFERENCE_CVE_RE.fullmatch(str(reference).strip())

        if match:
            found.add(f"CVE-{match.group(1)}")

    return sorted(found)


def _content_patterns(
    rule: dict[str, Any],
) -> list[str]:
    """Return the literal content patterns a rule searches for."""
    patterns: list[str] = []

    for item in _json_list(rule.get("content_matches_json")):
        text = str(item).strip()
        quoted = _QUOTED_CONTENT_RE.match(text)
        pattern = (quoted.group(1) if quoted else text).strip()

        if pattern and pattern not in patterns:
            patterns.append(pattern)

    return patterns


def _describe_rule_logic(
    rule: dict[str, Any],
) -> str:
    """Describe what a rule inspects, using only the rule's own fields."""
    protocol = str(rule.get("protocol") or "").upper()
    service = str(rule.get("service") or "")
    flow = str(rule.get("flow") or "")
    patterns = _content_patterns(rule)

    if not (protocol or service or flow or patterns):
        return (
            "The traffic matched the conditions "
            "defined by the IDS rule."
        )

    sentence = (
        f"The rule inspects {protocol} traffic"
        if protocol
        else "The rule inspects traffic"
    )

    if service:
        sentence += f" for the {service} service"

    if "to_server" in flow:
        sentence += " sent to a server"
    elif "to_client" in flow:
        sentence += " sent to a client"

    if "established" in flow:
        sentence += " in an established session"

    sentence += "."

    if patterns:
        listed = ", ".join(f"`{pattern}`" for pattern in patterns[:5])
        sentence += f" It looks for: {listed}."

    return sentence


def _build_explanation(
    alert: dict[str, Any],
    base: dict[str, Any],
    cves: list[str],
    mitre_ids: list[str],
    vulnerabilities: dict[str, Any],
) -> dict[str, Any]:

    rule = base.get(
        "rule",
        {},
    )

    documentation = base.get(
        "documentation",
        {},
    )

    if not isinstance(
        rule,
        dict,
    ):
        rule = {}

    if not isinstance(
        documentation,
        dict,
    ):
        documentation = {}

    message = (
        alert.get("msg")
        or rule.get("msg")
        or "Unknown IDS alert"
    )

    protocol = (
        alert.get("protocol")
        or rule.get("protocol")
        or ""
    )

    explanation_text = (
        documentation.get(
            "rule_explanation"
        )
        or documentation.get(
            "alert_message_doc"
        )
        or ""
    )

    if not explanation_text:

        if protocol:

            explanation_text = (
                f"The IDS observed {protocol.upper()} "
                f"traffic that matched the rule "
                f"'{message}'."
            )

        else:

            explanation_text = (
                f"The IDS observed traffic that "
                f"matched the rule '{message}'."
            )

    why_triggered = (
        documentation.get(
            "what_to_look_for"
        )
        or ""
    )

    if not why_triggered:
        why_triggered = _describe_rule_logic(rule)

    known_usage = (
        documentation.get(
            "known_usage"
        )
        or ""
    )

    false_positives = (
        documentation.get(
            "false_positives"
        )
        or ""
    )

    vulnerability_note = (
        documentation.get(
            "rule_vulnerability"
        )
        or ""
    )

    known_exploited_cves = [
        cve
        for cve, info in vulnerabilities.items()
        if info.get(
            "cisa_kev"
        )
    ]

    if cves:

        cve_sentence = (
            f"The rule is associated with "
            f"{len(cves)} CVE"
            f"{'' if len(cves) == 1 else 's'}: "
            f"{', '.join(cves)}."
        )

        meaning = cve_sentence

        if known_exploited_cves:

            meaning += (
                " At least one of those CVEs is "
                "listed in CISA's Known Exploited "
                "Vulnerabilities catalog."
            )

        meaning += (
            " This association provides vulnerability "
            "context; the alert alone does not prove "
            "that the affected software is installed "
            "or that exploitation succeeded."
        )

    elif vulnerability_note:

        meaning = str(
            vulnerability_note
        )

        meaning += (
            " The alert itself still does not prove "
            "successful exploitation."
        )

    else:

        meaning = (
            "This alert shows that traffic matched "
            "the detection rule. Whether the activity "
            "is malicious depends on the source, target, "
            "environment, and surrounding events."
        )

    what_to_check: list[str] = []

    if why_triggered:
        what_to_check.append(
            str(why_triggered)
        )

    if false_positives:
        what_to_check.append(
            "Check for the documented false-positive "
            "conditions before treating the alert as "
            "malicious: "
            f"{false_positives}"
        )

    if cves:

        what_to_check.append(
            "Verify whether the destination system "
            "actually runs an affected product or "
            "version."
        )

    what_to_check.append(
        "Review the source and destination addresses, "
        "the surrounding network activity, and any "
        "follow-up connections."
    )

    action_items: list[str] = []

    if known_exploited_cves:

        action_items.append(
            "Prioritize checking the affected asset "
            "because an associated CVE is present in "
            "CISA KEV."
        )

    if cves:

        action_items.append(
            "Check the affected product/version and "
            "apply the vendor or operating-system "
            "security update when applicable."
        )

    if not cves:

        action_items.append(
            "Confirm whether this traffic is expected "
            "in the environment."
        )

    action_items.append(
        "Review surrounding IDS alerts and host logs "
        "before concluding that compromise occurred."
    )

    return {
        "title": str(message),
        "explanation_source": (
            "vendor_documentation"
            if documentation.get("rule_explanation")
            else "rule_fields"
        ),
        "what_happened": str(
            explanation_text
        ),
        "why_triggered": str(
            why_triggered
        ),
        "what_it_means": meaning,
        "known_usage": str(
            known_usage
        ),
        "false_positives": str(
            false_positives
        ),
        "what_to_check": what_to_check,
        "recommended_actions": action_items,
        "mitre_context": mitre_ids,
        "confidence_note": (
            "This intelligence is deterministic and "
            "source-backed. It explains the detection "
            "and its vulnerability context; it does "
            "not infer compromise."
        ),
    }


def build_extended_alert_intelligence_context(
    alert: dict[str, Any],
    force_refresh: bool = False,
    allow_network: bool = True,
) -> dict[str, Any]:

    base = build_alert_intelligence_context(
        alert
    )

    cves = sorted(
        set(_rule_reference_cves(base.get("rule", {})))
        | set(
            _recursive_ids(
                base.get(
                    "rule",
                    {},
                ),
                CVE_RE,
            )
        )
        | set(
            _recursive_ids(
                base.get(
                    "documentation",
                    {},
                ),
                CVE_RE,
            )
        )
        | set(
            _recursive_ids(
                alert,
                CVE_RE,
            )
        )
    )

    mitre_ids = sorted(
        set(
            _recursive_ids(
                base.get(
                    "rule",
                    {},
                ),
                MITRE_RE,
            )
        )
        | set(
            _recursive_ids(
                base.get(
                    "documentation",
                    {},
                ),
                MITRE_RE,
            )
        )
        | set(
            _recursive_ids(
                alert,
                MITRE_RE,
            )
        )
    )

    vulnerabilities: dict[str, Any] = {}

    epss_records: dict[str, Any] = {}

    if allow_network and cves:
        epss_records = _fetch_epss(
            cves,
            force=force_refresh,
        )

    max_cvss: float | None = None
    max_epss: float | None = None
    known_exploited = False

    for cve in cves:

        nvd_raw = (
            _fetch_nvd(
                cve,
                force=force_refresh,
            )
            if allow_network
            else _load_cached_nvd(
                cve
            )
        )

        nvd_summary = _extract_nvd_summary(
            nvd_raw
        )

        kev = _get_kev(
            cve
        )

        epss_payload = epss_records.get(
            cve
        )

        epss_data = {}

        if isinstance(
            epss_payload,
            dict,
        ):

            epss_data = epss_payload.get(
                "data",
                {}
            )

            if isinstance(
                epss_data,
                list,
            ):

                epss_data = (
                    epss_data[0]
                    if epss_data
                    else {}
                )

        circl_payload = None

        if allow_network:
            circl_payload = _fetch_circl(
                cve,
                force=force_refresh,
            )

        epss_score = None
        epss_percentile = None

        try:

            if epss_data.get(
                "epss"
            ) is not None:
                epss_score = float(
                    epss_data[
                        "epss"
                    ]
                )

            if epss_data.get(
                "percentile"
            ) is not None:
                epss_percentile = float(
                    epss_data[
                        "percentile"
                    ]
                )

        except (
            TypeError,
            ValueError,
        ):
            pass

        cvss = nvd_summary.get(
            "cvss"
        )

        cvss_score = None

        if isinstance(
            cvss,
            dict,
        ):

            try:

                if cvss.get(
                    "base_score"
                ) is not None:
                    cvss_score = float(
                        cvss[
                            "base_score"
                        ]
                    )

            except (
                TypeError,
                ValueError,
            ):
                pass

        if (
            cvss_score is not None
            and (
                max_cvss is None
                or cvss_score > max_cvss
            )
        ):
            max_cvss = cvss_score

        if (
            epss_score is not None
            and (
                max_epss is None
                or epss_score > max_epss
            )
        ):
            max_epss = epss_score

        if kev:
            known_exploited = True

        vulnerabilities[cve] = {
            "nvd": nvd_summary,
            "cisa_kev": kev,
            "epss": {
                "score": epss_score,
                "percentile": epss_percentile,
                "raw": epss_data,
            },
            "circl": (
                _extract_circl_summary(
                    circl_payload
                )
                if circl_payload
                else {}
            ),
        }

    mitre_enrichment = {}

    for technique_id in mitre_ids:

        details = (
            _find_project_mitre_details(
                technique_id
            )
        )

        if details:
            mitre_enrichment[
                technique_id
            ] = details

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

    references: list[dict[str, str]] = []

    for source_name, url in [
        (
            "NVD",
            NVD_API,
        ),
        (
            "FIRST EPSS",
            EPSS_API,
        ),
        (
            "CIRCL Vulnerability-Lookup",
            CIRCL_API,
        ),
        (
            "CISA KEV",
            "https://www.cisa.gov/"
            "known-exploited-vulnerabilities-catalog",
        ),
    ]:

        references.append(
            {
                "source": source_name,
                "url": url,
            }
        )

    for cve, info in vulnerabilities.items():

        nvd = info.get(
            "nvd",
            {}
        )

        for reference in nvd.get(
            "references",
            [],
        ):

            if not isinstance(
                reference,
                dict,
            ):
                continue

            url = reference.get(
                "url"
            )

            if url:

                references.append(
                    {
                        "source": (
                            reference.get(
                                "source"
                            )
                            or f"NVD {cve}"
                        ),
                        "url": str(
                            url
                        ),
                    }
                )

        for url in info.get(
            "circl",
            {}
        ).get(
            "urls",
            [],
        ):

            references.append(
                {
                    "source": (
                        f"CIRCL {cve}"
                    ),
                    "url": str(
                        url
                    ),
                }
            )

    deduped_references = []
    seen_urls: set[str] = set()

    for reference in references:

        url = reference.get(
            "url"
        )

        if not url or url in seen_urls:
            continue

        seen_urls.add(url)
        deduped_references.append(
            reference
        )

    return {
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
                for cve, info in vulnerabilities.items()
                if info.get(
                    "cisa_kev"
                )
            ],
            "disclaimer": (
                "This is vulnerability-priority context, "
                "not proof that the alert is malicious or "
                "that exploitation succeeded."
            ),
        },
        "explanation": explanation,
        "references": deduped_references,
        "retrieved_at": _now_iso(),
        "sources": {
            "rule_database": (
                "data/lab/rules/ids_rules.db"
            ),
            "rule_documentation": (
                "data/json/"
                "rule_docs_preprocessed_by_sid.json"
            ),
            "nvd": NVD_API,
            "epss": EPSS_API,
            "cisa_kev": (
                "CISA Known Exploited "
                "Vulnerabilities Catalog"
            ),
            "circl": CIRCL_API,
        },
    }


__all__ = [
    "build_extended_alert_intelligence_context",
]
