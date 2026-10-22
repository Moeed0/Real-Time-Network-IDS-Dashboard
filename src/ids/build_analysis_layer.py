#!/usr/bin/env python3

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    PROJECT_ROOT
    / "data/lab/enriched/all_alerts_enriched.json"
)

PHASE_FILE = (
    PROJECT_ROOT
    / "config/lab_phases.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data/lab/analysis"
)

FINAL_ALL = (
    PROJECT_ROOT
    / "data/lab/enriched/all_alerts_final.json"
)

FINAL_SNORT = (
    PROJECT_ROOT
    / "data/lab/enriched/snort_final_alerts.json"
)

FINAL_SURICATA = (
    PROJECT_ROOT
    / "data/lab/enriched/suricata_final_alerts.json"
)

ANALYSIS_OUTPUT = (
    OUTPUT_DIR
    / "cross_engine_analysis.json"
)

SUMMARY_OUTPUT = (
    OUTPUT_DIR
    / "analysis_summary.json"
)


CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

MITRE_RE = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)


STOP_WORDS = {
    "alert",
    "attempt",
    "attempted",
    "possible",
    "detected",
    "detection",
    "request",
    "response",
    "server",
    "client",
    "traffic",
    "protocol",
    "generic",
    "info",
    "indicator",
    "policy",
    "other",
    "access",
    "connection",
    "network",
    "command",
    "commandline",
    "event",
    "invalid",
    "contains",
    "incoming",
    "outgoing",
    "unknown",
    "test",
    "try",
    "packet",
    "packets",
    "message",
    "exploit",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            value,
            handle,
            indent=2,
            ensure_ascii=False,
        )


def walk_values(value: Any):
    """
    Recursively yield scalar values from nested dictionaries/lists.
    """
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_values(child)

    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child)

    else:
        yield value


def text_from(value: Any) -> str:
    parts = []

    for item in walk_values(value):
        if item is None:
            continue

        if isinstance(item, (str, int, float, bool)):
            parts.append(str(item))

    return " ".join(parts)


def extract_cves(value: Any) -> list[str]:
    found = set()

    for item in walk_values(value):
        if not isinstance(item, str):
            continue

        for match in CVE_RE.findall(item):
            found.add(match.upper())

    return sorted(found)


def extract_mitre(value: Any) -> list[str]:
    found = set()

    for item in walk_values(value):
        if not isinstance(item, str):
            continue

        for match in MITRE_RE.findall(item):
            found.add(match.upper())

    return sorted(found)


def tokens_for_message(text: str) -> set[str]:
    words = re.findall(
        r"[a-z0-9][a-z0-9_-]{2,}",
        text.lower(),
    )

    tokens = set()

    for word in words:
        word = word.strip("_-")

        if not word:
            continue

        if word in STOP_WORDS:
            continue

        if word.startswith("cve-"):
            continue

        if re.fullmatch(
            r"t\d{4}(?:\.\d{3})?",
            word,
            re.IGNORECASE,
        ):
            continue

        tokens.add(word)

    return tokens


def jaccard(
    left: set[str],
    right: set[str],
) -> float:
    if not left and not right:
        return 0.0

    union = left | right

    if not union:
        return 0.0

    return len(left & right) / len(union)


def get_message(record: dict[str, Any]) -> str:
    alert = record.get("alert", {})

    message = alert.get("message")

    if message:
        return str(message)

    rule = record.get("rule", {})

    if isinstance(rule, dict):
        message = rule.get("msg")

        if message:
            return str(message)

    native = record.get("native_event", {})

    if isinstance(native, dict):
        message = native.get("msg")

        if message:
            return str(message)

    return ""


def get_service(record: dict[str, Any]) -> str | None:
    network = record.get("network", {})

    if not isinstance(network, dict):
        return None

    value = network.get("service")

    if value:
        return str(value).lower()

    return None


def get_protocol(record: dict[str, Any]) -> str | None:
    network = record.get("network", {})

    if not isinstance(network, dict):
        return None

    value = network.get("protocol")

    if value:
        return str(value).lower()

    return None


def get_ports(record: dict[str, Any]) -> set[int]:
    network = record.get("network", {})

    if not isinstance(network, dict):
        return set()

    ports = set()

    for key in (
        "source_port",
        "destination_port",
    ):
        value = network.get(key)

        try:
            if value is not None:
                ports.add(int(value))
        except (TypeError, ValueError):
            pass

    return ports


def get_rule_classification(
    record: dict[str, Any],
) -> str | None:

    alert = record.get("alert", {})

    if not isinstance(alert, dict):
        return None

    value = alert.get("classification")

    if value:
        return str(value).lower()

    rule = record.get("rule", {})

    if isinstance(rule, dict):
        value = rule.get("classtype")

        if value:
            return str(value).lower()

    return None


def build_observed_evidence(
    record: dict[str, Any],
) -> dict[str, Any]:

    phase = record.get("phase", {})

    return {
        "source": "controlled_lab_observation",
        "evidence_type": "IDS_alert_observed_in_replayed_PCAP",
        "engine": record.get("engine"),
        "record_id": record.get("record_id"),
        "phase_id": phase.get("phase_id"),
        "phase_name": phase.get("name"),
        "pcap": phase.get("pcap"),
        "attacker_ip": phase.get("attacker_ip"),
        "target_ip": phase.get("target_ip"),
        "capture_interface": (
            record.get("network", {}).get(
                "capture_interface"
            )
        ),
        "attack_duration_seconds": (
            phase.get("attack_duration_seconds")
        ),
        "pcap_packets": phase.get(
            "pcap_total_packets"
        ),
        "pcap_bytes": phase.get(
            "pcap_total_bytes"
        ),
        "kali_to_target_packets": phase.get(
            "kali_to_target_packets"
        ),
        "target_to_kali_packets": phase.get(
            "target_to_kali_packets"
        ),
        "other_packets": phase.get(
            "other_packets"
        ),
    }


def build_rule_intelligence(
    record: dict[str, Any],
) -> dict[str, Any]:

    rule = record.get("rule")

    status = record.get(
        "enrichment_status",
        {},
    )

    exact_found = bool(
        status.get(
            "exact_rule_found"
        )
    )

    if not isinstance(rule, dict):
        rule = None

    return {
        "exact_rule_found": exact_found,
        "source": (
            "data/lab/rules/ids_rules.db"
            if exact_found
            else None
        ),
        "engine": record.get("engine"),
        "gid": (
            rule.get("gid")
            if rule
            else record.get("alert", {}).get("gid")
        ),
        "sid": (
            rule.get("sid")
            if rule
            else record.get("alert", {}).get("sid")
        ),
        "rev": (
            rule.get("rev")
            if rule
            else record.get("alert", {}).get("rev")
        ),
        "message": (
            rule.get("msg")
            if rule
            else record.get("alert", {}).get("message")
        ),
        "classification": (
            rule.get("classtype")
            if rule
            else record.get("alert", {}).get(
                "classification"
            )
        ),
        "priority": (
            rule.get("priority")
            if rule
            else record.get("alert", {}).get(
                "priority"
            )
        ),
        "service": (
            rule.get("service")
            if rule
            else record.get("network", {}).get(
                "service"
            )
        ),
        "flow": (
            rule.get("flow")
            if rule
            else None
        ),
        "references": (
            rule.get("references")
            if rule
            else []
        ),
        "cve_ids_from_rule_index": (
            rule.get("cve_ids")
            if rule
            else []
        ),
        "mitre_ids_from_rule_index": (
            rule.get("mitre_ids")
            if rule
            else []
        ),
        "source_file": (
            rule.get("source_file")
            if rule
            else None
        ),
        "source_line": (
            rule.get("source_line")
            if rule
            else None
        ),
        "native_rule_text": (
            rule.get("rule_text")
            if rule
            else None
        ),
        "full_indexed_rule_record": rule,
    }


def build_project_documentation(
    record: dict[str, Any],
) -> dict[str, Any]:

    enrichment = record.get(
        "project_enrichment",
        {},
    )

    if not isinstance(
        enrichment,
        dict,
    ):
        enrichment = {}

    documentation = enrichment.get(
        "documentation"
    )

    return {
        "found": bool(
            enrichment.get(
                "documentation_found"
            )
        ),
        "source": enrichment.get(
            "documentation_source"
        ),
        "documentation": documentation,
        "cve_ids": extract_cves(
            documentation
        ),
        "mitre_ids": extract_mitre(
            documentation
        ),
    }


def build_identifier_evidence(
    record: dict[str, Any],
) -> dict[str, Any]:

    rule = record.get("rule", {})
    project = record.get(
        "project_enrichment",
        {},
    )
    native = record.get(
        "native_event",
        {},
    )

    sources = {
        "rule_index": rule,
        "project_documentation": (
            project.get(
                "documentation"
            )
            if isinstance(project, dict)
            else {}
        ),
        "native_event": native,
    }

    cve_evidence = defaultdict(list)
    mitre_evidence = defaultdict(list)

    for source_name, source_value in sources.items():

        for cve in extract_cves(
            source_value
        ):
            cve_evidence[cve].append(
                source_name
            )

        for technique in extract_mitre(
            source_value
        ):
            mitre_evidence[
                technique
            ].append(
                source_name
            )

    external = record.get(
        "external_enrichment",
        {},
    )

    identifiers = {}

    if isinstance(
        external,
        dict,
    ):
        identifiers = external.get(
            "identifiers",
            {},
        )

        if not isinstance(
            identifiers,
            dict,
        ):
            identifiers = {}

    for cve in identifiers.get(
        "cve_ids",
        [],
    ):
        cve = str(cve).upper()

        if cve not in cve_evidence:
            cve_evidence[cve].append(
                "external_identifier_extraction"
            )

    for technique in identifiers.get(
        "mitre_technique_ids",
        [],
    ):
        technique = str(technique).upper()

        if technique not in mitre_evidence:
            mitre_evidence[
                technique
            ].append(
                "external_identifier_extraction"
            )

    for key in cve_evidence:
        cve_evidence[key] = sorted(
            set(cve_evidence[key])
        )

    for key in mitre_evidence:
        mitre_evidence[key] = sorted(
            set(mitre_evidence[key])
        )

    return {
        "cves": {
            key: {
                "evidence_sources": value
            }
            for key, value
            in sorted(
                cve_evidence.items()
            )
        },
        "mitre_techniques": {
            key: {
                "evidence_sources": value
            }
            for key, value
            in sorted(
                mitre_evidence.items()
            )
        },
    }


def build_vulnerability_intelligence(
    record: dict[str, Any],
    identifier_evidence: dict[str, Any],
) -> dict[str, Any]:

    external = record.get(
        "external_enrichment",
        {},
    )

    if not isinstance(
        external,
        dict,
    ):
        external = {}

    nvd = external.get(
        "nvd",
        {},
    )

    if not isinstance(
        nvd,
        dict,
    ):
        nvd = {}

    nvd_records = nvd.get(
        "records",
        [],
    )

    if not isinstance(
        nvd_records,
        list,
    ):
        nvd_records = []

    nvd_by_cve = {}

    for item in nvd_records:
        if not isinstance(
            item,
            dict,
        ):
            continue

        cve_id = item.get(
            "cve_id"
        )

        if not cve_id:
            cve_id = item.get(
                "id"
            )

        if cve_id:
            nvd_by_cve[
                str(cve_id).upper()
            ] = item

    vulnerabilities = []

    for cve_id, evidence in (
        identifier_evidence[
            "cves"
        ].items()
    ):

        nvd_record = nvd_by_cve.get(
            cve_id
        )

        cisa_kev = None

        if isinstance(
            nvd_record,
            dict,
        ):
            cisa_kev = nvd_record.get(
                "cisa_kev"
            )

        vulnerabilities.append(
            {
                "cve_id": cve_id,
                "identifier_evidence_sources": (
                    evidence.get(
                        "evidence_sources",
                        []
                    )
                ),
                "nvd_found": (
                    nvd_record is not None
                ),
                "nvd_record": nvd_record,
                "cisa_kev": cisa_kev,
            }
        )

    return {
        "cves": vulnerabilities,

        "unique_cve_count": len(
            vulnerabilities
        ),

        "alerts_with_nvd_lookup_result": bool(
            nvd_records
        ),

        "known_exploited": any(
            isinstance(
                item.get("cisa_kev"),
                dict,
            )
            and item["cisa_kev"].get(
                "is_known_exploited"
            )
            for item in vulnerabilities
        ),

        "important_interpretation_note": (
            "A CVE attached to an IDS rule or "
            "external vulnerability record provides "
            "security context for the detection. "
            "It does not prove that the lab target "
            "was vulnerable or successfully exploited."
        ),
    }


def build_attack_intelligence(
    record: dict[str, Any],
    identifier_evidence: dict[str, Any],
) -> dict[str, Any]:

    external = record.get(
        "external_enrichment",
        {},
    )

    if not isinstance(
        external,
        dict,
    ):
        external = {}

    mitre_external = external.get(
        "mitre_attack",
        {},
    )

    if not isinstance(
        mitre_external,
        dict,
    ):
        mitre_external = {}

    techniques_external = mitre_external.get(
        "techniques",
        [],
    )

    if not isinstance(
        techniques_external,
        list,
    ):
        techniques_external = []

    by_id = {}

    for item in techniques_external:
        if not isinstance(
            item,
            dict,
        ):
            continue

        technique_id = (
            item.get("technique_id")
            or item.get("id")
        )

        if technique_id:
            by_id[
                str(technique_id).upper()
            ] = item

    techniques = []

    for technique_id, evidence in (
        identifier_evidence[
            "mitre_techniques"
        ].items()
    ):

        techniques.append(
            {
                "technique_id": technique_id,
                "identifier_evidence_sources": (
                    evidence.get(
                        "evidence_sources",
                        []
                    )
                ),
                "external_lookup_found": (
                    technique_id in by_id
                ),
                "attack_record": by_id.get(
                    technique_id
                ),
            }
        )

    return {
        "techniques": techniques,
        "unique_technique_count": len(
            techniques
        ),
    }


def build_security_context(
    record: dict[str, Any],
) -> dict[str, Any]:

    identifier_evidence = (
        build_identifier_evidence(
            record
        )
    )

    vulnerability_intelligence = (
        build_vulnerability_intelligence(
            record,
            identifier_evidence,
        )
    )

    attack_intelligence = (
        build_attack_intelligence(
            record,
            identifier_evidence,
        )
    )

    rule_intelligence = (
        build_rule_intelligence(
            record
        )
    )

    project_documentation = (
        build_project_documentation(
            record
        )
    )

    cve_count = (
        len(
            identifier_evidence[
                "cves"
            ]
        )
    )

    mitre_count = (
        len(
            identifier_evidence[
                "mitre_techniques"
            ]
        )
    )

    return {
        "schema_version": "2.0",

        "observed_lab_evidence":
            build_observed_evidence(
                record
            ),

        "rule_intelligence":
            rule_intelligence,

        "project_documentation":
            project_documentation,

        "identifier_evidence":
            identifier_evidence,

        "vulnerability_intelligence":
            vulnerability_intelligence,

        "mitre_attack_intelligence":
            attack_intelligence,

        "coverage": {
            "exact_rule_found": bool(
                record.get(
                    "enrichment_status",
                    {}
                ).get(
                    "exact_rule_found"
                )
            ),
            "project_documentation_found": bool(
                project_documentation.get(
                    "found"
                )
            ),
            "has_cve_context": cve_count > 0,
            "has_mitre_context": mitre_count > 0,
            "has_nvd_result": bool(
                vulnerability_intelligence.get(
                    "alerts_with_nvd_lookup_result"
                )
            ),
            "known_exploited_cve": bool(
                vulnerability_intelligence.get(
                    "known_exploited"
                )
            ),
        },

        "analysis_tags": {
            "engine": record.get(
                "engine"
            ),
            "phase_id": record.get(
                "phase",
                {}
            ).get(
                "phase_id"
            ),
            "service": get_service(
                record
            ),
            "protocol": get_protocol(
                record
            ),
            "ports": sorted(
                get_ports(record)
            ),
            "classification": (
                get_rule_classification(
                    record
                )
            ),
            "message_tokens": sorted(
                tokens_for_message(
                    get_message(record)
                )
            ),
        },
    }


def build_final_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    output = []

    for record in records:
        enriched = dict(record)

        enriched[
            "security_context"
        ] = build_security_context(
            record
        )

        enriched[
            "analysis_schema_version"
        ] = "2.0"

        output.append(enriched)

    return output


def comparison_score(
    snort: dict[str, Any],
    suricata: dict[str, Any],
) -> tuple[
    float,
    list[str],
    list[str],
]:

    snort_ctx = snort.get(
        "security_context",
        {}
    )

    suri_ctx = suricata.get(
        "security_context",
        {}
    )

    snort_ids = snort_ctx.get(
        "identifier_evidence",
        {}
    )

    suri_ids = suri_ctx.get(
        "identifier_evidence",
        {}
    )

    snort_cves = set(
        snort_ids.get(
            "cves",
            {}
        ).keys()
    )

    suri_cves = set(
        suri_ids.get(
            "cves",
            {}
        ).keys()
    )

    snort_mitre = set(
        snort_ids.get(
            "mitre_techniques",
            {}
        ).keys()
    )

    suri_mitre = set(
        suri_ids.get(
            "mitre_techniques",
            {}
        ).keys()
    )

    shared_cves = sorted(
        snort_cves & suri_cves
    )

    shared_mitre = sorted(
        snort_mitre & suri_mitre
    )

    snort_tokens = set(
        snort_ctx.get(
            "analysis_tags",
            {}
        ).get(
            "message_tokens",
            []
        )
    )

    suri_tokens = set(
        suri_ctx.get(
            "analysis_tags",
            {}
        ).get(
            "message_tokens",
            []
        )
    )

    token_similarity = jaccard(
        snort_tokens,
        suri_tokens,
    )

    snort_ports = set(
        snort_ctx.get(
            "analysis_tags",
            {}
        ).get(
            "ports",
            []
        )
    )

    suri_ports = set(
        suri_ctx.get(
            "analysis_tags",
            {}
        ).get(
            "ports",
            []
        )
    )

    shared_ports = sorted(
        snort_ports & suri_ports
    )

    snort_service = (
        snort_ctx.get(
            "analysis_tags",
            {}
        ).get(
            "service"
        )
    )

    suri_service = (
        suri_ctx.get(
            "analysis_tags",
            {}
        ).get(
            "service"
        )
    )

    same_service = (
        bool(snort_service)
        and bool(suri_service)
        and snort_service == suri_service
    )

    score = 0.0
    reasons = []
    strength = []

    if shared_cves:
        score += 0.70
        reasons.append(
            "shared_cve"
        )
        strength.append(
            "strong"
        )

    if shared_mitre:
        score += 0.20
        reasons.append(
            "shared_mitre_technique"
        )

    if shared_ports:
        score += 0.10
        reasons.append(
            "shared_port"
        )

    if same_service:
        score += 0.10
        reasons.append(
            "same_service"
        )

    if token_similarity >= 0.50:
        score += 0.25
        reasons.append(
            "strong_message_similarity"
        )

    elif token_similarity >= 0.30:
        score += 0.15
        reasons.append(
            "message_similarity"
        )

    score = min(
        score,
        1.0
    )

    return (
        score,
        reasons,
        strength,
    )


def relation_from_score(
    score: float,
    reasons: list[str],
) -> str | None:

    if "shared_cve" in reasons:
        return "same_vulnerability"

    if "shared_mitre_technique" in reasons:
        return "same_attack_mapping"

    if (
        "strong_message_similarity" in reasons
        and (
            "same_service" in reasons
            or "shared_port" in reasons
        )
    ):
        return "same_detection_concept"

    if (
        "message_similarity" in reasons
        and (
            "same_service" in reasons
            or "shared_port" in reasons
        )
    ):
        return "related_test_detection"

    if (
        "same_service" in reasons
        and "shared_port" in reasons
    ):
        return "same_test_related"

    return None


def build_cross_engine_analysis(
    records: list[dict[str, Any]],
    phases: dict[str, Any],
) -> dict[str, Any]:

    snort = [
        r for r in records
        if r.get("engine") == "Snort"
    ]

    suricata = [
        r for r in records
        if r.get("engine") == "Suricata"
    ]

    by_phase_snort = defaultdict(list)
    by_phase_suri = defaultdict(list)

    for record in snort:
        phase_id = str(
            record.get(
                "phase",
                {}
            ).get(
                "phase_id"
            )
        )

        by_phase_snort[
            phase_id
        ].append(record)

    for record in suricata:
        phase_id = str(
            record.get(
                "phase",
                {}
            ).get(
                "phase_id"
            )
        )

        by_phase_suri[
            phase_id
        ].append(record)

    phase_analysis = {}

    for phase_id in sorted(
        phases.keys(),
        key=lambda value: int(value),
    ):

        snort_records = by_phase_snort.get(
            phase_id,
            []
        )

        suri_records = by_phase_suri.get(
            phase_id,
            []
        )

        pair_matches = []

        for s_record in snort_records:

            best = []

            for u_record in suri_records:

                score, reasons, _ = (
                    comparison_score(
                        s_record,
                        u_record,
                    )
                )

                relation = (
                    relation_from_score(
                        score,
                        reasons,
                    )
                )

                if relation:
                    best.append(
                        {
                            "suricata_record_id":
                                u_record.get(
                                    "record_id"
                                ),
                            "score":
                                round(
                                    score,
                                    4
                                ),
                            "relation":
                                relation,
                            "reasons":
                                reasons,
                            "suricata_message":
                                get_message(
                                    u_record
                                ),
                        }
                    )

            best.sort(
                key=lambda item: item[
                    "score"
                ],
                reverse=True,
            )

            if best:
                pair_matches.append(
                    {
                        "snort_record_id":
                            s_record.get(
                                "record_id"
                            ),
                        "snort_message":
                            get_message(
                                s_record
                            ),
                        "matches":
                            best[:5],
                    }
                )

        snort_cves = set()
        suri_cves = set()
        snort_mitre = set()
        suri_mitre = set()

        for record in snort_records:
            ids = record.get(
                "security_context",
                {}
            ).get(
                "identifier_evidence",
                {}
            )

            snort_cves.update(
                ids.get(
                    "cves",
                    {}
                ).keys()
            )

            snort_mitre.update(
                ids.get(
                    "mitre_techniques",
                    {}
                ).keys()
            )

        for record in suri_records:
            ids = record.get(
                "security_context",
                {}
            ).get(
                "identifier_evidence",
                {}
            )

            suri_cves.update(
                ids.get(
                    "cves",
                    {}
                ).keys()
            )

            suri_mitre.update(
                ids.get(
                    "mitre_techniques",
                    {}
                ).keys()
            )

        shared_cves = sorted(
            snort_cves & suri_cves
        )

        shared_mitre = sorted(
            snort_mitre & suri_mitre
        )

        snort_only_cves = sorted(
            snort_cves - suri_cves
        )

        suri_only_cves = sorted(
            suri_cves - snort_cves
        )

        snort_only_mitre = sorted(
            snort_mitre - suri_mitre
        )

        suri_only_mitre = sorted(
            suri_mitre - snort_mitre
        )

        snort_signatures = Counter(
            (
                record.get(
                    "rule",
                    {}
                ).get(
                    "sid"
                ),
                get_message(record),
            )
            for record in snort_records
        )

        suri_signatures = Counter(
            (
                record.get(
                    "rule",
                    {}
                ).get(
                    "sid"
                ),
                get_message(record),
            )
            for record in suri_records
        )

        phase = phases[phase_id]

        phase_analysis[phase_id] = {
            "phase_id": int(phase_id),
            "phase_name": phase.get(
                "name"
            ),
            "test_description": phase.get(
                "description"
            ),
            "pcap": phase.get(
                "pcap"
            ),
            "snort_alert_count": len(
                snort_records
            ),
            "suricata_alert_count": len(
                suri_records
            ),
            "shared_security_identifiers": {
                "cves": shared_cves,
                "mitre_techniques": (
                    shared_mitre
                ),
            },
            "snort_only_identifiers": {
                "cves": snort_only_cves,
                "mitre_techniques": (
                    snort_only_mitre
                ),
            },
            "suricata_only_identifiers": {
                "cves": suri_only_cves,
                "mitre_techniques": (
                    suri_only_mitre
                ),
            },
            "cross_engine_related_alerts": (
                pair_matches
            ),
            "snort_signatures": [
                {
                    "sid": item[0],
                    "message": item[1],
                    "alert_count": item_count,
                }
                for item, item_count
                in snort_signatures.items()
            ],
            "suricata_signatures": [
                {
                    "sid": item[0],
                    "message": item[1],
                    "alert_count": item_count,
                }
                for item, item_count
                in suri_signatures.items()
            ],
            "interpretation": (
                "Alerts are compared inside the same "
                "controlled test phase. Shared CVEs "
                "are treated as the strongest direct "
                "cross-engine relationship. Message, "
                "service and port similarity are "
                "reported separately and do not mean "
                "the two engines used the same rule."
            ),
        }

    total_snort = len(snort)
    total_suri = len(suricata)

    total_shared_cves = sorted(
        set().union(
            *[
                set(
                    item[
                        "shared_security_identifiers"
                    ][
                        "cves"
                    ]
                )
                for item in phase_analysis.values()
            ]
        )
    )

    return {
        "schema_version": "2.0",
        "generated_at": utc_now(),

        "dataset": {
            "input_file":
                str(
                    INPUT_FILE.relative_to(
                        PROJECT_ROOT
                    )
                ),
            "total_alerts":
                len(records),
            "snort_alerts":
                total_snort,
            "suricata_alerts":
                total_suri,
        },

        "comparison_method": {
            "phase_isolation": True,
            "shared_cve_is_strong_match": True,
            "shared_mitre_is_secondary_match": True,
            "message_similarity_is_supporting_only": True,
            "same_rule_not_assumed": True,
            "target_vulnerability_not_assumed": True,
        },

        "overall": {
            "shared_cves":
                total_shared_cves,
            "phase_count":
                len(phase_analysis),
        },

        "by_phase":
            phase_analysis,
    }


def build_summary(
    records: list[dict[str, Any]],
    analysis: dict[str, Any],
) -> dict[str, Any]:

    engine_counts = Counter(
        record.get("engine")
        for record in records
    )

    cve_alert_count = 0
    mitre_alert_count = 0
    kev_alert_count = 0
    docs_alert_count = 0
    rule_alert_count = 0

    unique_cves = set()
    unique_mitre = set()

    for record in records:

        context = record.get(
            "security_context",
            {}
        )

        coverage = context.get(
            "coverage",
            {}
        )

        if coverage.get(
            "has_cve_context"
        ):
            cve_alert_count += 1

        if coverage.get(
            "has_mitre_context"
        ):
            mitre_alert_count += 1

        if coverage.get(
            "known_exploited_cve"
        ):
            kev_alert_count += 1

        if coverage.get(
            "project_documentation_found"
        ):
            docs_alert_count += 1

        if coverage.get(
            "exact_rule_found"
        ):
            rule_alert_count += 1

        identifiers = context.get(
            "identifier_evidence",
            {}
        )

        unique_cves.update(
            identifiers.get(
                "cves",
                {}
            ).keys()
        )

        unique_mitre.update(
            identifiers.get(
                "mitre_techniques",
                {}
            ).keys()
        )

    return {
        "generated_at": utc_now(),

        "alerts": {
            "total": len(records),
            "snort": engine_counts.get(
                "Snort",
                0
            ),
            "suricata": engine_counts.get(
                "Suricata",
                0
            ),
        },

        "coverage": {
            "exact_rule_found": rule_alert_count,
            "project_documentation_found": (
                docs_alert_count
            ),
            "alerts_with_cve_context": (
                cve_alert_count
            ),
            "alerts_with_mitre_context": (
                mitre_alert_count
            ),
            "alerts_with_known_exploited_cve": (
                kev_alert_count
            ),
        },

        "identifiers": {
            "unique_cves": sorted(
                unique_cves
            ),
            "unique_cve_count": len(
                unique_cves
            ),
            "unique_mitre_techniques": sorted(
                unique_mitre
            ),
            "unique_mitre_technique_count": len(
                unique_mitre
            ),
        },

        "cross_engine_analysis": {
            "shared_cves": analysis[
                "overall"
            ][
                "shared_cves"
            ],
            "phase_count": analysis[
                "overall"
            ][
                "phase_count"
            ],
        },

        "data_integrity": {
            "native_events_preserved": all(
                "native_event" in record
                for record in records
            ),
            "original_external_enrichment_preserved":
                all(
                    "external_enrichment"
                    in record
                    for record in records
                ),
            "original_rule_record_preserved":
                all(
                    "rule" in record
                    for record in records
                ),
        },

        "important_note": (
            "The final analysis layer enriches the "
            "existing alerts without replacing native "
            "Snort or Suricata data. Vulnerability and "
            "ATT&CK information is contextual enrichment, "
            "not proof of successful exploitation."
        ),
    }


def main() -> None:

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    records = load_json(
        INPUT_FILE,
        None,
    )

    phases = load_json(
        PHASE_FILE,
        {},
    )

    if not isinstance(records, list):
        raise SystemExit(
            f"Invalid input file: {INPUT_FILE}"
        )

    if not isinstance(phases, dict) or not phases:
        raise SystemExit(
            f"Invalid phase manifest: {PHASE_FILE}"
        )

    print(
        f"Loaded {len(records)} enriched alerts."
    )

    final_records = build_final_records(
        records
    )

    print(
        "Built security_context v2 for "
        f"{len(final_records)} alerts."
    )

    analysis = build_cross_engine_analysis(
        final_records,
        phases,
    )

    summary = build_summary(
        final_records,
        analysis,
    )

    snort_records = [
        record
        for record in final_records
        if record.get("engine") == "Snort"
    ]

    suricata_records = [
        record
        for record in final_records
        if record.get("engine") == "Suricata"
    ]

    write_json(
        FINAL_ALL,
        final_records,
    )

    write_json(
        FINAL_SNORT,
        snort_records,
    )

    write_json(
        FINAL_SURICATA,
        suricata_records,
    )

    write_json(
        ANALYSIS_OUTPUT,
        analysis,
    )

    write_json(
        SUMMARY_OUTPUT,
        summary,
    )

    print()
    print("=" * 72)
    print("FINAL ANALYSIS LAYER COMPLETE")
    print("=" * 72)

    print(
        f"Total alerts:              {len(final_records)}"
    )

    print(
        f"Snort:                     {len(snort_records)}"
    )

    print(
        f"Suricata:                  {len(suricata_records)}"
    )

    print(
        "Exact rule coverage:       "
        f"{summary['coverage']['exact_rule_found']}"
    )

    print(
        "Project documentation:     "
        f"{summary['coverage']['project_documentation_found']}"
    )

    print(
        "Alerts with CVE context:   "
        f"{summary['coverage']['alerts_with_cve_context']}"
    )

    print(
        "Alerts with MITRE context: "
        f"{summary['coverage']['alerts_with_mitre_context']}"
    )

    print(
        "Known-exploited CVE alerts:"
        f" {summary['coverage']['alerts_with_known_exploited_cve']}"
    )

    print()
    print(
        "Unique CVEs: "
        f"{summary['identifiers']['unique_cve_count']}"
    )

    print(
        "Unique MITRE techniques: "
        f"{summary['identifiers']['unique_mitre_technique_count']}"
    )

    print()
    print(
        "Shared cross-engine CVEs: "
        f"{analysis['overall']['shared_cves']}"
    )

    print()
    print(
        "Output:"
    )
    print(
        FINAL_ALL
    )

    print(
        ANALYSIS_OUTPUT
    )

    print(
        SUMMARY_OUTPUT
    )


if __name__ == "__main__":
    main()
