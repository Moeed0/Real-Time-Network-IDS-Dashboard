"""Compose existing IDS evidence and intelligence into one alert result.

This module is intentionally pure: it does not access databases, make network
requests, change alerts, or infer that missing information means an alert is safe.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


ENRICHMENT_SCHEMA_ID = "ids.alert-enrichment"
ENRICHMENT_SCHEMA_VERSION = "1.0"

MISSING_DATA_NOTE = (
    "No matching record was available from the configured local sources. "
    "This does not prove that the identifier is invalid or that the alert is safe."
)

EVIDENCE_NOTE = (
    "Alert and packet records describe retained observations. They do not, "
    "by themselves, prove that an attack succeeded."
)


def _object(value: Any) -> dict[str, Any]:
    """Return a defensive dictionary from a mapping or JSON object string."""
    if isinstance(value, Mapping):
        return dict(value)

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}

    return {}


def _present(value: Any) -> bool:
    """Treat empty values as unavailable without interpreting false as missing."""
    return value is not None and value != "" and value != [] and value != {}


def _first(*values: Any) -> Any:
    """Return the first meaningful value without overwriting valid zero values."""
    for value in values:
        if _present(value):
            return value
    return None


def _identifier_list(value: Any) -> list[str]:
    """Normalize common identifier-container shapes without inventing IDs."""
    if isinstance(value, str):
        values = [value] if value.strip() else []
    elif isinstance(value, Mapping):
        values = list(value.keys())
    elif isinstance(value, (list, tuple, set, frozenset)):
        values = list(value)
    else:
        values = []

    return sorted({
        str(item).strip()
        for item in values
        if item is not None and str(item).strip()
    })


def _native_event(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Decode the original event when available; leave the input untouched."""
    for key in ("raw_json", "native_event", "event"):
        event = _object(alert.get(key))
        if event:
            return event
    return {}


def _nonempty_record(value: Any) -> bool:
    """Return whether a source supplied a useful record, not just an empty object."""
    if isinstance(value, Mapping):
        return any(_present(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return bool(value)
    return _present(value)


def _vulnerability_coverage(
    cves: list[str],
    vulnerabilities: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Describe per-CVE local source coverage without claiming safety."""
    results = []

    for cve in cves:
        info = _object(vulnerabilities.get(cve))
        nvd = _object(info.get("nvd"))
        epss = _object(info.get("epss"))
        kev = info.get("cisa_kev")

        nvd_found = bool(nvd)
        epss_found = (
            epss.get("score") is not None
            or epss.get("epss") is not None
            or epss.get("percentile") is not None
        )
        kev_found = _nonempty_record(kev)

        found_sources = []
        if nvd_found:
            found_sources.append("nvd")
        if epss_found:
            found_sources.append("epss")
        if kev_found:
            found_sources.append("cisa_kev")

        results.append({
            "identifier": cve,
            "status": (
                "source_record_found"
                if found_sources
                else "unresolved_in_local_sources"
            ),
            "sources_with_records": found_sources,
            "note": None if found_sources else MISSING_DATA_NOTE,
        })

    return results


def _technique_coverage(
    technique_ids: list[str],
    technique_enrichment: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Report ATT&CK identifier resolution without silently remapping IDs."""
    results = []

    for technique_id in technique_ids:
        details = technique_enrichment.get(technique_id)
        found = _nonempty_record(details)

        results.append({
            "identifier": technique_id,
            "status": (
                "source_record_found"
                if found
                else "unresolved_in_local_sources"
            ),
            "note": None if found else MISSING_DATA_NOTE,
        })

    return results


def build_alert_enrichment(
    alert: Mapping[str, Any],
    intelligence: Mapping[str, Any] | None = None,
    investigation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a canonical enrichment result from existing alert evidence.

    Inputs are supplied by the caller. This function performs no I/O and
    retains the supplied alert and supporting dictionaries without mutation.
    The original event remains in the caller's alert/export record.
    """
    if not isinstance(alert, Mapping):
        raise TypeError("alert must be a mapping")

    if intelligence is not None and not isinstance(intelligence, Mapping):
        raise TypeError("intelligence must be a mapping or None")

    if investigation is not None and not isinstance(investigation, Mapping):
        raise TypeError("investigation must be a mapping or None")

    intel = dict(intelligence or {})
    evidence = dict(investigation or {})
    base = _object(intel.get("base_intelligence"))
    rule = _object(base.get("rule"))
    documentation = _object(base.get("documentation"))
    explanation = _object(intel.get("explanation"))

    event = _native_event(alert)
    native_alert = _object(event.get("alert"))

    engine = str(
        _first(alert.get("engine_key"), alert.get("engine"), event.get("engine"))
        or "unknown"
    ).lower()

    if engine not in {"snort", "suricata"}:
        engine = "unknown"

    alert_id = _first(
        alert.get("record_id"),
        alert.get("id"),
        alert.get("alert_id"),
    )

    signature = _first(
        native_alert.get("signature"),
        event.get("msg"),
        alert.get("msg"),
        alert.get("rule"),
        alert.get("signature"),
    )

    if engine == "snort":
        native_severity = _first(event.get("priority"), alert.get("priority"))
        severity_semantics = "snort_priority"
    elif engine == "suricata":
        native_severity = _first(
            native_alert.get("severity"),
            alert.get("native_severity"),
        )
        severity_semantics = "suricata_alert_severity"
    else:
        native_severity = alert.get("native_severity")
        severity_semantics = "unknown"

    src_ip = _first(
        event.get("src_addr"),
        event.get("src_ip"),
        event.get("source_ip"),
        alert.get("src_addr"),
        alert.get("src_ip"),
        alert.get("source_ip"),
    )
    src_port = _first(event.get("src_port"), alert.get("src_port"))

    dst_ip = _first(
        event.get("dst_addr"),
        event.get("dest_ip"),
        event.get("dst_ip"),
        event.get("destination_ip"),
        alert.get("dst_addr"),
        alert.get("dest_ip"),
        alert.get("dst_ip"),
        alert.get("destination_ip"),
    )
    dst_port = _first(
        event.get("dst_port"),
        event.get("dest_port"),
        alert.get("dst_port"),
        alert.get("dest_port"),
    )

    protocol = _first(event.get("proto"), alert.get("protocol"))
    app_protocol = _first(
        event.get("app_proto"),
        event.get("service"),
        alert.get("service"),
    )

    community_id = _first(
        event.get("community_id"),
        alert.get("community_id"),
    )
    flow_id = _first(event.get("flow_id"), alert.get("flow_id"))

    network_evidence = {
        name: event[name]
        for name in (
            "http", "dns", "tls", "ssh", "ftp",
            "files", "metadata",
        )
        if _present(event.get(name))
    }

    if _present(native_alert.get("metadata")):
        network_evidence["alert_metadata"] = native_alert["metadata"]

    flow = _object(event.get("flow"))
    if not flow:
        # Preserve equivalent native Snort flow counters when present.
        flow = {
            key: event[key]
            for key in (
                "client_pkts", "client_bytes",
                "server_pkts", "server_bytes",
                "flowstart_time",
            )
            if _present(event.get(key))
        }

    network_fields_present = any((
        _present(src_ip),
        _present(dst_ip),
        _present(src_port),
        _present(dst_port),
        _present(protocol),
        _present(app_protocol),
        _present(event.get("in_iface")),
        _present(event.get("iface")),
        _present(event.get("pkt_src")),
        _present(event.get("suricata_version")),
        _present(alert.get("iface")),
        bool(flow),
        bool(network_evidence),
    ))

    endpoints_complete = (
        _present(src_ip)
        and _present(dst_ip)
        and _present(protocol)
    )

    if endpoints_complete:
        network_status = "available"
    elif network_fields_present:
        network_status = "partial"
    else:
        network_status = "unavailable"

    rule_available = bool(rule) or bool(documentation) or bool(explanation)

    identifiers = _object(intel.get("identifiers"))
    cves = _identifier_list(identifiers.get("cves"))
    technique_ids = _identifier_list(
        identifiers.get("mitre_attack")
        or identifiers.get("mitre_techniques")
    )

    vulnerabilities = _object(intel.get("vulnerabilities"))
    technique_enrichment = _object(intel.get("mitre_enrichment"))

    vuln_coverage = _vulnerability_coverage(cves, vulnerabilities)
    attack_coverage = _technique_coverage(
        technique_ids,
        technique_enrichment,
    )

    unresolved_cves = [
        item["identifier"]
        for item in vuln_coverage
        if item["status"] == "unresolved_in_local_sources"
    ]
    unresolved_techniques = [
        item["identifier"]
        for item in attack_coverage
        if item["status"] == "unresolved_in_local_sources"
    ]

    related_alerts = evidence.get("related_alerts")
    if not isinstance(related_alerts, list):
        related_alerts = []

    packet_summary = _object(evidence.get("packet_summary"))
    packets = evidence.get("packets")
    if not isinstance(packets, list):
        packets = []

    if investigation is None:
        packet_status = "not_loaded"
    elif packet_summary.get("total_packets", len(packets)) > 0:
        packet_status = "retained_evidence_found"
    else:
        packet_status = "no_matching_retained_packets"

    if len(related_alerts) > 1:
        correlation_status = "related_alerts_found"
    elif (
        _present(alert.get("correlation_group_id"))
        or _present(event.get("correlation_group_id"))
    ):
        correlation_status = "correlation_group_available"
    elif _present(community_id):
        correlation_status = "community_id_available"
    else:
        correlation_status = "no_correlation_match_recorded"

    sources = _object(intel.get("sources"))
    data_as_of = _object(intel.get("data_as_of"))
    lookup_mode = intel.get("lookup_mode")

    return {
        "schema": {
            "id": ENRICHMENT_SCHEMA_ID,
            "version": ENRICHMENT_SCHEMA_VERSION,
        },
        "summary": {
            "alert_id": alert_id,
            "engine": engine,
            "signature": signature,
            "timestamp": _first(
                event.get("timestamp"),
                alert.get("timestamp"),
                alert.get("event_ts_utc"),
            ),
            "native_severity": native_severity,
            "severity_semantics": severity_semantics,
            "rule_context_available": rule_available,
            "network_context_status": network_status,
            "cve_identifier_count": len(cves),
            "attack_technique_count": len(technique_ids),
        },
        "detection": {
            "rule": rule,
            "documentation": documentation,
            "analysis": explanation,
            "rule_context_found": bool(
                base.get("rule_context_found") or rule
            ),
        },
        "network": {
            "source": {
                "ip": src_ip,
                "port": src_port,
            },
            "destination": {
                "ip": dst_ip,
                "port": dst_port,
            },
            "protocol": protocol,
            "application_protocol": app_protocol,
            "direction": _first(event.get("direction"), event.get("dir"), alert.get("direction")),
            "interface": _first(event.get("in_iface"), event.get("iface"), alert.get("iface")),
            "community_id": community_id,
            "flow_id": flow_id,
            "flow": flow,
            "protocol_evidence": network_evidence,
        },
        "threat_intelligence": {
            "identifiers": {
                "cves": cves,
                "mitre_attack": technique_ids,
            },
            "vulnerabilities": vulnerabilities,
            "mitre_enrichment": technique_enrichment,
            "references": intel.get("references", []),
            "coverage": {
                "vulnerabilities": vuln_coverage,
                "mitre_attack": attack_coverage,
                "unresolved_cves": unresolved_cves,
                "unresolved_techniques": unresolved_techniques,
            },
        },
        "investigation": {
            "status": packet_status,
            "packet_summary": packet_summary,
            "packets": packets,
            "correlation": {
                "status": correlation_status,
                "correlation_group_id": _first(
                    alert.get("correlation_group_id"),
                    event.get("correlation_group_id"),
                ),
                "community_id": community_id,
            },
            "evidence_note": EVIDENCE_NOTE,
        },
        "assessment": {
            "risk_context": _object(intel.get("risk_context")),
            "explanation": explanation,
            "confidence": {
                "status": "not_numerically_scored",
                "note": (
                    "No numerical confidence score is inferred. Interpret "
                    "findings in the context of the recorded source evidence."
                ),
            },
        },
        "coverage": {
            "native_event": (
                "available" if bool(event) else "unavailable"
            ),
            "rule_intelligence": (
                "available" if rule_available else "unavailable"
            ),
            "network": network_status,
            "vulnerability_intelligence": (
                "not_applicable_no_cve_identifier"
                if not cves
                else (
                    "partially_unresolved"
                    if unresolved_cves
                    else "local_records_found"
                )
            ),
            "attack_intelligence": (
                "not_applicable_no_technique_identifier"
                if not technique_ids
                else (
                    "partially_unresolved"
                    if unresolved_techniques
                    else "local_records_found"
                )
            ),
            "packet_investigation": packet_status,
            "correlation": correlation_status,
        },
        "provenance": {
            "lookup_mode": lookup_mode or "not_recorded",
            "retrieved_at": intel.get("retrieved_at"),
            "sources": sources,
            "data_as_of": data_as_of,
        },
    }


__all__ = [
    "ENRICHMENT_SCHEMA_ID",
    "ENRICHMENT_SCHEMA_VERSION",
    "build_alert_enrichment",
]
