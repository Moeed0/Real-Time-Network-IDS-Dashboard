"""Read-only adapter for live IDS alerts and cached intelligence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ids.live_dashboard import load_live_alerts, load_live_summary
from ids.live_intelligence_cache import load_cached_live_intelligence


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_ids(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return sorted({
        str(item).strip().upper()
        for item in value
        if str(item).strip()
    })


def adapt_live_alert(
    alert: dict[str, Any],
    intelligence: dict[str, Any] | None = None,
    *,
    intelligence_loaded: bool = True,
) -> dict[str, Any]:
    """Adapt one live alert into a common dashboard-friendly structure."""
    intelligence = _mapping(intelligence)
    base = _mapping(intelligence.get("base_intelligence"))
    identifiers = _mapping(intelligence.get("identifiers"))
    risk = _mapping(intelligence.get("risk_context"))
    rule = dict(_mapping(base.get("rule")))
    documentation = _mapping(base.get("documentation"))

    cves = set(_string_ids(identifiers.get("cves")))
    mitre_ids = set(_string_ids(identifiers.get("mitre_attack")))

    vulnerabilities = _mapping(intelligence.get("vulnerabilities"))
    cves.update(
        str(key).strip().upper()
        for key in vulnerabilities
        if str(key).strip()
    )

    mitre_enrichment = _mapping(intelligence.get("mitre_enrichment"))
    mitre_ids.update(
        str(key).strip().upper()
        for key in mitre_enrichment
        if str(key).strip()
    )

    vulnerability_rows = []
    for cve in sorted(cves):
        item = _mapping(vulnerabilities.get(cve))
        vulnerability_rows.append({
            "cve_id": cve,
            "nvd_found": bool(item.get("nvd")),
            "nvd_record": _mapping(item.get("nvd")),
            "cisa_kev": bool(item.get("cisa_kev")),
            "epss": _mapping(item.get("epss")),
            "circl": _mapping(item.get("circl")),
        })

    techniques = []
    for technique_id in sorted(mitre_ids):
        details = _mapping(mitre_enrichment.get(technique_id))
        techniques.append({
            "technique_id": technique_id,
            "external_lookup_found": bool(details),
            "attack_record": details,
        })

    known_exploited_cves = _string_ids(
        risk.get("known_exploited_cves")
    )
    known_exploited = bool(
        risk.get("known_exploited") or known_exploited_cves
    )

    engine_key = str(alert.get("engine") or "unknown").strip().lower()
    engine_display = {
        "snort": "Snort",
        "suricata": "Suricata",
    }.get(engine_key, engine_key.title())

    message = alert.get("msg") or alert.get("rule") or ""
    timestamp = alert.get("timestamp") or alert.get("event_ts_utc")

    rule.setdefault("engine", engine_key)
    rule.setdefault("gid", alert.get("gid"))
    rule.setdefault("sid", alert.get("sid"))
    rule.setdefault("rev", alert.get("rev"))
    rule.setdefault("msg", message)
    rule.setdefault("classtype", alert.get("classification"))

    context = {
        "schema_version": "live-cache-adapter-1",
        "rule_intelligence": {
            "found": bool(base.get("rule_context_found")),
            "rule": rule,
            "documentation": documentation,
        },
        "project_documentation": {
            "found": bool(documentation),
            "documentation": documentation,
        },
        "identifier_evidence": {
            "cves": {cve: {} for cve in sorted(cves)},
            "mitre_techniques": {
                technique: {} for technique in sorted(mitre_ids)
            },
        },
        "vulnerability_intelligence": {
            "cves": vulnerability_rows,
            "known_exploited": known_exploited,
            "known_exploited_cves": known_exploited_cves,
            "risk_context": risk,
        },
        "mitre_attack_intelligence": {
            "techniques": techniques,
        },
        "coverage": {
            "exact_rule_found": bool(base.get("rule_context_found")),
            "project_documentation_found": bool(documentation),
            "has_cve_context": bool(cves),
            "has_mitre_context": bool(mitre_ids),
            "known_exploited_cve": known_exploited,
        },
        "analysis_tags": {
            "engine": engine_key,
            "service": alert.get("service"),
            "protocol": alert.get("protocol"),
            "classification": alert.get("classification"),
        },
    }

    adapted = dict(alert)
    adapted.update({
        "record_id": alert.get("id", alert.get("record_id")),
        "intelligence_loaded": bool(intelligence_loaded),
        "engine": engine_display,
        "engine_key": engine_key,
        "alert": {
            "message": message,
            "classification": alert.get("classification"),
            "timestamp": timestamp,
            "gid": alert.get("gid"),
            "sid": alert.get("sid"),
            "rev": alert.get("rev"),
            "priority": alert.get("priority"),
        },
        "rule": rule,
        "network": {
            "service": alert.get("service") or "",
            "protocol": alert.get("protocol") or "",
            "source_ip": alert.get("src_addr"),
            "source_port": alert.get("src_port"),
            "destination_ip": alert.get("dst_addr"),
            "destination_port": alert.get("dst_port"),
        },
        "security_context": context,
        "live_intelligence": intelligence,
    })
    return adapted


def load_live_alert_view_records(
    db_path: str | Path,
    *,
    limit: int | None = None,
    include_cached_intelligence: bool = True,
) -> list[dict[str, Any]]:
    """Load live alerts and cached intelligence without network lookups."""
    db_path = Path(db_path).expanduser().resolve()
    summary = load_live_summary(db_path)
    total = int(summary.get("total_alerts") or 0)

    effective_limit = max(1, total) if limit is None else int(limit)
    if effective_limit < 1:
        raise ValueError("limit must be >= 1 or None")

    rows = load_live_alerts(db_path, limit=effective_limit)
    records = []

    for row in rows:
        cached = (
            load_cached_live_intelligence(row)
            if include_cached_intelligence
            else None
        )
        records.append(
            adapt_live_alert(
                row,
                cached,
                intelligence_loaded=include_cached_intelligence,
            )
        )

    return records


__all__ = ["adapt_live_alert", "load_live_alert_view_records"]
