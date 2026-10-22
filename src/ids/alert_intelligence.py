import json
import sqlite3
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RULE_DB_PATH = PROJECT_ROOT / "data/lab/rules/ids_rules.db"
RULE_DOCS_PATH = PROJECT_ROOT / "data/json/rule_docs_preprocessed_by_sid.json"


def _load_rule_docs() -> dict[str, Any]:
    """Load the existing preprocessed rule documentation dataset."""

    if not RULE_DOCS_PATH.exists():
        raise FileNotFoundError(
            f"Rule documentation dataset not found: {RULE_DOCS_PATH}"
        )

    with RULE_DOCS_PATH.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(
            "Rule documentation dataset must be a JSON object keyed by SID."
        )

    return data


def _fetch_rule(
    gid: int,
    sid: int,
    db_path: str | Path = RULE_DB_PATH,
    *,
    engine: str | None = None,
    rev: int | None = None,
) -> dict[str, Any] | None:
    """
    Retrieve the best matching rule from the normalized rule database.

    The engine is a hard filter when known, because SIDs are not unique
    across Snort and Suricata. GID and revision are preferences, so a
    source that does not populate them consistently still matches.
    """
    db_path = Path(db_path)

    if not db_path.exists():
        raise FileNotFoundError(
            f"Rule database not found: {db_path}"
        )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(
            """
            SELECT *
            FROM rules
            WHERE sid = ?
              AND (? IS NULL OR engine = ?)
            ORDER BY
                CASE WHEN gid = ? THEN 0 ELSE 1 END,
                CASE WHEN rev = ? THEN 0 ELSE 1 END,
                CASE WHEN engine = 'snort' THEN 0 ELSE 1 END,
                rev DESC,
                id DESC
            LIMIT 1
            """,
            (sid, engine, engine, gid, rev),
        ).fetchone()

        return dict(row) if row is not None else None

    finally:
        conn.close()


def _get_documentation(
    sid: int,
    docs: dict[str, Any],
) -> dict[str, Any]:
    """
    Retrieve documentation using the existing SID-keyed dataset.

    The dataset may contain SID keys as strings and, depending on the
    preprocessing version, may store GID inside the record.
    """

    candidates = [
        str(sid),
        sid,
    ]

    for key in candidates:
        if key in docs:
            value = docs[key]

            if isinstance(value, dict):
                return value

    return {}


_PLACEHOLDER_TEXT = frozenset(
    {
        "none provided",
        "no information provided",
        "no public information",
    }
)


def _clean_documentation(
    documentation: dict[str, Any],
) -> dict[str, Any]:
    """Drop placeholder strings so empty fields are not shown as information."""
    return {
        key: value
        for key, value in documentation.items()
        if not (
            isinstance(value, str)
            and value.strip().rstrip(".").lower() in _PLACEHOLDER_TEXT
        )
    }


def _documentation_for_rule(
    rule: dict[str, Any],
    docs: dict[str, Any],
) -> dict[str, Any]:
    """
    Return documentation only for rules the dataset actually describes.

    The dataset is keyed by bare SID and covers Snort rules, so a Suricata
    rule that shares a SID must not inherit a Snort rule's documentation.
    """
    if rule.get("engine") != "snort":
        return {}

    return _clean_documentation(
        _get_documentation(
            sid=rule["sid"],
            docs=docs,
        )
    )


def get_alert_intelligence(
    gid: int,
    sid: int,
    rule_db_path: str | Path = RULE_DB_PATH,
    rule_docs_path: str | Path = RULE_DOCS_PATH,
    *,
    engine: str | None = None,
    rev: int | None = None,
) -> dict[str, Any] | None:
    """
    Retrieve deterministic intelligence for a Snort rule.

    Sources:
      1. data/lab/rules/ids_rules.db
      2. data/json/rule_docs_preprocessed_by_sid.json

    Returns None when no rule can be found.
    """

    rule_db_path = Path(rule_db_path)
    rule_docs_path = Path(rule_docs_path)

    rule = _fetch_rule(
        gid=gid,
        sid=sid,
        db_path=rule_db_path,
        engine=engine,
        rev=rev,
    )

    if rule is None:
        return None

    if not rule_docs_path.exists():
        raise FileNotFoundError(
            f"Rule documentation dataset not found: {rule_docs_path}"
        )

    with rule_docs_path.open("r", encoding="utf-8") as handle:
        docs = json.load(handle)

    if not isinstance(docs, dict):
        raise ValueError(
            "Rule documentation dataset must be a JSON object keyed by SID."
        )

    documentation = _documentation_for_rule(
        rule=rule,
        docs=docs,
    )

    return {
        "rule": rule,
        "documentation": documentation,
        "sources": {
            "rule_database": str(
                rule_db_path.relative_to(PROJECT_ROOT)
            ),
            "rule_documentation": str(
                rule_docs_path.relative_to(PROJECT_ROOT)
            ),
        },
    }




def _build_normalized_alert(
    alert: dict[str, Any],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build one common alert representation for Snort and Suricata."""

    protocol = alert.get("protocol")
    service = alert.get("service", "")

    source = alert.get("src")
    if source is None:
        source_ip = alert.get("src_addr")
        source_port = alert.get("src_port")

        if source_ip:
            source = (
                f"{source_ip}:{source_port}"
                if source_port is not None
                else str(source_ip)
            )

    destination = alert.get("dst")
    if destination is None:
        destination_ip = alert.get("dst_addr")
        destination_port = alert.get("dst_port")

        if destination_ip:
            destination = (
                f"{destination_ip}:{destination_port}"
                if destination_port is not None
                else str(destination_ip)
            )

    return {
        "engine": str(
            alert.get(
                "engine",
                rule.get("engine", "unknown"),
            )
        ),
        "timestamp": str(
            alert.get(
                "event_ts_utc",
                alert.get("timestamp", ""),
            )
            or ""
        ),
        "gid": alert.get(
            "gid",
            rule.get("gid"),
        ),
        "sid": alert.get(
            "sid",
            rule.get("sid"),
        ),
        "revision": alert.get(
            "rev",
            rule.get("rev"),
        ),
        "message": rule.get(
            "msg",
            alert.get(
                "msg",
                alert.get("message", ""),
            ),
        ),
        "classification": alert.get(
            "classification",
            rule.get("classtype"),
        ),
        "priority": alert.get("priority"),
        "protocol": (
            str(protocol).upper()
            if protocol is not None
            else ""
        ),
        "service": (
            str(service)
            if service is not None
            else ""
        ),
        "source": str(source or ""),
        "destination": str(destination or ""),
        "direction": str(
            alert.get(
                "direction",
                "",
            )
            or ""
        ),
        "severity": alert.get("severity"),
        "flow_id": alert.get("flow_id"),
        "community_id": str(
            alert.get("community_id", "")
            or ""
        ),
        "correlation_group_id": str(
            alert.get("correlation_group_id", "")
            or ""
        ),
    }


def build_alert_intelligence_context(
    alert: dict[str, Any],
    rule_db_path: str | Path = RULE_DB_PATH,
    rule_docs_path: str | Path = RULE_DOCS_PATH,
) -> dict[str, Any]:
    """
    Combine a live alert with deterministic rule intelligence.

    The original alert is preserved under 'alert'.
    """

    context: dict[str, Any] = {
        "alert": alert,
        "rule_context_found": False,
        "rule": {},
        "documentation": {},
        "security_references": {
            "cves": [],
            "mitre_attack": [],
        },
        "normalized_alert": {
            "engine": str(alert.get("engine", "unknown")),
            "timestamp": str(
                alert.get(
                    "event_ts_utc",
                    alert.get("timestamp", ""),
                )
                or ""
            ),
            "gid": alert.get("gid"),
            "sid": alert.get("sid"),
            "revision": alert.get("rev"),
            "message": str(
                alert.get(
                    "msg",
                    alert.get("message", ""),
                )
            ),
            "classification": alert.get("classification"),
            "priority": alert.get("priority"),
            "protocol": (
                str(alert.get("protocol")).upper()
                if alert.get("protocol") is not None
                else ""
            ),
            "service": str(
                alert.get("service", "")
                or ""
            ),
            "source": str(
                alert.get("src", "")
                or ""
            ),
            "destination": str(
                alert.get("dst", "")
                or ""
            ),
            "direction": str(
                alert.get("direction", "")
                or ""
            ),
            "severity": alert.get("severity"),
            "flow_id": alert.get("flow_id"),
            "community_id": str(
                alert.get("community_id", "")
                or ""
            ),
            "correlation_group_id": str(
                alert.get("correlation_group_id", "")
                or ""
            ),
        },
        "summary": {
            "engine": str(alert.get("engine", "unknown")),
            "gid": alert.get("gid"),
            "sid": alert.get("sid"),
            "message": str(
                alert.get(
                    "msg",
                    alert.get("message", ""),
                )
            ),
            "protocol": alert.get("protocol"),
            "classification": None,
            "priority": None,
            "documentation_available": False,
            "cves": [],
            "mitre_attack": [],
        },
        "sources": {},
    }

    gid = alert.get("gid")
    sid = alert.get("sid")

    try:
        gid = int(gid) if gid is not None else None
        sid = int(sid) if sid is not None else None
    except (TypeError, ValueError):
        return context

    if gid is None or sid is None:
        return context

    engine = alert.get("engine")

    intelligence = get_alert_intelligence(
        gid=gid,
        sid=sid,
        rule_db_path=rule_db_path,
        rule_docs_path=rule_docs_path,
        engine=str(engine).lower() if engine else None,
        rev=alert.get("rev"),
    )

    if intelligence is None:
        return context

    context.update(intelligence)

    rule = intelligence.get("rule", {})
    documentation = intelligence.get("documentation", {})

    context["normalized_alert"] = _build_normalized_alert(
        alert=alert,
        rule=rule,
    )

    context["summary"] = {
        "engine": str(
            alert.get(
                "engine",
                rule.get("engine", "unknown"),
            )
        ),
        "gid": rule.get(
            "gid",
            alert.get("gid"),
        ),
        "sid": rule.get(
            "sid",
            alert.get("sid"),
        ),
        "message": rule.get(
            "msg",
            alert.get(
                "msg",
                alert.get("message", ""),
            ),
        ),
        "protocol": (
            str(
                rule.get(
                    "protocol",
                    alert.get("protocol"),
                )
            ).upper()
            if rule.get(
                "protocol",
                alert.get("protocol"),
            ) is not None
            else None
        ),
        "classification": rule.get(
            "classtype",
            alert.get("classification"),
        ),
        "priority": rule.get(
            "priority",
            alert.get("priority"),
        ),
        "documentation_available": bool(documentation),
        "cves": [],
        "mitre_attack": [],
    }

    cves = rule.get("cve_ids_json") or []
    mitre_ids = rule.get("mitre_ids_json") or []

    if isinstance(cves, str):
        try:
            cves = json.loads(cves)
        except json.JSONDecodeError:
            cves = []

    if isinstance(mitre_ids, str):
        try:
            mitre_ids = json.loads(mitre_ids)
        except json.JSONDecodeError:
            mitre_ids = []

    if not isinstance(cves, list):
        cves = [cves]

    if not isinstance(mitre_ids, list):
        mitre_ids = [mitre_ids]

    context["security_references"] = {
        "cves": cves,
        "mitre_attack": mitre_ids,
    }

    context["summary"]["cves"] = cves
    context["summary"]["mitre_attack"] = mitre_ids

    context["rule_context_found"] = True

    return context
