from __future__ import annotations

import json
from typing import Any

from ids.db import canonical_event_hash
from ids.community_id import community_id
from ids.time_utils import (
    parse_event_timestamp,
    parse_suricata_timestamp,
    to_epoch_ms,
)


def to_int(value: Any) -> int | None:
    if value in (None, ""):
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def endpoint(ip: Any, port: Any) -> str | None:
    if not ip:
        return None

    if port in (None, ""):
        return str(ip)

    return f"{ip}:{port}"


def unified_severity(value: Any) -> int:
    """Return severity 1-4, where 1 is highest and 4 is lowest."""
    parsed = to_int(value)
    if parsed is None:
        return 4
    return max(1, min(4, parsed))


def preserve_native_severity(value: Any) -> int:
    """Compatibility wrapper for the unified severity scale."""
    return unified_severity(value)

def normalize_snort_timestamp(alert: dict[str, Any]) -> int | None:
    return parse_event_timestamp(alert)


def normalize_suricata_timestamp(event: dict[str, Any]) -> int | None:
    raw = event.get("timestamp")

    if not raw:
        return None

    try:
        parsed = parse_suricata_timestamp(str(raw))
        return to_epoch_ms(parsed)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def normalize_snort(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Convert one native Snort alert_json event into the shared live alert row.
    """
    event_ts_utc = normalize_snort_timestamp(alert)

    msg = alert.get("msg")
    priority = to_int(alert.get("priority"))

    src_addr = alert.get("src_addr")
    src_port = to_int(alert.get("src_port"))
    dst_addr = alert.get("dst_addr")
    dst_port = to_int(alert.get("dst_port"))

    return {
        "timestamp": (
            str(alert["timestamp"])
            if alert.get("timestamp")
            else None
        ),
        "rule": msg,
        "classification": alert.get("class"),
        "priority": priority,
        "protocol": alert.get("proto"),
        "src": endpoint(src_addr, src_port),
        "dst": endpoint(dst_addr, dst_port),
        "snort_rule": alert.get("rule"),
        "iface": alert.get("iface"),
        "service": alert.get("service"),
        "src_addr": src_addr,
        "src_port": src_port,
        "dst_addr": dst_addr,
        "dst_port": dst_port,
        "direction": alert.get("dir"),
        "pkt_len": to_int(alert.get("pkt_len")),
        "action": alert.get("action"),
        "msg": msg,
        "gid": to_int(alert.get("gid")),
        "sid": to_int(alert.get("sid")),
        "rev": to_int(alert.get("rev")),
        "ttl": to_int(alert.get("ttl")),
        "tos": to_int(alert.get("tos")),
        "tcp_flags": alert.get("tcp_flags"),
        "icmp_type": to_int(alert.get("icmp_type")),
        "icmp_code": to_int(alert.get("icmp_code")),
        "client_pkts": to_int(alert.get("client_pkts")),
        "client_bytes": to_int(alert.get("client_bytes")),
        "server_pkts": to_int(alert.get("server_pkts")),
        "server_bytes": to_int(alert.get("server_bytes")),
        "raw_json": json.dumps(
            alert,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        "engine": "snort",
        "event_ts_utc": event_ts_utc,
        "flow_id": (
            str(alert["flow_id"])
            if alert.get("flow_id") is not None
            else None
        ),
        "community_id": (
            community_id(
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                alert.get("proto"),
            )
            if (
                src_addr
                and dst_addr
                and str(alert.get("proto", "")).upper()
                in {"TCP", "UDP"}
            )
            else None
        ),
        "severity": unified_severity(priority),
        "rule_key": (
            f"snort:"
            f"{to_int(alert.get('gid')) or 1}:"
            f"{to_int(alert.get('sid'))}:"
            f"{to_int(alert.get('rev')) or 0}"
            if alert.get("sid") is not None
            else None
        ),
        "correlation_group_id": None,
        "event_hash": canonical_event_hash(
            alert,
            engine="snort",
        ),
    }


def normalize_suricata(event: dict[str, Any]) -> dict[str, Any] | None:
    """
    Convert one Suricata EVE alert event into the shared live alert row.

    Non-alert EVE events must be filtered before reaching this function.
    """
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert")

    if not isinstance(alert, dict):
        return None

    event_ts_utc = normalize_suricata_timestamp(event)

    src_addr = event.get("src_ip")
    src_port = to_int(event.get("src_port"))
    dst_addr = event.get("dest_ip")
    dst_port = to_int(event.get("dest_port"))

    gid = to_int(alert.get("gid"))
    sid = to_int(alert.get("signature_id"))
    rev = to_int(alert.get("rev"))
    native_severity = to_int(alert.get("severity"))
    native_priority = to_int(
        alert.get("priority")
        if alert.get("priority") is not None
        else event.get("priority")
    )

    signature = alert.get("signature")
    category = alert.get("category")

    return {
        "timestamp": (
            str(event["timestamp"])
            if event.get("timestamp")
            else None
        ),
        "rule": signature,
        "classification": category,
        "priority": native_priority,
        "protocol": event.get("proto"),
        "src": endpoint(src_addr, src_port),
        "dst": endpoint(dst_addr, dst_port),
        # Snort-specific field remains NULL for Suricata.
        "snort_rule": None,
        "iface": event.get("in_iface"),
        "service": event.get("app_proto"),
        "src_addr": src_addr,
        "src_port": src_port,
        "dst_addr": dst_addr,
        "dst_port": dst_port,
        "direction": event.get("direction"),
        "pkt_len": None,
        "action": alert.get("action"),
        "msg": signature,
        "gid": gid,
        "sid": sid,
        "rev": rev,
        "ttl": None,
        "tos": None,
        "tcp_flags": None,
        "icmp_type": None,
        "icmp_code": None,
        "client_pkts": to_int(
            (event.get("flow") or {}).get("pkts_toserver")
        ),
        "client_bytes": to_int(
            (event.get("flow") or {}).get("bytes_toserver")
        ),
        "server_pkts": to_int(
            (event.get("flow") or {}).get("pkts_toclient")
        ),
        "server_bytes": to_int(
            (event.get("flow") or {}).get("bytes_toclient")
        ),
        "raw_json": json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        "engine": "suricata",
        "event_ts_utc": event_ts_utc,
        "flow_id": (
            str(event["flow_id"])
            if event.get("flow_id") is not None
            else None
        ),
        "community_id": (
            str(event["community_id"])
            if event.get("community_id") is not None
            else None
        ),
        "severity": unified_severity(native_severity),
        "rule_key": (
            f"suricata:"
            f"{gid if gid is not None else 1}:"
            f"{sid}:"
            f"{rev if rev is not None else 0}"
            if sid is not None
            else None
        ),
        "correlation_group_id": None,
        "event_hash": canonical_event_hash(
            event,
            engine="suricata",
        ),
    }


def normalize_live_event(
    engine: str,
    event: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Common entry point for live Snort/Suricata ingestion.
    """
    normalized_engine = engine.strip().lower()

    if normalized_engine == "snort":
        return normalize_snort(event)

    if normalized_engine == "suricata":
        return normalize_suricata(event)

    raise ValueError(f"Unsupported IDS engine: {engine!r}")
