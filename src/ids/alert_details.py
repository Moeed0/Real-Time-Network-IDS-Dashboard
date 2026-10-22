"""Read-only flow and packet details for a selected live IDS alert."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


PACKET_TIME_PADDING_MS = 5_000


def _readonly_connect(db_path: Path) -> sqlite3.Connection:
    path = Path(db_path).expanduser().resolve()
    conn = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True,
        timeout=5.0,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def load_alert_investigation(
    db_path: Path,
    alert_id: int,
    *,
    time_padding_ms: int = PACKET_TIME_PADDING_MS,
) -> dict[str, Any] | None:
    """
    Load one alert and matching, already-captured packets.

    Packet association uses the exact bidirectional IP/port tuple when
    ports are available, plus a time window around the related alert events.
    ICMP/ARP records without ports can be matched by endpoints and protocol.
    The result describes retained observations, not guaranteed complete traffic.
    """
    if time_padding_ms < 0:
        raise ValueError("time_padding_ms must be >= 0")

    conn = _readonly_connect(db_path)

    try:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (int(alert_id),),
        ).fetchone()

        if row is None:
            return None

        alert = dict(row)
        correlation_id = alert.get("correlation_group_id")
        community_id = alert.get("community_id")

        related_columns = """
            id, timestamp, engine, event_ts_utc, msg,
            src_addr, src_port, dst_addr, dst_port, protocol,
            severity, gid, sid, rev, community_id,
            correlation_group_id, client_pkts, client_bytes,
            server_pkts, server_bytes
        """

        if correlation_id:
            related_rows = conn.execute(
                f"""
                SELECT {related_columns}
                FROM alerts
                WHERE correlation_group_id = ?
                ORDER BY event_ts_utc, id
                """,
                (correlation_id,),
            ).fetchall()
        elif community_id:
            related_rows = conn.execute(
                f"""
                SELECT {related_columns}
                FROM alerts
                WHERE community_id = ?
                ORDER BY event_ts_utc, id
                """,
                (community_id,),
            ).fetchall()
        else:
            related_rows = conn.execute(
                f"""
                SELECT {related_columns}
                FROM alerts
                WHERE id = ?
                """,
                (int(alert_id),),
            ).fetchall()

        related_alerts = [dict(item) for item in related_rows]
        related_times = [
            value
            for item in related_alerts
            if (value := _as_int(item.get("event_ts_utc"))) is not None
        ]

        if not related_times:
            timestamp = _as_int(alert.get("event_ts_utc"))
            if timestamp is None:
                return {
                    "alert": alert,
                    "packets": [],
                    "packet_summary": {
                        "total_packets": 0,
                        "reason": (
                            "The selected alert has no usable event timestamp; "
                            "packet association cannot be time-bounded safely."
                        ),
                        "association": "unavailable",
                    },
                }
            related_times = [timestamp]

        window_start = max(0, min(related_times) - time_padding_ms)
        window_end = max(related_times) + time_padding_ms

        src = str(alert.get("src_addr") or alert.get("src") or "")
        dst = str(alert.get("dst_addr") or alert.get("dst") or "")
        src_port = alert.get("src_port")
        dst_port = alert.get("dst_port")
        protocol = str(alert.get("protocol") or "").upper()

        packet_rows = []
        association = "unavailable"
        reason = (
            "No matching packets were found in the currently retained packet "
            "records for this flow and time window. This does not mean the "
            "traffic never occurred: relevant packets may have fallen outside "
            "the alert time window or been removed by packet retention. "
            "Generate the traffic again while the passive packet collector is "
            "running to investigate a fresh occurrence."
        )

        if src and dst and src_port is not None and dst_port is not None:
            flow_clause = """
                (
                    (src = ? AND CAST(src_port AS TEXT) = ?
                     AND dst = ? AND CAST(dst_port AS TEXT) = ?)
                    OR
                    (src = ? AND CAST(src_port AS TEXT) = ?
                     AND dst = ? AND CAST(dst_port AS TEXT) = ?)
                )
            """
            params: list[Any] = [
                src, str(src_port), dst, str(dst_port),
                dst, str(dst_port), src, str(src_port),
                window_start, window_end,
            ]
            association = "exact_bidirectional_ip_port_tuple"
            reason = ""
        elif src and dst and protocol in {"ICMP", "ARP"}:
            flow_clause = """
                (
                    (src = ? AND dst = ?)
                    OR
                    (src = ? AND dst = ?)
                )
                AND UPPER(protocol) = ?
            """
            params = [
                src, dst, dst, src, protocol,
                window_start, window_end,
            ]
            association = "endpoint_protocol_time_window"
            reason = ""
        else:
            flow_clause = ""
            params = []

        if flow_clause:
            packet_rows = [
                dict(item)
                for item in conn.execute(
                    f"""
                    SELECT id, timestamp, event_ts_utc,
                           src, src_port, dst, dst_port,
                           protocol, size, info, tcp_flags
                    FROM packets
                    WHERE {flow_clause}
                      AND event_ts_utc BETWEEN ? AND ?
                    ORDER BY event_ts_utc, id
                    """,
                    params,
                ).fetchall()
            ]

        forward = []
        reverse = []

        for packet in packet_rows:
            direct = (
                str(packet.get("src")) == src
                and str(packet.get("dst")) == dst
            )
            if src_port is not None and dst_port is not None:
                direct = direct and (
                    str(packet.get("src_port")) == str(src_port)
                    and str(packet.get("dst_port")) == str(dst_port)
                )
            if direct:
                forward.append(packet)
            else:
                reverse.append(packet)

        all_sizes_known = all(
            packet.get("size") is not None for packet in packet_rows
        )

        def packet_bytes(items: list[dict[str, Any]]) -> int:
            return sum(
                int(item["size"])
                for item in items
                if _as_int(item.get("size")) is not None
            )

        packet_times = [
            value
            for packet in packet_rows
            if (value := _as_int(packet.get("event_ts_utc"))) is not None
        ]

        duration_ms = (
            max(packet_times) - min(packet_times)
            if packet_times
            else None
        )

        forward_fin = False
        reverse_fin = False
        reset_seen = False
        tcp_flags_seen = False

        for packet in packet_rows:
            flags = {
                value.strip().upper()
                for value in str(packet.get("tcp_flags") or "").split(",")
            }
            if not flags or flags == {""}:
                continue

            tcp_flags_seen = True
            reset_seen = reset_seen or "RST" in flags

            direct = (
                str(packet.get("src")) == src
                and str(packet.get("dst")) == dst
            )
            if src_port is not None and dst_port is not None:
                direct = direct and (
                    str(packet.get("src_port")) == str(src_port)
                    and str(packet.get("dst_port")) == str(dst_port)
                )

            if "FIN" in flags:
                if direct:
                    forward_fin = True
                else:
                    reverse_fin = True

        tcp_close_observed = (
            (reset_seen or (forward_fin and reverse_fin))
            if tcp_flags_seen
            else None
        )

        earliest_packet = min(packet_times) if packet_times else None
        latest_packet = max(packet_times) if packet_times else None
        first_alert_time = min(related_times) if related_times else None

        event_time_gap_ms = None
        if earliest_packet is not None and first_alert_time is not None:
            event_time_gap_ms = first_alert_time - earliest_packet

        packet_summary = {
            "association": association,
            "reason": reason if not packet_rows else "",
            "window_start_ms": window_start,
            "window_end_ms": window_end,
            "total_packets": len(packet_rows),
            "source_to_destination_packets": len(forward),
            "destination_to_source_packets": len(reverse),
            "source_to_destination_bytes": packet_bytes(forward),
            "destination_to_source_bytes": packet_bytes(reverse),
            "total_bytes": packet_bytes(packet_rows),
            "all_packet_sizes_known": all_sizes_known,
            "first_packet_ts_ms": earliest_packet,
            "last_packet_ts_ms": latest_packet,
            "duration_ms": duration_ms,
            "tcp_close_observed": tcp_close_observed,
            "first_alert_event_minus_first_packet_ms": event_time_gap_ms,
        }

        return {
            "alert": alert,
            "packets": packet_rows,
            "packet_summary": packet_summary,
        }
    finally:
        conn.close()


def load_alert_native_event(
    db_path: Path,
    alert_id: int,
) -> dict[str, Any] | None:
    """Load only the selected alert's stored source payload, read-only."""
    conn = _readonly_connect(Path(db_path))
    try:
        row = conn.execute(
            "SELECT id, engine, raw_json FROM alerts WHERE id = ?",
            (int(alert_id),),
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


_NATIVE_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "engine": ("engine",),
    "event_ts_utc": ("timestamp", "@timestamp", "ts"),
    "classification": (
        "classification", "class", "classtype", "category",
    ),
    "msg": ("msg", "message", "signature"),
    "gid": ("gid", "generator_id", "generatorid"),
    "sid": ("sid", "signature_id", "signatureid"),
    "rev": ("rev", "revision"),
    "severity": ("severity", "priority"),
    "protocol": ("protocol", "proto"),
    "service": ("service", "app_proto"),
    "src_addr": ("src_addr", "src_ip", "source_ip", "src", "source"),
    "src_port": ("src_port", "source_port"),
    "dst_addr": ("dst_addr", "dest_ip", "dst_ip", "destination_ip", "dst", "destination"),
    "dst_port": ("dst_port", "dest_port", "destination_port"),
    "direction": ("direction", "dir"),
    "action": ("action",),
    "pkt_len": ("pkt_len", "packet_length"),
    "client_pkts": ("client_pkts", "pkts_toserver"),
    "client_bytes": ("client_bytes", "bytes_toserver"),
    "server_pkts": ("server_pkts", "pkts_toclient"),
    "server_bytes": ("server_bytes", "bytes_toclient"),
    "flow_id": ("flow_id",),
    "community_id": ("community_id",),
}


def build_non_repeating_normalized_record(
    selected_record: dict[str, Any],
    native_payload: Any,
) -> dict[str, Any]:
    """Return useful normalized fields not already present in the native event.

    The source payload is never modified. Aliases account for common Snort
    fields and Suricata's nested EVE alert/network fields.
    """
    native_keys: set[str] = set()

    def collect_keys(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key).strip().lower()
                native_keys.add(key_text)
                native_keys.add(key_text.rsplit(".", 1)[-1])
                collect_keys(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect_keys(child)

    collect_keys(native_payload)

    # Keep one database identity, one normalized engine name, and one
    # standardized timestamp. Do not duplicate endpoint composite strings,
    # raw priority, or the derived rule_key.
    fields = (
        "record_id",
        "engine",
        "event_ts_utc",
        "classification",
        "msg",
        "gid",
        "sid",
        "rev",
        "severity",
        "protocol",
        "service",
        "src_addr",
        "src_port",
        "dst_addr",
        "dst_port",
        "direction",
        "action",
        "pkt_len",
        "client_pkts",
        "client_bytes",
        "server_pkts",
        "server_bytes",
        "flow_id",
        "community_id",
        "correlation_group_id",
        "event_hash",
    )

    result: dict[str, Any] = {}
    for field in fields:
        value = selected_record.get(field)

        if value is None or value == "":
            continue

        aliases = _NATIVE_FIELD_ALIASES.get(field, ())
        if any(alias.lower() in native_keys for alias in aliases):
            continue

        result[field] = value

    return result
