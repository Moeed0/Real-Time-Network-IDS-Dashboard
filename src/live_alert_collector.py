from __future__ import annotations

import json
import time
from datetime import datetime

from ids.config import Settings, get_settings
from ids.db import canonical_event_hash, connect_database, insert_alert_batch, prune_alerts
from ids.schema import ensure_schema
from ids.time_utils import local_timezone, parse_event_timestamp


def to_int(value):
    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def endpoint(ip, port):
    if not ip:
        return None

    if port is None or port == "":
        return ip

    return f"{ip}:{port}"


def native_severity(value) -> int:
    """Return unified severity 1-4; missing or invalid values become 4."""
    try:
        parsed = int(value) if value not in (None, "") else 4
    except (TypeError, ValueError):
        parsed = 4
    return max(1, min(4, parsed))

def rule_key_for_snort(alert: dict) -> str | None:
    sid = alert.get("sid")

    if sid in (None, ""):
        return None

    gid = alert.get("gid")
    rev = alert.get("rev")

    if gid in (None, ""):
        gid = 1

    if rev in (None, ""):
        rev = 0

    return f"snort:{int(gid)}:{int(sid)}:{int(rev)}"


def old_timestamp(alert: dict, event_ts_utc: int | None) -> str:
    """
    Preserve the original timestamp field when Snort supplied one.

    When it is missing, create the same readable local timestamp format
    used by the old collector.
    """
    timestamp = alert.get("timestamp")

    if timestamp:
        return str(timestamp)

    if event_ts_utc is not None:
        dt = datetime.fromtimestamp(
            event_ts_utc / 1000,
            tz=local_timezone(),
        )
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def alert_to_row(alert: dict) -> dict:
    event_ts_utc = parse_event_timestamp(alert)

    msg = alert.get("msg")
    snort_rule = alert.get("rule")
    classification = alert.get("class")
    priority = to_int(alert.get("priority"))
    protocol = alert.get("proto")

    src_addr = alert.get("src_addr")
    src_port = to_int(alert.get("src_port"))
    dst_addr = alert.get("dst_addr")
    dst_port = to_int(alert.get("dst_port"))

    src = endpoint(src_addr, src_port)
    dst = endpoint(dst_addr, dst_port)

    raw_json = json.dumps(
        alert,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    event_hash = canonical_event_hash(alert, engine="snort")

    return {
        "timestamp": old_timestamp(alert, event_ts_utc),
        # Preserve old dashboard meaning of "rule".
        "rule": msg,
        "classification": classification,
        "priority": priority,
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "snort_rule": snort_rule,
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
        "raw_json": raw_json,
        "engine": "snort",
        "event_ts_utc": event_ts_utc,
        "flow_id": alert.get("flow_id"),
        "severity": native_severity(alert.get("priority")),
        "rule_key": rule_key_for_snort(alert),
        "correlation_group_id": None,
        "event_hash": event_hash,
    }


def setup_database(settings: Settings) -> None:
    conn = connect_database(settings.db_file)

    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()


def flush_pending(settings: Settings, pending: list[tuple]) -> None:
    if not pending:
        return

    conn = connect_database(settings.db_file)

    try:
        insert_alert_batch(conn, pending)
        conn.commit()
    finally:
        conn.close()

    pending.clear()


def run_periodic_retention(settings: Settings) -> None:
    conn = connect_database(settings.db_file)

    try:
        prune_alerts(conn, settings.alert_retention)
        conn.commit()
    finally:
        conn.close()


def follow_alert_file(settings: Settings) -> None:
    alert_file = settings.snort_alert_file
    pending: list[tuple] = []

    last_flush = time.monotonic()
    last_retention = time.monotonic()

    print(f"Watching Snort JSON alert file: {alert_file}")
    print(f"Writing latest {settings.alert_retention} alerts to: {settings.db_file}")

    while True:
        try:
            with alert_file.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as f:
                f.seek(0)

                while True:
                    line = f.readline()
                    now = time.monotonic()

                    if line:
                        line = line.strip()

                        if line:
                            try:
                                alert = json.loads(line)

                                if not isinstance(alert, dict):
                                    print("[!] Skipping non-object JSON alert.")
                                else:
                                    pending.append(alert_to_row(alert))

                                    print(
                                        f"[ALERT] {alert.get('timestamp')} | "
                                        f"{alert.get('msg')} | "
                                        f"{alert.get('src_addr')} -> "
                                        f"{alert.get('dst_addr')} | "
                                        f"Priority: {alert.get('priority')}"
                                    )

                            except json.JSONDecodeError:
                                print(
                                    f"[!] Skipping invalid JSON line: "
                                    f"{line[:120]}"
                                )

                    flush_due = (
                        len(pending) >= settings.batch_size
                        or (
                            pending
                            and (
                                (now - last_flush) * 1000
                                >= settings.batch_flush_ms
                            )
                        )
                    )

                    if flush_due:
                        flush_pending(settings, pending)
                        last_flush = time.monotonic()

                    if (
                        now - last_retention
                        >= settings.retention_interval_seconds
                    ):
                        run_periodic_retention(settings)
                        last_retention = time.monotonic()

                    if not line:
                        try:
                            if alert_file.stat().st_size < f.tell():
                                print(
                                    "[*] Alert file was truncated. "
                                    "Resetting reader."
                                )
                                f.seek(0)
                                continue
                        except FileNotFoundError:
                            break

                        time.sleep(0.05)

        except FileNotFoundError:
            print(f"[!] Alert file not found: {alert_file}")
            time.sleep(1)

        except PermissionError:
            print(f"[!] Alert file is not readable: {alert_file}")
            time.sleep(2)

        except KeyboardInterrupt:
            flush_pending(settings, pending)
            print("\nCollector stopped.")
            return

        except OSError as exc:
            print(f"[!] Alert file error: {exc}")
            time.sleep(1)


def main() -> None:
    settings = get_settings()
    setup_database(settings)
    follow_alert_file(settings)


if __name__ == "__main__":
    main()
