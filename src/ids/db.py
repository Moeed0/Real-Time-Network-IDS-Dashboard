from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def canonical_event_hash(
    event: dict[str, Any],
    *,
    engine: str = "snort",
) -> str:
    payload = (
        f"{engine}\n"
        f"{canonical_json(event)}"
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def connect_database(
    db_path: Path,
) -> sqlite3.Connection:
    db_path = Path(db_path).expanduser().resolve()
    db_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    conn = sqlite3.connect(
        db_path,
        timeout=5.0,
        check_same_thread=False,
    )

    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    _restore_sudo_user_ownership(db_path)

    return conn


def _restore_sudo_user_ownership(db_path: Path) -> None:
    """
    When a collector is temporarily run through sudo, keep SQLite's
    database/WAL files owned by the invoking normal user where possible.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

    if not sudo_uid or not sudo_gid:
        return

    try:
        uid = int(sudo_uid)
        gid = int(sudo_gid)
    except ValueError:
        return

    for path in (
        db_path,
        Path(f"{db_path}-wal"),
        Path(f"{db_path}-shm"),
    ):
        if not path.exists():
            continue

        try:
            os.chown(path, uid, gid)
            os.chmod(path, 0o664)
        except PermissionError:
            pass


def insert_alert_batch(
    conn: sqlite3.Connection,
    rows: Iterable[dict[str, Any]],
) -> int:
    rows = list(rows)

    if not rows:
        return 0

    sql = """
        INSERT INTO alerts (
            timestamp,
            rule,
            classification,
            priority,
            protocol,
            src,
            dst,
            snort_rule,
            iface,
            service,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            direction,
            pkt_len,
            action,
            msg,
            gid,
            sid,
            rev,
            ttl,
            tos,
            tcp_flags,
            icmp_type,
            icmp_code,
            client_pkts,
            client_bytes,
            server_pkts,
            server_bytes,
            raw_json,
            engine,
            event_ts_utc,
            flow_id,
            community_id,
            severity,
            rule_key,
            correlation_group_id,
            event_hash
        )
        VALUES (
            ?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?,?,?,?,?,
            ?,?,?,?,?,?,?,?,?
        )
        ON CONFLICT(event_hash) DO NOTHING
    """

    values = []

    for row in rows:
        values.append(
            (
                row.get("timestamp"),
                row.get("rule"),
                row.get("classification"),
                row.get("priority"),
                row.get("protocol"),
                row.get("src"),
                row.get("dst"),
                row.get("snort_rule"),
                row.get("iface"),
                row.get("service"),
                row.get("src_addr"),
                row.get("src_port"),
                row.get("dst_addr"),
                row.get("dst_port"),
                row.get("direction"),
                row.get("pkt_len"),
                row.get("action"),
                row.get("msg"),
                row.get("gid"),
                row.get("sid"),
                row.get("rev"),
                row.get("ttl"),
                row.get("tos"),
                row.get("tcp_flags"),
                row.get("icmp_type"),
                row.get("icmp_code"),
                row.get("client_pkts"),
                row.get("client_bytes"),
                row.get("server_pkts"),
                row.get("server_bytes"),
                row.get("raw_json"),
                row.get("engine"),
                row.get("event_ts_utc"),
                row.get("flow_id"),
                row.get("community_id"),
                row.get("severity"),
                row.get("rule_key"),
                row.get("correlation_group_id"),
                row.get("event_hash"),
            )
        )

    before = conn.total_changes

    conn.executemany(
        sql,
        values,
    )

    inserted = conn.total_changes - before
    conn.commit()

    return inserted


def insert_packet_batch(
    conn: sqlite3.Connection,
    rows: Iterable[dict[str, Any]],
) -> int:
    rows = list(rows)

    if not rows:
        return 0

    sql = """
        INSERT INTO packets (
            timestamp,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            size,
            info,
            tcp_flags,
            event_ts_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    values = [
        (
            row.get("timestamp"),
            row.get("src"),
            row.get("dst"),
            row.get("protocol"),
            row.get("src_port"),
            row.get("dst_port"),
            row.get("size"),
            row.get("info"),
            row.get("tcp_flags"),
            row.get("event_ts_utc"),
        )
        for row in rows
    ]

    before = conn.total_changes

    conn.executemany(
        sql,
        values,
    )

    inserted = conn.total_changes - before
    conn.commit()

    return inserted


def prune_alerts(
    conn: sqlite3.Connection,
    max_rows: int,
) -> int:
    if max_rows < 1:
        raise ValueError("max_rows must be >= 1")

    before = conn.total_changes

    conn.execute(
        """
        DELETE FROM alerts
        WHERE id NOT IN (
            SELECT id
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        )
        """,
        (max_rows,),
    )

    conn.commit()

    return conn.total_changes - before


def prune_packets(
    conn: sqlite3.Connection,
    max_rows: int,
) -> int:
    if max_rows < 1:
        raise ValueError("max_rows must be >= 1")

    before = conn.total_changes

    conn.execute(
        """
        DELETE FROM packets
        WHERE id NOT IN (
            SELECT id
            FROM packets
            ORDER BY id DESC
            LIMIT ?
        )
        """,
        (max_rows,),
    )

    conn.commit()

    return conn.total_changes - before
