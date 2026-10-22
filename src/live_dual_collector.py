from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from ids.config import Settings, get_settings
from ids.correlator import correlate_alerts
from ids.db import (
    connect_database,
    insert_alert_batch,
    prune_alerts,
)
from ids.live_normalizer import normalize_live_event
from ids.schema import ensure_schema
from ids.tailer import PersistentJsonTailer


@dataclass
class PendingBatch:
    """
    Alerts waiting for a database flush plus the latest source position
    that has been fully processed in this batch.

    Source positions are acknowledged only after the database write
    succeeds. This keeps non-alert Suricata events from advancing the
    persisted position past an earlier uncommitted alert.
    """

    rows: list[dict] = field(default_factory=list)
    latest_positions: dict[str, tuple[int, int]] = field(
        default_factory=dict
    )
    processed_lines: int = 0

    def record_position(
        self,
        engine: str,
        inode: int,
        offset: int,
    ) -> None:
        self.latest_positions[engine] = (
            inode,
            offset,
        )
        self.processed_lines += 1


def setup_database(settings: Settings) -> None:
    conn = connect_database(settings.db_file)

    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()


def flush_pending(
    settings: Settings,
    pending: PendingBatch,
    tailers: dict[str, PersistentJsonTailer],
) -> None:
    if not pending.latest_positions:
        return

    # First write alerts. If this fails, no source position is acknowledged.
    if pending.rows:
        conn = connect_database(settings.db_file)

        try:
            insert_alert_batch(
                conn,
                pending.rows,
            )

            # Find the database IDs for the pending events and assign
            # deterministic correlation groups. event_hash is unique,
            # so duplicate/replayed events resolve to the same rows.
            event_hashes = [
                row.get("event_hash")
                for row in pending.rows
                if row.get("event_hash")
            ]

            if event_hashes:
                placeholders = ",".join(
                    "?"
                    for _ in event_hashes
                )

                alert_ids = [
                    row[0]
                    for row in conn.execute(
                        f"""
                        SELECT id
                        FROM alerts
                        WHERE event_hash IN ({placeholders})
                        """,
                        event_hashes,
                    ).fetchall()
                ]

                correlate_alerts(
                    conn,
                    alert_ids,
                )

            conn.commit()

        finally:
            conn.close()

    # Acknowledge only after the successful database write and correlation.
    for engine, (inode, offset) in (
        pending.latest_positions.items()
    ):
        tailers[engine].acknowledge(
            inode,
            offset,
        )

    pending.rows.clear()
    pending.latest_positions.clear()
    pending.processed_lines = 0


def run_periodic_retention(
    settings: Settings,
    last_retention: float,
) -> float:
    now = time.monotonic()

    if (
        now - last_retention
        < settings.retention_interval_seconds
    ):
        return last_retention

    conn = connect_database(settings.db_file)

    try:
        prune_alerts(
            conn,
            settings.alert_retention,
        )
        conn.commit()
    finally:
        conn.close()

    return time.monotonic()


def handle_line(
    engine: str,
    line: str,
    inode: int,
    offset: int,
    pending: PendingBatch,
) -> None:
    # Every successfully handled line advances the in-memory batch position.
    # Persistence happens only after flush_pending succeeds.
    if not line.strip():
        pending.record_position(
            engine,
            inode,
            offset,
        )
        return

    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        print(
            f"[!] {engine}: invalid JSON at offset {offset}; "
            "skipping line."
        )

        pending.record_position(
            engine,
            inode,
            offset,
        )
        return

    if not isinstance(event, dict):
        print(
            f"[!] {engine}: JSON value is not an object; "
            "skipping line."
        )

        pending.record_position(
            engine,
            inode,
            offset,
        )
        return

    normalized = normalize_live_event(
        engine,
        event,
    )

    # Suricata has many EVE event types. Only alert events are inserted.
    if normalized is None:
        pending.record_position(
            engine,
            inode,
            offset,
        )
        return

    pending.rows.append(normalized)

    pending.record_position(
        engine,
        inode,
        offset,
    )

    print(
        f"[ALERT] {engine:<8} | "
        f"{normalized.get('timestamp')} | "
        f"{normalized.get('msg')} | "
        f"{normalized.get('src')} -> "
        f"{normalized.get('dst')} | "
        f"Severity: {normalized.get('severity')}"
    )


def run_collector(
    settings: Settings,
    *,
    start_at_end: bool = True,
) -> None:
    tailers = {
        "snort": PersistentJsonTailer(
            settings.snort_alert_file,
            settings.state_file,
            "snort",
            start_at_end=start_at_end,
        ),
        "suricata": PersistentJsonTailer(
            settings.suricata_eve_file,
            settings.state_file,
            "suricata",
            start_at_end=start_at_end,
        ),
    }

    pending = PendingBatch()

    last_flush = time.monotonic()
    last_retention = time.monotonic()

    print("=== Dual IDS Collector ===")
    print(
        f"Database:        {settings.db_file}"
    )
    print(
        f"Snort:            {settings.snort_alert_file}"
    )
    print(
        f"Suricata:         {settings.suricata_eve_file}"
    )
    print(
        f"State:            {settings.state_file}"
    )
    print(
        f"Start at end:     {start_at_end}"
    )
    print(
        f"Batch size:       {settings.batch_size} | "
        f"Flush: {settings.batch_flush_ms} ms"
    )

    while True:
        try:
            for engine, tailer in tailers.items():

                def callback(
                    line: str,
                    inode: int,
                    offset: int,
                ) -> None:
                    handle_line(
                        engine,
                        line,
                        inode,
                        offset,
                        pending,
                    )

                try:
                    tailer.poll(callback)

                except FileNotFoundError:
                    print(
                        f"[!] {engine}: log file not found: "
                        f"{tailer.path}"
                    )

                except PermissionError:
                    print(
                        f"[!] {engine}: log file not readable: "
                        f"{tailer.path}"
                    )

            now = time.monotonic()

            flush_due = (
                pending.rows
                and (
                    len(pending.rows)
                    >= settings.batch_size
                    or (
                        (
                            now - last_flush
                        ) * 1000
                        >= settings.batch_flush_ms
                    )
                )
            )

            # If there are only non-alert lines, we still need to persist
            # their source position eventually.
            position_flush_due = (
                pending.latest_positions
                and (
                    now - last_flush
                ) * 1000 >= settings.batch_flush_ms
            )

            if flush_due or position_flush_due:
                flush_pending(
                    settings,
                    pending,
                    tailers,
                )
                last_flush = time.monotonic()

            last_retention = run_periodic_retention(
                settings,
                last_retention,
            )

            time.sleep(0.05)

        except KeyboardInterrupt:
            if pending.latest_positions:
                flush_pending(
                    settings,
                    pending,
                    tailers,
                )

            print(
                "\nDual collector stopped."
            )
            return


def main() -> None:
    settings = get_settings()

    # Print the resolved paths BEFORE database setup/migration so an
    # incorrect environment variable is immediately visible.
    print("=== Dual IDS Collector Startup ===")
    print(f"Database:        {settings.db_file}")
    print(f"State:            {settings.state_file}")
    print(f"Snort:            {settings.snort_alert_file}")
    print(f"Suricata:         {settings.suricata_eve_file}")
    print()

    setup_database(settings)

    run_collector(
        settings,
        start_at_end=True,
    )


if __name__ == "__main__":
    main()
