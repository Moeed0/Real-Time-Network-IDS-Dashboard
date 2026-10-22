from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

from ids.config import get_settings
from ids.tailer import PersistentJsonTailer
from live_dual_collector import (
    PendingBatch,
    flush_pending,
    handle_line,
    setup_database,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _process_file(engine, tailer, pending):
    def callback(line, inode, offset):
        handle_line(
            engine,
            line,
            inode,
            offset,
            pending,
        )

    return tailer.poll(callback)


def test_dual_collector_ingests_both_engines_and_restarts_without_duplicates(
    tmp_path,
    monkeypatch,
):
    db_file = tmp_path / "ids.db"
    state_file = tmp_path / "state.json"
    snort_file = tmp_path / "alert_json.txt"
    suricata_file = tmp_path / "eve.json"

    shutil.copy2(
        REPO_ROOT
        / "sample_data/snort/alert_json.txt",
        snort_file,
    )

    shutil.copy2(
        REPO_ROOT
        / "sample_data/suricata/eve.json",
        suricata_file,
    )

    monkeypatch.setenv(
        "IDS_DB_FILE",
        str(db_file),
    )
    monkeypatch.setenv(
        "IDS_STATE_FILE",
        str(state_file),
    )
    monkeypatch.setenv(
        "IDS_SNORT_ALERT_FILE",
        str(snort_file),
    )
    monkeypatch.setenv(
        "IDS_SURICATA_EVE_FILE",
        str(suricata_file),
    )
    monkeypatch.setenv(
        "IDS_BATCH_SIZE",
        "20",
    )
    monkeypatch.setenv(
        "IDS_BATCH_FLUSH_MS",
        "100",
    )

    settings = get_settings()

    assert settings.db_file == db_file.resolve()
    assert settings.state_file == state_file.resolve()
    assert settings.snort_alert_file == snort_file.resolve()
    assert settings.suricata_eve_file == suricata_file.resolve()

    setup_database(settings)

    tailers = {
        "snort": PersistentJsonTailer(
            snort_file,
            state_file,
            "snort",
            start_at_end=False,
        ),
        "suricata": PersistentJsonTailer(
            suricata_file,
            state_file,
            "suricata",
            start_at_end=False,
        ),
    }

    pending = PendingBatch()

    snort_lines = _process_file(
        "snort",
        tailers["snort"],
        pending,
    )

    suricata_lines = _process_file(
        "suricata",
        tailers["suricata"],
        pending,
    )

    assert snort_lines > 0
    assert suricata_lines > 0

    flush_pending(
        settings,
        pending,
        tailers,
    )

    conn = sqlite3.connect(db_file)

    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        snort_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE engine='snort'"
        ).fetchone()[0]

        suricata_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE engine='suricata'"
        ).fetchone()[0]

        distinct_hashes = conn.execute(
            "SELECT COUNT(DISTINCT event_hash) FROM alerts"
        ).fetchone()[0]

        assert total == 6
        assert snort_count == 3
        assert suricata_count == 3
        assert distinct_hashes == 6

    finally:
        conn.close()

    saved = json.loads(
        state_file.read_text(encoding="utf-8")
    )

    assert "snort" in saved
    assert "suricata" in saved

    # Fresh tailers simulate a process restart.
    restarted_tailers = {
        "snort": PersistentJsonTailer(
            snort_file,
            state_file,
            "snort",
            start_at_end=True,
        ),
        "suricata": PersistentJsonTailer(
            suricata_file,
            state_file,
            "suricata",
            start_at_end=True,
        ),
    }

    snort_replay = []
    suricata_replay = []

    restarted_tailers["snort"].poll(
        lambda line, inode, offset:
        snort_replay.append(line)
    )

    restarted_tailers["suricata"].poll(
        lambda line, inode, offset:
        suricata_replay.append(line)
    )

    assert snort_replay == []
    assert suricata_replay == []

    conn = sqlite3.connect(db_file)

    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0] == 6

        assert conn.execute(
            "SELECT COUNT(DISTINCT event_hash) FROM alerts"
        ).fetchone()[0] == 6

    finally:
        conn.close()


def test_dual_collector_assigns_correlation_groups(
    tmp_path,
    monkeypatch,
):
    from ids.community_id import community_id as make_community_id
    from ids.correlator import correlation_group_id_for_community

    db_file = tmp_path / "ids.db"
    state_file = tmp_path / "state.json"
    snort_file = tmp_path / "alert_json.txt"
    suricata_file = tmp_path / "eve.json"

    # Build a matching flow inside temporary test files. The published sample
    # dataset remains independent and contains no cross-engine correlation case.
    snort_record = json.loads(
        (REPO_ROOT / "sample_data/snort/alert_json.txt")
        .read_text(encoding="utf-8").splitlines()[0]
    )
    suricata_record = json.loads(
        (REPO_ROOT / "sample_data/suricata/eve.json")
        .read_text(encoding="utf-8").splitlines()[0]
    )

    src_ip = "192.0.2.77"
    dst_ip = "198.51.100.77"
    src_port = 40000
    dst_port = 80
    protocol = "TCP"

    snort_record.update({
        "src_addr": src_ip,
        "dst_addr": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": protocol,
    })

    expected_community_id = make_community_id(
        src_ip, src_port, dst_ip, dst_port, protocol
    )

    suricata_record.update({
        "src_ip": src_ip,
        "dest_ip": dst_ip,
        "src_port": src_port,
        "dest_port": dst_port,
        "proto": protocol,
        "community_id": expected_community_id,
    })

    snort_file.write_text(
        json.dumps(snort_record) + "\n",
        encoding="utf-8",
    )
    suricata_file.write_text(
        json.dumps(suricata_record) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("IDS_DB_FILE", str(db_file))
    monkeypatch.setenv("IDS_STATE_FILE", str(state_file))
    monkeypatch.setenv("IDS_SNORT_ALERT_FILE", str(snort_file))
    monkeypatch.setenv("IDS_SURICATA_EVE_FILE", str(suricata_file))
    monkeypatch.setenv("IDS_BATCH_SIZE", "20")
    monkeypatch.setenv("IDS_BATCH_FLUSH_MS", "100")

    settings = get_settings()
    setup_database(settings)

    tailers = {
        "snort": PersistentJsonTailer(
            snort_file, state_file, "snort", start_at_end=False
        ),
        "suricata": PersistentJsonTailer(
            suricata_file, state_file, "suricata", start_at_end=False
        ),
    }

    pending = PendingBatch()
    _process_file("snort", tailers["snort"], pending)
    _process_file("suricata", tailers["suricata"], pending)
    flush_pending(settings, pending, tailers)

    expected_group = correlation_group_id_for_community(
        expected_community_id
    )

    conn = sqlite3.connect(db_file)
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        grouped = conn.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE correlation_group_id IS NOT NULL"
        ).fetchone()[0]

        groups = conn.execute(
            """
            SELECT correlation_group_id,
                   COUNT(*) AS alert_count,
                   COUNT(DISTINCT engine) AS engine_count
            FROM alerts
            WHERE correlation_group_id IS NOT NULL
            GROUP BY correlation_group_id
            """
        ).fetchall()

        assert total == 2
        assert grouped == 2
        assert len(groups) == 1

        group_id, alert_count, engine_count = groups[0]
        assert group_id == expected_group
        assert alert_count == 2
        assert engine_count == 2

        rows = conn.execute(
            """
            SELECT engine, community_id, correlation_group_id
            FROM alerts
            WHERE community_id = ?
            ORDER BY id
            """,
            (expected_community_id,),
        ).fetchall()

        assert len(rows) == 2
        assert {row[0] for row in rows} == {"snort", "suricata"}
        assert all(row[1] == expected_community_id for row in rows)
        assert all(row[2] == expected_group for row in rows)

    finally:
        conn.close()
