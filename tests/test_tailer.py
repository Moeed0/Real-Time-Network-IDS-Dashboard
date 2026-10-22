from __future__ import annotations

import json

from ids.tailer import PersistentJsonTailer


def _consume_and_ack(tailer, collected):
    tailer.poll(
        lambda line, inode, offset: (
            collected.append(line),
            tailer.acknowledge(inode, offset),
        )
    )


def test_partial_line_is_not_consumed(tmp_path):
    path = tmp_path / "events.json"
    state = tmp_path / "state.json"

    path.write_text(
        '{"id":1}\n{"id":2',
        encoding="utf-8",
    )

    tailer = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=False,
    )

    first = []
    _consume_and_ack(tailer, first)

    assert first == ['{"id":1}']

    with path.open("a", encoding="utf-8") as f:
        f.write("}\n")

    second = []
    _consume_and_ack(tailer, second)

    assert second == ['{"id":2}']


def test_rename_and_recreate_rotation(tmp_path):
    path = tmp_path / "events.json"
    rotated = tmp_path / "events.json.rotated"
    state = tmp_path / "state.json"

    path.write_text(
        '{"id":1}\n{"id":2}\n',
        encoding="utf-8",
    )

    tailer = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=False,
    )

    first = []
    _consume_and_ack(tailer, first)

    old_inode = path.stat().st_ino

    path.rename(rotated)
    path.write_text(
        '{"id":3}\n',
        encoding="utf-8",
    )

    new_inode = path.stat().st_ino

    assert new_inode != old_inode

    restarted = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=True,
    )

    second = []
    _consume_and_ack(restarted, second)

    assert second == ['{"id":3}']


def test_copytruncate_detects_new_content_even_when_larger_than_old_offset(
    tmp_path,
):
    path = tmp_path / "events.json"
    state = tmp_path / "state.json"

    old_lines = [
        json.dumps(
            {
                "id": index,
                "payload": "A" * 80,
            }
        )
        for index in range(1, 6)
    ]

    path.write_text(
        "\n".join(old_lines) + "\n",
        encoding="utf-8",
    )

    tailer = PersistentJsonTailer(
        path,
        state,
        "test",
        start_at_end=False,
    )

    before = []
    _consume_and_ack(tailer, before)

    old_stat = path.stat()
    old_inode = old_stat.st_ino
    old_size = old_stat.st_size

    assert old_size > 256

    new_lines = [
        json.dumps(
            {
                "id": index,
                "payload": "B" * 80,
            }
        )
        for index in range(100, 110)
    ]

    # copytruncate: truncate the same inode and immediately write enough
    # new data that the new file is already larger than the old offset.
    new_content = "\n".join(new_lines) + "\n"

    with path.open("w", encoding="utf-8") as f:
        f.write(new_content)

    new_stat = path.stat()
    new_size = new_stat.st_size

    assert new_stat.st_ino == old_inode
    assert new_size > old_size

    after = []
    _consume_and_ack(tailer, after)

    assert after == new_lines


def test_shared_state_preserves_both_sources(tmp_path):
    state = tmp_path / "state.json"
    snort_path = tmp_path / "snort.json"
    suricata_path = tmp_path / "suricata.json"

    snort_path.write_text(
        '{"id":"snort"}\n',
        encoding="utf-8",
    )

    suricata_path.write_text(
        '{"id":"suricata"}\n',
        encoding="utf-8",
    )

    snort = PersistentJsonTailer(
        snort_path,
        state,
        "snort",
        start_at_end=False,
    )

    suricata = PersistentJsonTailer(
        suricata_path,
        state,
        "suricata",
        start_at_end=False,
    )

    snort_lines = []
    suricata_lines = []

    _consume_and_ack(snort, snort_lines)
    _consume_and_ack(suricata, suricata_lines)

    saved = json.loads(
        state.read_text(encoding="utf-8")
    )

    assert snort_lines == ['{"id":"snort"}']
    assert suricata_lines == ['{"id":"suricata"}']

    assert "snort" in saved
    assert "suricata" in saved

    assert saved["snort"]["fingerprint"]
    assert saved["suricata"]["fingerprint"]

    assert saved["snort"]["fingerprint_length"] > 0
    assert saved["suricata"]["fingerprint_length"] > 0
