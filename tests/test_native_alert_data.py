import json
import sqlite3

import pytest

from ids.alert_details import (
    build_non_repeating_normalized_record,
    load_alert_native_event,
)


@pytest.fixture
def native_event_db(tmp_path):
    database = tmp_path / "native-events.db"
    conn = sqlite3.connect(database)
    try:
        conn.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY,
                engine TEXT,
                raw_json TEXT
            )
            """
        )
        conn.executemany(
            "INSERT INTO alerts (id, engine, raw_json) VALUES (?, ?, ?)",
            [
                (15034, "snort", '{"msg":"Snort source event","sid":31978}'),
                (
                    15028,
                    "suricata",
                    '{"event_type":"alert","alert":{"signature":"Suricata source event"}}',
                ),
                (15035, "snort", '{"malformed":'),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return database


@pytest.mark.parametrize(
    ("alert_id", "expected_engine", "expected_message"),
    [
        (15034, "snort", "Snort source event"),
        (15028, "suricata", "Suricata source event"),
    ],
)
def test_loads_only_the_selected_engine_original_payload(
    native_event_db,
    alert_id,
    expected_engine,
    expected_message,
):
    result = load_alert_native_event(native_event_db, alert_id)

    assert result is not None
    assert result["id"] == alert_id
    assert result["engine"] == expected_engine

    payload = json.loads(result["raw_json"])
    serialized = json.dumps(payload)
    assert expected_message in serialized


def test_malformed_payload_is_returned_without_rewriting(native_event_db):
    result = load_alert_native_event(native_event_db, 15035)

    assert result is not None
    assert result["raw_json"] == '{"malformed":'
    with pytest.raises(json.JSONDecodeError):
        json.loads(result["raw_json"])


def test_missing_alert_returns_none(native_event_db):
    assert load_alert_native_event(native_event_db, 99999) is None


def test_normalized_fields_hide_snort_source_duplicates():
    native = {
        "timestamp": "2026-10-15T10:54:02Z",
        "msg": "Snort message",
        "gid": 1,
        "sid": 31978,
        "rev": 5,
        "protocol": "TCP",
        "src_addr": "192.168.50.141",
        "src_port": 36788,
        "dst_addr": "192.168.50.114",
        "dst_port": 80,
        "dir": "C2S",
        "action": "allow",
        "class": "Attempted Administrator Privilege Gain",
        "priority": 1,
        "service": "http",
        "flow_id": "flow-1",
        "client_pkts": 3,
        "client_bytes": 351,
    }
    selected = {
        "id": 15034,
        "record_id": 15034,
        "engine": "Snort",
        "timestamp": "10/15-15:54:02.661821",
        "event_ts_utc": 1792061642662,
        "classification": "Attempted Administrator Privilege Gain",
        "msg": "Snort message",
        "gid": 1,
        "sid": 31978,
        "rev": 5,
        "priority": 1,
        "severity": 1,
        "protocol": "TCP",
        "service": "http",
        "src": "192.168.50.141:36788",
        "src_addr": "192.168.50.141",
        "src_port": 36788,
        "dst": "192.168.50.114:80",
        "dst_addr": "192.168.50.114",
        "dst_port": 80,
        "direction": "C2S",
        "action": "allow",
        "client_pkts": 3,
        "client_bytes": 351,
        "flow_id": "flow-1",
        "correlation_group_id": "cid:example",
        "event_hash": "hash-example",
        "rule_key": "snort:1:31978:5",
    }

    result = build_non_repeating_normalized_record(selected, native)

    assert result == {
        "record_id": 15034,
        "engine": "Snort",
        "correlation_group_id": "cid:example",
        "event_hash": "hash-example",
    }


def test_normalized_fields_hide_nested_suricata_source_duplicates():
    native = {
        "timestamp": "2026-10-15T15:54:02.681047+0500",
        "event_type": "alert",
        "src_ip": "192.168.50.141",
        "src_port": 36788,
        "dest_ip": "192.168.50.114",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "flow_id": "579200695037415",
        "alert": {
            "signature": "Suricata message",
            "signature_id": 2019232,
            "rev": 7,
            "severity": 1,
            "category": "Attempted Administrator Privilege Gain",
            "action": "allowed",
        },
    }
    selected = {
        "record_id": 15028,
        "engine": "Suricata",
        "timestamp": "2026-10-15T15:54:02.681047+0500",
        "event_ts_utc": 1792061642681,
        "classification": "Attempted Administrator Privilege Gain",
        "msg": "Suricata message",
        "gid": 1,
        "sid": 2019232,
        "rev": 7,
        "severity": 1,
        "protocol": "TCP",
        "service": "http",
        "src_addr": "192.168.50.141",
        "src_port": 36788,
        "dst_addr": "192.168.50.114",
        "dst_port": 80,
        "flow_id": "579200695037415",
        "correlation_group_id": "cid:example",
        "event_hash": "hash-example",
        "rule_key": "suricata:1:2019232:7",
    }

    result = build_non_repeating_normalized_record(selected, native)

    assert result == {
        "record_id": 15028,
        "engine": "Suricata",
        "gid": 1,
        "correlation_group_id": "cid:example",
        "event_hash": "hash-example",
    }


def test_normalized_fields_remain_available_without_native_payload():
    selected = {
        "record_id": 8,
        "engine": "Suricata",
        "event_ts_utc": 123456,
        "msg": "Alert message",
        "gid": 1,
        "sid": 22,
        "rev": 3,
        "severity": 2,
        "protocol": "TCP",
        "src_addr": "192.0.2.1",
        "src_port": 1234,
    }

    result = build_non_repeating_normalized_record(selected, None)

    assert result == selected
