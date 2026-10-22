import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from ids.alert_bundle import (
    BUNDLE_SCHEMA_VERSION,
    BUNDLE_TYPE,
    EVIDENCE_NOTE,
    build_alert_bundle,
    serialize_alert_bundle,
)


def test_builds_single_alert_bundle_and_preserves_original_alert():
    alert = {
        "record_id": 42,
        "engine": "snort",
        "msg": "Example alert",
        "raw_json": '{"example": true}',
    }

    bundle = build_alert_bundle(
        [alert],
        created_at=datetime(2026, 10, 19, 6, 0, tzinfo=timezone.utc),
    )

    assert bundle["schema_version"] == BUNDLE_SCHEMA_VERSION
    assert bundle["bundle_type"] == BUNDLE_TYPE
    assert bundle["created_at_utc"] == "2026-10-19T06:00:00Z"
    assert bundle["summary"]["alert_count"] == 1
    assert bundle["summary"]["alerts_with_intelligence"] == 0
    assert bundle["summary"]["alerts_with_packet_investigation"] == 0
    assert bundle["summary"]["alerts_with_enrichment"] == 0
    assert bundle["alerts"][0]["alert_id"] == 42
    assert bundle["alerts"][0]["alert"] == alert
    assert bundle["alerts"][0]["intelligence"] is None
    assert bundle["alerts"][0]["packet_investigation"] is None
    assert bundle["alerts"][0]["enrichment"] is None
    assert EVIDENCE_NOTE in bundle["evidence_note"]


def test_attaches_intelligence_and_investigation_by_alert_id():
    alerts = [
        {"record_id": 1, "msg": "First alert"},
        {"id": 2, "msg": "Second alert"},
    ]
    intelligence = {
        "1": {"lookup_mode": "offline_local"},
        2: {"lookup_mode": "offline_local"},
    }
    investigations = {
        1: {"packet_summary": {"total_packets": 3}, "packets": []},
        "2": {"packet_summary": {"total_packets": 5}, "packets": []},
    }
    enrichments = {
        "1": {
            "schema": {"id": "ids.alert-enrichment", "version": "1.0"},
            "coverage": {"network": "available"},
        },
        2: {
            "schema": {"id": "ids.alert-enrichment", "version": "1.0"},
            "coverage": {"network": "partial"},
        },
    }

    bundle = build_alert_bundle(
        alerts,
        intelligence_by_alert_id=intelligence,
        investigations_by_alert_id=investigations,
        enrichment_by_alert_id=enrichments,
    )

    assert bundle["alerts"][0]["intelligence"]["lookup_mode"] == "offline_local"
    assert (
        bundle["alerts"][0]["packet_investigation"]["packet_summary"]
        ["total_packets"]
        == 3
    )
    assert (
        bundle["alerts"][1]["packet_investigation"]["packet_summary"]
        ["total_packets"]
        == 5
    )
    assert bundle["summary"]["alerts_with_intelligence"] == 2
    assert bundle["summary"]["alerts_with_packet_investigation"] == 2
    assert bundle["summary"]["alerts_with_enrichment"] == 2
    assert (
        bundle["alerts"][0]["enrichment"]["schema"]["id"]
        == "ids.alert-enrichment"
    )
    assert (
        bundle["alerts"][1]["enrichment"]["coverage"]["network"]
        == "partial"
    )


def test_supports_string_ids_and_alert_id_fallback():
    bundle = build_alert_bundle(
        [{"alert_id": "abc", "msg": "An alert"}],
        intelligence_by_alert_id={"abc": {"result": "local"}},
    )

    assert bundle["alerts"][0]["alert_id"] == "abc"
    assert bundle["alerts"][0]["intelligence"] == {"result": "local"}


def test_empty_bundle_is_valid():
    bundle = build_alert_bundle([])

    assert bundle["summary"]["alert_count"] == 0
    assert bundle["alerts"] == []


def test_serialization_handles_unicode_dates_paths_sets_and_bytes():
    created_at = datetime(
        2026, 10, 19, 11, 0,
        tzinfo=timezone(timedelta(hours=5)),
    )
    bundle = build_alert_bundle(
        [{
            "id": 7,
            "msg": "قواعد الأمن — alert",
            "created": created_at,
            "path": Path("/tmp/example.json"),
            "tags": {"beta", "alpha"},
            "raw": b"abc",
        }],
        created_at=created_at,
    )

    serialized = serialize_alert_bundle(bundle)
    decoded = json.loads(serialized)
    alert = decoded["alerts"][0]["alert"]

    assert "قواعد الأمن" in serialized
    assert decoded["created_at_utc"] == "2026-10-19T06:00:00Z"
    assert alert["created"] == "2026-10-19T06:00:00Z"
    assert alert["path"] == "/tmp/example.json"
    assert alert["tags"] == ["alpha", "beta"]
    assert alert["raw"] == {
        "encoding": "base64",
        "data": "YWJj",
    }
    assert serialized.endswith("\n")


def test_builder_does_not_mutate_input_alert_or_attachments():
    alert = {"record_id": 9, "nested": {"items": [1, 2]}}
    intelligence = {9: {"tags": ["CVE-2021-44228"]}}
    alert_before = json.dumps(alert)
    intelligence_before = json.dumps(intelligence)

    bundle = build_alert_bundle(
        [alert],
        intelligence_by_alert_id=intelligence,
    )
    serialize_alert_bundle(bundle)

    assert json.dumps(alert) == alert_before
    assert json.dumps(intelligence) == intelligence_before


@pytest.mark.parametrize("invalid_alerts", ["not alerts", b"bytes", {"id": 1}])
def test_rejects_invalid_alert_container(invalid_alerts):
    with pytest.raises(TypeError):
        build_alert_bundle(invalid_alerts)


def test_rejects_non_mapping_alert_item():
    with pytest.raises(TypeError, match=r"alerts\[1\]"):
        build_alert_bundle([{"id": 1}, None])


@pytest.mark.parametrize("indent", [-1, 1.5, True, "2"])
def test_rejects_invalid_serialization_indent(indent):
    with pytest.raises(ValueError):
        serialize_alert_bundle({}, indent=indent)
