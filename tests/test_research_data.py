import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from dashboard_pages.research_data import (
    build_research_manifest,
    build_research_package,
    serialize_alerts_csv,
    serialize_alerts_json,
)


def sample_alerts():
    return [
        {
            "id": 101,
            "engine": "snort",
            "event_ts_utc": 1792400000000,
            "severity": "high",
            "msg": "SQL injection attempt",
            "bundle_intelligence": {
                "lookup_mode": "offline_local",
                "identifiers": {"cves": ["CVE-2021-44228"]},
            },
        },
        {
            "id": 202,
            "engine": "suricata",
            "event_ts_utc": 1792400001000,
            "severity": "high",
            "msg": "HTTP exploit attempt",
            "optional_evidence": None,
        },
    ]


def test_manifest_reports_counts_fields_and_utc_coverage(tmp_path):
    config = tmp_path / "config" / "ids_sources.json"
    config.parent.mkdir()
    config.write_text('{"sources": []}', encoding="utf-8")
    alerts = sample_alerts()

    manifest = build_research_manifest(
        alerts,
        ids_sources_file=config,
        project_root=tmp_path,
        live_db_file=tmp_path / "ids_live.db",
        exported_at_utc=datetime(2026, 10, 19, tzinfo=timezone.utc),
    )

    assert manifest["schema_version"] == 1
    assert manifest["dataset"]["record_count"] == 2
    assert manifest["dataset"]["records_by_engine"] == {
        "snort": 1,
        "suricata": 1,
    }
    assert manifest["dataset"]["first_event_utc"] == "2026-10-19T08:53:20+00:00"
    assert manifest["dataset"]["last_event_utc"] == "2026-10-19T08:53:21+00:00"
    assert "bundle_intelligence" in manifest["dataset"]["top_level_fields"]
    assert manifest["source"]["live_database_file"] == "ids_live.db"
    assert manifest["source"]["ids_source_configuration_available"] is True


def test_csv_preserves_nested_values_as_json_text():
    alerts = sample_alerts()
    serialized = serialize_alerts_csv(alerts)
    rows = list(csv.DictReader(io.StringIO(serialized)))

    assert len(rows) == 2
    nested = json.loads(rows[0]["bundle_intelligence"])
    assert nested["lookup_mode"] == "offline_local"
    assert nested["identifiers"]["cves"] == ["CVE-2021-44228"]
    assert rows[1]["optional_evidence"] == ""


def test_json_preserves_nested_values():
    result = json.loads(serialize_alerts_json(sample_alerts()))
    assert result[0]["bundle_intelligence"]["lookup_mode"] == "offline_local"


def test_research_package_contains_snapshot_manifest_readme_and_config(tmp_path):
    config = tmp_path / "config" / "ids_sources.json"
    config.parent.mkdir()
    config.write_text('{"sources": []}', encoding="utf-8")

    package = build_research_package(
        sample_alerts(),
        ids_sources_file=config,
        project_root=tmp_path,
        live_db_file=tmp_path / "ids_live.db",
        exported_at_utc=datetime(2026, 10, 19, tzinfo=timezone.utc),
    )

    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        names = set(archive.namelist())
        assert "dataset/live_alert_snapshot.json" in names
        assert "dataset/live_alert_snapshot.csv" in names
        assert "metadata/research_manifest.json" in names
        assert "configuration/ids_sources.json" in names
        assert "README.txt" in names

        exported_alerts = json.loads(
            archive.read("dataset/live_alert_snapshot.json")
        )
        manifest = json.loads(
            archive.read("metadata/research_manifest.json")
        )

    assert len(exported_alerts) == 2
    assert manifest["dataset"]["record_count"] == 2


def test_manifest_handles_empty_dataset_and_missing_config(tmp_path):
    manifest = build_research_manifest(
        [],
        ids_sources_file=tmp_path / "missing.json",
        project_root=tmp_path,
    )

    assert manifest["dataset"]["record_count"] == 0
    assert manifest["dataset"]["records_by_engine"] == {}
    assert manifest["dataset"]["first_event_utc"] is None
    assert manifest["dataset"]["last_event_utc"] is None
    assert manifest["source"]["ids_source_configuration_available"] is False


def test_timestamp_parser_supports_pk_t_formatted_timestamp():
    from dashboard_pages.research_data import _normalise_datetime

    parsed = _normalise_datetime("2026-10-19 13:53:20 PKT (UTC+05:00)")
    assert parsed is not None
    assert parsed.isoformat(timespec="seconds") == "2026-10-19T08:53:20+00:00"
