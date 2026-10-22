import io
import json
import zipfile
from datetime import datetime, timezone

import pytest

from ids.alert_bundle import (
    BUNDLE_TYPE,
    build_alert_bundle,
    build_individual_alert_document,
    build_individual_alert_zip,
    individual_alert_filename,
    serialize_alert_bundle,
    serialize_individual_alert_document,
)
from ids.alert_bundle_import import (
    AlertBundleImportError,
    build_manual_correlation_analysis,
    parse_alert_bundle_upload,
)


def make_bundle():
    alerts = [
        {"id": 101, "engine": "snort", "msg": "SQL injection attempt",
         "event_ts_utc": 1000, "community_id": "community-one"},
        {"id": 202, "engine": "suricata", "msg": "HTTP exploit attempt",
         "event_ts_utc": 2000, "community_id": "community-one"},
    ]
    intelligence = {101: {"lookup_mode": "offline_local", "identifiers": {"cves": ["CVE-2021-44228"]}}}
    investigations = {101: {"packet_summary": {"total_packets": 4}, "packets": [{"id": 1}]}}
    enrichments = {
        101: {
            "schema": {"id": "ids.alert-enrichment", "version": "1.0"},
            "summary": {"alert_id": 101},
            "coverage": {"network": "available"},
        }
    }
    return build_alert_bundle(
        alerts,
        intelligence_by_alert_id=intelligence,
        investigations_by_alert_id=investigations,
        enrichment_by_alert_id=enrichments,
        created_at=datetime(2026, 10, 19, tzinfo=timezone.utc),
    )


def make_zip(bundle_bytes):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("alert_bundle.json", bundle_bytes)
        archive.writestr("README.txt", "Test bundle")
    return buffer.getvalue()


def test_parse_json_bundle_preserves_alert_intelligence_and_evidence():
    payload = serialize_alert_bundle(make_bundle()).encode("utf-8")
    parsed = parse_alert_bundle_upload("example.json", payload)

    assert parsed["filename"] == "example.json"
    assert parsed["record_count"] == 2
    first = parsed["records"][0]
    assert first["alert"]["id"] == 101
    assert first["intelligence"]["lookup_mode"] == "offline_local"
    assert first["packet_investigation"]["packet_summary"]["total_packets"] == 4
    assert first["enrichment"]["schema"]["id"] == "ids.alert-enrichment"
    assert first["enrichment"]["coverage"]["network"] == "available"
    assert first["record_key"]


def test_parse_zip_bundle_reads_root_member_without_extracting():
    payload = serialize_alert_bundle(make_bundle()).encode("utf-8")
    parsed = parse_alert_bundle_upload("example.zip", make_zip(payload))

    assert parsed["record_count"] == 2
    assert parsed["records"][1]["alert"]["id"] == 202


@pytest.mark.parametrize(
    "filename,content",
    [
        ("wrong.txt", b"{}"),
        ("wrong.json", b"{invalid"),
        ("root-array.json", b"[]"),
    ],
)
def test_rejects_bad_format_or_json(filename, content):
    with pytest.raises(AlertBundleImportError):
        parse_alert_bundle_upload(filename, content)


def test_rejects_wrong_bundle_type():
    payload = json.dumps({"bundle_type": "other", "schema_version": 1, "alerts": []}).encode()
    with pytest.raises(AlertBundleImportError, match="not a supported"):
        parse_alert_bundle_upload("wrong.json", payload)


def test_rejects_bad_record_shape():
    payload = json.dumps({
        "bundle_type": BUNDLE_TYPE,
        "schema_version": 1,
        "alerts": [{"alert": "not an object"}],
    }).encode()
    with pytest.raises(AlertBundleImportError, match="original alert"):
        parse_alert_bundle_upload("bad.json", payload)


def test_rejects_non_object_intelligence():
    payload = json.dumps({
        "bundle_type": BUNDLE_TYPE,
        "schema_version": 1,
        "alerts": [{"alert": {"id": 1}, "intelligence": []}],
    }).encode()
    with pytest.raises(AlertBundleImportError, match="intelligence"):
        parse_alert_bundle_upload("bad.json", payload)


def test_rejects_non_object_enrichment():
    payload = json.dumps({
        "bundle_type": BUNDLE_TYPE,
        "schema_version": 1,
        "alerts": [{"alert": {"id": 1}, "enrichment": []}],
    }).encode()
    with pytest.raises(AlertBundleImportError, match="enrichment"):
        parse_alert_bundle_upload("bad.json", payload)


def make_individual_export(alert_id, engine, native_event=None):
    alert = {
        "record_id": alert_id,
        "engine": engine,
        "sid": 50000 + alert_id,
        "msg": f"Example alert {alert_id}",
    }
    document = build_individual_alert_document(
        alert,
        native_event=native_event,
        enrichment={
            "schema": {"id": "ids.alert-enrichment", "version": "1.0"},
            "summary": {"alert_id": alert_id},
            "coverage": {"network": "available"},
        },
        created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
    )
    return alert, document, serialize_individual_alert_document(document)


def test_imports_one_individual_alert_json_file():
    native_event = {
        "event_type": "alert",
        "src_ip": "192.0.2.5",
        "dest_ip": "192.0.2.10",
    }
    alert, document, serialized = make_individual_export(
        301, "snort", native_event=native_event
    )
    parsed = parse_alert_bundle_upload(
        "alert-301-snort.json",
        serialized.encode("utf-8"),
    )

    assert parsed["record_count"] == 1
    record = parsed["records"][0]
    assert record["alert"] == alert
    assert record["native_event"] == native_event
    assert record["alert_id"] == 301
    assert record["intelligence"] is None
    assert record["enrichment"] == document["enrichment"]
    assert record["enrichment"]["schema"]["id"] == "ids.alert-enrichment"


def test_imports_older_individual_json_without_native_event():
    alert, document, _ = make_individual_export(303, "suricata")
    document.pop("native_event", None)
    serialized = serialize_individual_alert_document(document)

    parsed = parse_alert_bundle_upload("older-alert.json", serialized.encode("utf-8"))

    assert parsed["record_count"] == 1
    assert parsed["records"][0]["alert"] == alert
    assert parsed["records"][0]["native_event"] is None


def test_imports_zip_of_individual_json_files_without_readme():
    alert_one, _, json_one = make_individual_export(401, "snort")
    alert_two, _, json_two = make_individual_export(402, "suricata")

    names = {
        individual_alert_filename(alert_one, sequence=1): json_one,
        individual_alert_filename(alert_two, sequence=2): json_two,
    }
    archive_bytes = build_individual_alert_zip(names)

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        assert set(archive.namelist()) == set(names)
        assert all(name.endswith(".json") for name in archive.namelist())
        assert "README.txt" not in archive.namelist()

    parsed = parse_alert_bundle_upload("individual-alerts.zip", archive_bytes)

    assert parsed["record_count"] == 2
    assert {item["alert_id"] for item in parsed["records"]} == {401, 402}
    assert all(item["enrichment"]["schema"]["id"] == "ids.alert-enrichment"
               for item in parsed["records"])
    assert parsed["summary"]["alerts_with_enrichment"] == 2


def test_rejects_oversized_upload():
    with pytest.raises(AlertBundleImportError, match="size limit"):
        parse_alert_bundle_upload("big.json", b"12345", max_size_bytes=4)


def test_rejects_zip_without_exact_root_bundle_member():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("nested/alert_bundle.json", "{}")
    with pytest.raises(AlertBundleImportError, match="root"):
        parse_alert_bundle_upload("nested.zip", buffer.getvalue())


def test_manual_analysis_preserves_imported_context_and_groups_selected_alerts():
    payload = serialize_alert_bundle(make_bundle()).encode("utf-8")
    imported = parse_alert_bundle_upload("research.zip", make_zip(payload))
    selected = [item["record_key"] for item in imported["records"]]

    analysis = build_manual_correlation_analysis(
        [imported],
        selected,
        "Manual test case",
        classify_alert=lambda alert: "SECURITY_ALERT",
        is_security_related=lambda alert: True,
        format_alert_timestamp_pkt=lambda record: str(record.get("event_ts_utc", "Unavailable")),
        created_at=datetime(2026, 10, 19, tzinfo=timezone.utc),
    )

    assert analysis["correlation_group_id"] == "manual:manual-test-case"
    assert analysis["source_mode"] == "imported_alert_bundles"
    assert analysis["summary"]["record_count"] == 2
    assert analysis["summary"]["security_related_record_count"] == 2
    assert analysis["summary"]["engines"] == ["snort", "suricata"]
    assert analysis["source_bundle_files"] == ["research.zip"]

    first = next(row for row in analysis["alerts"] if row["id"] == 101)
    assert first["bundle_intelligence"]["lookup_mode"] == "offline_local"
    assert first["bundle_packet_investigation"]["packet_summary"]["total_packets"] == 4
    assert first["bundle_enrichment"]["schema"]["id"] == "ids.alert-enrichment"
    assert first["bundle_record"]["alert"]["id"] == 101
    assert (
        first["bundle_record"]["enrichment"]["coverage"]["network"]
        == "available"
    )


def test_manual_analysis_rejects_empty_selection_and_unknown_key():
    imported = parse_alert_bundle_upload(
        "bundle.json",
        serialize_alert_bundle(make_bundle()).encode(),
    )
    callbacks = {
        "classify_alert": lambda alert: "SECURITY_ALERT",
        "is_security_related": lambda alert: True,
        "format_alert_timestamp_pkt": lambda record: "time",
    }

    with pytest.raises(ValueError, match="Select at least one"):
        build_manual_correlation_analysis([imported], [], "Case", **callbacks)

    with pytest.raises(ValueError, match="not present"):
        build_manual_correlation_analysis([imported], ["unknown"], "Case", **callbacks)


def test_manual_analysis_rejects_blank_label():
    imported = parse_alert_bundle_upload(
        "bundle.json",
        serialize_alert_bundle(make_bundle()).encode(),
    )
    key = imported["records"][0]["record_key"]
    with pytest.raises(ValueError, match="label"):
        build_manual_correlation_analysis(
            [imported],
            [key],
            "///",
            classify_alert=lambda alert: "SECURITY_ALERT",
            is_security_related=lambda alert: True,
            format_alert_timestamp_pkt=lambda record: "time",
        )



def test_imports_legacy_version_1_individual_json():
    alert, document, _ = make_individual_export(303, "suricata")
    document["document_version"] = 1
    document.pop("native_event", None)
    serialized = serialize_individual_alert_document(document)

    parsed = parse_alert_bundle_upload(
        "older-alert.json",
        serialized.encode("utf-8"),
    )

    assert parsed["record_count"] == 1
    assert parsed["records"][0]["alert"] == alert
    assert parsed["records"][0]["native_event"] is None
