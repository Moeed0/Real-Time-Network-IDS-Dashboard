import io
import json
import zipfile
from datetime import datetime, timezone

from ids.alert_bundle import (
    build_individual_alert_document,
    build_individual_alert_zip,
    individual_alert_filename,
    serialize_individual_alert_document,
)


def test_individual_document_is_compact_and_preserves_alert_and_enrichment():
    alert = {
        "record_id": 27416,
        "engine": "snort",
        "sid": 50447,
        "msg": "Example alert",
        "raw_json": '{"event_type":"alert"}',
    }
    alert_before = json.dumps(alert, sort_keys=True)
    enrichment = {
        "schema": {"id": "ids.alert-enrichment", "version": "1.0"},
        "summary": {"alert_id": 27416},
        "coverage": {"network": "available"},
    }
    native_event = {
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "192.0.2.20",
    }

    document = build_individual_alert_document(
        alert,
        enrichment=enrichment,
        native_event=native_event,
        investigation=None,
        created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
    )
    decoded = json.loads(serialize_individual_alert_document(document))

    assert decoded["document_type"] == "real_time_network_ids_alert"
    assert decoded["document_version"] == 2
    assert decoded["alert_id"] == 27416
    assert decoded["alert"]["record_id"] == alert["record_id"]
    assert decoded["alert"]["engine"] == alert["engine"]
    assert "raw_json" not in decoded["alert"]
    assert decoded["native_event"] == native_event
    assert decoded["enrichment"] == enrichment
    assert decoded["packet_investigation"] is None
    assert "intelligence" not in decoded
    assert json.dumps(alert, sort_keys=True) == alert_before


def test_individual_filename_is_safe_and_ends_in_json():
    filename = individual_alert_filename(
        {
            "record_id": "../../unexpected/path",
            "engine": "Snort",
            "sid": 50447,
        }
    )

    assert "/" not in filename
    assert "\\\\" not in filename
    assert filename.endswith(".json")
    assert filename.startswith("alert-")


def test_zip_contains_exactly_the_individual_json_files():
    files = {
        "01-alert-101-snort-sid-50101.json": '{"alert_id":101}',
        "02-alert-202-suricata-sid-50202.json": '{"alert_id":202}',
    }
    payload = build_individual_alert_zip(files)

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert set(archive.namelist()) == set(files)
        assert len(archive.namelist()) == 2
        assert all(name.endswith(".json") for name in archive.namelist())
        assert "README.txt" not in archive.namelist()
        for name, expected in files.items():
            assert archive.read(name).decode("utf-8") == expected



def test_compact_export_deduplicates_and_summarizes_large_nvd_data():
    native_event = {
        "event_type": "alert",
        "flow": {"src_ip": "192.0.2.1", "pkts_toserver": 4},
        "http": {"url": "/test", "http_method": "GET"},
    }
    alert = {
        "record_id": 900,
        "engine": "suricata",
        "sid": 2019232,
        "msg": "Example CVE alert",
        "security_context": {"native_event": native_event, "legacy_cache": {"old": True}},
        "alert": {
            "message": "Example CVE alert",
            "classification": "Attempted Administrator Privilege Gain",
            "security_context": {"old": True},
        },
        "rule": {"sid": 2019232, "msg": "Example CVE alert"},
    }
    references = [
        {"url": f"https://example.test/ref/{n}", "name": str(n), "large_field": "drop"}
        for n in range(8)
    ]
    nvd = {
        "id": "CVE-2024-0001",
        "description": "Example vulnerability",
        "references": references,
        "configurations": [
            {"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                "vulnerable": True,
                "versionEndIncluding": "1.2.3",
            }]}]}
            for _ in range(6)
        ],
    }
    explanation = {"what_happened": "A rule matched."}
    enrichment = {
        "schema": {"id": "ids.alert-enrichment", "version": "1.0"},
        "detection": {
            "rule": {
                "rule_text": "alert http any any -> any any (sid:2019232; rev:1;)",
                "raw_options": "duplicate copy",
                "options_json": '{"duplicate": true}',
            },
            "analysis": explanation,
        },
        "network": {
            "flow": dict(native_event["flow"]),
            "protocol_evidence": dict(native_event["http"]),
            "source": {"ip": "192.0.2.1"},
        },
        "threat_intelligence": {
            "vulnerabilities": {
                "CVE-2024-0001": {
                    "nvd": nvd,
                    "epss": {"score": 0.25, "percentile": 0.7, "raw": {"copy": True}},
                }
            },
            "references": references,
        },
        "assessment": {"explanation": explanation},
        "investigation": {"status": "not_loaded", "packets": []},
    }

    original_alert = json.dumps(alert, sort_keys=True)
    result = build_individual_alert_document(
        alert,
        native_event=native_event,
        enrichment=enrichment,
        created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
    )

    assert result["document_version"] == 2
    assert result["native_event"] == native_event
    assert "security_context" not in result["alert"]
    assert result["alert"]["alert"]["classification"] == (
        "Attempted Administrator Privilege Gain"
    )
    assert json.dumps(alert, sort_keys=True) == original_alert

    compact = result["enrichment"]
    assert "flow" not in compact["network"]
    assert "protocol_evidence" not in compact["network"]
    assert "raw_options" not in compact["detection"]["rule"]
    assert "options_json" not in compact["detection"]["rule"]
    assert compact["assessment"]["explanation_ref"] == "detection.analysis"
    assert "explanation" not in compact["assessment"]

    compact_nvd = compact["threat_intelligence"]["vulnerabilities"]["CVE-2024-0001"]["nvd"]
    assert compact_nvd["references"]["count"] == 8
    assert len(compact_nvd["references"]["preview"]) == 5
    assert compact_nvd["references"]["omitted"] == 3
    assert compact_nvd["configuration_summary"]["configuration_count"] == 6
    assert compact_nvd["configuration_summary"]["cpe_match_count"] == 1

    compact_epss = compact["threat_intelligence"]["vulnerabilities"]["CVE-2024-0001"]["epss"]
    assert compact_epss == {
        "score": 0.25,
        "percentile": 0.7,
        "raw_data_omitted": True,
    }



def test_packet_investigation_export_deduplicates_alert_and_nested_http():
    native_event = {
        "event_type": "alert",
        "proto": "TCP",
        "src_ip": "192.0.2.10",
        "src_port": 1234,
        "dest_ip": "192.0.2.20",
        "dest_port": 80,
        "direction": "to_server",
        "in_iface": "ens38",
        "alert": {
            "signature": "Repeated alert",
            "category": "Attempted Administrator Privilege Gain",
            "metadata": {"confidence": ["Medium"]},
        },
        "http": {"url": "/test", "http_method": "GET", "status": 404},
    }
    alert = {
        "record_id": 50,
        "engine": "suricata",
        "msg": "Repeated alert",
        "classification": "Attempted Administrator Privilege Gain",
        "src_addr": "192.0.2.10",
        "src_port": 1234,
        "dst_addr": "192.0.2.20",
        "dst_port": 80,
        "protocol": "TCP",
        "direction": "to_server",
        "timestamp": "2026-10-21T10:00:00Z",
        "security_context": {"legacy_copy": True},
    }
    packets = [{"id": 700, "info": "HTTP GET request", "size": 257}]
    related_alerts = [
        {"id": 50, "msg": "Repeated alert"},
        {"id": 51, "msg": "Distinct related alert"},
    ]
    packet_summary = {"total_packets": 1, "total_bytes": 257}
    investigation = {
        "alert": {
            "id": 50,
            "engine": "suricata",
            "msg": "Repeated alert",
            "timestamp": "2026-10-21T10:00:00Z",
            "src_addr": "192.0.2.10",
            "src_port": 1234,
            "dst_addr": "192.0.2.20",
            "dst_port": 80,
            "protocol": "TCP",
            "direction": "to_server",
            "iface": "ens38",
            "raw_json": json.dumps(native_event),
            "unique_investigation_note": "keep this unique note",
        },
        "related_alerts": related_alerts,
        "packets": packets,
        "packet_summary": packet_summary,
    }
    metadata = {"confidence": ["Medium"]}
    explanation = {"what_happened": "A rule matched."}
    enrichment = {
        "schema": {"id": "ids.alert-enrichment", "version": "1.0"},
        "detection": {
            "rule": {"rule_text": "alert http any any -> any any (sid:1;)"},
            "analysis": explanation,
        },
        "network": {
            "protocol_evidence": {
                "http": dict(native_event["http"]),
                "alert_metadata": metadata,
            },
        },
        "investigation": {
            "packet_summary": packet_summary,
            "packets": packets,
            "related_alerts": related_alerts,
        },
        "assessment": {"explanation": explanation},
    }
    original_alert = json.dumps(alert, sort_keys=True)
    original_native_event = json.dumps(native_event, sort_keys=True)

    document = build_individual_alert_document(
        alert,
        native_event=native_event,
        enrichment=enrichment,
        investigation=investigation,
        created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
    )

    assert json.dumps(alert, sort_keys=True) == original_alert
    assert json.dumps(document["native_event"], sort_keys=True) == original_native_event

    packet_export = document["packet_investigation"]
    assert packet_export["alert"]["unique_investigation_note"] == "keep this unique note"
    assert "raw_json" not in packet_export["alert"]
    assert "msg" not in packet_export["alert"]
    assert packet_export["alert_reference"]["section"] == "alert"
    assert "related_alerts" not in packet_export
    assert "selected_alert_excluded_from_related_alerts" not in packet_export
    assert "related_alert_count" not in packet_export
    assert packet_export["packets"] == packets
    assert packet_export["packet_summary"] == packet_summary

    network = document["enrichment"]["network"]
    assert "protocol_evidence" not in network
    assert "protocol_evidence.http" in network["deduplicated_fields"]
    assert "protocol_evidence.alert_metadata" in network["deduplicated_fields"]

    canonical_investigation = document["enrichment"]["investigation"]
    assert "packets" not in canonical_investigation
    assert canonical_investigation["details_reference"] == "packet_investigation"
