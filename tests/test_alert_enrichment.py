import json

import pytest

from ids.alert_enrichment import (
    ENRICHMENT_SCHEMA_ID,
    ENRICHMENT_SCHEMA_VERSION,
    MISSING_DATA_NOTE,
    build_alert_enrichment,
)


def test_composes_complete_suricata_alert_enrichment():
    alert = {
        "record_id": 16411,
        "engine": "suricata",
        "timestamp": "2026-10-21T07:00:00Z",
        "raw_json": json.dumps({
            "event_type": "alert",
            "timestamp": "2026-10-21T07:00:00Z",
            "src_ip": "192.0.2.10",
            "src_port": 51000,
            "dest_ip": "198.51.100.20",
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "http",
            "community_id": "community-example",
            "flow": {"pkts_toserver": 4, "bytes_toserver": 500},
            "http": {"hostname": "example.test", "url": "/login"},
            "alert": {
                "signature_id": 12345,
                "gid": 1,
                "rev": 2,
                "signature": "Web attack attempt",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
        }),
    }

    intelligence = {
        "lookup_mode": "offline_local",
        "retrieved_at": "2026-10-21T07:01:00Z",
        "base_intelligence": {
            "rule_context_found": True,
            "rule": {"sid": 12345, "msg": "Web attack attempt"},
            "documentation": {"rule_explanation": "Example documented rule."},
        },
        "explanation": {"what_happened": "A web rule matched."},
        "identifiers": {
            "cves": ["CVE-2021-44228", "CVE-2020-12345"],
            "mitre_attack": ["T1059"],
        },
        "vulnerabilities": {
            "CVE-2021-44228": {
                "nvd": {"id": "CVE-2021-44228"},
                "epss": {"score": 0.99},
                "cisa_kev": {"cveID": "CVE-2021-44228"},
            },
            "CVE-2020-12345": {
                "nvd": {},
                "epss": {"score": None},
                "cisa_kev": None,
            },
        },
        "mitre_enrichment": {
            "T1059": [{"name": "Command and Scripting Interpreter"}],
        },
        "risk_context": {"known_exploited": True},
        "sources": {"nvd": "local SQLite"},
        "data_as_of": {"nvd": "2026-10-16"},
    }

    investigation = {
        "related_alerts": [
            {"id": 16411, "engine": "suricata"},
            {"id": 16420, "engine": "snort"},
        ],
        "packet_summary": {"total_packets": 4},
        "packets": [{"id": 1}, {"id": 2}],
    }

    result = build_alert_enrichment(alert, intelligence, investigation)

    assert result["schema"] == {
        "id": ENRICHMENT_SCHEMA_ID,
        "version": ENRICHMENT_SCHEMA_VERSION,
    }
    assert result["network"]["source"] == {
        "ip": "192.0.2.10", "port": 51000
    }
    assert result["network"]["destination"]["ip"] == "198.51.100.20"
    assert result["network"]["protocol_evidence"]["http"]["hostname"] == "example.test"
    assert result["detection"]["documentation"]["rule_explanation"].startswith("Example")
    assert result["threat_intelligence"]["coverage"]["unresolved_cves"] == [
        "CVE-2020-12345"
    ]
    assert result["threat_intelligence"]["coverage"]["unresolved_techniques"] == []
    assert "related_alert_count" not in result["investigation"]
    assert "related_alerts" not in result["investigation"]
    assert result["investigation"]["correlation"]["status"] == "related_alerts_found"
    assert result["assessment"]["risk_context"]["known_exploited"] is True
    assert result["provenance"]["data_as_of"]["nvd"] == "2026-10-16"


def test_incomplete_suricata_event_remains_enrichable():
    alert = {
        "record_id": 1714,
        "engine": "suricata",
        "raw_json": json.dumps({
            "event_type": "alert",
            "timestamp": "2026-10-21T07:00:00Z",
            "in_iface": "ens38",
            "pkt_src": "wire/pcap",
            "suricata_version": "8.0.3",
            "alert": {
                "signature_id": 9876,
                "gid": 1,
                "rev": 1,
                "signature": "Example signature",
                "category": "Misc activity",
                "severity": 3,
            },
        }),
    }
    intelligence = {
        "base_intelligence": {
            "rule_context_found": True,
            "rule": {"sid": 9876, "msg": "Example signature"},
            "documentation": {},
        },
        "identifiers": {"cves": [], "mitre_attack": []},
    }

    result = build_alert_enrichment(alert, intelligence)

    assert result["summary"]["rule_context_available"] is True
    assert result["network"]["source"]["ip"] is None
    assert result["coverage"]["network"] == "partial"
    assert result["coverage"]["vulnerability_intelligence"] == (
        "not_applicable_no_cve_identifier"
    )
    assert result["coverage"]["packet_investigation"] == "not_loaded"
    assert result["investigation"]["status"] == "not_loaded"


def test_snort_uses_native_priority_semantics_and_flow_counters():
    alert = {
        "id": 8,
        "engine": "snort",
        "raw_json": json.dumps({
            "msg": "Example alert",
            "priority": 1,
            "src_addr": "192.0.2.1",
            "src_port": 1234,
            "dst_addr": "198.51.100.1",
            "dst_port": 80,
            "proto": "TCP",
            "client_pkts": 3,
            "server_bytes": 1200,
        }),
    }

    result = build_alert_enrichment(alert)

    assert result["summary"]["native_severity"] == 1
    assert result["summary"]["severity_semantics"] == "snort_priority"
    assert result["network"]["protocol"] == "TCP"
    assert result["network"]["flow"]["client_pkts"] == 3
    assert result["network"]["flow"]["server_bytes"] == 1200
    assert result["coverage"]["native_event"] == "available"


def test_missing_cve_and_attack_records_are_explicitly_unresolved():
    result = build_alert_enrichment(
        {"record_id": 2, "engine": "suricata"},
        {
            "identifiers": {
                "cves": ["CVE-2024-12345"],
                "mitre_attack": ["T9999"],
            },
            "vulnerabilities": {"CVE-2024-12345": {}},
            "mitre_enrichment": {},
        },
    )

    coverage = result["threat_intelligence"]["coverage"]
    assert coverage["unresolved_cves"] == ["CVE-2024-12345"]
    assert coverage["unresolved_techniques"] == ["T9999"]
    assert coverage["vulnerabilities"][0]["note"] == MISSING_DATA_NOTE
    assert result["coverage"]["vulnerability_intelligence"] == "partially_unresolved"
    assert result["coverage"]["attack_intelligence"] == "partially_unresolved"


def test_no_identifiers_does_not_claim_that_no_vulnerability_exists():
    result = build_alert_enrichment({"id": 1, "engine": "snort"})

    assert result["coverage"]["vulnerability_intelligence"] == (
        "not_applicable_no_cve_identifier"
    )
    assert result["coverage"]["attack_intelligence"] == (
        "not_applicable_no_technique_identifier"
    )


def test_builder_does_not_mutate_inputs():
    alert = {
        "id": 4,
        "engine": "suricata",
        "raw_json": '{"event_type":"alert","src_ip":"192.0.2.1"}',
    }
    intelligence = {
        "base_intelligence": {"rule": {"sid": 10}},
        "identifiers": {"cves": ["CVE-2024-12345"]},
    }
    alert_before = json.dumps(alert, sort_keys=True)
    intelligence_before = json.dumps(intelligence, sort_keys=True)

    build_alert_enrichment(alert, intelligence)

    assert json.dumps(alert, sort_keys=True) == alert_before
    assert json.dumps(intelligence, sort_keys=True) == intelligence_before


@pytest.mark.parametrize("bad_alert", ["not an alert", None, 3])
def test_rejects_invalid_alert_input(bad_alert):
    with pytest.raises(TypeError, match="alert must be a mapping"):
        build_alert_enrichment(bad_alert)


@pytest.mark.parametrize("bad_attachment", ["invalid", []])
def test_rejects_invalid_intelligence_attachment(bad_attachment):
    with pytest.raises(TypeError, match="intelligence must be a mapping"):
        build_alert_enrichment({"id": 1}, bad_attachment)
