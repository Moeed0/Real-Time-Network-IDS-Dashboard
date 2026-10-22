import ids.live_alert_view as live_alert_view
from ids.live_alert_view import adapt_live_alert


def sample_alert():
    return {
        "id": 41,
        "timestamp": "2026-10-14T07:00:00Z",
        "rule": "SQL injection attempt",
        "classification": "web-application-attack",
        "priority": 2,
        "protocol": "TCP",
        "src": "192.168.50.141:45000",
        "dst": "192.168.50.114:80",
        "src_addr": "192.168.50.141",
        "src_port": 45000,
        "dst_addr": "192.168.50.114",
        "dst_port": 80,
        "msg": "SQL injection attempt",
        "gid": 1,
        "sid": 12345,
        "rev": 2,
        "service": "http",
        "engine": "snort",
        "event_ts_utc": 1791961200000,
        "severity": 2,
        "correlation_group_id": "group-1",
    }


def test_adapts_live_alert_fields():
    result = adapt_live_alert(sample_alert())

    assert result["record_id"] == 41
    assert result["engine"] == "Snort"
    assert result["engine_key"] == "snort"
    assert result["alert"]["message"] == "SQL injection attempt"
    assert result["alert"]["sid"] == 12345
    assert result["network"]["source_ip"] == "192.168.50.141"
    assert result["network"]["destination_port"] == 80
    assert result["severity"] == 2
    assert result["security_context"]["identifier_evidence"]["cves"] == {}


def test_maps_cached_cve_and_mitre_intelligence():
    intelligence = {
        "base_intelligence": {
            "rule_context_found": True,
            "rule": {
                "engine": "snort",
                "gid": 1,
                "sid": 12345,
                "msg": "SQL injection attempt",
            },
            "documentation": {"summary": "Example rule documentation"},
        },
        "identifiers": {
            "cves": ["CVE-2020-1234"],
            "mitre_attack": ["T1190"],
        },
        "vulnerabilities": {
            "CVE-2020-1234": {
                "nvd": {"summary": "Example vulnerability"},
                "cisa_kev": True,
                "epss": {"score": 0.7},
                "circl": {},
            }
        },
        "mitre_enrichment": {
            "T1190": {"name": "Exploit Public-Facing Application"}
        },
        "risk_context": {
            "known_exploited": True,
            "known_exploited_cves": ["CVE-2020-1234"],
        },
    }

    result = adapt_live_alert(sample_alert(), intelligence)
    context = result["security_context"]

    assert list(context["identifier_evidence"]["cves"]) == ["CVE-2020-1234"]
    assert list(context["identifier_evidence"]["mitre_techniques"]) == ["T1190"]
    assert context["coverage"]["known_exploited_cve"] is True
    assert context["vulnerability_intelligence"]["cves"][0]["cisa_kev"] is True
    assert (
        context["mitre_attack_intelligence"]["techniques"][0]
        ["attack_record"]["name"]
        == "Exploit Public-Facing Application"
    )
    assert result["live_intelligence"] == intelligence


def test_missing_cache_does_not_invent_intelligence():
    context = adapt_live_alert(sample_alert())["security_context"]

    assert context["identifier_evidence"]["cves"] == {}
    assert context["identifier_evidence"]["mitre_techniques"] == {}
    assert context["coverage"]["known_exploited_cve"] is False
    assert context["vulnerability_intelligence"]["cves"] == []
    assert context["mitre_attack_intelligence"]["techniques"] == []

def test_lightweight_loader_skips_per_alert_cache_reads(monkeypatch):
    monkeypatch.setattr(
        live_alert_view,
        "load_live_summary",
        lambda _path: {"total_alerts": 1},
    )
    monkeypatch.setattr(
        live_alert_view,
        "load_live_alerts",
        lambda _path, *, limit: [sample_alert()],
    )

    def unexpected_cache_read(_alert):
        raise AssertionError("Lightweight loading must not read cache files.")

    monkeypatch.setattr(
        live_alert_view,
        "load_cached_live_intelligence",
        unexpected_cache_read,
    )

    records = live_alert_view.load_live_alert_view_records(
        "unused-read-only-test.db",
        include_cached_intelligence=False,
    )

    assert len(records) == 1
    assert records[0]["record_id"] == 41
    assert records[0]["intelligence_loaded"] is False
    assert records[0]["live_intelligence"] == {}
