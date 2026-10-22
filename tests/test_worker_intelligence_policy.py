from ids.alert_classification import (
    classify_alert,
    should_enrich_category,
)


def test_security_alerts_are_eligible_for_intelligence():
    alert = {
        "msg": "OS-OTHER Bash CGI environment variable injection attempt"
    }
    category = classify_alert(alert)
    assert category == "SECURITY_ALERT"
    assert should_enrich_category(category)


def test_supporting_detections_are_not_independently_enriched():
    for message in (
        "SERVER-WEBAPP test.cgi access",
        "POLICY-OTHER HTTP request by IPv4 address attempt",
    ):
        category = classify_alert({"msg": message})
        assert category == "SECURITY_SUPPORT"
        assert not should_enrich_category(category)


def test_routine_events_are_not_enriched():
    for message in (
        "OS-WINDOWS Microsoft Windows UPnP malformed advertisement",
        "PROTOCOL-ICMP IPv6 MLD multicast listener query attempt",
        "POLICY-OTHER IGMP membership query attempt",
    ):
        category = classify_alert({"msg": message})
        assert category == "NETWORK_EVENT"
        assert not should_enrich_category(category)


def test_unknown_categories_are_not_enriched():
    assert not should_enrich_category("UNKNOWN")
    assert not should_enrich_category("")
