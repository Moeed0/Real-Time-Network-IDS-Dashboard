from ids.alert_intelligence import _clean_documentation
from ids.extended_alert_intelligence import (
    _content_patterns,
    _describe_rule_logic,
    _rule_reference_cves,
)


def test_snort_style_references_become_cve_ids():
    rule = {"references_json": '["cve,2014-6271", "cve,2014-6277", "url,example.com"]'}
    assert _rule_reference_cves(rule) == ["CVE-2014-6271", "CVE-2014-6277"]


def test_reference_parsing_is_defensive():
    assert _rule_reference_cves(None) == []
    assert _rule_reference_cves({}) == []
    assert _rule_reference_cves({"references_json": "not json"}) == []
    assert _rule_reference_cves({"references_json": ["CVE,2014-6271"]}) == ["CVE-2014-6271"]


def test_content_patterns_handle_both_stored_shapes():
    snort = {"content_matches_json": '["\\"() {\\",fast_pattern,nocase"]'}
    suricata = {"content_matches_json": '[" HTTP/1.", "\\"|28 29 20 7b|\\"; fast_pattern"]'}
    assert _content_patterns(snort) == ["() {"]
    assert _content_patterns(suricata) == ["HTTP/1.", "|28 29 20 7b|"]


def test_rule_logic_description_uses_only_rule_fields():
    rule = {
        "protocol": "tcp",
        "service": "http",
        "flow": "to_server,established",
        "content_matches_json": '["\\"() {\\",fast_pattern,nocase"]',
    }
    text = _describe_rule_logic(rule)
    assert "TCP traffic" in text and "http service" in text
    assert "sent to a server" in text and "established session" in text
    assert "`() {`" in text


def test_rule_logic_falls_back_when_rule_has_no_detail():
    assert _describe_rule_logic({}) == "The traffic matched the conditions defined by the IDS rule."


def test_placeholder_documentation_is_dropped_but_real_text_kept():
    cleaned = _clean_documentation(
        {
            "rule_explanation": "None provided",
            "what_to_look_for": "No information provided.",
            "known_usage": "No public information",
            "false_positives": "No known false positives",
            "msg": "x",
            "sid": 401,
        }
    )
    assert "rule_explanation" not in cleaned
    assert "what_to_look_for" not in cleaned
    assert "known_usage" not in cleaned
    assert cleaned["false_positives"] == "No known false positives"
    assert cleaned["sid"] == 401
