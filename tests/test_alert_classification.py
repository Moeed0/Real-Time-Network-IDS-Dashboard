import pytest

from ids.alert_classification import classify_alert


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "OS-WINDOWS Microsoft Windows UPnP malformed advertisement",
            "NETWORK_EVENT",
        ),
        ("SURICATA Ethertype unknown", "NETWORK_EVENT"),
        (
            "PROTOCOL-ICMP IPv6 MLD multicast listener query attempt",
            "NETWORK_EVENT",
        ),
        ("POLICY-OTHER IGMP membership query attempt", "NETWORK_EVENT"),
        ("PROTOCOL-ICMP PING", "NETWORK_EVENT"),
        ("ET INFO Windows Update P2P Activity", "NETWORK_EVENT"),
        (
            "ET INFO External IP Lookup Domain in DNS Lookup",
            "NETWORK_EVENT",
        ),
        (
            "SURICATA STREAM excessive retransmissions",
            "NETWORK_EVENT",
        ),
        (
            "POLICY-OTHER HTTP request by IPv4 address attempt",
            "SECURITY_SUPPORT",
        ),
        ("SERVER-WEBAPP test.cgi access", "SECURITY_SUPPORT"),
        (
            "OS-OTHER Bash CGI environment variable injection attempt",
            "SECURITY_ALERT",
        ),
        (
            "ET WEB_SERVER Possible CVE-2014-6271 Attempt",
            "SECURITY_ALERT",
        ),
    ],
)
def test_classification_examples(message, expected):
    assert classify_alert({"msg": message}) == expected


def test_missing_message_is_network_event():
    assert classify_alert({}) == "NETWORK_EVENT"


def test_rule_field_is_used_when_message_is_missing():
    assert classify_alert({
        "rule": "OS-OTHER Bash CGI environment variable injection attempt"
    }) == "SECURITY_ALERT"
