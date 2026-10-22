"""
Deterministic classification of IDS records for dashboard presentation.

This module does not modify the IDS database. It only decides how an
already-collected IDS record should be presented.
"""

from __future__ import annotations

from typing import Any


# High-confidence routine telemetry that should not appear as a
# security alert on the analyst-facing dashboard.
ROUTINE_PATTERNS = (
    "SURICATA ETHERTYPE UNKNOWN",
    "WINDOWS UPDATE P2P ACTIVITY",
    "EXTERNAL IP LOOKUP DOMAIN IN DNS LOOKUP",
    "MICROSOFT WINDOWS UPNP MALFORMED ADVERTISEMENT",
    "UPNP SERVICE DISCOVER ATTEMPT",
    "IPV6 MLD MULTICAST LISTENER QUERY ATTEMPT",
    "IGMP MEMBERSHIP QUERY ATTEMPT",
    "IPV6 MULTICAST NEIGHBOR ADD ATTEMPT",
    "PROTOCOL-ICMP PING",
    "PROTOCOL-ICMP ECHO REPLY",
    "PROTOCOL-ICMP PING UNIX",
    "PROTOCOL-ICMP UNUSUAL PING DETECTED",
    "DESTINATION UNREACHABLE NETWORK UNREACHABLE",
    "SURICATA STREAM EXCESSIVE RETRANSMISSIONS",
    "SURICATA STREAM BAD WINDOW UPDATE",
)


# High-confidence security detections.
SECURITY_PATTERNS = (
    "CVE-",
    "EXPLOIT",
    "EXPLOITATION",
    "INJECTION",
    "MALWARE",
    "SHELLCODE",
    "BRUTE FORCE",
    "BRUTE-FORCE",
    "COMMAND EXECUTION",
    "COMMAND INJECTION",
    "CODE INJECTION",
    "SQL INJECTION",
    "CROSS SITE SCRIPTING",
    "XSS",
    "BACKDOOR",
    "BOTNET",
    "TROJAN",
    "RANSOMWARE",
    "SHELLSHOCK",
)


# Detections that are useful supporting evidence for an attack,
# but are not themselves proof of malicious activity.
SUPPORT_PATTERNS = (
    "HTTP REQUEST BY IPV4 ADDRESS",
    "TEST.CGI ACCESS",
)


def classify_alert(alert: dict[str, Any]) -> str:
    """
    Return one of:

        SECURITY_ALERT
        SECURITY_SUPPORT
        NETWORK_EVENT

    Classification is deterministic and based on the observed IDS
    message rather than external intelligence.
    """

    message = str(
        alert.get("msg")
        or alert.get("rule")
        or ""
    ).strip().upper()

    if not message:
        return "NETWORK_EVENT"

    # Explicit routine/noise classification takes precedence.
    for pattern in ROUTINE_PATTERNS:
        if pattern in message:
            return "NETWORK_EVENT"

    # Supporting evidence for an attack.
    for pattern in SUPPORT_PATTERNS:
        if pattern in message:
            return "SECURITY_SUPPORT"

    # High-confidence security detection.
    for pattern in SECURITY_PATTERNS:
        if pattern in message:
            return "SECURITY_ALERT"

    # Unknown IDS matches stay out of the security-alert view until
    # there is enough evidence to classify them.
    return "NETWORK_EVENT"




def should_enrich_category(category: str) -> bool:
    """Only high-confidence security alerts receive intelligence enrichment."""
    return category == "SECURITY_ALERT"

def is_security_alert(alert: dict[str, Any]) -> bool:
    return classify_alert(alert) == "SECURITY_ALERT"


def is_security_related(alert: dict[str, Any]) -> bool:
    return classify_alert(alert) in {
        "SECURITY_ALERT",
        "SECURITY_SUPPORT",
    }
