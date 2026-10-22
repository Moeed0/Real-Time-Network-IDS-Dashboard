from scapy.all import (
    DNS,
    DNSQR,
    Ether,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
)

from live_packet_collector import packet_to_row


def convert(packet):
    packet.time = 1_700_000_000.0
    return packet_to_row(packet)


def test_ipv6_mdns_query_has_real_addresses_and_name():
    packet = (
        Ether()
        / IPv6(
            src="fe80::2d37:6cf4:f5c8:64f7",
            dst="ff02::fb",
        )
        / UDP(sport=5353, dport=5353)
        / DNS(
            qr=0,
            qd=DNSQR(qname="node-3.local"),
        )
    )

    row = convert(packet)

    assert row["src"] == "fe80::2d37:6cf4:f5c8:64f7"
    assert row["dst"] == "ff02::fb"
    assert row["protocol"] == "MDNS"
    assert "node-3.local" in row["info"]


def test_ipv6_llmnr_is_not_other_or_unknown():
    packet = (
        Ether()
        / IPv6(src="fe80::1", dst="ff02::1:3")
        / UDP(sport=57987, dport=5355)
        / Raw(load=b"test")
    )

    row = convert(packet)

    assert row["src"] == "fe80::1"
    assert row["dst"] == "ff02::1:3"
    assert row["protocol"] == "LLMNR"
    assert row["info"] != "Unrecognized packet type"


def test_ipv6_icmp_echo_request_is_recognized():
    packet = (
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / ICMPv6EchoRequest()
    )

    row = convert(packet)

    assert row["src"] == "2001:db8::1"
    assert row["dst"] == "2001:db8::2"
    assert row["protocol"] == "ICMPv6"
    assert row["info"] == "ICMPv6 Echo Request"


def test_ipv6_tcp_keeps_ports_and_flags():
    packet = (
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=45000, dport=443, flags="S")
    )

    row = convert(packet)

    assert row["src"] == "2001:db8::1"
    assert row["dst"] == "2001:db8::2"
    assert row["src_port"] == 45000
    assert row["dst_port"] == 443
    assert row["protocol"] == "HTTPS"
    assert "SYN" in row["tcp_flags"]


def test_ipv4_tcp_behavior_is_preserved():
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / TCP(sport=12345, dport=22, flags="S")
    )

    row = convert(packet)

    assert row["src"] == "192.0.2.1"
    assert row["dst"] == "192.0.2.2"
    assert row["protocol"] == "SSH"


def test_genuinely_unrecognized_packet_stays_other():
    packet = Ether(type=0x88B5) / Raw(load=b"unknown protocol")

    row = convert(packet)

    assert row["src"] == "unknown"
    assert row["dst"] == "unknown"
    assert row["protocol"] == "OTHER"
    assert row["info"] == "Unrecognized packet type"
