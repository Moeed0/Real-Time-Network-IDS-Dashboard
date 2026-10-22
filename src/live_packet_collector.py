from __future__ import annotations

import queue
import time

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
    AsyncSniffer,
)

from ids.config import Settings, get_settings
from ids.db import connect_database, insert_packet_batch, prune_packets
from ids.schema import ensure_schema
from ids.time_utils import packet_time_fields


def get_tcp_flags(pkt):
    flags = pkt[TCP].flags
    flag_names = []

    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x01:
        flag_names.append("FIN")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x20:
        flag_names.append("URG")

    return ",".join(flag_names) if flag_names else "NONE"


def packet_to_row(pkt) -> dict:
    """Extract metadata from IPv4, IPv6, ARP, and common transport traffic."""
    src = "unknown"
    dst = "unknown"
    protocol = "OTHER"
    src_port = None
    dst_port = None
    size = len(pkt)
    info = ""
    tcp_flags = None

    has_ipv4 = IP in pkt
    has_ipv6 = IPv6 in pkt
    has_arp = ARP in pkt

    # Recognize both IPv4 and IPv6 network addresses.
    if has_ipv4:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif has_ipv6:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    elif has_arp:
        src = pkt[ARP].psrc or "unknown"
        dst = pkt[ARP].pdst or "unknown"
        protocol = "ARP"

        if pkt[ARP].op == 1:
            info = "ARP Request"
        elif pkt[ARP].op == 2:
            info = "ARP Reply"
        else:
            info = "ARP packet"

    if has_ipv4 or has_ipv6:
        # TCP works the same way over IPv4 and IPv6.
        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = get_tcp_flags(pkt)

            if src_port in (80, 8080) or dst_port in (80, 8080):
                protocol = "HTTP"
                info = "HTTP traffic"
            elif src_port == 22 or dst_port == 22:
                protocol = "SSH"
                info = "SSH traffic"
            elif src_port == 443 or dst_port == 443:
                protocol = "HTTPS"
                info = "HTTPS traffic"
            else:
                protocol = "TCP"
                info = f"TCP flags: {tcp_flags}"

            if Raw in pkt:
                payload_text = bytes(pkt[Raw].load).decode(errors="ignore")
                if payload_text.startswith("GET"):
                    info = "HTTP GET request"
                elif payload_text.startswith("POST"):
                    info = "HTTP POST request"
                elif payload_text.startswith("HEAD"):
                    info = "HTTP HEAD request"

        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

            if src_port in (5353,) or dst_port in (5353,):
                protocol = "MDNS"
                info = "Multicast DNS traffic"
            elif src_port in (5355,) or dst_port in (5355,):
                protocol = "LLMNR"
                info = "Link-Local Multicast Name Resolution traffic"
            elif src_port == 53 or dst_port == 53:
                protocol = "DNS"
                info = "DNS traffic"
            else:
                protocol = "UDP"
                info = "UDP traffic"

            if DNS in pkt and DNSQR in pkt:
                try:
                    query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    if protocol == "MDNS":
                        info = f"mDNS query: {query}"
                    elif protocol == "LLMNR":
                        info = f"LLMNR query: {query}"
                    else:
                        info = f"DNS query: {query}"
                except (AttributeError, TypeError, ValueError):
                    pass

        elif ICMP in pkt:
            protocol = "ICMP"
            icmp_type = int(pkt[ICMP].type)

            if icmp_type == 8:
                info = "ICMP Echo Request"
            elif icmp_type == 0:
                info = "ICMP Echo Reply"
            else:
                info = f"ICMP type {icmp_type}"

        else:
            # Detect common ICMPv6 message classes without requiring imports
            # for every individual ICMPv6 subtype.
            icmpv6_name = next(
                (
                    layer.__name__
                    for layer in pkt.layers()
                    if layer.__name__.startswith("ICMPv6")
                ),
                None,
            )

            if icmpv6_name:
                protocol = "ICMPv6"
                descriptions = {
                    "ICMPv6EchoRequest": "ICMPv6 Echo Request",
                    "ICMPv6EchoReply": "ICMPv6 Echo Reply",
                    "ICMPv6ND_NS": "IPv6 Neighbor Solicitation",
                    "ICMPv6ND_NA": "IPv6 Neighbor Advertisement",
                    "ICMPv6ND_RS": "IPv6 Router Solicitation",
                    "ICMPv6ND_RA": "IPv6 Router Advertisement",
                    "ICMPv6MLQuery2": "IPv6 Multicast Listener Query",
                    "ICMPv6MLReport2": "IPv6 Multicast Listener Report",
                }
                info = descriptions.get(
                    icmpv6_name,
                    f"ICMPv6 message: {icmpv6_name}",
                )
            else:
                protocol = "IPv6" if has_ipv6 else "IP"
                info = f"{protocol} packet"

    elif not has_arp:
        # Preserve genuinely unrecognized link-layer packets, but don't
        # mislabel recognized IPv6 packets as unknown.
        protocol = "OTHER"
        info = "Unrecognized packet type"

    timestamp, event_ts_utc = packet_time_fields(float(pkt.time))

    return {
        "timestamp": timestamp,
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "size": size,
        "info": info,
        "tcp_flags": tcp_flags,
        "event_ts_utc": event_ts_utc,
    }


def setup_database(settings: Settings) -> None:
    conn = connect_database(settings.db_file)

    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()


def flush_pending(settings: Settings, pending: list[tuple]) -> None:
    if not pending:
        return

    conn = connect_database(settings.db_file)

    try:
        insert_packet_batch(conn, pending)
        conn.commit()
    finally:
        conn.close()

    pending.clear()


def run_periodic_retention(settings: Settings) -> None:
    conn = connect_database(settings.db_file)

    try:
        prune_packets(conn, settings.packet_retention)
        conn.commit()
    finally:
        conn.close()


def run_collector(settings: Settings) -> None:
    packets: queue.Queue = queue.Queue()
    last_flush = time.monotonic()
    last_retention = time.monotonic()
    pending: list[tuple] = []

    def capture_packet(pkt) -> None:
        try:
            packets.put_nowait(packet_to_row(pkt))
        except Exception as exc:
            print(f"[!] Packet conversion error: {exc}")

    sniffer = AsyncSniffer(
        iface=settings.interface,
        prn=capture_packet,
        store=False,
    )

    print(f"Listening on {settings.interface}...")
    print(f"Writing packets to: {settings.db_file}")

    sniffer.start()

    try:
        while True:
            drained = 0

            while drained < settings.batch_size:
                try:
                    pending.append(packets.get_nowait())
                    drained += 1
                except queue.Empty:
                    break

            now = time.monotonic()

            flush_due = (
                len(pending) >= settings.batch_size
                or (
                    pending
                    and (
                        (now - last_flush) * 1000
                        >= settings.batch_flush_ms
                    )
                )
            )

            if flush_due:
                flush_pending(settings, pending)
                last_flush = time.monotonic()

            if (
                now - last_retention
                >= settings.retention_interval_seconds
            ):
                run_periodic_retention(settings)
                last_retention = time.monotonic()

            time.sleep(0.02)

    except KeyboardInterrupt:
        flush_pending(settings, pending)
        print("\nCollector stopped.")

    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


def main() -> None:
    settings = get_settings()
    setup_database(settings)
    run_collector(settings)


if __name__ == "__main__":
    main()
