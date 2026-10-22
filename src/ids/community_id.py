from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct


COMMUNITY_ID_VERSION = 1
DEFAULT_SEED = 0


_PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "IGMP": 2,
    "ICMPV6": 58,
    "SCTP": 132,
}


def protocol_number(
    protocol: str | int | None,
) -> int:
    if isinstance(protocol, int):
        if 0 <= protocol <= 255:
            return protocol

        raise ValueError(
            f"Protocol number out of range: {protocol}"
        )

    if protocol is None:
        raise ValueError(
            "Protocol is required"
        )

    value = str(protocol).strip().upper()

    if value in _PROTOCOL_NUMBERS:
        return _PROTOCOL_NUMBERS[value]

    try:
        number = int(value)
    except ValueError as exc:
        raise ValueError(
            f"Unsupported protocol: {protocol!r}"
        ) from exc

    if not 0 <= number <= 255:
        raise ValueError(
            f"Protocol number out of range: {number}"
        )

    return number


def _address_bytes(
    ip: str,
) -> bytes:
    return ipaddress.ip_address(ip).packed


def _canonical_flow(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> tuple[bytes, bytes, int, int]:
    """
    Return the flow endpoints in canonical order.

    Ordering is based on the IP addresses first. When the IPs are equal,
    ports provide the tie-breaker.
    """
    src = _address_bytes(src_ip)
    dst = _address_bytes(dst_ip)

    if not 0 <= src_port <= 65535:
        raise ValueError(
            f"Source port out of range: {src_port}"
        )

    if not 0 <= dst_port <= 65535:
        raise ValueError(
            f"Destination port out of range: {dst_port}"
        )

    if src < dst:
        return (
            src,
            dst,
            src_port,
            dst_port,
        )

    if src > dst:
        return (
            dst,
            src,
            dst_port,
            src_port,
        )

    # Same IP: use ports to make the ordering deterministic.
    if src_port <= dst_port:
        return (
            src,
            dst,
            src_port,
            dst_port,
        )

    return (
        dst,
        src,
        dst_port,
        src_port,
    )


def community_id(
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
    protocol: str | int,
    *,
    seed: int = DEFAULT_SEED,
) -> str:
    """
    Calculate Community ID version 1.

    Input layout:

        2-byte seed
        source address
        destination address
        1-byte protocol
        1-byte zero padding
        2-byte source port
        2-byte destination port

    The endpoint order is canonicalized so reversing the packet direction
    produces the same Community ID.
    """
    if not 0 <= seed <= 65535:
        raise ValueError(
            f"Seed out of range: {seed}"
        )

    proto = protocol_number(protocol)

    src_port = (
        0
        if src_port is None
        else int(src_port)
    )

    dst_port = (
        0
        if dst_port is None
        else int(dst_port)
    )

    (
        source_address,
        destination_address,
        source_port,
        destination_port,
    ) = _canonical_flow(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    )

    payload = (
        struct.pack(
            "!H",
            seed,
        )
        + source_address
        + destination_address
        + struct.pack(
            "!B",
            proto,
        )
        + b"\x00"
        + struct.pack(
            "!H",
            source_port,
        )
        + struct.pack(
            "!H",
            destination_port,
        )
    )

    digest = hashlib.sha1(
        payload
    ).digest()

    encoded = base64.b64encode(
        digest
    ).decode("ascii")

    return (
        f"{COMMUNITY_ID_VERSION}:{encoded}"
    )
