"""Network-related safety checks."""

from __future__ import annotations

import ipaddress
import re

# IPv4 ranges permitted for an isolated lab target. Multicast is deliberately
# excluded: it is not a single controlled endpoint and must never pass a dynamic
# validation safety gate.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private_ip(addr: str) -> bool:
    """Return True if ``addr`` is an IPv4 address in a private/reserved range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version != 4 or ip.is_multicast:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)


def contains_private_ip(text: str) -> bool:
    """Return True if ``text`` contains any IPv4 address in a private range."""
    for match in re.finditer(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        if is_private_ip(match.group(0)):
            return True
    return False
