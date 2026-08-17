"""Network-related safety checks."""

from __future__ import annotations

import ipaddress
import re

# RFC 1918 + link-local + loopback + multicast
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
]


def is_private_ip(addr: str) -> bool:
    """Return True if ``addr`` is an IPv4 address in a private/reserved range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_private:
        return True
    return any(ip in net for net in _PRIVATE_NETWORKS)


def contains_private_ip(text: str) -> bool:
    """Return True if ``text`` contains any IPv4 address in a private range."""
    for match in re.finditer(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        if is_private_ip(match.group(0)):
            return True
    return False
