"""M8 probes: harmless-marker whitelist, dangerous-payload detection, connectivity.

All probes are read-only or emit harmless marker files only (``touch``/``echo``/
``id``). The module rejects any dangerous payload (reverse shell, persistence,
download-and-execute) before it can run.
"""

from __future__ import annotations

import re
from typing import Any

# Harmless probe command templates: (name, argv). Only these may execute.
HARMLESS_PROBES: dict[str, list[str]] = {
    "touch_marker": ["touch", "/tmp/lab_marker"],
    "echo_marker": ["echo", "LAB", ">", "/tmp/lab_marker.txt"],
    "id_check": ["id"],
    "uname_check": ["uname", "-a"],
}

# Patterns that indicate a weaponized / dangerous payload (always rejected).
_DANGEROUS_PATTERNS = [
    r"nc\s+-e",  # reverse shell via netcat
    r"bash\s+-i",  # interactive reverse shell
    r"sh\s+-i",
    r">\s*/dev/tcp/",  # bash /dev/tcp reverse shell
    r"crontab",  # persistence
    r"/etc/rc\.local",  # persistence
    r"init\.d",  # persistence
    r"wget\b.*\|\s*(sh|bash)",  # download-and-execute
    r"curl\b.*\|\s*(sh|bash)",  # download-and-execute
    r"tftp\s+-g",  # download
    r"chmod\s+[0-7]{3,4}",  # permission escalation
    r"mkfs",  # destructive
    r"dd\s+if=.*of=/dev/",  # destructive disk write
    r"rm\s+-rf\s+/",  # destructive
]


def is_harmless_probe(argv: list[str] | str) -> bool:
    """Return True if ``argv`` exactly matches a whitelisted harmless probe."""
    if isinstance(argv, str):
        argv = [argv]
    return argv in [list(t) for t in HARMLESS_PROBES.values()]


def detect_dangerous_payload(command: str) -> list[str]:
    """Return the list of dangerous patterns matched in ``command``."""
    matches: list[str] = []
    for pattern in _DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            matches.append(pattern)
    return matches


def assert_harmless(command: str) -> None:
    """Raise :class:`ValueError` if ``command`` matches a dangerous pattern."""
    matched = detect_dangerous_payload(command)
    if matched:
        msg = f"dangerous payload rejected: {command!r} (matched {matched})"
        raise ValueError(msg)


def build_connectivity_probe(host: str, port: int, *, timeout: int = 5) -> list[str]:
    """Return a read-only connectivity probe command (curl HEAD-ish).

    The probe only checks that the service responds; it sends no exploit.
    """
    return ["curl", "-i", "--max-time", str(timeout), f"http://{host}:{port}/"]


def build_marker_probe(name: str = "touch_marker") -> list[str]:
    """Return a whitelisted harmless-marker probe command."""
    if name not in HARMLESS_PROBES:
        raise KeyError(f"unknown harmless probe: {name!r}")
    return list(HARMLESS_PROBES[name])


def record_startup_check(
    *,
    probe_name: str,
    cold_start_ok: bool,
    hot_start_ok: bool,
) -> dict[str, Any]:
    """Record cold/hot start repeatability evidence.

    Both a cold start and a hot restart must be observed at least once each
    for the L2/L3 baseline to be considered repeatable.
    """
    return {
        "probe": probe_name,
        "cold_start_ok": cold_start_ok,
        "hot_start_ok": hot_start_ok,
        "repeatable": bool(cold_start_ok and hot_start_ok),
    }
