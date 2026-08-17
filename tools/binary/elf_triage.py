"""M4 first-pass triage scoring for ELF binaries.

Scores start at 0 and accumulate weighted signals so that only the most
promising binaries are promoted to deep decompilation (never decompile the
whole rootfs). The raw score is normalised to a ``triage_score`` in ``[0, 1]``
for the ``binary_summary.schema.json`` field.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.binary.danger_scan import scan_dangerous_functions
from tools.binary.elf_read import canonical_arch, iter_imports, iter_strings, load_elf

# Network-facing imports that suggest the binary handles external input.
_NETWORK_IMPORTS = {
    "socket",
    "recv",
    "recvfrom",
    "recvmsg",
    "send",
    "sendto",
    "sendmsg",
    "accept",
    "connect",
    "bind",
    "listen",
    "gethostbyname",
    "inet_ntoa",
    "inet_aton",
    "inet_pton",
    "inet_ntop",
    "select",
    "poll",
    "httpd",
}

# Strings that hint at a web handler / router / UPnP service.
_WEB_HANDLER_STRINGS = (
    "/cgi-bin",
    "http",
    "HTTP",
    "upnp",
    "UPnP",
    "soap",
    "SOAP",
    "formexeCommand",
    "websGetVar",
    "QUERY_STRING",
    "SOAPAction",
    "NewDownloadURL",
    "NewStatusURL",
)

# Raw-score weights (documented in the M4 plan).
_WEIGHT_STARTUP = 3
_WEIGHT_NETWORK = 2
_WEIGHT_WEB = 3
_WEIGHT_ATTACK_SURFACE = 4
_MAX_DANGER_WEIGHT = 3
_MAX_RAW_SCORE = 15.0


def _danger_signal(path: str | Path) -> dict[str, Any]:
    report = scan_dangerous_functions(path)
    return {
        "total_weight": report["total_weight"],
        "critical": report["critical"],
        "hits": report["hits"],
    }


def triage_elf(
    path: str | Path,
    *,
    startup_refs: int = 0,
    attack_surface_refs: int = 0,
) -> dict[str, Any]:
    """Score a single ELF and return a triage report.

    Args:
        path: Path to the ELF binary.
        startup_refs: Number of startup-script references (``+3`` each).
        attack_surface_refs: Number of M3 attack-surface references (``+4`` each).

    Returns:
        Dict with ``raw_score``, ``triage_score`` (0..1), ``architecture``,
        ``reasons``, ``network_imports``, ``web_handler_strings``, and the
        danger-scan detail. A non-ELF input yields a zero score.
    """
    elf = load_elf(path)
    if elf is None:
        return {
            "raw_score": 0,
            "triage_score": 0.0,
            "architecture": "unknown",
            "reasons": ["not an ELF"],
            "network_imports": [],
            "web_handler_strings": [],
            "danger": {"total_weight": 0, "critical": False, "hits": []},
        }

    imports = set(iter_imports(elf))
    strings = list(iter_strings(elf))

    raw = 0.0
    reasons: list[str] = []

    if startup_refs > 0:
        raw += _WEIGHT_STARTUP * startup_refs
        reasons.append(f"startup_refs={startup_refs}")

    network_imports = sorted(_NETWORK_IMPORTS & imports)
    if network_imports:
        raw += _WEIGHT_NETWORK
        reasons.append("network_imports")

    web_strings = sorted(
        {s for s in strings if any(hint.lower() in s.lower() for hint in _WEB_HANDLER_STRINGS)}
    )
    if web_strings:
        raw += _WEIGHT_WEB
        reasons.append("web_handler_strings")

    danger = _danger_signal(path)
    if danger["total_weight"] > 0:
        raw += min(danger["total_weight"], _MAX_DANGER_WEIGHT)
        reasons.append("dangerous_imports")
    if danger["critical"]:
        reasons.append("command_execution+format_string")

    if attack_surface_refs > 0:
        raw += _WEIGHT_ATTACK_SURFACE * attack_surface_refs
        reasons.append(f"attack_surface_refs={attack_surface_refs}")

    triage_score = round(min(raw / _MAX_RAW_SCORE, 1.0), 3)

    return {
        "raw_score": round(raw, 1),
        "triage_score": triage_score,
        "architecture": canonical_arch(elf),
        "reasons": reasons,
        "network_imports": network_imports,
        "web_handler_strings": web_strings,
        "danger": danger,
    }
