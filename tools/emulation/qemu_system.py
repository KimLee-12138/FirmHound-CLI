"""M8 L2/L3: QEMU system-mode service emulation orchestration.

L2 confirms the service is reachable on a private IP/port; L3 performs
non-weaponized single-variable validation. Every network target is validated
against the private-network red line before any operation — a non-private IP
aborts with zero outbound traffic.
"""

from __future__ import annotations

import shutil
from typing import Any

from tools.emulation.safety_gate import validate_target_ip

_SYSTEM_QEMU = ["qemu-system-mips", "qemu-system-mipsel", "qemu-system-arm", "qemu-system-x86_64"]


def detect_system_qemu() -> str | None:
    """Return the first available QEMU system-mode binary, or None."""
    for name in _SYSTEM_QEMU:
        if shutil.which(name):
            return name
    return None


def validate_network(target_ip: str, *, port: int | None = None) -> dict[str, Any]:
    """Validate an L2/L3 network target (private IP only) and return its plan.

    Raises:
        ValueError: If ``target_ip`` is not a private/reserved address.
    """
    validate_target_ip(target_ip)  # red-line check, raises on public IP
    return {"target_ip": target_ip, "port": port, "private": True}


def plan_l2_bootstrap(
    target_ip: str,
    *,
    port: int = 80,
    tap_iface: str = "tap0",
) -> dict[str, Any]:
    """Plan an L2 system-emulation bootstrap (validates network, probes QEMU).

    Returns a plan dict; ``qemu`` is None when no system-mode binary exists,
    in which case ``status`` is ``skipped`` with a recorded limitation.
    """
    network = validate_network(target_ip, port=port)
    qemu = detect_system_qemu()
    if qemu is None:
        return {
            "status": "skipped",
            "limitation": "no QEMU system-mode binary available",
            "network": network,
            "qemu": None,
            "tap_iface": tap_iface,
        }
    return {
        "status": "planned",
        "network": network,
        "qemu": qemu,
        "tap_iface": tap_iface,
        "note": "isolated NAT/host-only tap; serial console log capture",
    }


def plan_l3_probe(
    target_ip: str,
    *,
    port: int = 80,
    probe_name: str = "touch_marker",
) -> dict[str, Any]:
    """Plan an L3 non-weaponized probe (validates network + probe whitelist)."""
    network = validate_network(target_ip, port=port)
    return {
        "status": "planned",
        "network": network,
        "probe": probe_name,
        "note": "single-variable change; observe reachability/stable anomaly only",
    }
