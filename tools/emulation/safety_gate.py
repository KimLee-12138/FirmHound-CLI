"""M8 safety gate: four hard gates that must ALL pass before dynamic validation.

The gate is the single choke point before any emulation or network activity.
It answers only "reachable / not-reachable, stable anomaly / not", and never
constructs an exploit chain.

Four hard gates (from the M8 plan):

* ``AUTHORIZED``       — explicit authorization flag is true.
* ``LOCAL_LAB``        — running in an isolated local lab environment.
* ``PRIVATE_NETWORK``  — target IP is inside a private/reserved range.
* ``BASELINE_READY``   — a clean baseline (service responds normally) is ready.

If any gate fails, the whole dynamic-validation stage returns
``ABORT_DYNAMIC_VALIDATION`` and no outbound traffic is generated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fsa.utils.netcheck import is_private_ip

ABORT_ACTION = "ABORT_DYNAMIC_VALIDATION"


@dataclass(frozen=True)
class GateResult:
    """Outcome of the safety gate evaluation."""

    allowed: bool
    gates: dict[str, bool] = field(default_factory=dict)
    target_ip: str = ""
    reason: str | None = None

    @property
    def is_abort(self) -> bool:
        """Return True if dynamic validation must be aborted."""
        return not self.allowed

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "allowed": self.allowed,
            "gates": dict(self.gates),
            "target_ip": self.target_ip,
            "reason": self.reason,
        }


def evaluate_gate(
    *,
    authorized: bool,
    local_lab: bool,
    target_ip: str,
    baseline_ready: bool,
) -> GateResult:
    """Evaluate the four hard gates and return a decision.

    Args:
        authorized: Explicit authorization to validate this firmware.
        local_lab: Running in an isolated local lab (no real device / public net).
        target_ip: Target IP address (must be private for the gate to pass).
        baseline_ready: A clean baseline response has been confirmed.

    Returns:
        A :class:`GateResult`. When ``allowed`` is False, ``reason`` names the
        failing gates; callers must abort and emit zero outbound traffic.
    """
    gates = {
        "authorized": bool(authorized),
        "local_lab": bool(local_lab),
        "private_network": is_private_ip(target_ip),
        "baseline_ready": bool(baseline_ready),
    }
    allowed = all(gates.values())
    reason: str | None = None
    if not allowed:
        failing = [name for name, ok in gates.items() if not ok]
        reason = f"{ABORT_ACTION}: {', '.join(failing)}"
    return GateResult(allowed=allowed, gates=gates, target_ip=target_ip, reason=reason)


def validate_target_ip(target_ip: str) -> None:
    """Raise :class:`ValueError` if ``target_ip`` is not a private address.

    This is the red-line check used by the emulation layer *before* any
    network operation; a non-private target must abort with zero traffic.
    """
    if not is_private_ip(target_ip):
        msg = f"refusing non-private target IP: {target_ip!r}"
        raise ValueError(msg)
