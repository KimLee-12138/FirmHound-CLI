"""Authentication hint matrix for attack surface entries.

Implements a three-layer cross-check:
  L1: route-level exemption markers (noauth, skip_auth, whitelist, etc.)
  L2: handler-level authentication function calls
  L3: script-level session/authorization checks
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


L1_EXEMPT_KEYWORDS = ["noauth", "skip_auth", "whitelist", "auth_not_required", "public"]
L2_AUTH_FUNCTIONS = [
    "sess_validate",
    "check_auth",
    "is_login",
    "verify_token",
    "auth_check",
    "require_auth",
]
L3_AUTH_MARKERS = [
    "AUTHORIZED_GROUP",
    "http_session",
    "session_id",
    "check_user",
    "login_check",
]


@dataclass
class AuthHint:
    """Result of authentication analysis for one surface entry."""

    hint: str  # preauth | auth | local_only | ipc | unknown
    confidence: float
    reasons: list[str]


def _check_route_exemption(route: str | None) -> tuple[bool, list[str]]:
    if not route:
        return False, []
    lowered = route.lower()
    hits = [kw for kw in L1_EXEMPT_KEYWORDS if kw in lowered]
    return bool(hits), [f"L1 route marker: {kw}" for kw in hits]


def _handler_calls_auth(binary_path: str | Path, handler_name: str) -> tuple[bool, list[str]]:
    """Check whether the binary contains known auth function references."""
    path = Path(binary_path)
    if not path.exists():
        return False, []
    try:
        data = path.read_bytes()
    except OSError:
        return False, []
    text = data.decode("utf-8", errors="ignore")
    hits = [fn for fn in L2_AUTH_FUNCTIONS if fn in text]
    return bool(hits), [f"L2 auth function: {fn}" for fn in hits]


def _script_auth_check(script_path: str | Path) -> tuple[bool, list[str]]:
    """Check whether a script contains session/authorization markers."""
    path = Path(script_path)
    if not path.exists():
        return False, []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False, []
    hits = [marker for marker in L3_AUTH_MARKERS if marker in text]
    return bool(hits), [f"L3 auth marker: {marker}" for marker in hits]


def classify_auth(
    route: str | None,
    binary_path: str | Path | None,
    handler_name: str | None,
    script_path: str | Path | None,
    reachability: str = "external",
) -> AuthHint:
    """Return authentication hint and confidence for a surface entry.

    Args:
        route: URL route string (e.g. /goform/formexeCommand).
        binary_path: Path to the handler binary.
        handler_name: Handler function/binary name.
        script_path: Optional path to a script handler.
        reachability: external | local | ipc.
    """
    reasons: list[str] = []

    if reachability in ("local", "ipc"):
        return AuthHint(hint="local_only", confidence=0.8, reasons=[f"reachability={reachability}"])

    l1_exempt, l1_reasons = _check_route_exemption(route)
    reasons.extend(l1_reasons)

    l2_auth = False
    if binary_path:
        l2_auth, l2_reasons = _handler_calls_auth(binary_path, handler_name or "")
        reasons.extend(l2_reasons)

    l3_auth = False
    if script_path:
        l3_auth, l3_reasons = _script_auth_check(script_path)
        reasons.extend(l3_reasons)

    if l1_exempt:
        return AuthHint(hint="preauth", confidence=0.75, reasons=reasons)
    if not l2_auth and not l3_auth:
        return AuthHint(
            hint="preauth",
            confidence=0.5,
            reasons=reasons + ["no auth evidence found"],
        )
    if l2_auth or l3_auth:
        return AuthHint(hint="auth", confidence=0.8, reasons=reasons)

    return AuthHint(hint="unknown", confidence=0.3, reasons=["insufficient information"])


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.web.auth_matrix <binary_path>")
        raise SystemExit(1)
    result = classify_auth("/goform/formexeCommand", sys.argv[1], "formexeCommand", None)
    print(f"hint={result.hint} confidence={result.confidence}")
    for r in result.reasons:
        print(f"  - {r}")
