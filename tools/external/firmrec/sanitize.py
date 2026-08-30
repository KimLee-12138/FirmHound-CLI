"""PoC sanitizer for FirmRec — thin re-export of the canonical BOND sanitizer.

F-FirmRec.md §7.4 mandates that every ``poc_info`` PoC must pass sanitization
before the finding may be persisted. The canonical, group-wide sanitizer lives
in H's BOND package (``tools.external.bond.sanitize.sanitize_poc``) and is the
single source of truth for the safety red line (no reverse shells, no download-
exec, no persistence, no real-target payloads). FirmRec imports it directly now
that BOND has landed (TODO(de=H) resolved).

Public contract (identical across the group):

    sanitize_poc(payload: str, *, strict: bool = True) -> tuple[str, bool]
    # -> (sanitized_or_empty, ok)
"""

from __future__ import annotations

from tools.external.bond.sanitize import sanitize_poc as _bond_sanitize

__all__ = ["sanitize_poc"]


def sanitize_poc(payload: str | None, *, strict: bool = True) -> tuple[str, bool]:
    """Reject unsafe PoCs using the canonical BOND sanitizer.

    Returns ``(sanitized, ok)``. ``ok`` is False when the payload hit a red line
    and must not be persisted (the caller drops the finding).
    """
    return _bond_sanitize(payload, strict=strict)
