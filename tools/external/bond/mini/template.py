"""M3 - deterministic HTTP-template generation (mini-BOND X2).

Infers the HTTP request shape (method / entry-point prefix / param format) needed to
reach a sink from the candidate's real ``entry_point`` / ``constraints`` metadata.
The production runner uses this deterministic path so offline execution does not
pretend that model inference occurred.

Hard rule: HTTP requests are generated only; we never construct or execute command
primitives. No ``curl`` / ``wget`` is ever produced.
"""

from __future__ import annotations

from typing import Any


def generate_template(candidate: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic template from the candidate's recorded metadata."""
    entry = candidate.get("entry_point") or {}
    vuln_class = str(candidate.get("vuln_class") or "other")
    keyword = str(entry.get("keyword") or entry.get("func") or "handler")
    # command_injection over QUERY_STRING is typically GET; body sinks are POST.
    method = "GET" if vuln_class == "command_injection" else "POST"
    constraints = candidate.get("constraints") or []
    params = []
    for c in constraints:
        p = c.get("param") if isinstance(c, dict) else None
        if p:
            params.append(str(p))
    if not params:
        params = ["payload"]
    return {
        "method": method,
        "entry_point": str(entry.get("path") or f"/goform/{keyword}"),
        "prefix": str(entry.get("prefix") or keyword),
        "param_format": "key-value",
        "params": params,
        "source": "deterministic-rule",
    }


__all__ = ["generate_template"]
