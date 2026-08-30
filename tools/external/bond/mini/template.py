"""M3 - LLM HTTP-template generation with a rule-based fallback (mini-BOND X2).

Infers the HTTP request shape (method / entry-point prefix / param format) needed to
reach a sink, per BOND's Fig.1 template prompt. Uses the in-house OpenAI-compatible
runtime when available; otherwise falls back to a deterministic rule template built
from the candidate's own ``entry_point`` / ``constraints``. The module MUST NOT fail
when the LLM is down -- it must degrade to the rule template (H-BOND.md §4.3, §10).

Hard rule: HTTP requests are generated only; we never construct or execute command
primitives. No ``curl`` / ``wget`` is ever produced.
"""

from __future__ import annotations

from typing import Any

_SYSTEM_PROMPT = (
    "You are an IoT vulnerability triage expert. Given a firmware entry point and its "
    "parameters, infer the HTTP request structure: http method (GET/POST), entry point "
    "location (url/body), entry point prefix (string or null), and param format "
    "(key-value / JSON / XML / custom). Respond ONLY with compact JSON."
)


def _rule_template(candidate: dict[str, Any]) -> dict[str, Any]:
    """Deterministic fallback template from the candidate's metadata."""
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
        "source": "rule",
    }


def generate_template(
    candidate: dict[str, Any],
    *,
    llm_runtime: Any | None = None,
) -> dict[str, Any]:
    """Return an HTTP template dict for a candidate.

    Tries the LLM first; on ANY failure (unavailable, timeout, bad JSON) returns the
    rule template. Never raises.
    """
    fallback = _rule_template(candidate)
    if llm_runtime is None:
        return fallback

    entry = candidate.get("entry_point") or {}
    keyword = str(entry.get("keyword") or entry.get("func") or "handler")
    params = [c.get("param") for c in (candidate.get("constraints") or [])
              if isinstance(c, dict)]
    try:
        prompt = (
            f"Entry keyword: {keyword}. Sink: {candidate.get('sink_func') or ''}. "
            f"Vuln class: {candidate.get('vuln_class')}. "
            f"Params: {params}"
        )
        resp = llm_runtime.generate(system=_SYSTEM_PROMPT, user=prompt)
        parsed = _parse_llm_json(resp)
        if parsed:
            parsed.setdefault("source", "llm")
            return parsed
    except Exception:
        # LLM unavailable / malformed -> rule fallback (never abort the module).
        return fallback
    return fallback


def _parse_llm_json(text: str) -> dict[str, Any] | None:
    """Extract the first JSON object from an LLM reply; None on failure."""
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    import json

    try:
        obj = json.loads(text[start : end + 1])
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    # sanitise: no executable command primitives may survive in the template.
    return {k: v for k, v in obj.items() if k in {
        "method", "entry_point", "prefix", "param_format", "params"}}


__all__ = ["generate_template"]
