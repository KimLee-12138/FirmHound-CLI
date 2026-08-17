"""False-positive exclusion engine (M5).

Five rules from the legacy method, each recording counter-evidence when it
downgrades a candidate. These run *before* risk scoring so that obvious
false positives never reach the Verifier.
"""

from __future__ import annotations

from typing import Any

# CLI / system utilities whose dangerous imports are not attacker-reachable
# via a network handler. Presence alone should not produce a candidate.
_CLI_TOOLS = {
    "busybox",
    "iptables",
    "ip6tables",
    "sh",
    "ash",
    "bash",
    "dropbear",
    "udhcpc",
    "miniupnpd",
}

# Command templates that do not splice user input (no format specifier).
# A system() call on a static string is not user-controllable.
_RULE_COMMAND_TEMPLATE = "command_template_without_input"
_RULE_CLI_TOOL = "cli_tool"
_RULE_INTERNAL_IPC = "internal_ipc_only"
_RULE_NO_EXTERNAL_ENTRY = "no_reachable_external_entry"
_RULE_DEAD_CODE = "dead_code_or_not_started"


def _is_cli_tool(binary_id: str, path: str) -> bool:
    lowered = (binary_id + " " + path).lower()
    return any(tool in lowered for tool in _CLI_TOOLS)


def apply_fp_filters(
    candidate: dict[str, Any],
    *,
    binary_path: str = "",
    attack_surface: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply the five exclusion rules to a candidate.

    Args:
        candidate: A candidate dict in ``candidate.schema.json`` shape.
        binary_path: Path of the host binary (for CLI-tool detection).
        attack_surface: Optional M3 attack-surface record (for reachability).

    Returns:
        Dict with ``excluded`` (bool), ``rules`` (list of triggered rule ids),
        ``counterevidence`` (list of strings), and a ``suggested_category``.
    """
    rules: list[str] = []
    counterevidence: list[str] = []

    binary_id = candidate.get("binary_id", "")

    # Rule 1: CLI / system utility — dangerous imports are not network-reachable.
    if _is_cli_tool(binary_id, binary_path):
        rules.append(_RULE_CLI_TOOL)
        counterevidence.append(
            f"{binary_id} is a CLI/system utility, not an attacker-reachable handler"
        )

    # Rule 2: command template without input splice.
    sink = candidate.get("sink", {})
    transform = candidate.get("transform", [])
    transform_text = " ".join(t.get("detail", "") for t in transform).lower()
    is_command = sink.get("type") == "command_execution"
    if is_command and "%s" not in transform_text and "%d" not in transform_text:
        rules.append(_RULE_COMMAND_TEMPLATE)
        counterevidence.append("command template has no format specifier; no user input spliced")

    # Rule 3: pure internal IPC — source is an internal config/bus, not an external entry.
    source = candidate.get("source", {})
    source_type = source.get("type", "")
    internal_source = source_type in {"config_import", "environment"}
    if internal_source and candidate.get("user_control") in ("none", "partial"):
        rules.append(_RULE_INTERNAL_IPC)
        counterevidence.append(
            "source is an internal config/environment channel, not external input"
        )

    # Rule 4: no reachable external entry.
    if attack_surface is not None and not _has_external_entry(candidate, attack_surface):
        rules.append(_RULE_NO_EXTERNAL_ENTRY)
        counterevidence.append("no reachable external entry found in the attack surface")

    # Rule 5: dead code / service not started.
    entry = candidate.get("entry", {})
    if entry.get("dead") is True or entry.get("started") is False:
        rules.append(_RULE_DEAD_CODE)
        counterevidence.append("entry is dead code or its service is not started at boot")

    excluded = bool(rules)
    suggested_category = (
        "false-positive" if excluded else candidate.get("conclusion_category", "unknown")
    )

    return {
        "excluded": excluded,
        "rules": rules,
        "counterevidence": counterevidence,
        "suggested_category": suggested_category,
    }


def _has_external_entry(candidate: dict[str, Any], attack_surface: dict[str, Any]) -> bool:
    """Return True if the candidate's entry is referenced as an external endpoint."""
    entry_func = (candidate.get("entry") or {}).get("function", "")
    if not entry_func:
        return True
    endpoints = attack_surface.get("endpoints", [])
    if isinstance(endpoints, list):
        for ep in endpoints:
            if isinstance(ep, dict):
                handler = ep.get("handler", ep.get("function", ""))
                if entry_func in str(handler):
                    return True
            if isinstance(ep, str) and entry_func in ep:
                return True
    return False
