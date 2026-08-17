"""Dataflow chain assembly and variable-usage verification (M5).

Implements the unified analysis model ``Entry → Source → Transform →
Validation → Authorization → Sink`` and the seven-layer HTTP template plus the
socket variant described in the M5 plan. Variable-usage verification is a
*mandatory* step: a candidate whose variable is defined but never used (or used
but never defined) is flagged with counter-evidence.
"""

from __future__ import annotations

from typing import Any

# Seven-layer template for HTTP handlers (legacy M5 model).
HTTP_LAYERS = [
    "request",
    "route",
    "c_handler",
    "ipc_xmldb",
    "php_receive",
    "php_sink",
    "shell_execute",
]

# Socket-packet variant template.
SOCKET_LAYERS = ["packet", "recvfrom", "copy_format", "sink"]

_LAYER_TEMPLATES: dict[str, list[str]] = {
    "http": HTTP_LAYERS,
    "socket": SOCKET_LAYERS,
}


def assemble_chain(
    entry: dict[str, Any] | None,
    source: dict[str, Any] | None,
    sink: dict[str, Any] | None,
    *,
    protocol: str = "http",
    validations: list[dict[str, Any]] | None = None,
    transform: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble a candidate dataflow chain from the source/sink/validation records.

    Args:
        entry: Entry-point record (e.g. ``{"function": "formexeCommand"}``).
        source: Source record (e.g. ``{"type": "http_param", "name": "cmd"}``).
        sink: Sink record (e.g. ``{"function": "system", "type": "command_execution"}``).
        protocol: ``"http"`` (default) or ``"socket"``.
        validations: Validation records produced by :mod:`source_sink_rules`.
        transform: Explicit transform records; defaults to a concat when both
            source and sink are present.

    Returns:
        A dict with ``protocol``, ``layers`` (per-layer filter presence),
        ``call_chain`` (string list for the candidate schema), ``transform``,
        and ``has_filter``.
    """
    layers_template = _LAYER_TEMPLATES.get(protocol, HTTP_LAYERS)
    validations = validations or []

    layers: list[dict[str, Any]] = []
    for index, name in enumerate(layers_template):
        node: dict[str, Any] = {"name": name, "index": index, "filter": False}
        if index == 0 and source:
            node["role"] = "source"
            node["source"] = source
        elif index == len(layers_template) - 1 and sink:
            node["role"] = "sink"
            node["sink"] = sink
        else:
            node["role"] = "transform"
        layers.append(node)

    # Validation filters sit on the transform layers before the sink.
    if validations:
        for layer in layers:
            if layer["role"] == "transform":
                layer["filter"] = True

    if transform is None and source is not None and sink is not None:
        detail = f"{source.get('name', '')} -> {sink.get('function', '')}"
        transform = [{"type": "concat", "detail": detail}]

    return {
        "protocol": protocol,
        "layers": layers,
        "call_chain": list(layers_template),
        "transform": transform or [],
        "validations": validations,
        "has_filter": bool(validations),
    }


def verify_variable_usage(
    functions: list[dict[str, Any]],
    variable: str,
    *,
    define_markers: tuple[str, ...] = ("=", "param", "input"),
) -> dict[str, Any]:
    """Verify that a variable has both a definition site and a use site.

    This is the mandatory cross-check from the M5 plan: a candidate claiming a
    controllable variable must show the variable being defined (assigned /
    received from input) and consumed (used at a sink), otherwise it is flagged.

    Args:
        functions: List of ``binary_summary`` function records (each with
            ``name`` and ``strings``).
        variable: The variable / parameter name to verify.
        define_markers: Substrings indicating a definition site.

    Returns:
        A dict with ``defined``, ``used``, ``ok``, ``definitions`` and ``uses``.
    """
    definitions: list[str] = []
    uses: list[str] = []
    for fn in functions:
        name = fn.get("name", "")
        for text in fn.get("strings", []):
            if variable not in text:
                continue
            if any(marker in text for marker in define_markers) or fn.get("is_source"):
                definitions.append(name)
            else:
                uses.append(name)

    defined = bool(definitions)
    used = bool(uses)
    return {
        "variable": variable,
        "defined": defined,
        "used": used,
        "ok": defined and used,
        "definitions": sorted(set(definitions)),
        "uses": sorted(set(uses)),
    }
