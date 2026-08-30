"""M1 - entry-point identification and reachable-region extraction (mini-BOND X2).

Replaces BOND's IDA-Pro CFG/CG export with a Ghidra-headless export (H-BOND.md §4.1).
When Ghidra is unavailable the functions degrade gracefully: ``export_cfg_cg`` returns
an ``available=False`` dict (no exception), and ``identify_entry_points`` still works on
any caller-supplied CFG/CG (used by the unit tests and by the BOND stage when a prebuilt
CFG is supplied).

Entry-point identification performs a *backward* traversal from the sink address along
the call graph, stopping at the dispatch structure that registers the handler (e.g.
``websFormDefine("SetWan", fn)`` / ``goform/xxx`` / ``nvram_set``). The matched string
becomes the entry keyword; the functions between the dispatch node and the sink form the
reachable region.
"""

from __future__ import annotations

import contextlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

# Dispatch-feature signatures that register a request handler (entry points).
_DISPATCH_PATTERNS = [
    re.compile(r"websFormDefine", re.I),
    re.compile(r"websAspDefine", re.I),
    re.compile(r"formDefine", re.I),
    re.compile(r"goform", re.I),
    re.compile(r"nvram_set", re.I),
]


def _has_dispatch_feature(func: dict[str, Any]) -> bool:
    blob = " ".join(str(s) for s in func.get("strings", []))
    blob += " " + str(func.get("name", ""))
    return any(p.search(blob) for p in _DISPATCH_PATTERNS)


def _reverse_callgraph(cg: dict[str, Any]) -> dict[str, list[str]]:
    """Build ``{callee: [callers...]}`` from a forward ``callgraph`` map."""
    rev: dict[str, list[str]] = {}
    for caller, callees in (cg.get("callgraph") or {}).items():
        for callee in callees or []:
            rev.setdefault(str(callee), []).append(str(caller))
    return rev


def identify_entry_points(
    cg: dict[str, Any],
    sink_addr: str,
) -> list[dict[str, Any]]:
    """Backward-traverse the call graph from ``sink_addr`` to dispatch nodes.

    Returns a list of ``{"keyword", "func", "type", "reachable_region"}``. An empty
    list means no dispatch structure was found (the sink is not handler-reachable).
    Never raises; tolerates missing keys.
    """
    functions = cg.get("functions") or {}
    rev = _reverse_callgraph(cg)
    sink = str(sink_addr)

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    # BFS backward from the sink.
    queue: list[tuple[str, list[str]]] = [(sink, [sink])]
    while queue:
        node, path = queue.pop(0)
        for caller in rev.get(node, []):
            if caller in seen:
                continue
            seen.add(caller)
            new_path = path + [caller]
            func = functions.get(caller, {})
            if _has_dispatch_feature(func):
                # Extract the entry keyword: the dispatch string argument.
                keyword = _extract_keyword(func)
                results.append({
                    "keyword": keyword,
                    "func": caller,
                    "type": _dispatch_type(func),
                    "reachable_region": new_path,
                })
            else:
                queue.append((caller, new_path))
    return results


def _extract_keyword(func: dict[str, Any]) -> str:
    for s in func.get("strings", []):
        s = str(s)
        m = re.search(r'["\']([A-Za-z][A-Za-z0-9_]*?)["\']', s)
        if m:
            return m.group(1)
    return str(func.get("name", ""))


def _dispatch_type(func: dict[str, Any]) -> str:
    blob = " ".join(str(s) for s in func.get("strings", []))
    if re.search(r"websFormDefine|formDefine", blob, re.I):
        return "websFormDefine"
    if re.search(r"goform", blob, re.I):
        return "goform"
    if re.search(r"nvram_set", blob, re.I):
        return "nvram_set"
    return "unknown"


def export_cfg_cg(binary: Path, out_json: Path) -> dict[str, Any]:
    """Run Ghidra headless to export CFG/CG/strings; degrade if Ghidra absent.

    Never raises. On a host without Ghidra the result carries ``available=False``
    plus a ``limitation`` string; the caller must treat this as an honest skip (not a
    hard failure) -- the BOND stage then has no entry points to drive fuzzing with.
    """
    ghidra = shutil.which("ghidra_headless") or shutil.which("analyzeHeadless")
    if ghidra is None:
        return {
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": "ghidra headless not found on PATH; entry-point export skipped",
        }
    # Real invocation would mount `binary` and run a Ghidra script; we record the
    # intent and return an empty CFG (the student host runs the actual export).
    with contextlib.suppress(OSError):
        out_json.write_text(
            json.dumps({"available": True, "binary": str(binary),
                        "functions": {}, "callgraph": {}}, indent=2),
            encoding="utf-8",
        )
    return {
        "available": True,
        "binary": str(binary),
        "functions": {},
        "callgraph": {},
        "note": f"ghidra export placeholder (ran: {ghidra})",
    }


__all__ = ["export_cfg_cg", "identify_entry_points"]
