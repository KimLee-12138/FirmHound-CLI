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

import json
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from fsa.utils.proc import run_command

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
                results.append(
                    {
                        "keyword": keyword,
                        "func": caller,
                        "type": _dispatch_type(func),
                        "reachable_region": new_path,
                    }
                )
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
    binary = Path(binary).resolve()
    out_json = Path(out_json).resolve()
    if not binary.is_file():
        return {
            "status": "failed",
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": "binary does not exist or is not a file",
        }

    ghidra = shutil.which("analyzeHeadless") or shutil.which("ghidra_headless")
    if ghidra is None:
        return {
            "status": "degraded",
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": "ghidra headless not found on PATH; entry-point export skipped",
        }

    script_dir = Path(__file__).resolve().parent.parent / "ghidra_scripts"
    script_file = script_dir / "ExportCfgCg.java"
    if not script_file.is_file():
        return {
            "status": "failed",
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": f"Ghidra export script missing: {script_file}",
        }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    project_dir = out_json.parent / ".ghidra-projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = f"bond_{uuid.uuid4().hex[:12]}"
    command = [
        ghidra,
        str(project_dir),
        project_name,
        "-import",
        str(binary),
        "-overwrite",
        "-scriptPath",
        str(script_dir),
        "-postScript",
        script_file.name,
        str(out_json),
        "-deleteProject",
    ]
    result = run_command(command, timeout=900)
    if result.status != "success":
        return {
            "status": "degraded" if result.status == "timeout" else "failed",
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": (
                f"Ghidra export {result.status}: " f"{(result.stderr or result.stdout)[-500:]}"
            ),
        }
    if not out_json.is_file():
        return {
            "status": "failed",
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": "Ghidra completed without producing the requested JSON artifact",
        }
    try:
        exported = json.loads(out_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "failed",
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": f"invalid Ghidra export JSON: {exc}",
        }
    if not isinstance(exported.get("functions"), dict) or not isinstance(
        exported.get("callgraph"), dict
    ):
        return {
            "status": "failed",
            "available": False,
            "binary": str(binary),
            "functions": {},
            "callgraph": {},
            "limitation": "Ghidra export is missing functions/callgraph mappings",
        }
    exported.update(
        {
            "status": "ok",
            "available": True,
            "binary": str(binary),
            "artifact": str(out_json),
        }
    )
    return exported


__all__ = ["export_cfg_cg", "identify_entry_points"]
