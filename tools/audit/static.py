"""Evidence-backed static vulnerability candidate generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fsa.reporting.evidence_store import EvidenceStore
from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from tools.analysis.source_sink_rules import match_binary
from tools.binary.call_chain import recover_chains
from tools.pipeline_context import load_artifact, run_path, save_artifact

# Sink imports worth recovering an actual call site for (ARM32 disassembly).
_CHAIN_SINKS = {
    "doSystemCmd",
    "system",
    "popen",
    "execve",
    "sprintf",
    "vsprintf",
    "strcpy",
    "strncpy",
    "memcpy",
    "strcat",
    "snprintf",
}

# API name -> verifier-recognised validation kind (mirrors source_sink rules).
_KIND_BY_API = {
    "strlen": "length_check",
    "strncmp": "whitelist",
    "strcmp": "whitelist",
    "atoi": "type_limit",
    "strtol": "type_limit",
    "strtoul": "type_limit",
    "strtok": "blacklist",
    "isalpha": "charset_check",
    "isdigit": "charset_check",
}

_chain_cache: dict[str, dict[str, Any]] = {}


def _resolve_rootfs(run_dir: str) -> str:
    payload = load_artifact(run_dir, "rootfs.json", {})
    if isinstance(payload, dict):
        return str(payload.get("rootfs_path") or "")
    return ""


def _enrich_with_chain(
    candidate: dict[str, Any],
    summary: dict[str, Any],
    rootfs: str,
    evidence_store: EvidenceStore,
    run_id: str,
) -> None:
    """Attach a disassembly-backed call chain when one exists for this sink.

    Uses :mod:`tools.binary.call_chain` (capstone, ARM32). Only upgrades the
    candidate when a concrete enclosing function calling the sink was found --
    otherwise the candidate keeps its honest "call-chain-not-proven" state.
    """
    sink_func = str((candidate.get("sink") or {}).get("function", ""))
    binary_path = str(summary.get("path", ""))
    if not (rootfs and binary_path and sink_func in _CHAIN_SINKS):
        return
    elf_path = Path(rootfs, binary_path)
    if not elf_path.is_file():
        return
    cache_key = str(elf_path)
    if cache_key not in _chain_cache:
        try:
            _chain_cache[cache_key] = recover_chains(elf_path, sink_functions=list(_CHAIN_SINKS))
        except Exception:  # noqa: BLE001 - degrade, never abort a run
            _chain_cache[cache_key] = {"status": "failed", "sink_callers": []}
    report = _chain_cache[cache_key]
    callers = report.get("sink_callers", []) or []
    if not callers:
        return
    for caller in callers:
        if caller.get("sink") != sink_func or caller.get("func_addr") is None:
            continue
        func_addr = caller["func_addr"]
        candidate["call_chain"] = [
            {
                "addr": hex(func_addr),
                "func": f"sub_{func_addr:x}",
                "note": "enclosing function calls the sink",
            },
            {
                "addr": hex(caller["call_addr"]),
                "func": sink_func,
                "note": "sink call site",
            },
        ]
        filters = caller.get("same_func_filters", []) or []
        if filters:
            seen_kinds: set[str] = set()
            validation = []
            for api in filters:
                kind = _KIND_BY_API.get(api, "other")
                if kind in seen_kinds:
                    continue
                seen_kinds.add(kind)
                validation.append({"api": api, "kind": kind, "same_function": True})
            candidate["validation"] = validation
        if "call-chain-not-proven" in candidate.get("counterevidence", []):
            candidate["counterevidence"] = [
                ce for ce in candidate["counterevidence"] if ce != "call-chain-not-proven"
            ]
        evidence_id = evidence_store.add(
            run_id=run_id,
            stage="DECOMPILE_FALLBACK",
            type="decompile",
            observation=(
                f"ARM32 disassembly: function sub_{func_addr:x} calls {sink_func} "
                f"at 0x{caller['call_addr']:x} in {binary_path}; "
                f"same-function source-API read: {caller.get('same_func_source')}"
            ),
            tool="tools.binary.call_chain",
            tool_version="1.0",
            source_file=binary_path,
            artifact_path=binary_path,
            fact_status="confirmed",
            supports=[candidate["candidate_id"]],
        )
        candidate["evidence"].append(evidence_id["evidence_id"])
        break


def _candidate_id(binary_id: str, source: str, sink: str) -> str:
    raw = f"{binary_id}:{source}:{sink}"
    return f"cand-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


def _class_for_sink(sink: dict[str, Any]) -> str:
    if sink["type"] == "command_execution":
        return "command_injection"
    if sink["type"] == "memory_safety":
        return "overflow"
    if sink["type"] == "format_string":
        return "format_string"
    if sink["type"] == "filesystem":
        return "path_traversal"
    return "other"


def _matching_surface(summary: dict[str, Any], surfaces: list[dict[str, Any]]) -> dict[str, Any]:
    """Attach the attack surface that *actually* belongs to this binary.

    Old behaviour matched on bare basename (``Path(surface.binary).name ==
    Path(summary.path).name``), which made candidates inherit a *different*
    binary's surface whenever two files shared a name -- and, worse, attached
    bogus ``/goform/format`` noise surfaces. New rules:

    1. exact rootfs-relative path equality between ``surface.binary`` and the
       binary summary path (covers CGI surfaces and ``daemon`` surfaces);
    2. among exact matches, prefer one whose handler token appears in the
       binary's own string sample (best-effort handler attribution);
    3. then prefer ``preauth`` (unauthenticated) surfaces -- worst case is the
       honest assumption for a blind run.
    """
    binary_path = summary.get("path", "")
    string_sample = " ".join(
        str(sample)
        for sample in (summary.get("strings_summary") or {}).get("sample", [])
    )
    exact = [
        surface
        for surface in surfaces
        if surface.get("binary") == binary_path
        or (
            surface.get("category") == "daemon"
            and surface.get("handler") == Path(binary_path).name
        )
    ]
    if not exact:
        return {}
    for surface in exact:
        handler = str(surface.get("handler") or "")
        if handler and handler in string_sample:
            return surface
    for surface in exact:
        if surface.get("auth_hint") == "preauth":
            return surface
    return exact[0]


def execute_static(run_dir: str) -> dict[str, Any]:
    """Create candidates only when a real binary contains source and sink signals."""
    binary_payload = load_artifact(run_dir, "binary_summaries.json")
    if not isinstance(binary_payload, dict):
        return {"status": "failed", "reason": "binary summaries are missing"}
    surface_payload = load_artifact(run_dir, "attack_surface.json", {"surfaces": []})
    surfaces = surface_payload.get("surfaces", []) if isinstance(surface_payload, dict) else []
    run = run_path(run_dir)
    rootfs_dir = _resolve_rootfs(run_dir)
    evidence_store = EvidenceStore(run)
    candidates: list[dict[str, Any]] = []

    for summary in binary_payload.get("summaries", []):
        summary_path = str(summary.get("path", ""))
        # Kernel modules (.ko) and shared libraries (.so) are not user-space
        # entry points: they have no reachable network surface and only pollute
        # the candidate set (e.g. a .ko exporting _raw_write_lock_bh must never
        # rank above a web daemon's command-injection sink).
        if summary_path.endswith(".ko") or ".so" in summary_path:
            continue
        matched = match_binary(summary)
        if not matched["sources"] or not matched["sinks"]:
            continue
        surface = _matching_surface(summary, surfaces)
        for sink in matched["sinks"]:
            network_types = {
                "http_param",
                "http_header",
                "http_query",
                "http_cookie",
                "soap_param",
                "socket_buffer",
                "file_upload",
            }
            source = next(
                (item for item in matched["sources"] if item["type"] in network_types),
                matched["sources"][0],
            )
            source_signal = source.get("api") or source.get("string")
            # Blind-run precision gate: a candidate needs either a mapped attack
            # surface or a network-borne source. Sinks reached only from internal
            # env/config sources with no entry point are noise; skipping them
            # keeps candidates.json focused on reachable attack surface.
            if not surface and source.get("type") not in network_types:
                continue
            # Filesystem sinks (open/fwrite/write_mtd/...) of an *unmapped*
            # flash/updater binary are by-design behaviour, not a reachable
            # attack surface; they used to flood candidates and outrank real
            # web command injection in the ranking.
            if sink.get("type") == "filesystem" and not surface:
                continue
            candidate_id = _candidate_id(summary["binary_id"], source["type"], sink["function"])
            evidence = evidence_store.add(
                run_id=run.name,
                stage="STATIC_ANALYSIS",
                type="file_observation",
                observation=(
                    f"ELF {summary['path']} contains source signal {source_signal} "
                    f"and imported sink {sink['function']}; data-flow reachability is not proven."
                ),
                tool="tools.audit.static",
                tool_version="1.0",
                source_file=summary["path"],
                artifact_path=str(run / "artifacts" / "binary_summaries.json"),
                fact_status="confirmed",
                supports=[candidate_id],
            )
            auth_hint = surface.get("auth_hint", "unknown")
            candidate: dict[str, Any] = {
                "candidate_id": candidate_id,
                "surface_id": surface.get("surface_id", "unmapped-surface"),
                "binary_id": summary["binary_id"],
                "entry": {
                    "route": surface.get("route"),
                    "handler": surface.get("handler"),
                },
                "source": source,
                "transform": [],
                "validation": matched["validations"],
                "authorization": {
                    "required": True
                    if auth_hint == "auth"
                    else False
                    if auth_hint == "preauth"
                    else None,
                    "hint": auth_hint,
                },
                "sink": sink,
                "call_chain": [],
                "user_control": "partial",
                "vuln_class_hypothesis": _class_for_sink(sink),
                "risk_score": 0,
                "risk_level": "LOW",
                "evidence": [evidence["evidence_id"]],
                "counterevidence": ["call-chain-not-proven"],
                "conclusion_category": "unknown",
                "decisive_missing_fact": "source-to-sink data-flow and call-chain reachability",
                "status": "analyzing",
            }
            validate(candidate, schema_name="candidate")
            _enrich_with_chain(
                candidate, summary, rootfs_dir, evidence_store, run.name
            )
            candidates.append(candidate)

    result = {"run_id": run.name, "candidates": candidates}
    artifact = save_artifact(run, "candidates.json", result)
    save_json(run / "candidates.json", result)
    return {
        "status": "ok",
        "candidate_count": len(candidates),
        "candidates": str(artifact),
    }
