"""Evidence-backed static vulnerability candidate generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fsa.reporting.evidence_store import EvidenceStore
from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from tools.analysis.source_sink_rules import match_binary
from tools.pipeline_context import load_artifact, run_path, save_artifact


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
    binary_name = Path(summary["path"]).name
    return next(
        (
            surface
            for surface in surfaces
            if Path(str(surface.get("binary") or "")).name == binary_name
            or surface.get("handler") == binary_name
        ),
        {},
    )


def execute_static(run_dir: str) -> dict[str, Any]:
    """Create candidates only when a real binary contains source and sink signals."""
    binary_payload = load_artifact(run_dir, "binary_summaries.json")
    if not isinstance(binary_payload, dict):
        return {"status": "failed", "reason": "binary summaries are missing"}
    surface_payload = load_artifact(run_dir, "attack_surface.json", {"surfaces": []})
    surfaces = surface_payload.get("surfaces", []) if isinstance(surface_payload, dict) else []
    run = run_path(run_dir)
    evidence_store = EvidenceStore(run)
    candidates: list[dict[str, Any]] = []

    for summary in binary_payload.get("summaries", []):
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
            candidates.append(candidate)

    result = {"run_id": run.name, "candidates": candidates}
    artifact = save_artifact(run, "candidates.json", result)
    save_json(run / "candidates.json", result)
    return {
        "status": "ok",
        "candidate_count": len(candidates),
        "candidates": str(artifact),
    }
