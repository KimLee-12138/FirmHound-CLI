"""KLEE pruning + false-positive guard (X2 -- G-KLEE.md §4.3).

KLEE's ``infeasible`` verdict only means "under *my harness model* this path
cannot be reached" -- not "the real firmware is safe". A simplified stub may have
dropped a real library call or global state that makes the path feasible in
production. So we apply three hard rules:

  1. An ``infeasible`` result is written as **counterevidence only**. We NEVER
     delete the candidate or flip its ``conclusion_category``; that decision is
     deferred to the Verifier (10 questions + 12 hard rules).
  2. The verdict MUST carry the ``harness_version`` so the report can state the
     modelling assumptions the conclusion rests on.
  3. A prune-rate > 70% triggers a manual 5-sample audit (``needs_manual_audit``).

Timeouts / path explosions are NOT prunes: they are appended to
``limitations`` and leave the candidate's score untouched (F7).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fsa.utils.jsonio import save_json
from tools.external.base import normalize_addr

# Single source of truth for the audit threshold (G-KLEE.md §8.2).
AUDIT_PRUNE_RATE_THRESHOLD = 0.70
AUDIT_SAMPLE_SIZE = 5


def prune_candidate(
    candidate: dict[str, Any],
    symex_result: dict[str, Any],
    *,
    finding_id: str = "",
    harness_version: str = "v1",
) -> dict[str, Any]:
    """Attach KLEE's verdict to a candidate without ever deleting it.

    Args:
        candidate: the unified candidate dict (mutated in place, returned).
        symex_result: ``{"reachable": bool|None, "reason": str, ...}``.
        finding_id: the KLEE finding id, for traceable counterevidence.
        harness_version: stamped on the verdict (modelling traceability).

    Returns the (same) candidate dict. Never raises.
    """
    reachable = symex_result.get("reachable")
    reason = str(symex_result.get("reason", "error"))

    candidate.setdefault("counterevidence", [])
    candidate.setdefault("limitations", [])

    if reachable is False and reason == "infeasible":
        # Counterevidence ONLY. Do not touch conclusion_category.
        candidate["counterevidence"].append(f"klee:infeasible:{harness_version}:{finding_id}")
    elif reason in ("timeout", "path_explosion"):
        # Feasibility undetermined -> record as a limitation, do not change score.
        candidate["limitations"].append(f"klee:{reason}")
    elif reason == "unsupported_arch":
        # model.err / exec.err: modelling limitation, not a verdict.
        candidate["limitations"].append("klee:unsupported_arch")
    # reachable == True (or None w/o timeout/explosion): candidate stands; the
    # KLEE finding in fused.json already carries the witness / evidence.

    return candidate


def prune_rate(symex_results: list[dict[str, Any]]) -> float:
    """Fraction of candidates KLEE judged ``infeasible``.

    ``symex_results`` is the list of ``symex`` dicts KLEE emitted. Returns 0.0
    when the list is empty (no pruning happened -> no audit needed).
    """
    if not symex_results:
        return 0.0
    infeasible = sum(
        1 for r in symex_results if r.get("reachable") is False and r.get("reason") == "infeasible"
    )
    return round(infeasible / len(symex_results), 3)


def needs_manual_audit(
    symex_results: list[dict[str, Any]],
    *,
    threshold: float = AUDIT_PRUNE_RATE_THRESHOLD,
) -> bool:
    """True when the prune-rate exceeds the threshold and a 5-sample audit is due."""
    return prune_rate(symex_results) > threshold


def sample_for_audit(
    findings: list[dict[str, Any]],
    *,
    size: int = AUDIT_SAMPLE_SIZE,
) -> list[str]:
    """Return up to ``size`` finding ids of infeasible candidates to manually audit.

    Deterministic: takes the first ``size`` infeasible finding ids in order. The
    caller (benchmarks/external/klee/comparison.md) records the audit outcome.
    """
    infeasible_ids = [
        f.get("finding_id", "")
        for f in findings
        if (f.get("symex") or {}).get("reachable") is False
        and (f.get("symex") or {}).get("reason") == "infeasible"
    ]
    return infeasible_ids[:size]


def _matches(candidate: dict[str, Any], finding: dict[str, Any]) -> bool:
    """Return whether a KLEE finding belongs to a unified candidate."""
    if candidate.get("binary_id") != finding.get("binary_id"):
        return False
    candidate_sink = candidate.get("sink") or {}
    finding_sink = finding.get("sink") or {}
    candidate_addr = normalize_addr(candidate_sink.get("addr"))
    finding_addr = normalize_addr(finding_sink.get("addr"))
    if candidate_addr and finding_addr:
        return candidate_addr == finding_addr
    return candidate_sink.get("function") == finding_sink.get("function")


def apply_findings(
    candidates: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    """Apply KLEE evidence without deleting or directly rejecting candidates."""
    applied = 0
    reachable = 0
    infeasible = 0
    for finding in findings:
        symex = finding.get("symex") or {}
        for candidate in candidates:
            if not _matches(candidate, finding):
                continue
            prune_candidate(
                candidate,
                symex,
                finding_id=str(finding.get("finding_id", "")),
                harness_version=str(symex.get("harness_version", "v1")),
            )
            candidate["symex"] = symex
            if symex.get("reachable") is True:
                reachable += 1
                witness = symex.get("witness_input")
                if witness is not None:
                    candidate["poc_candidate"] = witness
                evidence = candidate.setdefault("evidence", [])
                marker = f"klee:reachable:{finding.get('finding_id', '')}"
                if marker not in evidence:
                    evidence.append(marker)
            elif symex.get("reachable") is False and symex.get("reason") == "infeasible":
                infeasible += 1
            applied += 1
            break
    symex_results = [f.get("symex") or {} for f in findings]
    return {
        "applied": applied,
        "reachable": reachable,
        "infeasible": infeasible,
        "prune_rate": prune_rate(symex_results),
        "needs_manual_audit": needs_manual_audit(symex_results),
        "audit_sample": sample_for_audit(findings),
    }


def execute_prune(run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Registry entry for SYMEX_PRUNE: run KLEE and persist conservative updates."""
    from tools.external.adapter import run_klee

    run_dir = Path(run_dir)
    result = run_klee(run_dir, config_path)
    if result.get("status") != "ok":
        return {
            "status": result.get("status", "failed"),
            "tool": "klee",
            "metrics": {"applied": 0, "prune_rate": 0.0},
            "limitation": result.get("limitation", "KLEE did not produce findings"),
        }

    unified_path = run_dir / "artifacts" / "unified_candidates.json"
    if not unified_path.exists():
        return {
            "status": "failed",
            "tool": "klee",
            "metrics": {"applied": 0, "prune_rate": 0.0},
            "limitation": "unified_candidates.json missing; FUSION must run before SYMEX_PRUNE",
        }
    try:
        document = json.loads(unified_path.read_text(encoding="utf-8"))
        candidates = document.get("candidates", [])
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "failed",
            "tool": "klee",
            "metrics": {"applied": 0, "prune_rate": 0.0},
            "limitation": f"could not load unified candidates: {exc}",
        }

    metrics = apply_findings(candidates, result.get("findings", []))
    document["candidates"] = candidates
    document["symex"] = metrics
    save_json(unified_path, document)
    return {
        "status": "ok",
        "tool": "klee",
        "metrics": metrics,
        "artifact": str(unified_path),
        "limitation": "",
    }


__all__ = [
    "AUDIT_PRUNE_RATE_THRESHOLD",
    "AUDIT_SAMPLE_SIZE",
    "prune_candidate",
    "prune_rate",
    "needs_manual_audit",
    "sample_for_audit",
    "apply_findings",
    "execute_prune",
]
