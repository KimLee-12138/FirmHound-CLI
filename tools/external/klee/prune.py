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

from typing import Any

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
        candidate["counterevidence"].append(
            f"klee:infeasible:{harness_version}:{finding_id}"
        )
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
        1 for r in symex_results
        if r.get("reachable") is False and r.get("reason") == "infeasible"
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


__all__ = [
    "AUDIT_PRUNE_RATE_THRESHOLD",
    "AUDIT_SAMPLE_SIZE",
    "prune_candidate",
    "prune_rate",
    "needs_manual_audit",
    "sample_for_audit",
]
