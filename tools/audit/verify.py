"""Falsification-first Top-K verification wrapper."""

from __future__ import annotations

from typing import Any

from fsa.orchestrator.verifier import CandidateVerifier
from fsa.utils.jsonio import save_json
from tools.analysis.risk_score import select_top
from tools.pipeline_context import load_artifact, run_path, save_artifact


def execute_verify(run_dir: str, top_k: int = 5) -> dict[str, Any]:
    """Review the highest-ranked candidates using the ten counterchecks."""
    ranking = load_artifact(run_dir, "ranking.json")
    if not isinstance(ranking, dict):
        return {"status": "failed", "reason": "ranking artifact is missing"}
    surface = load_artifact(run_dir, "attack_surface.json", {"surfaces": []})
    selected = select_top(ranking.get("candidates", []), limit=top_k)
    verdict = CandidateVerifier(run_path(run_dir)).review(selected, surface)
    artifact = save_artifact(run_dir, "verdict.json", verdict)
    save_json(run_path(run_dir) / "verdict.json", verdict)
    return {
        "status": "ok",
        "verified_count": len(verdict["verdicts"]),
        "verdict": str(artifact),
    }
