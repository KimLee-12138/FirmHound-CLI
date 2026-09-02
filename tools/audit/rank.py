"""Risk-ranking stage wrapper."""

from __future__ import annotations

from typing import Any

from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from tools.analysis.risk_score import rank_candidates
from tools.pipeline_context import load_artifact, run_path, save_artifact


def execute_rank(run_dir: str) -> dict[str, Any]:
    """Apply the ten-dimension score to every real static candidate."""
    payload = load_artifact(run_dir, "unified_candidates.json")
    if not isinstance(payload, dict):
        payload = load_artifact(run_dir, "candidates.json")
    if not isinstance(payload, dict):
        return {"status": "failed", "reason": "candidate artifact is missing"}
    ranked = rank_candidates(payload.get("candidates", []))
    for candidate in ranked:
        validate(candidate, schema_name="candidate")
    result = {"run_id": run_path(run_dir).name, "candidates": ranked}
    artifact = save_artifact(run_dir, "ranking.json", result)
    save_json(run_path(run_dir) / "ranking.json", result)
    return {"status": "ok", "ranked_count": len(ranked), "ranking": str(artifact)}
