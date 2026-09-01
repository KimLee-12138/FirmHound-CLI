"""Apply sanitized BOND validation evidence to unified candidates.

Only a sanitized marker/crash trigger may confirm a candidate.  A fuzzing run
that does not trigger is inconclusive and therefore records a limitation rather
than rejecting the candidate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fsa.utils.jsonio import save_json
from tools.external.base import normalize_addr


def _matches(candidate: dict[str, Any], finding: dict[str, Any]) -> bool:
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
) -> dict[str, int]:
    """Apply BOND findings conservatively and return mutation counters."""
    applied = 0
    confirmed = 0
    inconclusive = 0
    rejected_unsafe = 0
    for finding in findings:
        validation = finding.get("validation") or {}
        sanitized = validation.get("poc_sanitized") is True
        triggered = validation.get("triggered") is True
        if triggered and not sanitized:
            rejected_unsafe += 1
            continue
        for candidate in candidates:
            if not _matches(candidate, finding):
                continue
            candidate["constrained_validation"] = validation
            if triggered:
                candidate["conclusion_category"] = "confirmed-issue"
                candidate["status"] = "confirmed"
                evidence = candidate.setdefault("evidence", [])
                marker = f"bond:triggered:sanitized:{finding.get('finding_id', '')}"
                if marker not in evidence:
                    evidence.append(marker)
                confirmed += 1
            else:
                candidate[
                    "decisive_missing_fact"
                ] = "constrained fuzzing did not trigger; needs manual review"
                limitations = candidate.setdefault("limitations", [])
                marker = f"bond:{validation.get('probe', 'none')}:inconclusive"
                if marker not in limitations:
                    limitations.append(marker)
                inconclusive += 1
            applied += 1
            break
    return {
        "applied": applied,
        "confirmed": confirmed,
        "inconclusive": inconclusive,
        "rejected_unsafe": rejected_unsafe,
    }


def execute_validation(run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Registry entry for CONSTRAINED_VALIDATION."""
    from tools.external.adapter import run_bond

    run_dir = Path(run_dir)
    result = run_bond(run_dir, config_path)
    if result.get("status") != "ok":
        return {
            "status": result.get("status", "failed"),
            "tool": "bond",
            "metrics": {"applied": 0, "confirmed": 0},
            "limitation": result.get("limitation", "BOND did not produce findings"),
        }

    unified_path = run_dir / "artifacts" / "unified_candidates.json"
    if not unified_path.exists():
        return {
            "status": "failed",
            "tool": "bond",
            "metrics": {"applied": 0, "confirmed": 0},
            "limitation": "unified_candidates.json missing; FUSION must run first",
        }
    try:
        document = json.loads(unified_path.read_text(encoding="utf-8"))
        candidates = document.get("candidates", [])
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "failed",
            "tool": "bond",
            "metrics": {"applied": 0, "confirmed": 0},
            "limitation": f"could not load unified candidates: {exc}",
        }

    metrics = apply_findings(candidates, result.get("findings", []))
    document["candidates"] = candidates
    document["constrained_validation"] = metrics
    save_json(unified_path, document)
    return {
        "status": "ok",
        "tool": "bond",
        "metrics": metrics,
        "artifact": str(unified_path),
        "limitation": "",
    }


__all__ = ["apply_findings", "execute_validation"]
