"""Tests for the end-to-end static-analysis pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from fsa.schemas.loader import validate
from scripts.run_pipeline import load_benchmark, render_report, run_pipeline


@pytest.fixture()
def benchmark() -> tuple[list[dict], dict]:
    return load_benchmark()


def test_load_benchmark(benchmark: tuple[list[dict], dict]) -> None:
    candidates, attack_surface = benchmark
    assert len(candidates) == 9
    assert len(attack_surface["surfaces"]) == 9


def test_run_pipeline_structure(benchmark: tuple[list[dict], dict], tmp_path: Path) -> None:
    candidates, attack_surface = benchmark
    result = run_pipeline(candidates, attack_surface, tmp_path / "run")
    assert result["total_candidates"] == 9
    assert result["top_k"] <= 5
    assert len(result["ranking"]) == 9
    assert "verdicts" in result
    # verdicts must satisfy the verdict schema.
    validate(result["verdicts"], schema_name="verdict")


def test_run_pipeline_accepts_confirmed(benchmark: tuple[list[dict], dict], tmp_path: Path) -> None:
    candidates, attack_surface = benchmark
    result = run_pipeline(candidates, attack_surface, tmp_path / "run")
    verdicts = result["verdicts"]["verdicts"]
    # The confirmed-issue CRITICAL candidates must be accepted, not rejected.
    accepted = [v for v in verdicts if v["action"] == "ACCEPT"]
    assert accepted, "expected at least one ACCEPT verdict"
    # No confirmed candidate should be REJECTed due to a source-type mismatch.
    assert all(v["action"] != "REJECT" for v in verdicts)


def test_render_report_nonempty(benchmark: tuple[list[dict], dict], tmp_path: Path) -> None:
    candidates, attack_surface = benchmark
    result = run_pipeline(candidates, attack_surface, tmp_path / "run")
    report = render_report(result)
    assert "风险评分排序" in report
    assert "Verifier 反证审查" in report
    assert "CVE-2017-17215" in report


def test_pipeline_ranking_order(benchmark: tuple[list[dict], dict], tmp_path: Path) -> None:
    candidates, attack_surface = benchmark
    result = run_pipeline(candidates, attack_surface, tmp_path / "run")
    scores = [item["risk_score"] for item in result["ranking"]]
    assert scores == sorted(scores, reverse=True)
