"""Tests for the end-to-end static-analysis pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from fsa.schemas.loader import validate
from scripts.run_pipeline import load_benchmark, main, render_report, run_pipeline


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
    assert "外部工具交叉验证" in report


def test_pipeline_ranking_order(benchmark: tuple[list[dict], dict], tmp_path: Path) -> None:
    candidates, attack_surface = benchmark
    result = run_pipeline(candidates, attack_surface, tmp_path / "run")
    scores = [item["risk_score"] for item in result["ranking"]]
    assert scores == sorted(scores, reverse=True)


def test_full_depth_degrades_and_writes_external_artifacts(
    benchmark: tuple[list[dict], dict], tmp_path: Path
) -> None:
    candidates, attack_surface = benchmark
    run_dir = tmp_path / "full"
    result = run_pipeline(
        candidates,
        attack_surface,
        run_dir,
        depth="full",
        blind=True,
    )
    assert result["status"] == "ok"
    assert result["external"]["status"] == "degraded"
    assert (run_dir / "artifacts" / "unified_candidates.json").exists()
    assert (run_dir / "artifacts" / "external_findings" / "fused.json").exists()


def test_legacy_entrypoint_requires_benchmark_acknowledgement(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["run_pipeline.py"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
