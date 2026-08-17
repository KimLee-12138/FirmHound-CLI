"""Tests for the candidate verifier."""

from __future__ import annotations

from pathlib import Path

import pytest

from fsa.orchestrator.verifier import CandidateVerifier, Verdict


@pytest.fixture
def verifier(tmp_path: Path) -> CandidateVerifier:
    return CandidateVerifier(tmp_path, reviewer="rule")


def _make_candidate(**overrides: object) -> dict:
    defaults = {
        "candidate_id": "cand-001",
        "surface_id": "surf-001",
        "binary_id": "bin-001",
        "entry": {"function": "formexeCommand"},
        "source": {"type": "http_param", "name": "cmd"},
        "transform": [],
        "validation": [],
        "authorization": {"required": False, "evidence": []},
        "sink": {"function": "system", "type": "command_execution"},
        "call_chain": ["formexeCommand", "system"],
        "user_control": "full",
        "vuln_class_hypothesis": "command_injection",
        "risk_score": 28,
        "risk_level": "CRITICAL",
        "evidence": ["ev-001"],
        "counterevidence": [],
        "conclusion_category": "confirmed-issue",
        "decisive_missing_fact": None,
        "status": "confirmed",
    }
    defaults.update(overrides)  # type: ignore[typeddict-item]
    return defaults


def test_verifier_accepts_confirmed_command_injection(verifier: CandidateVerifier) -> None:
    candidate = _make_candidate()
    attack_surface = {
        "surfaces": [
            {
                "surface_id": "surf-001",
                "handler": "formexeCommand",
                "startup_evidence": ["etc/init.d/rcS:12"],
                "confidence": 0.9,
            }
        ]
    }
    result = verifier.review([candidate], attack_surface)
    assert result["run_id"] == verifier.run_id
    assert len(result["verdicts"]) == 1
    verdict = result["verdicts"][0]
    assert verdict["candidate_id"] == "cand-001"
    assert verdict["action"] == "ACCEPT"
    assert verdict["reviewer"] == "rule"


def test_verifier_rejects_missing_source(verifier: CandidateVerifier) -> None:
    candidate = _make_candidate(source={"type": "constant", "name": "debug_flag"})
    result = verifier.review([candidate])
    verdict = result["verdicts"][0]
    assert verdict["action"] == "REJECT"
    assert verdict["revised_score"] < 28


def test_verifier_downgrades_auth_required(verifier: CandidateVerifier) -> None:
    candidate = _make_candidate(authorization={"required": True, "evidence": ["ev-auth"]})
    result = verifier.review([candidate])
    verdict = result["verdicts"][0]
    assert verdict["action"] == "DOWNGRADE"
    assert any("authentication" in r.lower() for r in verdict["reasons"])


def test_verifier_downgrades_filter_present(verifier: CandidateVerifier) -> None:
    candidate = _make_candidate(transform=[{"type": "whitelist", "detail": "alnum only"}])
    result = verifier.review([candidate])
    verdict = result["verdicts"][0]
    assert verdict["action"] == "DOWNGRADE"


def test_verdict_to_dict() -> None:
    verdict = Verdict(
        candidate_id="cand-x",
        action="ACCEPT",
        original_score=20,
        revised_score=20,
        reasons=["ok"],
    )
    data = verdict.to_dict()
    assert data["action"] == "ACCEPT"
    assert data["candidate_id"] == "cand-x"


def test_verifier_loads_candidates_from_file(verifier: CandidateVerifier, tmp_path: Path) -> None:
    path = tmp_path / "candidates.json"
    path.write_text('[{"candidate_id": "cand-002", "risk_score": 15}]')
    loaded = verifier.load_candidates(path)
    assert loaded[0]["candidate_id"] == "cand-002"


def test_verifier_validates_output_schema(verifier: CandidateVerifier) -> None:
    candidate = _make_candidate()
    result = verifier.review([candidate])
    assert "verdicts" in result
    assert all(
        v["action"] in {"ACCEPT", "DOWNGRADE", "REJECT", "NEED_DYNAMIC"} for v in result["verdicts"]
    )
