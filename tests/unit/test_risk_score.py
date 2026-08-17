"""Unit and regression tests for the M6 risk scoring module."""

from __future__ import annotations

import json
from pathlib import Path

from tools.analysis.risk_score import _level, rank_candidates, score_candidate, select_top

BENCHMARK_DIR = Path(__file__).parent.parent.parent / "benchmarks" / "CVEs"


def _candidate(**overrides: object) -> dict:
    base = {
        "candidate_id": "cand-1",
        "binary_id": "httpd",
        "entry": {"function": "formexeCommand"},
        "source": {"type": "http_param", "name": "cmd"},
        "transform": [{"type": "concat", "detail": "user input passed to shell template"}],
        "validation": [],
        "authorization": {"required": False, "evidence": []},
        "sink": {"function": "system", "type": "command_execution"},
        "call_chain": ["formexeCommand", "system"],
        "user_control": "full",
        "vuln_class_hypothesis": "command_injection",
        "evidence": ["ev-source", "ev-sink"],
        "counterevidence": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def test_command_injection_scores_critical() -> None:
    report = score_candidate(_candidate())
    assert report["risk_level"] == "CRITICAL"
    assert report["risk_score"] >= 24


def test_preauth_dimension_zero_when_required() -> None:
    report = score_candidate(_candidate(authorization={"required": True}))
    dims = {d["key"]: d for d in report["dimensions"]}
    assert dims["P"]["score"] == 0


def test_validation_dimension_inverse_scoring() -> None:
    no_validation = score_candidate(_candidate(validation=[]))
    dims = {d["key"]: d for d in no_validation["dimensions"]}
    assert dims["V"]["score"] == 3  # no validation => highest risk

    strong = score_candidate(_candidate(validation=[{"api": "escapeshellarg", "kind": "escape"}]))
    dims = {d["key"]: d for d in strong["dimensions"]}
    assert dims["V"]["score"] == 0  # strong validation => no risk


def test_concat_dimension_distinguishes_format_vs_raw() -> None:
    fmt = score_candidate(_candidate(transform=[{"type": "concat", "detail": "%s; %s"}]))
    dims = {d["key"]: d for d in fmt["dimensions"]}
    assert dims["C"]["score"] == 2  # formatted with input

    raw = score_candidate(_candidate(transform=[{"type": "concat", "detail": "raw concatenation"}]))
    dims = {d["key"]: d for d in raw["dimensions"]}
    assert dims["C"]["score"] == 3  # raw concatenation


def test_buffer_overflow_scores_high() -> None:
    candidate = _candidate(
        sink={"function": "strcpy", "type": "memory_safety"},
        source={"type": "header", "name": "User-Agent"},
        vuln_class_hypothesis="overflow",
    )
    report = score_candidate(candidate)
    assert report["risk_level"] in ("HIGH", "CRITICAL")
    dims = {d["key"]: d for d in report["dimensions"]}
    assert dims["S"]["score"] == 0  # no shell context for a memcpy/strcpy sink


def test_every_dimension_has_evidence_or_zero() -> None:
    report = score_candidate(_candidate())
    for dim in report["dimensions"]:
        if dim["score"] > 0:
            assert dim["evidence"], f"dimension {dim['key']} scored >0 without evidence"
        else:
            assert dim["score"] == 0


def test_level_thresholds() -> None:
    assert _level(24) == "CRITICAL"
    assert _level(30) == "CRITICAL"
    assert _level(23) == "HIGH"
    assert _level(18) == "HIGH"
    assert _level(17) == "MEDIUM"
    assert _level(12) == "MEDIUM"
    assert _level(11) == "LOW"
    assert _level(0) == "LOW"


# ---------------------------------------------------------------------------
# ranking / selection
# ---------------------------------------------------------------------------


def test_rank_candidates_sorted_descending() -> None:
    high = _candidate(candidate_id="high", authorization={"required": False})
    low = _candidate(candidate_id="low", authorization={"required": True})
    ranked = rank_candidates([low, high])
    assert ranked[0]["candidate_id"] == "high"
    assert ranked[1]["candidate_id"] == "low"
    assert ranked[0]["risk_score"] >= ranked[1]["risk_score"]


def test_select_top_returns_all_when_small() -> None:
    candidates = [_candidate(candidate_id=f"c{i}") for i in range(4)]
    assert len(select_top(candidates, limit=5)) == 4


def test_select_top_preserves_class_diversity() -> None:
    cmd = _candidate(candidate_id="cmd", vuln_class_hypothesis="command_injection")
    overflow = _candidate(candidate_id="of", vuln_class_hypothesis="overflow")
    path = _candidate(candidate_id="pt", vuln_class_hypothesis="path_traversal")
    overflow2 = _candidate(candidate_id="of2", vuln_class_hypothesis="overflow")
    selected = select_top([cmd, overflow, path, overflow2], limit=3, keep_diversity=True)
    classes = {c["vuln_class_hypothesis"] for c in selected}
    assert len(classes) == 3
    assert len(selected) == 3


# ---------------------------------------------------------------------------
# regression against benchmark fixtures
# ---------------------------------------------------------------------------


def _load(cve_id: str) -> dict:
    with (BENCHMARK_DIR / cve_id / "candidate.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def test_regression_hg532e_upnp_is_critical() -> None:
    """CVE-2017-17215 (HG532e UPnP) must score CRITICAL."""
    report = score_candidate(_load("CVE-2017-17215"))
    assert report["risk_level"] == "CRITICAL"
    assert report["risk_score"] >= 24


def test_regression_auth_required_cves_are_not_critical() -> None:
    """CVE-2018-5767 / CVE-2020-9373 require auth and must not be CRITICAL."""
    for cve in ("CVE-2018-5767", "CVE-2020-9373"):
        report = score_candidate(_load(cve))
        assert report["risk_level"] != "CRITICAL", cve


def test_regression_upnp_ranks_above_web_and_cms() -> None:
    """HG532e ordering: P0 = upnp > web > cms."""
    upnp = _load("CVE-2017-17215")
    web = _candidate(candidate_id="web", source={"type": "http_param", "name": "cmd"})
    cms = _candidate(
        candidate_id="cms",
        source={"type": "config_import", "name": "nvram_get"},
        authorization={"required": True},
        user_control="partial",
    )
    ranked = rank_candidates([cms, web, upnp])
    order = [c["candidate_id"] for c in ranked]
    assert order.index("cand-CVE-2017-17215") < order.index("web")
    assert order.index("web") < order.index("cms")
