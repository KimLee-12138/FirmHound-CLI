"""Candidate mutation tests for KLEE pruning and BOND validation."""

from __future__ import annotations

from tools.external.bond.validate import apply_findings as apply_bond
from tools.external.klee.prune import apply_findings as apply_klee


def _candidate() -> dict:
    return {
        "candidate_id": "cand-1",
        "binary_id": "sbin/httpd",
        "sink": {"function": "system", "addr": "0x40a1b0"},
        "evidence": [],
        "counterevidence": [],
        "conclusion_category": "observation",
        "status": "analyzing",
    }


def test_klee_infeasible_is_counterevidence_only() -> None:
    candidate = _candidate()
    finding = {
        "finding_id": "klee-1",
        "binary_id": "sbin/httpd",
        "sink": {"function": "system", "addr": "0x40a1b0"},
        "symex": {
            "reachable": False,
            "reason": "infeasible",
            "harness_version": "v1",
        },
    }
    metrics = apply_klee([candidate], [finding])
    assert metrics["infeasible"] == 1
    assert candidate["conclusion_category"] == "observation"
    assert candidate["status"] == "analyzing"
    assert candidate["counterevidence"] == ["klee:infeasible:v1:klee-1"]


def test_klee_reachable_stores_witness() -> None:
    candidate = _candidate()
    finding = {
        "finding_id": "klee-2",
        "binary_id": "sbin/httpd",
        "sink": {"function": "system", "addr": "0x40a1b0"},
        "symex": {
            "reachable": True,
            "reason": "ok",
            "harness_version": "v1",
            "witness_input": {"cmd": "<BENIGN_MARKER>"},
        },
    }
    metrics = apply_klee([candidate], [finding])
    assert metrics["reachable"] == 1
    assert candidate["poc_candidate"] == {"cmd": "<BENIGN_MARKER>"}


def test_bond_requires_sanitized_trigger_to_confirm() -> None:
    candidate = _candidate()
    unsafe = {
        "finding_id": "bond-unsafe",
        "binary_id": "sbin/httpd",
        "sink": {"function": "system", "addr": "0x40a1b0"},
        "validation": {"triggered": True, "probe": "marker", "poc_sanitized": False},
    }
    safe = {
        "finding_id": "bond-safe",
        "binary_id": "sbin/httpd",
        "sink": {"function": "system", "addr": "0x40a1b0"},
        "validation": {"triggered": True, "probe": "marker", "poc_sanitized": True},
    }
    first = apply_bond([candidate], [unsafe])
    assert first["rejected_unsafe"] == 1
    assert candidate["status"] == "analyzing"
    second = apply_bond([candidate], [safe])
    assert second["confirmed"] == 1
    assert candidate["status"] == "confirmed"
    assert candidate["conclusion_category"] == "confirmed-issue"


def test_bond_no_trigger_is_inconclusive() -> None:
    candidate = _candidate()
    finding = {
        "finding_id": "bond-none",
        "binary_id": "sbin/httpd",
        "sink": {"function": "system", "addr": "0x40a1b0"},
        "validation": {"triggered": False, "probe": "none", "poc_sanitized": True},
    }
    metrics = apply_bond([candidate], [finding])
    assert metrics["inconclusive"] == 1
    assert candidate["status"] == "analyzing"
    assert "needs manual review" in candidate["decisive_missing_fact"]
