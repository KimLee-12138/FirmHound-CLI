"""Unit tests for the KLEE parser (F3 + F4 parser branches).

These run the real ``klee-out-N`` fixtures under ``tools/external/klee/fixtures/raw``
through :func:`parse_klee_output` with a hand-built ``harness_map``. They never
invoke KLEE (CI constraint, G-KLEE.md §7.2).

Covered branches (G-KLEE.md §7.2):
  * reachable (path feasible, witness emitted)
  * ptr.err (strong overflow evidence)
  * model.err / exec.err -> limitation, NOT a vuln (anti-false-positive)
  * empty directory -> no finding
  * malformed .err -> skipped + limitation
  * timeout -> reachable=null, reason=timeout
  * path_explosion -> reachable=null, reason=path_explosion
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tools.external.klee.parser import parse_klee_output

FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "external" / "klee" / "fixtures" / "raw"


def _harness_map() -> dict[str, dict]:
    """A harness_map covering every fixture dir (klee-out-0 .. klee-out-6)."""
    base = {
        "binary_id": "sbin/httpd",
        "vuln_class": "command_injection",
        "sink": {"function": "system", "addr": "0x40a100", "type": "command_execution"},
        "source": {"type": "http_param", "name": "cmd"},
        "entry_point": {"type": "http"},
        "call_trace": [],
        "constraints": [],
        "harness_version": "v1",
    }
    overrides = {
        1: {"sink": {"function": "strcpy", "addr": "0x40a200", "type": "memory_copy"}},
        2: {"sink": {"function": "system", "addr": "0x40a300", "type": "command_execution"}},
        6: {"sink": {"function": "strcpy", "addr": "0x40a600", "type": "memory_copy"}},
    }
    m: dict[str, dict] = {}
    for i in range(7):
        entry = dict(base)
        entry.update(overrides.get(i, {}))
        entry["binary_id"] = f"sbin/httpd@{i}"
        m[f"klee-out-{i}"] = entry
    return m


@pytest.fixture
def harness_map():
    return _harness_map()


def _find(findings, dir_name, harness_map):
    entry = harness_map[dir_name]
    slug = re.sub(r"[^A-Za-z0-9]+", "-", entry["binary_id"]).strip("-") or "unknown"
    sink_addr = (entry["sink"].get("addr") or "").lower()
    fid = f"klee-{slug}-{sink_addr}"
    for f in findings:
        if f["finding_id"] == fid:
            return f
    return None


def test_reachable_branch_emits_witness(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    f = _find(findings, "klee-out-0", harness_map)
    assert f is not None, "reachable branch must emit a finding"
    assert f["symex"]["reachable"] is True
    assert f["symex"]["reason"] == "ok"
    assert f["symex"]["witness_input"] is not None
    assert "reboot" in f["symex"]["witness_input"]["input"]
    assert f["vuln_class"] == "command_injection"


def test_ptr_err_is_overflow_evidence(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    f = _find(findings, "klee-out-1", harness_map)
    assert f is not None
    assert f["symex"]["reachable"] is True
    assert f["vuln_class"] == "overflow"  # ptr.err upgrades the class
    assert "ptr.err" in f["notes"]


def test_model_and_exec_err_are_limitation_not_vuln(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    f = _find(findings, "klee-out-2", harness_map)
    assert f is not None
    # MUST NOT be treated as a vulnerability.
    assert f["symex"]["reachable"] is None
    assert f["symex"]["reason"] == "unsupported_arch"
    assert "witness_input" not in f["symex"]
    assert "modelling limitation" in f.get("limitation", "")
    # vuln_class stays the candidate's original (not upgraded to overflow).
    assert f["vuln_class"] == "command_injection"


def test_empty_dir_produces_no_finding(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    f = _find(findings, "klee-out-3", harness_map)
    assert f is None


def test_malformed_err_is_skipped_with_limitation(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    f = _find(findings, "klee-out-4", harness_map)
    assert f is None  # malformed artifact -> skipped, not a spurious vuln
    assert any("malformed" in lim for lim in stats.limitations)


def test_timeout_does_not_change_score(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    f = _find(findings, "klee-out-5", harness_map)
    assert f is not None
    assert f["symex"]["reachable"] is None
    assert f["symex"]["reason"] == "timeout"
    assert "timeout" in f.get("limitation", "").lower()
    # confidence must be 0.0 -> score untouched (F7).
    assert f["confidence"] == 0.0


def test_path_explosion_does_not_change_score(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    f = _find(findings, "klee-out-6", harness_map)
    assert f is not None
    assert f["symex"]["reachable"] is None
    assert f["symex"]["reason"] == "path_explosion"
    assert "fork" in f.get("limitation", "").lower()
    assert f["confidence"] == 0.0


def test_parser_version_stamped(harness_map):
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map=harness_map, run_id="r1")
    assert findings, "at least the reachable/ptr/limitation branches emit findings"
    assert all("klee-parser-v1" in f["notes"] for f in findings)


def test_missing_harness_map_entry_is_skipped():
    findings, stats = parse_klee_output(FIXTURE_DIR, harness_map={}, run_id="r1")
    assert findings == []
    assert any("no harness_map" in lim or "no klee-out" in lim for lim in stats.limitations)
