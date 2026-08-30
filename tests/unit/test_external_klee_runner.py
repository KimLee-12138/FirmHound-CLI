"""Integration tests for the KLEE runner (prepare) and the prune guard (X2).

Covers:
  * ``KleeAnalyzer.prepare`` writes ``harness_map.json`` (one entry per candidate).
  * ``probe()`` never raises and degrades cleanly when KLEE is absent.
  * X2 prune rules: infeasible -> counterevidence only (never deletes); timeout /
    path_explosion -> limitation (score untouched); prune-rate > 70% audit.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.external.base import AnalysisContext
from tools.external.klee.prune import (
    needs_manual_audit,
    prune_candidate,
    prune_rate,
    sample_for_audit,
)
from tools.external.klee.runner import KleeAnalyzer


# --------------------------------------------------------------------------- #
# runner.prepare
# --------------------------------------------------------------------------- #


def _ctx(workdir: Path, candidates):
    return AnalysisContext(
        run_id="t-run",
        rootfs_dir=workdir,
        workdir=workdir,
        candidates=candidates,
        config={},
    )


def test_prepare_writes_harness_map(tmp_path):
    candidates = [
        {"binary_id": "sbin/httpd", "vuln_class": "command_injection",
         "sink": {"function": "system", "addr": "0x40a100", "type": "command_execution"}},
        {"binary_id": "sbin/upnpd", "vuln_class": "overflow",
         "sink": {"function": "strcpy", "addr": "0x40b200", "type": "memory_copy"}, "buf_size": 32},
    ]
    analyzer = KleeAnalyzer({"harness": "auto"})
    ctx = _ctx(tmp_path / "w", candidates)
    analyzer.prepare(ctx)
    hmap = json.loads((ctx.workdir / "harness_map.json").read_text(encoding="utf-8"))
    assert set(hmap.keys()) == {"klee-out-0", "klee-out-1"}
    assert hmap["klee-out-0"]["binary_id"] == "sbin/httpd"
    assert hmap["klee-out-0"]["strategy"] == "harness"
    assert hmap["klee-out-1"]["sink"]["function"] == "strcpy"


def test_prepare_with_source_path_selects_s1(tmp_path):
    candidates = [{"binary_id": "sbin/httpd", "vuln_class": "command_injection",
                   "source_path": "/src/httpd.c",
                   "sink": {"function": "system", "type": "command_execution"}}]
    analyzer = KleeAnalyzer({"harness": "auto"})
    ctx = _ctx(tmp_path / "w", candidates)
    analyzer.prepare(ctx)
    hmap = json.loads((ctx.workdir / "harness_map.json").read_text(encoding="utf-8"))
    assert hmap["klee-out-0"]["strategy"] == "source"


def test_probe_does_not_raise():
    analyzer = KleeAnalyzer({})
    probe = analyzer.probe()
    assert isinstance(probe.available, bool)
    assert probe.backend in {"wsl", "local", "docker"}


# --------------------------------------------------------------------------- #
# X2 prune guard
# --------------------------------------------------------------------------- #


def test_infeasible_writes_counterevidence_only():
    cand = {"finding_id": "c1", "conclusion_category": "suspect"}
    out = prune_candidate(
        cand, {"reachable": False, "reason": "infeasible"}, finding_id="klee-x-0", harness_version="v1"
    )
    assert "klee:infeasible:v1:klee-x-0" in out["counterevidence"]
    # The candidate is NEVER deleted or flipped.
    assert out["conclusion_category"] == "suspect"
    assert "limitations" not in out or not out.get("limitations")


def test_timeout_appends_limitation_only():
    cand = {"finding_id": "c2"}
    out = prune_candidate(cand, {"reachable": None, "reason": "timeout"})
    assert any("klee:timeout" in lim for lim in out.get("limitations", []))
    assert "klee:infeasible" not in out.get("counterevidence", [])


def test_path_explosion_appends_limitation_only():
    cand = {"finding_id": "c3"}
    out = prune_candidate(cand, {"reachable": None, "reason": "path_explosion"})
    assert any("klee:path_explosion" in lim for lim in out.get("limitations", []))
    assert "klee:infeasible" not in out.get("counterevidence", [])


def test_prune_rate_and_audit_trigger():
    results = [{"reachable": False, "reason": "infeasible"} for _ in range(8)]
    results += [{"reachable": True, "reason": "ok"} for _ in range(2)]  # 10 total, 80% infeasible
    assert prune_rate(results) == 0.8
    assert needs_manual_audit(results) is True
    results_low = [{"reachable": False, "reason": "infeasible"} for _ in range(3)]
    results_low += [{"reachable": True, "reason": "ok"} for _ in range(7)]
    assert needs_manual_audit(results_low) is False


def test_sample_for_audit_returns_infeasible_ids():
    findings = [
        {"finding_id": f"klee-t-{i}", "symex": {"reachable": False, "reason": "infeasible"}}
        for i in range(6)
    ]
    sample = sample_for_audit(findings, size=5)
    assert len(sample) == 5
    assert all(s.startswith("klee-t-") for s in sample)
