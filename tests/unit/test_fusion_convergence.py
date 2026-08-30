"""Convergence-layer tests (teacher's §3.2 cross-validation matrix).

Covers the semantics that were missing from the original fusion module:

  1. A main candidate corroborated by an external tool gets its
     ``conclusion_category`` bumped to ``high-confidence-candidate`` and an
     ``external corroboration`` evidence entry (matrix row 1).
  2. An external-only finding is materialised as a **new** candidate tagged
     ``external_only: true`` (matrix row 3 -- the benchmark's key metric).
  3. FirmRec findings stay out of ``unified_candidates.json`` entirely.
  4. ``fuse()`` is idempotent (re-running produces the same unified set).
  5. The adapter feeds ``unified_candidates.json`` to KLEE / BOND via
     ``AnalysisContext.candidates`` (preferring it over raw ``candidates.json``).
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.analysis.finding_fusion import fuse
from tools.external.adapter import _load_candidates


def _stage_findings(run_dir: Path, name: str, findings: list[dict]) -> None:
    d = run_dir / "artifacts" / "external_findings"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(
        json.dumps({"status": "ok", "findings": findings}, ensure_ascii=False),
        encoding="utf-8",
    )


def _stage_main_candidates(run_dir: Path, candidates: list[dict]) -> None:
    (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "candidates.json").write_text(
        json.dumps({"candidates": candidates}, ensure_ascii=False),
        encoding="utf-8",
    )


_MAIN_CAND = {
    "candidate_id": "cand-001",
    "surface_id": "surf-001",
    "binary_id": "bin/httpd",
    "entry": {"function": "formexeCommand", "addr": "0x00405000"},
    "source": {"type": "http_param", "name": "cmd"},
    "transform": [{"type": "concat", "detail": "%s; %s"}],
    "validation": [],
    "authorization": {"required": False, "evidence": []},
    "sink": {"function": "system", "type": "command_execution", "addr": "0x40a1b0"},
    "call_chain": ["formexeCommand", "system"],
    "user_control": "full",
    "vuln_class_hypothesis": "command_injection",
    "risk_score": 28,
    "risk_level": "CRITICAL",
    "evidence": ["ev-001"],
    "counterevidence": [],
    "conclusion_category": "observation",
    "decisive_missing_fact": None,
    "status": "analyzing",
}

_CORROBORATING_FINDING = {
    "tool": "satc",
    "finding_id": "satc-1",
    "binary_id": "bin/httpd",
    "vuln_class": "command_injection",
    "sink": {"function": "system", "addr": "0x40a1b0"},
    "confidence": 0.9,
    "status": "ok",
}

_EXTERNAL_ONLY_FINDING = {
    "tool": "satc",
    "finding_id": "satc-2",
    "binary_id": "bin/upnpd",
    "vuln_class": "overflow",
    "source": {"type": "http_param", "name": "ssdp_pkt"},
    "entry_point": {"type": "upnp", "path": "/rootDesc.xml"},
    "call_trace": [{"func": "upnp_recv"}, {"func": "strcpy"}],
    "sink": {"function": "strcpy", "addr": "0x40c1a0", "type": "memory_copy"},
    "confidence": 0.75,
    "status": "ok",
}

_FIRMREC_FINDING = {
    "tool": "firmrec",
    "finding_id": "firmrec-1",
    "binary_id": "bin/httpd",
    "vuln_class": "command_injection",
    "sink": {"function": "system", "addr": "0x40a1b0"},
    "matched_cve": "CVE-2017-17215",
    "confidence": 0.92,
    "status": "ok",
}


def _read_unified(run_dir: Path) -> list[dict]:
    path = run_dir / "artifacts" / "unified_candidates.json"
    assert path.exists(), "unified_candidates.json was not produced"
    return json.loads(path.read_text(encoding="utf-8"))["candidates"]


def test_corroborated_main_candidate_is_bumped(tmp_path):
    _stage_main_candidates(tmp_path, [_MAIN_CAND])
    _stage_findings(tmp_path, "satc.json", [_CORROBORATING_FINDING])

    fuse(tmp_path)

    unified = _read_unified(tmp_path)
    main = [c for c in unified if c["candidate_id"] == "cand-001"]
    assert len(main) == 1
    assert main[0]["conclusion_category"] == "high-confidence-candidate"
    assert main[0]["cross_validation"] == "both"
    assert main[0]["corroborated_by"] == ["satc-1"]
    assert any("external corroboration:satc" in e for e in main[0]["evidence"])
    # Only one candidate: the external finding corroborated, it did not duplicate.
    assert len(unified) == 1


def test_external_only_finding_becomes_new_candidate(tmp_path):
    _stage_main_candidates(tmp_path, [_MAIN_CAND])
    _stage_findings(tmp_path, "satc.json", [_EXTERNAL_ONLY_FINDING])

    fuse(tmp_path)

    unified = _read_unified(tmp_path)
    new = [c for c in unified if c.get("external_only")]
    assert len(new) == 1
    cand = new[0]
    assert cand["candidate_id"] == "ext-satc-2"
    assert cand["binary_id"] == "bin/upnpd"
    assert cand["vuln_class_hypothesis"] == "overflow"
    assert cand["sink"]["addr"] == "0x40c1a0"
    assert cand["cross_validation"] == "external_only"
    assert cand["status"] == "new"
    # The original main candidate is still there, untouched (no bump).
    main = [c for c in unified if c["candidate_id"] == "cand-001"][0]
    assert main["conclusion_category"] == "observation"
    assert "cross_validation" not in main


def test_firmrec_never_enters_unified_candidates(tmp_path):
    _stage_main_candidates(tmp_path, [_MAIN_CAND])
    _stage_findings(tmp_path, "satc.json", [_CORROBORATING_FINDING])
    _stage_findings(tmp_path, "firmrec.json", [_FIRMREC_FINDING])

    fuse(tmp_path)

    unified = _read_unified(tmp_path)
    assert all(c.get("tool") != "firmrec" for c in unified)
    rec = json.loads(
        (tmp_path / "artifacts" / "external_findings" / "recurrence_findings.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(rec["findings"]) == 1
    assert rec["findings"][0]["tool"] == "firmrec"
    assert rec["findings"][0]["blind_isolated"] is True


def test_fuse_is_idempotent(tmp_path):
    _stage_main_candidates(tmp_path, [_MAIN_CAND])
    _stage_findings(tmp_path, "satc.json", [_CORROBORATING_FINDING, _EXTERNAL_ONLY_FINDING])

    fuse(tmp_path)
    first = _read_unified(tmp_path)
    fuse(tmp_path)
    second = _read_unified(tmp_path)

    ids_first = {c["candidate_id"] for c in first}
    ids_second = {c["candidate_id"] for c in second}
    assert ids_first == ids_second
    assert len(second) == len(first)  # no duplicate external-only candidates


def test_adapter_prefers_unified_candidates(tmp_path):
    _stage_main_candidates(tmp_path, [_MAIN_CAND])
    _stage_findings(tmp_path, "satc.json", [_EXTERNAL_ONLY_FINDING])
    fuse(tmp_path)

    loaded = _load_candidates(tmp_path)
    ids = {c["candidate_id"] for c in loaded}
    assert "ext-satc-2" in ids  # external-only candidate flowed to KLEE/BOND
    assert "cand-001" in ids


def test_adapter_falls_back_to_raw_candidates(tmp_path):
    _stage_main_candidates(tmp_path, [_MAIN_CAND])
    loaded = _load_candidates(tmp_path)
    assert [c["candidate_id"] for c in loaded] == ["cand-001"]
