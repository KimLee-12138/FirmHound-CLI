"""FirmRec recurrence isolation tests (F-FirmRec.md §4.4 -- the academic-integrity gate).

These are the *unique* deliverable of student F: FirmRec requires known-vulnerability
signatures, so it must never participate in a blind benchmark run. Three guarantees:

  1. A blind run force-disables FirmRec at the config level.
  2. The fused (unified) candidate set never contains a FirmRec finding.
  3. FirmRec findings are saved to a *separate* recurrence_findings.json file.

Plus an end-to-end adapter check that the FORCED_DISABLE reaches the orchestrator.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from tools.analysis.finding_fusion import fuse
from tools.external.adapter import _resolve_external_config, _run_tool

# --------------------------------------------------------------------------- #
# 1. blind run force-disables FirmRec at the config level
# --------------------------------------------------------------------------- #


def test_blind_run_force_disables_firmrec():
    cfg = {"firmrec": {"enabled": True}, "satc": {"enabled": True}}
    out = _resolve_external_config(cfg, {"blind": True})
    assert out["firmrec"]["enabled"] is False
    # Non-recurrence tools are untouched by the blind gate.
    assert out["satc"]["enabled"] is True


def test_non_blind_run_leaves_firmrec_enabled():
    cfg = {"firmrec": {"enabled": True}}
    out = _resolve_external_config(cfg, {"blind": False})
    assert out["firmrec"]["enabled"] is True


# --------------------------------------------------------------------------- #
# 2 + 3. fusion keeps FirmRec out of unified candidates, separate file instead
# --------------------------------------------------------------------------- #


def _stage_findings(run_dir: Path, name: str, findings: list[dict]) -> None:
    d = run_dir / "artifacts" / "external_findings"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(
        json.dumps({"status": "ok", "findings": findings}, ensure_ascii=False),
        encoding="utf-8",
    )


_SATC_FINDING = {
    "tool": "satc",
    "finding_id": "satc-1",
    "binary_id": "bin/httpd",
    "vuln_class": "command_injection",
    "sink": {"function": "system", "addr": "0x40a1b0"},
    "confidence": 0.9,
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


def test_unified_candidates_contain_no_firmrec_findings(tmp_path):
    _stage_findings(tmp_path, "satc.json", [_SATC_FINDING])
    _stage_findings(tmp_path, "firmrec.json", [_FIRMREC_FINDING])

    fuse(tmp_path)

    fused = json.loads(
        (tmp_path / "artifacts" / "external_findings" / "fused.json").read_text(encoding="utf-8")
    )
    assert all(f["tool"] != "firmrec" for f in fused["findings"])
    assert any(f["tool"] == "satc" for f in fused["findings"])


def test_recurrence_findings_saved_separately(tmp_path):
    _stage_findings(tmp_path, "satc.json", [_SATC_FINDING])
    _stage_findings(tmp_path, "firmrec.json", [_FIRMREC_FINDING])

    fuse(tmp_path)

    rec_path = tmp_path / "artifacts" / "external_findings" / "recurrence_findings.json"
    assert rec_path.exists()
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    assert len(rec["findings"]) == 1
    assert rec["findings"][0]["tool"] == "firmrec"
    # Recurrence findings are flagged blind_isolated (never counted in external_only).
    assert rec["findings"][0].get("blind_isolated") is True


# --------------------------------------------------------------------------- #
# end-to-end: the adapter returns FORCED_DISABLE on a blind run
# --------------------------------------------------------------------------- #


def test_adapter_forces_disable_on_blind_run(tmp_path):
    cfg = {"external": {"enabled": True, "firmrec": {"enabled": True}}}
    cp = tmp_path / "cfg.yaml"
    cp.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state" / "task_card.json").write_text(
        json.dumps({"blind": True}), encoding="utf-8"
    )

    result = _run_tool("firmrec", tmp_path, str(cp))
    assert result["status"] == "skipped"
    assert "FORCED_DISABLE" in result["limitation"]
