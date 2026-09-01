"""Contract-level smoke test for the planned FUSION stage artifact."""

from __future__ import annotations

import json

from tools.analysis.finding_fusion import fuse


def test_fusion_without_external_tools_is_a_noop(tmp_path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True)
    candidate = {"candidate_id": "main-1", "binary_id": "bin/httpd"}
    (artifacts / "candidates.json").write_text(
        json.dumps({"candidates": [candidate]}), encoding="utf-8"
    )
    result = fuse(tmp_path)
    assert result["status"] == "ok"
    unified = json.loads((artifacts / "unified_candidates.json").read_text(encoding="utf-8"))
    assert unified["candidates"] == [candidate]
    assert unified["summary"]["external_only_new"] == 0
