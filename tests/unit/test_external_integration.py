"""Integration tests: registry resolution + F7 eight-switch degradation.

These verify the external track degrades gracefully under every switch
combination instead of aborting the pipeline (E-SaTC.md F7 / F5).
Docker is NOT required: with no SaTC image present, every tool resolves to
``skipped``, which is exactly the degradation we must guarantee.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from fsa.runtime.tool_registry import ToolRegistry
from tools.external.adapter import _tool_cfg
from tools.external.run_all import run_all

_EXPECTED_REGISTRY = [
    "tools.external.satc",
    "tools.external.firmrec",
    "tools.external.klee",
    "tools.external.bond",
    "tools.external.run_all",
    "tools.analysis.finding_fusion",
]


def test_registry_resolves_all_external_tools():
    reg = ToolRegistry()
    for name in _EXPECTED_REGISTRY:
        assert name in reg.list_tools(), f"{name} missing from registry"


def test_global_switch_cannot_be_bypassed_by_tool_switch():
    cfg = _tool_cfg({"enabled": False, "satc": {"enabled": True}}, "satc")
    assert cfg["enabled"] is False


def test_registry_resolves_convergence_tools():
    reg = ToolRegistry()
    assert "tools.external.klee.prune" in reg.list_tools()
    assert "tools.external.bond.validate" in reg.list_tools()


def _write_config(enabled_tools: set[str], *, external_enabled: bool = True, **satc_opts) -> str:
    satc = {"enabled": "satc" in enabled_tools, **satc_opts}
    cfg = {
        "external": {
            "enabled": external_enabled,
            "workdir": "./tmp/external",
            "timeout_s": 60,
            "satc": satc,
            "firmrec": {"enabled": "firmrec" in enabled_tools},
            "klee": {"enabled": "klee" in enabled_tools},
            "bond": {"enabled": "bond" in enabled_tools},
        }
    }
    p = Path(tempfile.mkdtemp()) / "ext_config.yaml"
    import yaml

    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(p)


# The eight switch combinations from F7.
COMBOS = [
    {"name": "all-off", "tools": set()},
    {"name": "satc-taint-off", "tools": {"satc"}, "taint_check": False},
    {"name": "satc-taint-on", "tools": {"satc"}, "taint_check": True},
    {"name": "satc-no-share2sink", "tools": {"satc"}, "enable_share2sink": False},
    {"name": "satc-firmrec", "tools": {"satc", "firmrec"}},
    {"name": "satc-klee", "tools": {"satc", "klee"}},
    {"name": "satc-bond", "tools": {"satc", "bond"}},
    {"name": "all-four", "tools": {"satc", "firmrec", "klee", "bond"}},
]


@pytest.mark.parametrize("combo", COMBOS, ids=[c["name"] for c in COMBOS])
def test_eight_switch_combos_degrade_without_abort(combo):
    cfg_path = _write_config(
        combo["tools"],
        **{k: v for k, v in combo.items() if k in ("taint_check", "enable_share2sink")},
    )
    run_dir = Path(tempfile.mkdtemp())
    # Must not raise, and must return a benign status dict.
    result = run_all(run_dir, config_path=cfg_path)
    assert isinstance(result, dict)
    assert result["status"] in {"ok", "skipped"}
    # Every per-tool entry is itself a dict (no exception leaked out).
    for tool, sub in result.get("per_tool", {}).items():
        assert isinstance(sub, dict), f"{tool} returned a non-dict: {sub!r}"


def test_run_external_via_registry_does_not_abort():
    """The orchestrator calls tools.external.satc through the registry; it must
    return a success ToolResult (wrapping a skipped analyzer), never error out."""
    reg = ToolRegistry()
    res = reg.call("tools.external.satc", {"run_dir": tempfile.mkdtemp()})
    assert res.status == "success"
    assert res.output["status"] == "skipped"  # disabled by default


def test_upstream_phase_excludes_downstream_tools(tmp_path):
    cfg_path = _write_config({"klee", "bond"})
    result = run_all(tmp_path, config_path=cfg_path, phase="upstream")
    assert result["status"] == "skipped"
    assert result["tools"] == []
