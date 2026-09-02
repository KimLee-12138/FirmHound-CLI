"""End-to-end tests for the formal ``fsa analyze`` command."""

from __future__ import annotations

import shutil
import sys
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from fsa.cli import main
from fsa.utils.jsonio import load_json, save_yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fixtures"))
from elf_builder import write_elf64  # noqa: E402


def _test_config(tmp_path: Path) -> Path:
    repo = Path(__file__).resolve().parents[2]
    runs = tmp_path / "runs"
    temp = tmp_path / "temp"
    rootfs = tmp_path / "rootfs"
    safety_path = tmp_path / "safety.yaml"
    save_yaml(
        safety_path,
        {
            "enforce": True,
            "abort_on_violation": True,
            "allowed_paths": [str(runs), str(temp), str(rootfs)],
            "blocked_paths": [],
            "command_blacklist": [],
            "network": {"allow_public": False, "allowed_hosts": ["localhost"]},
            "model": {},
        },
    )
    config_path = tmp_path / "dev.yaml"
    save_yaml(
        config_path,
        {
            "runtime": {"default": "mock"},
            "paths": {
                "runs": str(runs),
                "temp": str(temp),
                "schemas": str(repo / "schemas"),
                "models": str(repo / "config" / "models.yaml"),
            },
            "safety": {"config": str(safety_path), "enforce": True},
            "analysis": {
                "max_binaries": 50,
                "max_strings_per_binary": 100,
                "verify_top_k": 5,
            },
            "external": {"enabled": False},
        },
    )
    return config_path


def _rootfs(tmp_path: Path) -> Path:
    root = tmp_path / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "www" / "cgi-bin").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    write_elf64(
        root / "bin" / "httpd",
        imports=["system", "sprintf", "getenv"],
        defined_syms=["formexeCommand"],
        rodata_strings=["QUERY_STRING", "/cgi-bin/diagnostic.cgi"],
    )
    (root / "www" / "index.html").write_text("<html>router</html>", encoding="utf-8")
    (root / "etc" / "init.d" / "S50httpd").write_text("/bin/httpd -p 80\n", encoding="utf-8")
    return root


@pytest.mark.parametrize("depth", ["quick", "standard", "full"])
def test_cli_analyze_rootfs_reaches_done(depth: str) -> None:
    workspace = (Path("tmp") / f"cli-e2e-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                depth,
                "--authorization-holder",
                "fixture-owner",
                "--run-id",
                "cli-e2e",
            ],
        )
        assert result.exit_code == 0, result.output
        run = workspace / "runs" / "cli-e2e"
        state = load_json(run / "state" / "run_state.json")
        assert state["status"] == "done"
        assert state["current_stage"] == "DONE"
        assert load_json(run / "artifacts" / "rootfs.json")["input_type"] == "rootfs"
        assert load_json(run / "artifacts" / "binary_summaries.json")["summaries"]
        assert load_json(run / "artifacts" / "candidates.json")["candidates"]
        assert load_json(run / "artifacts" / "verdict.json")["verdicts"]
        assert (run / "report.md").read_text(encoding="utf-8").count("\n## ") == 21
        assert (run / "final_verdict.json").is_file()
        assert load_json(run / "artifacts" / "report_compliance.json")["status"] == "ok"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_status_rejects_path_traversal() -> None:
    workspace = (Path("tmp") / f"cli-status-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        result = CliRunner().invoke(
            main,
            ["--config", str(config), "status", "../outside"],
        )
        assert result.exit_code != 0
        assert "run_id" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
