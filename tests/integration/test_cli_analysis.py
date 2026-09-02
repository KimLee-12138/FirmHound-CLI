"""End-to-end tests for the formal ``fsa analyze`` command."""

from __future__ import annotations

import json
import shutil
import sys
import uuid
import zipfile
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
            "tools": {"use_wsl_wrappers": False},
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
        assert (run / "report.md").read_text(encoding="utf-8").count("\n## ") == 22
        assert "误报控制摘要" in (run / "report.md").read_text(encoding="utf-8")
        assert (run / "final_verdict.json").is_file()
        stats = load_json(run / "final_verdict.json")["stats"]
        assert "false_positive_control" in stats
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


def test_cli_plan_rejects_missing_firmware_path() -> None:
    workspace = (Path("tmp") / f"cli-plan-missing-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        missing = workspace / "rootfs" / "missing.bin"
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "plan",
                "--firmware-path",
                str(missing),
                "--authorization-holder",
                "fixture-owner",
                "--json-output",
            ],
        )

        assert result.exit_code != 0
        assert "firmware path not found" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_plan_from_natural_language_and_package() -> None:
    workspace = (Path("tmp") / f"cli-plan-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        package = workspace / "task.zip"
        with zipfile.ZipFile(package, "w") as zf:
            zf.writestr("firmware/router.bin", b"firmware")
            zf.writestr("README.txt", "authorized router analysis")

        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "plan",
                "--task",
                "分析厂商为Tenda、型号AC15的固件，授权测试，完整分析。",
                "--task-package",
                str(package),
                "--authorization-holder",
                "fixture-owner",
                "--json-output",
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "ok"
        assert payload["depth"] == "full"
        assert payload["firmware_path"].replace("\\", "/").endswith("firmware/router.bin")
        assert "EXTERNAL_ANALYSIS" in payload["stages"]
        assert "firmware/router.bin" in payload["attachments"]
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_doctor_reports_readiness() -> None:
    workspace = (Path("tmp") / f"cli-doctor-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        result = CliRunner().invoke(
            main,
            ["--config", str(config), "doctor", "--json-output"],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] in {"ok", "degraded"}
        assert payload["checks"]["schemas"]["status"] == "ok"
        assert payload["checks"]["paths"]["status"] == "ok"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_unpack_diagnose_reports_encrypted_firmware() -> None:
    workspace = (Path("tmp") / f"cli-diagnose-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        firmware = workspace / "rootfs" / "encrypted.bin"
        firmware.parent.mkdir(parents=True, exist_ok=True)
        firmware.write_bytes(b"HEAD" + b"Salted__" + b"0" * 64)
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "unpack-diagnose",
                str(firmware),
                "--json-output",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "blocked_needs_decryption"
        assert payload["magic_hits"]
        assert any("加密" in item or "OpenSSL" in item for item in payload["recommendations"])
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_explain_renders_candidate_ledger() -> None:
    workspace = (Path("tmp") / f"cli-explain-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        run_result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                "standard",
                "--authorization-holder",
                "fixture-owner",
                "--run-id",
                "cli-explain",
            ],
        )
        assert run_result.exit_code == 0, run_result.output
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "explain",
                "cli-explain",
                "--format",
                "markdown",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "漏洞证据账本" in result.output
        assert "十维评分" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
