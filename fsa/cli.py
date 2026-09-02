"""Command-line interface for the firmware security analysis pipeline."""

from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

import click
import structlog
from dotenv import load_dotenv

from fsa.orchestrator.engine import Orchestrator, validate_run_id
from fsa.schemas.loader import validate_all_examples
from fsa.utils.jsonio import load_json, load_yaml


def _emit(value: dict[str, Any], as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(value, ensure_ascii=False))
        return
    for key, item in value.items():
        click.echo(f"{key}: {item}")


def _status_from_checks(checks: dict[str, dict[str, Any]]) -> str:
    statuses = {item.get("status") for item in checks.values()}
    if "failed" in statuses:
        return "failed"
    if "degraded" in statuses:
        return "degraded"
    return "ok"


def _configure_tool_path(config_path: Path) -> None:
    """Apply configured local tool shims before any analyzer runs."""
    cfg = load_yaml(config_path)
    tool_cfg = cfg.get("tools", {}) if isinstance(cfg, dict) else {}
    if not tool_cfg.get("use_wsl_wrappers"):
        return
    wrappers = Path(tool_cfg.get("wsl_wrappers", ""))
    if not wrappers.is_absolute():
        wrappers = (config_path.parent.parent / wrappers).resolve()
    if wrappers.is_dir():
        os.environ["PATH"] = str(wrappers) + os.pathsep + os.environ.get("PATH", "")


@click.group()
@click.option(
    "--config",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("config/dev.yaml"),
    show_default=True,
    help="YAML configuration path.",
)
@click.pass_context
def main(ctx: click.Context, config: Path) -> None:
    """FirmHound firmware-security agent CLI."""
    config = config.resolve()
    if not config.is_file():
        raise click.ClickException(f"configuration not found: {config}")
    load_dotenv(config.parent.parent / ".env")
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    _configure_tool_path(config)


@main.command()
@click.option("--task", help="Natural-language task description.")
@click.option(
    "--task-package",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="ZIP package containing a task description and firmware artifacts.",
)
@click.option("--firmware-path", type=click.Path(path_type=Path), help="Firmware or rootfs path.")
@click.option(
    "--depth",
    type=click.Choice(["quick", "standard", "full"]),
    default="standard",
    show_default=True,
)
@click.option("--authorization-holder", default="", help="Authorized owner/operator name.")
@click.option("--authorization-scope", default="analysis-only", show_default=True)
@click.option("--allow-emulation", is_flag=True, help="Authorize isolated local emulation.")
@click.option("--vendor")
@click.option("--model")
@click.option("--version")
@click.option("--run-id", help="Optional stable run identifier.")
@click.option("--json-output", is_flag=True, help="Emit a machine-readable plan.")
@click.pass_context
def plan(
    ctx: click.Context,
    task: str | None,
    task_package: Path | None,
    firmware_path: Path | None,
    depth: str,
    authorization_holder: str,
    authorization_scope: str,
    allow_emulation: bool,
    vendor: str | None,
    model: str | None,
    version: str | None,
    run_id: str | None,
    json_output: bool,
) -> None:
    """Parse a task and show the planned CLI execution stages without running tools."""
    if not any((task, task_package, firmware_path)):
        raise click.ClickException("provide --task, --task-package, or --firmware-path")

    try:
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        if firmware_path:
            source = firmware_path.resolve()
            if not source.exists():
                raise click.ClickException(f"firmware path not found: {source}")
            orchestrator.policy.check_path(source)
            firmware_value = str(source)
        else:
            firmware_value = ""

        task_input: dict[str, Any] = {
            "task_id": run_id or uuid.uuid4().hex[:12],
            "natural_language": task or "",
            "task_package": str(task_package.resolve()) if task_package else "",
            "firmware_path": firmware_value,
            "vendor": vendor,
            "model": model,
            "version": version,
            "depth": depth,
            "authorization": {
                "holder": authorization_holder,
                "scope": authorization_scope,
                "allow_emulation": allow_emulation,
                "network_isolation": True,
            },
        }
        task_card = orchestrator.planner.parse_task(task_input)
        execution_plan = orchestrator.planner.build_plan(task_card)
    except Exception as exc:  # noqa: BLE001
        structlog.get_logger().error("planning_failed", error=str(exc))
        raise click.ClickException(str(exc)) from exc

    _emit(
        {
            "status": "needs_human_input" if task_card["requires_human_gate"] else "ok",
            "run_id": task_card["task_id"],
            "objective": task_card["objective"],
            "firmware_path": task_card["firmware_path"],
            "depth": task_card["depth"],
            "stages": execution_plan["stages"],
            "requires_human_gate": task_card["requires_human_gate"],
            "human_gate_reasons": task_card["human_gate_reasons"],
            "attachments": task_card.get("attachments", []),
        },
        json_output,
    )


@main.command()
@click.argument("input_path", type=click.Path(path_type=Path, exists=True))
@click.option(
    "--input-type",
    type=click.Choice(["auto", "firmware", "rootfs"]),
    default="auto",
    show_default=True,
)
@click.option(
    "--depth",
    type=click.Choice(["quick", "standard", "full"]),
    default="standard",
    show_default=True,
)
@click.option("--authorization-holder", required=True, help="Authorized owner/operator name.")
@click.option("--authorization-scope", default="analysis-only", show_default=True)
@click.option("--allow-emulation", is_flag=True, help="Authorize isolated local emulation.")
@click.option("--vendor")
@click.option("--model")
@click.option("--version")
@click.option("--run-id", help="Optional stable run identifier.")
@click.option("--json-output", is_flag=True, help="Emit a machine-readable result.")
@click.pass_context
def analyze(
    ctx: click.Context,
    input_path: Path,
    input_type: str,
    depth: str,
    authorization_holder: str,
    authorization_scope: str,
    allow_emulation: bool,
    vendor: str | None,
    model: str | None,
    version: str | None,
    run_id: str | None,
    json_output: bool,
) -> None:
    """Analyze a real firmware image or an already extracted ROOTFS directory."""
    source = input_path.resolve()
    detected_type = "rootfs" if source.is_dir() else "firmware"
    selected_type = detected_type if input_type == "auto" else input_type
    if selected_type == "rootfs" and not source.is_dir():
        raise click.ClickException("--input-type rootfs requires a directory")
    if selected_type == "firmware" and not source.is_file():
        raise click.ClickException("--input-type firmware requires a file")

    try:
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        orchestrator.policy.check_path(source)
        task_input: dict[str, Any] = {
            "task_id": run_id or uuid.uuid4().hex[:12],
            "firmware_path": str(source),
            "vendor": vendor,
            "model": model,
            "version": version,
            "depth": depth,
            "authorization": {
                "holder": authorization_holder,
                "scope": authorization_scope,
                "allow_emulation": allow_emulation,
                "network_isolation": True,
            },
        }
        if selected_type == "rootfs":
            task_input["rootfs_path"] = str(source)
        task_card = orchestrator.planner.parse_task(task_input)
        structlog.get_logger().info(
            "analysis_started",
            run_id=task_card["task_id"],
            input_type=selected_type,
            depth=depth,
        )
        state = orchestrator.run(task_card)
    except Exception as exc:  # noqa: BLE001
        structlog.get_logger().error("analysis_failed", error=str(exc))
        raise click.ClickException(str(exc)) from exc

    result = {
        "status": state["status"],
        "run_id": state["run_id"],
        "run_dir": str(Path(orchestrator.config["paths"]["runs"]) / state["run_id"]),
        "report": state.get("artifacts", {}).get("report"),
        "final_verdict": state.get("artifacts", {}).get("final_verdict"),
    }
    _emit(result, json_output)
    if state["status"] != "done":
        raise click.exceptions.Exit(2)


@main.command()
@click.option("--include-external-probes", is_flag=True, help="Probe optional external analyzers.")
@click.option("--json-output", is_flag=True, help="Emit machine-readable readiness data.")
@click.pass_context
def doctor(ctx: click.Context, include_external_probes: bool, json_output: bool) -> None:
    """Check local readiness for running and testing the CLI."""
    try:
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        config = orchestrator.config
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc

    checks: dict[str, dict[str, Any]] = {}
    path_results: dict[str, str] = {}
    for name, value in config.get("paths", {}).items():
        path = Path(value)
        exists = path.exists()
        if name in {"runs", "temp"}:
            path.mkdir(parents=True, exist_ok=True)
            exists = path.exists()
        path_results[name] = "ok" if exists else "missing"
    checks["paths"] = {
        "status": "ok" if all(v == "ok" for v in path_results.values()) else "failed",
        "items": path_results,
    }

    schema_errors = validate_all_examples()
    checks["schemas"] = {
        "status": "ok" if not schema_errors else "failed",
        "invalid_examples": [name for name, _ in schema_errors],
    }

    models_cfg = load_yaml(config["paths"]["models"])
    runtime_name = config.get("runtime", {}).get("default", "")
    model_env = (
        models_cfg.get("runtimes", {})
        .get("openai_compatible", {})
        .get("api_key_env", "OPENAI_API_KEY")
    )
    checks["runtime"] = {
        "status": "ok" if runtime_name == "offline" else "degraded",
        "default": runtime_name,
        "model_api_key_env": model_env,
        "model_api_key_present": bool(os.environ.get(model_env)),
        "note": (
            "offline runtime is deterministic; online model gateway credentials "
            "are optional for local CLI tests"
        ),
    }

    required_commands = ["python"]
    optional_commands = ["docker", "binwalk", "unsquashfs", "analyzeHeadless", "klee"]
    command_checks = {cmd: bool(shutil.which(cmd)) for cmd in required_commands + optional_commands}
    checks["commands"] = {
        "status": "ok" if all(command_checks[cmd] for cmd in required_commands) else "failed",
        "available": command_checks,
    }

    if include_external_probes:
        from tools.external.adapter import EXTERNAL_TOOLS, _build_analyzer, _load_global_external

        external = _load_global_external(config_path=ctx.obj["config"])
        tools: dict[str, dict[str, Any]] = {}
        for tool in EXTERNAL_TOOLS:
            cfg = dict(external.get(tool, {}) or {})
            analyzer = _build_analyzer(tool, cfg)
            if analyzer is None:
                tools[tool] = {
                    "status": "failed",
                    "available": False,
                    "limitation": "adapter could not be constructed",
                }
                continue
            try:
                probe = analyzer.probe()
                tools[tool] = {
                    "status": "ok" if probe.available else "degraded",
                    "available": probe.available,
                    "version": probe.version,
                    "backend": probe.backend,
                    "missing": probe.missing,
                    "limitation": probe.notes,
                }
            except Exception as exc:  # noqa: BLE001
                tools[tool] = {
                    "status": "failed",
                    "available": False,
                    "limitation": f"{type(exc).__name__}: {exc}",
                }
        checks["external"] = {"status": _status_from_checks(tools), "tools": tools}

    _emit({"status": _status_from_checks(checks), "checks": checks}, json_output)


@main.command(name="status")
@click.argument("run_id")
@click.option("--json-output", is_flag=True)
@click.pass_context
def show_status(ctx: click.Context, run_id: str, json_output: bool) -> None:
    """Show the persisted state of an analysis run."""
    try:
        validate_run_id(run_id)
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        run_dir = Path(orchestrator.config["paths"]["runs"]) / run_id
        orchestrator.policy.check_path(run_dir)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc
    path = run_dir / "state" / "run_state.json"
    if not path.is_file():
        raise click.ClickException(f"run not found: {run_id}")
    state = load_json(path)
    _emit(
        {
            "status": state["status"],
            "run_id": state["run_id"],
            "current_stage": state["current_stage"],
            "completed_stages": state["completed_stages"],
            "failed_stages": state["failed_stages"],
        },
        json_output,
    )


@main.command()
@click.argument("run_id")
@click.option("--json-output", is_flag=True)
@click.pass_context
def resume(ctx: click.Context, run_id: str, json_output: bool) -> None:
    """Resume an interrupted run from its first incomplete stage."""
    try:
        state = Orchestrator(config_path=ctx.obj["config"]).resume(run_id)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc
    _emit(
        {
            "status": state["status"],
            "run_id": state["run_id"],
            "current_stage": state["current_stage"],
        },
        json_output,
    )
    if state["status"] != "done":
        raise click.exceptions.Exit(2)


if __name__ == "__main__":
    main()
