"""Command-line interface for the firmware security analysis pipeline."""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any

import click
import structlog
from dotenv import load_dotenv

from fsa.orchestrator.engine import Orchestrator, validate_run_id
from fsa.utils.jsonio import load_json


def _emit(value: dict[str, Any], as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(value, ensure_ascii=False))
        return
    for key, item in value.items():
        click.echo(f"{key}: {item}")


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
