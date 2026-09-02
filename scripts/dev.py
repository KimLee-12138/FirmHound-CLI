"""Cross-platform development task runner.

Usage:
    python scripts/dev.py <command>

Commands:
    help          Show this help message
    install       Install production dependencies
    dev           Install package in editable mode with dev dependencies
    test          Run deterministic unit tests
    test-all      Run unit + optional host integration tests
    integration   Run host integration tests only
    ext-smoke     Probe all four optional external analyzers
    lint          Run ruff check
    format        Run ruff format
    clean         Remove build artifacts and caches
    smoke         Run end-to-end smoke test with fixture firmware
    docker-build  Build Docker image
    docker-run    Run one-shot analysis in Docker
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import structlog

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
PYTHON = sys.executable
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.JSONRenderer(),
    ]
)
LOG = structlog.get_logger("dev")


def run(cmd: list[str] | str, *, cwd: Path | None = None) -> int:
    """Run a command and return its exit code."""
    if isinstance(cmd, list):
        LOG.info("command_start", command=cmd)
    else:
        LOG.info("command_start", command=cmd)
    return subprocess.call(cmd, shell=isinstance(cmd, str), cwd=cwd)


def cmd_help(args: argparse.Namespace) -> int:
    """Show help."""
    parser.print_help()
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Install production dependencies."""
    return run([PYTHON, "-m", "pip", "install", "-r", "requirements.txt"], cwd=REPO_ROOT)


def cmd_dev(args: argparse.Namespace) -> int:
    """Install editable package and dev dependencies."""
    rc = run([PYTHON, "-m", "pip", "install", "-r", "requirements.txt"], cwd=REPO_ROOT)
    if rc != 0:
        return rc
    return run([PYTHON, "-m", "pip", "install", "-e", "."], cwd=REPO_ROOT)


def _pytest(paths: list[str], *, with_wsl_wrappers: bool = False) -> int:
    """Run pytest with optional WSL wrappers and an explicit test scope."""
    env = os.environ.copy()
    if with_wsl_wrappers and os.name == "nt":
        wrappers = REPO_ROOT / "tools" / "wsl_wrappers"
        env["PATH"] = str(wrappers) + os.pathsep + env.get("PATH", "")
    return subprocess.call([PYTHON, "-m", "pytest", *paths], cwd=REPO_ROOT, env=env)


def cmd_test(args: argparse.Namespace) -> int:
    """Run the deterministic CI unit-test suite."""
    return _pytest(["tests/unit"])


def cmd_test_all(args: argparse.Namespace) -> int:
    """Run unit tests plus host-dependent integration tests."""
    return _pytest(["tests"], with_wsl_wrappers=True)


def cmd_integration(args: argparse.Namespace) -> int:
    """Run host-dependent integration tests only."""
    return _pytest(["tests/integration"], with_wsl_wrappers=True)


def cmd_ext_smoke(args: argparse.Namespace) -> int:
    """Probe optional external analyzers without requiring them to be installed."""
    from tools.external.adapter import EXTERNAL_TOOLS, _build_analyzer, _load_global_external

    external = _load_global_external()
    results: dict[str, dict[str, object]] = {}
    for tool in EXTERNAL_TOOLS:
        cfg = dict(external.get(tool, {}) or {})
        analyzer = _build_analyzer(tool, cfg)
        if analyzer is None:
            results[tool] = {
                "status": "failed",
                "available": False,
                "limitation": "adapter could not be constructed",
            }
            continue
        try:
            probe = analyzer.probe()
            results[tool] = {
                "status": "ok" if probe.available else "degraded",
                "available": probe.available,
                "version": probe.version,
                "backend": probe.backend,
                "missing": probe.missing,
                "limitation": probe.notes,
            }
        except Exception as exc:  # noqa: BLE001 - smoke must report every tool
            results[tool] = {
                "status": "failed",
                "available": False,
                "limitation": f"{type(exc).__name__}: {exc}",
            }
    overall = "ok" if all(item["status"] == "ok" for item in results.values()) else "degraded"
    LOG.info("external_probe_complete", status=overall, tools=results)
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    """Run ruff check."""
    return run(
        [PYTHON, "-m", "ruff", "check", "fsa", "tools", "scripts", "tests"],
        cwd=REPO_ROOT,
    )


def cmd_format(args: argparse.Namespace) -> int:
    """Run ruff format."""
    return run(
        [PYTHON, "-m", "ruff", "format", "fsa", "tools", "scripts", "tests"],
        cwd=REPO_ROOT,
    )


def cmd_clean(args: argparse.Namespace) -> int:
    """Remove build artifacts and caches."""
    paths = [
        REPO_ROOT / "build",
        REPO_ROOT / "dist",
        REPO_ROOT / "*.egg-info",
        REPO_ROOT / ".pytest_cache",
        REPO_ROOT / ".coverage",
        REPO_ROOT / ".ruff_cache",
    ]
    for p in paths:
        if p.is_dir():
            shutil.rmtree(p)
        elif "*" in str(p):
            for match in REPO_ROOT.glob(p.name):
                if match.is_dir():
                    shutil.rmtree(match)

    for pycache in REPO_ROOT.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache)
    LOG.info("clean_complete", status="ok")
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    """Run an end-to-end smoke test through the product CLI."""
    suffix = uuid.uuid4().hex[:8]
    rootfs = REPO_ROOT / "tmp" / f"dev-smoke-rootfs-{suffix}"
    if rootfs.exists():
        shutil.rmtree(rootfs)
    (rootfs / "www" / "cgi-bin").mkdir(parents=True, exist_ok=True)
    (rootfs / "etc" / "init.d").mkdir(parents=True, exist_ok=True)
    (rootfs / "www" / "cgi-bin" / "ping.cgi").write_text(
        '#!/bin/sh\neval "ping -c 4 $QUERY_STRING"\n',
        encoding="utf-8",
    )
    (rootfs / "etc" / "init.d" / "S50web").write_text(
        "httpd -h /www -p 80\n",
        encoding="utf-8",
    )
    return run(
        [
            PYTHON,
            "-m",
            "fsa.cli",
            "--config",
            "config/dev.yaml",
            "analyze",
            str(rootfs),
            "--input-type",
            "rootfs",
            "--depth",
            "quick",
            "--authorization-holder",
            "local-smoke-fixture",
            "--run-id",
            f"dev-smoke-{suffix}",
        ],
        cwd=REPO_ROOT,
    )


def cmd_docker_build(args: argparse.Namespace) -> int:
    """Build Docker image."""
    return run(["docker", "build", "-t", "fsa:latest", "."], cwd=REPO_ROOT)


def cmd_docker_run(args: argparse.Namespace) -> int:
    """Run one-shot analysis in Docker."""
    runs_dir = REPO_ROOT / "runs"
    return run(
        ["docker", "run", "--rm", "-it", "-v", f"{runs_dir}:/workspace/runs", "fsa:latest"],
        cwd=REPO_ROOT,
    )


def main(argv: list[str] | None = None) -> int:
    global parser  # noqa: PLW0603
    parser = argparse.ArgumentParser(
        prog="dev.py", description="Cross-platform development task runner"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("help", help="Show this help message")
    sub.add_parser("install", help="Install production dependencies")
    sub.add_parser("dev", help="Install editable package and dev dependencies")
    sub.add_parser("test", help="Run deterministic unit tests with pytest")
    sub.add_parser("test-all", help="Run unit and optional integration tests")
    sub.add_parser("integration", help="Run host integration tests")
    sub.add_parser("ext-smoke", help="Probe optional external analyzers")
    sub.add_parser("lint", help="Run ruff check")
    sub.add_parser("format", help="Run ruff format")
    sub.add_parser("clean", help="Remove build artifacts and caches")
    sub.add_parser("smoke", help="Run end-to-end smoke test with fixture firmware")
    sub.add_parser("docker-build", help="Build Docker image")
    sub.add_parser("docker-run", help="Run one-shot analysis in Docker")

    args = parser.parse_args(argv)
    handlers = {
        "help": cmd_help,
        "install": cmd_install,
        "dev": cmd_dev,
        "test": cmd_test,
        "test-all": cmd_test_all,
        "integration": cmd_integration,
        "ext-smoke": cmd_ext_smoke,
        "lint": cmd_lint,
        "format": cmd_format,
        "clean": cmd_clean,
        "smoke": cmd_smoke,
        "docker-build": cmd_docker_build,
        "docker-run": cmd_docker_run,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
