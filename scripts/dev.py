"""Cross-platform development task runner.

Usage:
    python scripts/dev.py <command>

Commands:
    help          Show this help message
    install       Install production dependencies
    dev           Install package in editable mode with dev dependencies
    test          Run all tests with pytest
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
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def run(cmd: list[str] | str, *, cwd: Path | None = None) -> int:
    """Run a command and return its exit code."""
    if isinstance(cmd, list):
        print("$ " + " ".join(cmd))
    else:
        print("$ " + cmd)
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


def cmd_test(args: argparse.Namespace) -> int:
    """Run pytest with optional WSL tool wrappers on Windows."""
    wrappers = REPO_ROOT / "tools" / "wsl_wrappers"
    env = os.environ.copy()
    env["PATH"] = str(wrappers) + os.pathsep + env.get("PATH", "")
    return subprocess.call([PYTHON, "-m", "pytest"], cwd=REPO_ROOT, env=env)


def cmd_lint(args: argparse.Namespace) -> int:
    """Run ruff check."""
    return run([PYTHON, "-m", "ruff", "check", "fsa", "tools", "tests"], cwd=REPO_ROOT)


def cmd_format(args: argparse.Namespace) -> int:
    """Run ruff format."""
    return run([PYTHON, "-m", "ruff", "format", "fsa", "tools", "tests"], cwd=REPO_ROOT)


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
    print("Cleaned build artifacts and caches.")
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    """Run end-to-end smoke test."""
    return run(
        [
            PYTHON,
            "-m",
            "fsa.cli",
            "--config",
            "config/dev.yaml",
            "smoke",
            "tests/fixtures/sample.bin",
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
    sub.add_parser("test", help="Run all tests with pytest")
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
