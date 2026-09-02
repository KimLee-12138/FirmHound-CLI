"""Shared run-artifact helpers for executable pipeline stages."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.utils.jsonio import load_json, save_json


def run_path(run_dir: str | Path) -> Path:
    """Return an existing, resolved pipeline run directory."""
    path = Path(run_dir).resolve()
    if not path.is_dir():
        raise FileNotFoundError(f"Run directory not found: {path}")
    return path


def load_task(run_dir: str | Path) -> dict[str, Any]:
    """Load the immutable input contract for a run."""
    path = run_path(run_dir) / "state" / "task_card.json"
    if not path.is_file():
        raise FileNotFoundError(f"Task card not found: {path}")
    return load_json(path)


def save_artifact(run_dir: str | Path, name: str, value: Any) -> Path:
    """Persist a JSON stage artifact below the run artifact directory."""
    path = run_path(run_dir) / "artifacts" / name
    save_json(path, value)
    return path


def load_artifact(run_dir: str | Path, name: str, default: Any = None) -> Any:
    """Load a JSON artifact, returning ``default`` when it does not exist."""
    path = run_path(run_dir) / "artifacts" / name
    return load_json(path) if path.is_file() else default


def resolve_rootfs(run_dir: str | Path) -> Path:
    """Resolve the rootfs selected by the UNPACK stage (never guess)."""
    descriptor = load_artifact(run_dir, "rootfs.json")
    if not isinstance(descriptor, dict) or not descriptor.get("rootfs_path"):
        raise FileNotFoundError("UNPACK did not produce artifacts/rootfs.json")
    rootfs = Path(descriptor["rootfs_path"]).resolve()
    if not rootfs.is_dir():
        raise FileNotFoundError(f"Selected rootfs not found: {rootfs}")
    return rootfs
