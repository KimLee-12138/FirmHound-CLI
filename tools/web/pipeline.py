"""Orchestrator-facing attack-surface stage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.pipeline_context import resolve_rootfs, save_artifact
from tools.web.build_attack_surface import build_attack_surface


def execute_surface(run_dir: str) -> dict[str, Any]:
    """Build attack surfaces from the rootfs selected by UNPACK."""
    rootfs = resolve_rootfs(run_dir)
    run_path = Path(run_dir).resolve()
    result = build_attack_surface(rootfs, run_path.name, run_path.parent)
    artifact = save_artifact(run_dir, "attack_surface.json", result)
    return {
        "status": "ok",
        "surface_count": len(result.get("surfaces", [])),
        "attack_surface": str(artifact),
    }
