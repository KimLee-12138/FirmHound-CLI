"""Orchestrator-facing firmware/rootfs input stage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.safety.policy_engine import PolicyEngine
from fsa.utils.hashing import sha256_file
from tools.firmware.collect_info import collect_info
from tools.firmware.rootfs_score import score_rootfs_candidates
from tools.firmware.unpack import unpack
from tools.pipeline_context import load_task, save_artifact


def execute_unpack(
    run_dir: str,
    temp_root: str,
    safety_config: str,
) -> dict[str, Any]:
    """Accept a real rootfs or extract a real firmware image for later stages."""
    task = load_task(run_dir)
    policy = PolicyEngine.from_yaml(safety_config)
    input_path = Path(task.get("rootfs_path") or task["firmware_path"]).resolve()
    policy.check_path(input_path)

    if task.get("rootfs_path"):
        if not input_path.is_dir():
            return {"status": "failed", "reason": f"rootfs is not a directory: {input_path}"}
        descriptor = {
            "status": "ok",
            "input_type": "rootfs",
            "input_path": str(input_path),
            "rootfs_path": str(input_path),
            "extraction_confidence": 1.0,
        }
        path = save_artifact(run_dir, "rootfs.json", descriptor)
        return {**descriptor, "artifact": str(path)}

    if not input_path.is_file():
        return {"status": "failed", "reason": f"firmware is not a file: {input_path}"}

    out = (Path(temp_root).resolve() / Path(run_dir).resolve().name / "unpacked").resolve()
    policy.check_path(out)
    baseline = collect_info(input_path)
    extraction = unpack(input_path, out, policy=policy)
    scored = score_rootfs_candidates(out)
    best = scored.get("best")
    if not best:
        save_artifact(run_dir, "firmware_baseline.json", baseline)
        save_artifact(run_dir, "firmware_unpack.json", extraction)
        reason = "no rootfs candidate found after extraction"
        if extraction.get("encrypted"):
            reason = "encrypted firmware payload detected; decryption material is required"
        return {
            "status": "failed",
            "reason": reason,
            "unpack": extraction,
        }

    descriptor = {
        "status": "ok" if scored.get("threshold_met") else "degraded",
        "input_type": "firmware",
        "input_path": str(input_path),
        "firmware_sha256": sha256_file(input_path),
        "rootfs_path": best["path"],
        "rootfs_score": best["score"],
        "extraction_confidence": scored.get("extraction_confidence", 0.0),
        "unpack_method": extraction.get("method"),
    }
    save_artifact(run_dir, "firmware_baseline.json", baseline)
    path = save_artifact(run_dir, "rootfs.json", descriptor)
    return {**descriptor, "artifact": str(path)}
