"""Conservative local emulation validation stage."""

from __future__ import annotations

from typing import Any

from tools.emulation.qemu_user import run_l1_load_check
from tools.pipeline_context import load_artifact, load_task, resolve_rootfs, save_artifact


def execute_validation(run_dir: str) -> dict[str, Any]:
    """Run only the harmless QEMU load check; never claim exploit validation."""
    authorization = load_task(run_dir).get("authorization", {})
    if not authorization.get("allow_emulation", False):
        return {
            "status": "degraded",
            "reason": "local emulation was not authorized in the task card",
        }
    summaries = load_artifact(run_dir, "binary_summaries.json", {"summaries": []})
    rows = summaries.get("summaries", []) if isinstance(summaries, dict) else []
    arch = next((row.get("architecture") for row in rows if row.get("architecture")), None)
    if not arch:
        return {"status": "degraded", "reason": "target architecture is unknown"}
    result = run_l1_load_check(resolve_rootfs(run_dir), arch)
    artifact = save_artifact(run_dir, "local_validation.json", result)
    status = "ok" if result.get("load_ok") else "degraded"
    return {"status": status, "local_validation": str(artifact), "detail": result}
