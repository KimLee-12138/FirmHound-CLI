"""M8 optional FirmAE wrapper: enable only when FirmAE is present.

FirmAE is an optional system-emulation accelerator. If it is not installed,
every call degrades to a ``skipped`` result with a recorded limitation instead
of failing the run.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from tools.emulation.safety_gate import validate_target_ip


def detect_firmae(root: str | Path | None = None) -> str | None:
    """Return the FirmAE working directory if present, else None.

    Detection order: an explicit ``root`` that exists, the ``FIRMAE_DIR``
    environment variable, or a ``firmae`` executable on PATH.
    """
    if root is not None and Path(root).exists():
        return str(Path(root))
    import os

    env_dir = os.environ.get("FIRMAE_DIR")
    if env_dir and Path(env_dir).exists():
        return env_dir
    if shutil.which("firmae"):
        return "firmae"
    return None


def run_firmae(
    firmware_path: str | Path,
    target_ip: str,
    *,
    firmae_root: str | Path | None = None,
) -> dict[str, Any]:
    """Run FirmAE if available, otherwise record a limitation.

    The target IP must be private; a non-private IP aborts via the safety gate.
    """
    validate_target_ip(target_ip)

    root = detect_firmae(firmae_root)
    if root is None:
        return {
            "status": "skipped",
            "limitation": "FirmAE not detected; falling back to QEMU system mode",
            "firmware": str(firmware_path),
            "target_ip": target_ip,
        }

    return {
        "status": "planned",
        "firmae_root": root,
        "firmware": str(firmware_path),
        "target_ip": target_ip,
        "note": "FirmAE emulation; isolated private network only",
    }
