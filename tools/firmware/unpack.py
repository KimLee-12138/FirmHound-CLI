"""Firmware unpacking dispatcher.

Routes a firmware image to the right extraction strategy based on signatures
and falls back to carving when needed.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from fsa.safety.policy_engine import PolicyEngine
from fsa.utils.proc import run_command

# Map from binwalk description keyword to extraction strategy.
STRATEGIES: list[dict[str, Any]] = [
    {
        "name": "squashfs_standard",
        "keywords": ["Squashfs filesystem"],
        "tools": [["unsquashfs", "-d", "{out}", "{fw}"]],
    },
    {
        "name": "squashfs_lzma",
        "keywords": ["squashfs", "lzma"],
        "tools": [
            ["sasquatch", "-d", "{out}", "{fw}"],
            ["7z", "x", "-o{out}", "{fw}"],
        ],
    },
    {
        "name": "ubi",
        "keywords": ["UBI"],
        "tools": [["ubireader_extract_images", "-o", "{out}", "{fw}"]],
    },
    {
        "name": "jffs2",
        "keywords": ["JFFS2"],
        "tools": [["jefferson", "-d", "{out}", "{fw}"]],
    },
    {
        "name": "cpio",
        "keywords": ["cpio"],
        "tools": [["cpio", "-idmv", "-D", "{out}"]],
    },
    {
        "name": "gzip",
        "keywords": ["gzip"],
        "tools": [["gzip", "-dc", "{fw}"]],
    },
]


def _normalize_tool_args(args: list[str], fw: Path, out: Path) -> list[str]:
    """Replace {fw}/{out} placeholders in command arguments."""
    return [arg.replace("{fw}", str(fw)).replace("{out}", str(out)) for arg in args]


def _check_extractors() -> dict[str, bool]:
    """Check which external extractors are available on PATH."""
    names = [
        "unsquashfs",
        "sasquatch",
        "7z",
        "ubireader_extract_images",
        "jefferson",
        "cpio",
        "binwalk",
    ]
    return {name: shutil.which(name) is not None for name in names}


def _detect_strategy(signatures: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Choose extraction strategy based on binwalk signatures."""
    descriptions = " ".join(sig.get("description", "").lower() for sig in signatures)
    for strategy in STRATEGIES:
        if all(kw.lower() in descriptions for kw in strategy["keywords"]):
            return strategy
    return None


def _extract_with_strategy(
    fw: Path,
    out: Path,
    strategy: dict[str, Any],
) -> dict[str, Any]:
    """Try each tool chain in the strategy until one succeeds."""
    available = _check_extractors()
    attempts: list[dict[str, Any]] = []
    for tool_chain in strategy["tools"]:
        cmd = _normalize_tool_args(tool_chain, fw, out)
        binary = cmd[0]
        if binary not in ("dd", "gzip") and not available.get(binary):
            attempts.append(
                {"command": " ".join(cmd), "status": "skipped", "reason": "tool not found"}
            )
            continue

        out.mkdir(parents=True, exist_ok=True)
        result = run_command(cmd, timeout=300)
        attempts.append(
            {
                "command": result.command,
                "status": result.status,
                "returncode": result.returncode,
                "stderr_tail": result.stderr[-500:],
            }
        )
        if result.status == "success":
            return {"status": "success", "method": strategy["name"], "attempts": attempts}
    return {"status": "failed", "method": strategy["name"], "attempts": attempts}


def _carve_fallback(fw: Path, out: Path) -> dict[str, Any]:
    """Fallback: scan the image for known magic bytes and carve filesystems."""
    out.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []

    magics = [
        (b"hsqs", "squashfs"),
        (b"sqsh", "squashfs"),
        (b"UBI#", "ubi"),
        (b"\x1f\x8b", "gzip"),
    ]

    with fw.open("rb") as fh:
        data = fh.read()

    carved_any = False
    for magic, kind in magics:
        for offset in range(len(data) - len(magic)):
            if data[offset : offset + len(magic)] == magic:
                slice_path = out / f"carved_{kind}_{offset}.bin"
                with slice_path.open("wb") as wh:
                    wh.write(data[offset:])
                carved_any = True
                attempts.append(
                    {
                        "offset": offset,
                        "kind": kind,
                        "slice": str(slice_path),
                        "status": "carved",
                    }
                )

    return {
        "status": "partial" if carved_any else "failed",
        "method": "carve_fallback",
        "attempts": attempts,
    }


def unpack(
    firmware_path: str | Path,
    output_dir: str | Path,
    *,
    policy: PolicyEngine | None = None,
) -> dict[str, Any]:
    """Unpack a firmware image into ``output_dir``.

    Args:
        firmware_path: Path to the firmware file.
        output_dir: Directory where extracted contents should be placed.
        policy: Optional safety policy engine to validate paths.

    Returns:
        Dict with ``status``, ``method``, ``output_dir``, and ``attempts``.
    """
    fw = Path(firmware_path).resolve()
    out = Path(output_dir).resolve()

    if policy is not None:
        policy.check_path(out)

    if not fw.exists():
        raise FileNotFoundError(f"Firmware not found: {fw}")

    # Collect binwalk signatures to choose strategy when binwalk is available.
    from tools.firmware.collect_info import _binwalk_signatures

    signatures = _binwalk_signatures(fw)
    strategy = _detect_strategy(signatures)

    if strategy and any(shutil.which(cmd[0]) for cmd in strategy["tools"]):
        result = _extract_with_strategy(fw, out, strategy)
    else:
        result = {
            "status": "failed",
            "method": strategy["name"] if strategy else None,
            "attempts": [],
            "reason": "no matching strategy or extractors unavailable",
        }

    if result["status"] != "success":
        carve = _carve_fallback(fw, out)
        result["fallback"] = carve
        if carve["status"] == "partial":
            result["status"] = "partial"

    result["output_dir"] = str(out)
    result["binwalk_signatures"] = signatures
    return result


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 3:
        print("Usage: python -m tools.firmware.unpack <firmware> <output_dir>")
        raise SystemExit(1)
    result = unpack(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=2))
