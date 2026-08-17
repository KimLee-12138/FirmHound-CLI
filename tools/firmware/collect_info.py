"""Collect baseline information about a firmware image.

Outputs a dict matching the top-level fields of ``firmware_manifest.schema.json``
(sha256, md5, size, file_type, magic_bytes, vendor/model/version hints).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import shutil

from fsa.utils.hashing import md5_file, sha256_file
from fsa.utils.proc import run_command


def _first_bytes(path: Path, n: int = 256) -> str:
    with path.open("rb") as fh:
        data = fh.read(n)
    return data.hex()


def _run_file(path: Path) -> str:
    if shutil.which("file") is None:
        return "unknown"
    result = run_command(["file", str(path)])
    if result.status != "success":
        return "unknown"
    return result.stdout.strip()


def _binwalk_signatures(path: Path) -> list[dict[str, Any]]:
    """Run binwalk signature scan and parse matches."""
    if shutil.which("binwalk") is None:
        return []
    result = run_command(["binwalk", "--signature", "--term", str(path)])
    if result.status != "success":
        return []
    matches: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        # Typical line: "123456 | 0x1E240 | Squashfs filesystem ..."
        m = re.match(r"^\s*(\d+)\s+\|\s+(0x[0-9a-fA-F]+)\s+\|\s+(.+)$", line)
        if m:
            matches.append({
                "offset": int(m.group(1)),
                "offset_hex": m.group(2),
                "description": m.group(3).strip(),
            })
    return matches


def _extract_hints(strings_output: str) -> dict[str, Any]:
    """Extract vendor/model/version/kernel hints from strings."""
    hints: dict[str, Any] = {"vendor": None, "model": None, "version": None, "kernel": None}
    lines = strings_output.splitlines()

    for line in lines:
        if not hints["kernel"]:
            km = re.search(r"Linux version (\S+)", line)
            if km:
                hints["kernel"] = km.group(1)
        if not hints["vendor"]:
            vm = re.search(r"(?i)(?:vendor|manufacturer|company)\s*[:=]\s*(\S+)", line)
            if vm:
                hints["vendor"] = vm.group(1)
        if not hints["version"]:
            ver = re.search(r"(?i)(?:firmware|software)\s+version\s*[:=]\s*([\w._-]+)", line)
            if ver:
                hints["version"] = ver.group(1)

    return hints


def _run_strings(path: Path, min_len: int = 8) -> str:
    if shutil.which("strings") is None:
        return ""
    result = run_command(["strings", f"-n{min_len}", str(path)])
    return result.stdout if result.status == "success" else ""


def collect_info(firmware_path: str | Path) -> dict[str, Any]:
    """Collect baseline information about a firmware image.

    Args:
        firmware_path: Path to the firmware file.

    Returns:
        Dict with sha256, md5, size, file_type, magic_bytes_hex, hints,
        binwalk_signatures, tool_versions, and status.
    """
    path = Path(firmware_path)
    if not path.exists():
        raise FileNotFoundError(f"Firmware not found: {path}")

    strings_output = _run_strings(path)
    hints = _extract_hints(strings_output)

    info: dict[str, Any] = {
        "firmware_path": str(path.resolve()),
        "sha256": sha256_file(path),
        "md5": md5_file(path),
        "file_size": path.stat().st_size,
        "file_type": _run_file(path),
        "magic_bytes": _first_bytes(path, 256),
        "binwalk_signatures": _binwalk_signatures(path),
        "strings_summary": {
            "line_count": len(strings_output.splitlines()),
            "kernel_hint": hints.get("kernel"),
        },
        "vendor": hints["vendor"],
        "model": hints["model"],
        "version": hints["version"],
        "kernel_hint": hints["kernel"],
        "status": "success",
        "tool_versions": {},
    }
    return info


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.firmware.collect_info <firmware>")
        raise SystemExit(1)
    print(json.dumps(collect_info(sys.argv[1]), indent=2))
