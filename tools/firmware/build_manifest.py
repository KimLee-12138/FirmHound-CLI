"""Combine M2 tools to produce a firmware_manifest.json."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.reporting.store_base import RunLayout
from fsa.safety.policy_engine import PolicyEngine
from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from fsa.utils.traverse import iter_rootfs_files
from tools.firmware.arch_detect import detect_architecture
from tools.firmware.collect_info import collect_info
from tools.firmware.rootfs_score import score_rootfs_candidates
from tools.firmware.unpack import unpack


def build_manifest(
    firmware_path: str | Path,
    run_id: str,
    run_root: str | Path,
    *,
    policy: PolicyEngine | None = None,
) -> dict[str, Any]:
    """Run the full M2 pipeline and write ``firmware_manifest.json``.

    Args:
        firmware_path: Path to the firmware image.
        run_id: Run identifier.
        run_root: Parent directory for run artifacts.
        policy: Optional safety policy engine.

    Returns:
        Dict matching ``firmware_manifest.schema.json``.
    """
    fw = Path(firmware_path)
    if not fw.exists():
        raise FileNotFoundError(f"Firmware not found: {fw}")

    layout = RunLayout(run_id, run_root)

    info = collect_info(fw)
    extraction = unpack(fw, layout.root / "extracted", policy=policy)

    rootfs_result = score_rootfs_candidates(extraction["output_dir"])
    best_rootfs = rootfs_result["best"]

    arch_result: dict[str, Any] = {"architecture": "unknown"}
    if best_rootfs:
        arch_result = detect_architecture(best_rootfs["path"])

    manifest: dict[str, Any] = {
        "run_id": run_id,
        "firmware_path": str(fw.resolve()),
        "sha256": info["sha256"],
        "md5": info["md5"],
        "file_size": info["file_size"],
        "vendor": info.get("vendor"),
        "model": info.get("model"),
        "version": info.get("version"),
        "source": "local",
        "file_type": info["file_type"],
        "magic_bytes": info["magic_bytes"],
        "filesystem": [
            {
                "type": extraction.get("method") or "unknown",
                "offset": 0,
                "size": info["file_size"],
                "extract_method": extraction.get("method") or "unknown",
            }
        ],
        "rootfs_path": best_rootfs["path"] if best_rootfs else None,
        "rootfs_candidates": rootfs_result["candidates"],
        "architecture": arch_result.get("architecture"),
        "bits": arch_result.get("bits"),
        "endian": arch_result.get("endian"),
        "libc": arch_result.get("libc"),
        "kernel_hint": info.get("kernel_hint") or arch_result.get("kernel_hint"),
        "web_servers": [],
        "elf_count": 0,
        "extraction_confidence": rootfs_result["extraction_confidence"],
        "status": extraction["status"],
        "tool_versions": info.get("tool_versions", {}),
    }

    # Count ELF files if a rootfs was found.
    if best_rootfs:
        root = Path(best_rootfs["path"])
        manifest["elf_count"] = sum(
            1 for p in iter_rootfs_files(root) if p.read_bytes()[:4] == b"\x7fELF"
        )

    validate(manifest, schema_name="firmware_manifest")
    save_json(layout.firmware_manifest, manifest)
    return manifest


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 4:
        print("Usage: python -m tools.firmware.build_manifest <firmware> <run_id> <run_root>")
        raise SystemExit(1)
    manifest = build_manifest(sys.argv[1], sys.argv[2], sys.argv[3])
    print(json.dumps(manifest, indent=2))
