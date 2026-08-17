"""Detect target architecture from ELF files in a rootfs.

Cross-validates architecture, bitness, endianness, libc, and kernel hints.
"""

from __future__ import annotations

import re
import shutil
import struct
from collections import Counter
from pathlib import Path
from typing import Any

from fsa.utils.proc import run_command
from fsa.utils.traverse import iter_rootfs_files

# Map readelf architecture strings to a canonical name.
ARCH_MAP: dict[str, str] = {
    "mips": "mips",
    "mipsel": "mipsel",
    "mipseb": "mips",
    "arm": "arm",
    "aarch64": "aarch64",
    "x86-64": "x86_64",
    "i386": "i386",
    "powerpc": "powerpc",
}


def _readelf_header(path: Path) -> dict[str, Any] | None:
    """Parse ``readelf -h`` output for a single ELF."""
    if shutil.which("readelf") is None:
        return None
    result = run_command(["readelf", "-h", str(path)], timeout=30)
    if result.status != "success":
        return None
    text = result.stdout
    info: dict[str, Any] = {}

    m = re.search(r"Machine:\s+(\S+)", text)
    info["machine"] = m.group(1).strip() if m else "unknown"

    m = re.search(r"Class:\s+(\S+)", text)
    info["class"] = m.group(1).strip() if m else "unknown"

    m = re.search(r"Data:\s+(.+)", text)
    info["data"] = m.group(1).strip() if m else "unknown"

    m = re.search(r"Entry point address:\s+(0x[0-9a-fA-F]+)", text)
    info["entry"] = m.group(1) if m else None

    return info


def _detect_libc(rootfs: Path) -> str | None:
    """Detect libc family from shared libraries."""
    lib_dirs = [rootfs / "lib", rootfs / "usr" / "lib", rootfs / "lib64"]
    for lib_dir in lib_dirs:
        if not lib_dir.exists():
            continue
        for path in lib_dir.glob("*.so*"):
            name = path.name.lower()
            if "uclibc" in name:
                return "uClibc"
            if "musl" in name:
                return "musl"
            if "libc.so" in name or "libc-" in name:
                return "glibc"
    return None


def _kernel_hints(rootfs: Path) -> dict[str, Any]:
    """Extract kernel version / vermagic from kernel modules."""
    hints: dict[str, Any] = {"version": None, "vermagic": None}
    for ko in iter_rootfs_files(rootfs):
        if ko.suffix != ".ko":
            continue
        result = run_command(["modinfo", str(ko)], timeout=10)
        if result.status == "success":
            m = re.search(r"vermagic:\s+(.+)", result.stdout)
            if m:
                hints["vermagic"] = m.group(1).strip()
        # Only inspect first few modules.
        if hints["vermagic"]:
            break

    # Look for Linux version string in /lib/modules or boot.
    for candidate in [rootfs / "lib" / "modules", rootfs / "boot"]:
        if candidate.exists():
            for child in candidate.iterdir():
                if re.match(r"^\d+\.\d+", child.name):
                    hints["version"] = child.name
                    break
    return hints


def _parse_elf_magic(path: Path) -> dict[str, Any] | None:
    """Parse architecture from ELF header when readelf is unavailable."""
    with path.open("rb") as fh:
        header = fh.read(52)
    if len(header) < 52 or header[:4] != b"\x7fELF":
        return None

    ei_class = header[4]
    ei_data = header[5]
    endian_flag = "<" if ei_data == 1 else ">"
    bits = "ELF32" if ei_class == 1 else ("ELF64" if ei_class == 2 else "unknown")
    endian = "little" if ei_data == 1 else ("big" if ei_data == 2 else "unknown")

    # e_type at offset 16, e_machine at offset 18 (both 2 bytes).
    _e_type = struct.unpack_from(f"{endian_flag}H", header, 16)[0]
    machine = struct.unpack_from(f"{endian_flag}H", header, 18)[0]
    entry = struct.unpack_from(f"{endian_flag}I", header, 24)[0]

    machine_names: dict[int, str] = {
        0x02: "SPARC",
        0x03: "i386",
        0x08: "MIPS",
        0x14: "PowerPC",
        0x28: "ARM",
        0x3E: "x86-64",
        0xB7: "AArch64",
    }
    return {
        "machine": machine_names.get(machine, f"unknown(0x{machine:04x})"),
        "class": bits,
        "data": f"2's complement, {endian} endian",
        "entry": f"0x{entry:08x}",
    }


def detect_architecture(rootfs_dir: str | Path, max_samples: int = 20) -> dict[str, Any]:
    """Detect architecture by sampling ELF files in ``rootfs_dir``.

    Args:
        rootfs_dir: Root filesystem directory.
        max_samples: Maximum number of ELF files to sample.

    Returns:
        Dict with canonical ``architecture``, ``bits``, ``endian``, ``libc``,
        ``kernel_hint``, ``samples``, ``warning`` (if inconsistent), and
        ``qemu_binary`` recommendation.
    """
    root = Path(rootfs_dir)
    if not root.exists():
        raise FileNotFoundError(f"Rootfs directory not found: {root}")

    use_readelf = shutil.which("readelf") is not None
    samples: list[dict[str, Any]] = []
    for path in iter_rootfs_files(root):
        if path.stat().st_size < 4:
            continue
        with path.open("rb") as fh:
            magic = fh.read(4)
        if magic != b"\x7fELF":
            continue
        header = _readelf_header(path) if use_readelf else _parse_elf_magic(path)
        if header:
            samples.append(
                {
                    "path": str(path.relative_to(root)),
                    **header,
                }
            )
        if len(samples) >= max_samples:
            break

    if not samples:
        return {
            "architecture": "unknown",
            "bits": None,
            "endian": None,
            "libc": _detect_libc(root),
            "kernel_hint": _kernel_hints(root),
            "samples": samples,
            "warning": "no ELF samples found",
            "qemu_binary": None,
        }

    arch_counter: Counter[str] = Counter()
    bits_counter: Counter[str] = Counter()
    endian_counter: Counter[str] = Counter()

    for s in samples:
        raw_machine = s.get("machine", "unknown")
        canonical = ARCH_MAP.get(raw_machine.lower(), raw_machine.lower())
        arch_counter[canonical] += 1
        bits_counter[s.get("class", "unknown")] += 1
        data = s.get("data", "")
        if "little" in data.lower():
            endian_counter["little"] += 1
        elif "big" in data.lower():
            endian_counter["big"] += 1

    architecture = arch_counter.most_common(1)[0][0]
    bits = bits_counter.most_common(1)[0][0]
    endian = endian_counter.most_common(1)[0][0] if endian_counter else None

    warning: str | None = None
    if len(arch_counter) > 1:
        warning = f"mixed architectures: {dict(arch_counter)}"

    qemu_binary = _qemu_binary(architecture)

    return {
        "architecture": architecture,
        "bits": bits,
        "endian": endian,
        "libc": _detect_libc(root),
        "kernel_hint": _kernel_hints(root),
        "samples": samples,
        "warning": warning,
        "qemu_binary": qemu_binary,
    }


def _qemu_binary(architecture: str) -> str | None:
    """Recommend a QEMU user-mode binary name."""
    table: dict[str, str] = {
        "mipsel": "qemu-mipsel",
        "mips": "qemu-mips",
        "arm": "qemu-arm",
        "aarch64": "qemu-aarch64",
        "x86_64": "qemu-x86_64",
        "i386": "qemu-i386",
        "powerpc": "qemu-ppc",
    }
    return table.get(architecture)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.firmware.arch_detect <rootfs_dir>")
        raise SystemExit(1)
    print(json.dumps(detect_architecture(sys.argv[1]), indent=2))
