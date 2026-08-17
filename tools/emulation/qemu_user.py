"""M8 L1: QEMU user-mode load check (architecture/loader/basic boot).

Runs the harmless ``busybox echo QEMU_OK`` baseline self-check under
``qemu-<arch>`` / ``qemu-<arch>-static`` to prove the binary can be loaded for
the target architecture. Missing QEMU binaries degrade to a ``skipped`` result
with an explicit limitation — never a crash.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from fsa.utils.proc import run_command

# Architecture -> candidate QEMU user-mode binary names.
ARCH_QEMU: dict[str, list[str]] = {
    "mipsel": ["qemu-mipsel-static", "qemu-mipsel"],
    "mips": ["qemu-mips-static", "qemu-mips"],
    "arm": ["qemu-arm-static", "qemu-arm"],
    "aarch64": ["qemu-aarch64-static", "qemu-aarch64"],
    "x86_64": ["qemu-x86_64-static", "qemu-x86_64"],
    "i386": ["qemu-i386-static", "qemu-i386"],
    "powerpc": ["qemu-ppc-static", "qemu-ppc"],
}

_QEMU_OK = "QEMU_OK"


def detect_qemu(arch: str) -> str | None:
    """Return the first available QEMU user-mode binary for ``arch``, or None."""
    for name in ARCH_QEMU.get(arch, []):
        if shutil.which(name):
            return name
    return None


def run_l1_load_check(
    rootfs: str | Path,
    arch: str,
    *,
    busybox: str = "bin/busybox",
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run the L1 load check for a target binary under QEMU user mode.

    Args:
        rootfs: Extracted root filesystem directory.
        arch: Canonical architecture (e.g. ``mips`` / ``mipsel`` / ``arm``).
        busybox: Relative path to busybox inside the rootfs.
        timeout: Max runtime in seconds.

    Returns:
        A dict with ``status`` (``success``/``skipped``/``failed``), ``qemu``
        (binary name or None), ``load_ok`` (bool or None), and the command
        output. A missing QEMU binary yields ``skipped`` with ``limitation``.
    """
    qemu = detect_qemu(arch)
    if qemu is None:
        return {
            "status": "skipped",
            "qemu": None,
            "load_ok": None,
            "limitation": f"no QEMU user-mode binary for architecture {arch!r}",
        }

    # The '-static' variant needs no -L; the dynamic one needs the rootfs as
    # the sysroot. Using -L with a static binary is harmless, so keep it simple.
    cmd = [qemu, "-L", str(rootfs), str(Path(rootfs) / busybox), "echo", _QEMU_OK]
    result = run_command(cmd, timeout=timeout)
    load_ok = result.status == "success" and _QEMU_OK in result.stdout

    out: dict[str, Any] = {
        "status": "success" if load_ok else "failed",
        "qemu": qemu,
        "load_ok": load_ok,
        "command": result.command,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
    # A /dev/mem exit is a known-harmless QEMU behaviour, not a load failure.
    if not load_ok and "dev/mem" in result.stderr:
        out["limitation"] = "binary exited at /dev/mem (expected QEMU behaviour)"
    return out
