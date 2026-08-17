"""Smoke-test the WSL tool wrappers used by the M2 integration tests."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(tool: str, args: list[str], timeout: int = 60) -> None:
    resolved = shutil.which(tool) or tool
    t0 = time.time()
    try:
        r = subprocess.run(
            [resolved] + args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        print(f"--- {tool} rc={r.returncode} t={time.time() - t0:.1f}s")
        print("  out", repr(r.stdout[:300]))
        print("  err", repr(r.stderr[:300]))
    except subprocess.TimeoutExpired:
        print(f"--- {tool} TIMEOUT after {time.time() - t0:.1f}s")


def main() -> int:
    p = shutil.which("mksquashfs")
    if not p:
        print("mksquashfs not found on PATH", file=sys.stderr)
        return 1
    d = Path(tempfile.mkdtemp())
    root = d / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    (root / "bin" / "busybox").write_text("busybox", encoding="utf-8")
    (root / "etc" / "init.d" / "rcS").write_text("#!/bin/sh\n", encoding="utf-8")
    img = d / "fixture.squashfs"
    run("mksquashfs", [str(root), str(img), "-noappend", "-quiet"], timeout=120)
    print("squashfs built, size", img.stat().st_size)
    run("file", [str(img)])
    run("strings", ["-n8", str(img)])
    run("binwalk", ["--signature", "--term", str(img)])
    run("unsquashfs", ["-d", str(d / "out"), str(img)])
    print("extracted:", sorted(p.name for p in (d / "out").rglob("*") if p.is_file()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
