"""Robust filesystem traversal for extracted rootfs trees.

Real firmware rootfs trees contain Linux-only entries that Windows cannot
stat: symbolic links to absolute paths (``/dev/null``), device nodes,
sockets, FIFOs. A naive ``Path.rglob()`` + ``is_file()`` loop crashes with
``OSError: [WinError 1920]`` on such entries, which aborts the whole
pipeline mid-run.

These helpers traverse with ``os.walk(followlinks=False)``, skip symlinks
and special files, and swallow per-entry stat errors so a single bad entry
degrades to a warning instead of a hard failure.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path


def iter_rootfs_files(root: str | Path) -> Iterator[Path]:
    """Yield regular files under ``root``, skipping unreadable entries.

    Symbolic links, sockets, FIFOs and device nodes are skipped entirely
    (they are not analyzable as files anyway), and any path whose stat
    fails (e.g. a symlink pointing to a Linux-only absolute path on
    Windows) is skipped instead of raising.
    """
    root = Path(root)
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Never descend into symlinked directories (may point outside rootfs).
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            try:
                if path.is_file():
                    yield path
            except OSError:
                continue


def iter_rootfs_dirs(root: str | Path) -> Iterator[Path]:
    """Yield directories under ``root`` (non-recursive walk, symlink-safe)."""
    root = Path(root)
    if not root.exists():
        return
    for dirpath, dirnames, _ in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in dirnames:
            path = Path(dirpath) / name
            try:
                if path.is_dir():
                    yield path
            except OSError:
                continue
