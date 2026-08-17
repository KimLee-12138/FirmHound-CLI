"""Inventory a rootfs directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.utils.traverse import iter_rootfs_dirs, iter_rootfs_files

SCRIPT_EXTENSIONS = {".sh", ".lua", ".php", ".py", ".cgi", ".js"}
CONFIG_DIRS = {"etc", "conf", "config", "configs"}
WEBROOT_NAMES = {"www", "htdocs", "web", "webroot", "html"}


def inventory_rootfs(rootfs_dir: str | Path) -> dict[str, Any]:
    """Create a structured inventory of a rootfs.

    Returns counts and paths for ELF binaries, scripts, configuration files,
    webroots, and startup scripts. Traversal is symlink-safe: entries that
    cannot be stat'ed (e.g. symlinks to Linux-only paths on Windows) are
    skipped rather than aborting the run.
    """
    root = Path(rootfs_dir)
    if not root.exists():
        raise FileNotFoundError(f"Rootfs not found: {root}")

    elfs: list[str] = []
    scripts: list[str] = []
    configs: list[str] = []
    startup_scripts: list[str] = []
    webroots: list[str] = []

    for path in iter_rootfs_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            magic = path.read_bytes()[:4]
        except OSError:
            continue

        if magic == b"\x7fELF":
            elfs.append(rel)
        elif path.suffix.lower() in SCRIPT_EXTENSIONS:
            scripts.append(rel)
        elif _is_config(path):
            configs.append(rel)

        if _is_startup_script(path):
            startup_scripts.append(rel)

    # Also look for webroot directories that may be nested (e.g. usr/www).
    for path in iter_rootfs_dirs(root):
        if path.name.lower() in WEBROOT_NAMES:
            webroots.append(path.relative_to(root).as_posix())

    return {
        "rootfs": str(root.resolve()),
        "elf_count": len(elfs),
        "elf_paths": elfs,
        "script_count": len(scripts),
        "script_paths": scripts,
        "config_count": len(configs),
        "config_paths": configs,
        "startup_script_count": len(startup_scripts),
        "startup_script_paths": startup_scripts,
        "webroots": webroots,
    }


def _is_config(path: Path) -> bool:
    """Heuristic: file is a config if under a config dir or has common suffix."""
    suffixes = {".conf", ".cfg", ".ini", ".xml", ".json", ".yaml", ".yml"}
    if path.suffix.lower() in suffixes:
        return True
    return any(part.lower() in CONFIG_DIRS for part in path.parts)


def _is_startup_script(path: Path) -> bool:
    """Heuristic: file is a startup script if path contains init.d/rcS/rc.local."""
    parts = [p.lower() for p in path.parts]
    return any(p in parts for p in ("init.d", "rc.d", "rcs", "rc.local")) or path.name in (
        "rcS",
        "rc.local",
    )


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.filesystem.inventory <rootfs_dir>")
        raise SystemExit(1)
    print(json.dumps(inventory_rootfs(sys.argv[1]), indent=2))
