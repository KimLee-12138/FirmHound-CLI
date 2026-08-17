"""Parse startup scripts to extract running services and their arguments."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

SERVICE_PATTERNS = [
    re.compile(r"^\s*(?:/usr)?/s?bin/(\S+)\s+(.+)$"),
    re.compile(r"^\s*(\S+/\S+)\s+(.+)$"),
]

IGNORED_BINARIES = {"echo", "mkdir", "chmod", "chown", "rm", "cp", "mv", "sleep", "printf"}


def parse_startup_script(path: Path) -> list[dict[str, Any]]:
    """Parse a single startup script and extract service invocations."""
    services: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return services

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and "(" not in line.split("=")[0]:
            continue

        binary, args = _extract_command(line)
        if not binary:
            continue
        if Path(binary).name in IGNORED_BINARIES:
            continue

        services.append(
            {
                "binary": binary,
                "args": args,
                "source_file": str(path),
                "line": lineno,
                "raw": raw,
            }
        )
    return services


def _extract_command(line: str) -> tuple[str, str]:
    """Try to extract binary and arguments from a shell line."""
    # Remove shell control characters and background markers.
    cleaned = re.sub(r"[&|;`\\]", " ", line).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        return "", ""

    # Strip common prefixes like /usr/bin/env.
    if cleaned.startswith("/usr/bin/env "):
        cleaned = cleaned[len("/usr/bin/env ") :]

    tokens = cleaned.split()
    if not tokens:
        return "", ""
    binary = tokens[0]
    args = " ".join(tokens[1:])

    # Handle eval / source / .  by skipping the keyword.
    if binary in ("eval", "source", ".") and len(tokens) > 1:
        binary = tokens[1]
        args = " ".join(tokens[2:])

    return binary, args


def parse_all_startup(rootfs_dir: str | Path) -> dict[str, Any]:
    """Find and parse all startup scripts under ``rootfs_dir``.

    Returns a dict mapping service binary paths to lists of invocation records.
    """
    root = Path(rootfs_dir)
    if not root.exists():
        raise FileNotFoundError(f"Rootfs not found: {root}")

    all_services: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _is_startup_path(path):
            all_services.extend(parse_startup_script(path))

    # Group by binary basename.
    grouped: dict[str, list[dict[str, Any]]] = {}
    for svc in all_services:
        name = Path(svc["binary"]).name
        grouped.setdefault(name, []).append(svc)

    return {
        "rootfs": str(root.resolve()),
        "service_count": len(all_services),
        "services": all_services,
        "grouped": grouped,
    }


def _is_startup_path(path: Path) -> bool:
    """Heuristic to identify startup-related files."""
    parts = [p.lower() for p in path.parts]
    return any(p in parts for p in ("init.d", "rc.d", "rcS")) or path.name.lower() in {
        "rcs",
        "rc.local",
        "inittab",
        "profile",
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.filesystem.startup_parse <rootfs_dir>")
        raise SystemExit(1)
    print(json.dumps(parse_all_startup(sys.argv[1]), indent=2))
