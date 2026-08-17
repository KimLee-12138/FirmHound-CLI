"""Enumerate endpoints from a webroot directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.utils.traverse import iter_rootfs_dirs, iter_rootfs_files

ENDPOINT_SUFFIXES = {".cgi", ".asp", ".aspx", ".php", ".lua", ".json", ".xml", ".htm", ".html"}
WEBROOT_NAMES = {"www", "htdocs", "web", "webroot", "html"}
FUNCTIONAL_KEYWORDS: dict[str, list[str]] = {
    "auth": ["login", "logout", "auth", "session", "password", "token"],
    "config": ["config", "setting", "setup", "wizard"],
    "command": ["command", "exec", "cmd", "cli", "system", "form"],
    "upgrade": ["upgrade", "update", "firmware", "restore"],
    "status": ["status", "info", "diag", "log", "statistics"],
    "debug": ["debug", "test", "ping", "traceroute"],
}


def classify_endpoint(name: str) -> list[str]:
    """Classify an endpoint name into functional categories."""
    lowered = name.lower()
    categories: list[str] = []
    for category, keywords in FUNCTIONAL_KEYWORDS.items():
        if any(kw in lowered for kw in keywords):
            categories.append(category)
    return categories or ["unknown"]


def enumerate_webroot(webroot_dir: str | Path) -> dict[str, Any]:
    """Enumerate all likely endpoints under a webroot.

    Returns a dict with endpoint list, grouped by category, and static asset count.
    """
    root = Path(webroot_dir)
    if not root.exists():
        raise FileNotFoundError(f"Webroot not found: {root}")

    endpoints: list[dict[str, Any]] = []
    static_assets = 0

    for path in iter_rootfs_files(root):
        rel = path.relative_to(root)
        route = "/" + "/".join(rel.parts)
        suffix = path.suffix.lower()

        if suffix in {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg"}:
            static_assets += 1
            continue

        if (
            suffix in ENDPOINT_SUFFIXES
            or path.name in {"index.html", "index.htm"}
            or "goform" in [p.lower() for p in rel.parts]
            or "cgi-bin" in [p.lower() for p in rel.parts]
        ):
            categories = classify_endpoint(path.name)
            endpoints.append(
                {
                    "route": route,
                    "file": str(rel),
                    "handler": str(rel),
                    "category": categories,
                    "suffix": suffix,
                }
            )

    endpoints.sort(key=lambda x: x["route"])
    return {
        "webroot": str(root.resolve()),
        "endpoint_count": len(endpoints),
        "static_asset_count": static_assets,
        "endpoints": endpoints,
    }


def find_webroots(rootfs_dir: str | Path) -> list[Path]:
    """Find candidate webroot directories inside a rootfs."""
    root = Path(rootfs_dir)
    candidates: list[Path] = []
    for path in iter_rootfs_dirs(root):
        if path.name.lower() in WEBROOT_NAMES:
            candidates.append(path)
    return candidates


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.web.webroot_enum <webroot_dir>")
        raise SystemExit(1)
    print(json.dumps(enumerate_webroot(sys.argv[1]), indent=2))
