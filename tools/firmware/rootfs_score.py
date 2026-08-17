"""Score candidate rootfs directories extracted from a firmware image.

The highest-scoring directory is selected, but all candidates are returned so
that downstream modules can handle ambiguous cases.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MARKERS: dict[str, int] = {
    "has_bin": 1,
    "has_sbin": 1,
    "has_etc": 1,
    "has_lib": 1,
    "has_usr": 1,
    "has_web": 1,
    "has_initd": 1,
    "has_busybox": 1,
    "has_httpd": 2,
}


def _score_directory(path: Path) -> dict[str, Any]:
    """Return score details for a single candidate directory."""
    score = 0
    markers: list[str] = []

    checks = [
        ("has_bin", path / "bin"),
        ("has_sbin", path / "sbin"),
        ("has_etc", path / "etc"),
        ("has_lib", path / "lib"),
        ("has_usr", path / "usr"),
        ("has_busybox", path / "bin" / "busybox"),
        ("has_initd", path / "etc" / "init.d"),
    ]

    for marker, target in checks:
        if target.exists():
            if marker == "has_initd":
                # init.d must be non-empty to count.
                if target.is_dir() and any(target.iterdir()):
                    score += MARKERS[marker]
                    markers.append(marker)
            else:
                score += MARKERS[marker]
                markers.append(marker)

    # Web root markers
    web_dirs = [path / "www", path / "htdocs", path / "web", path / "usr" / "www"]
    if any(d.is_dir() for d in web_dirs):
        score += MARKERS["has_web"]
        markers.append("has_web")

    # HTTP daemon markers
    httpd_bins = [
        path / "usr" / "sbin" / "httpd",
        path / "bin" / "httpd",
        path / "usr" / "bin" / "goahead",
        path / "usr" / "sbin" / "goahead",
        path / "bin" / "goahead",
    ]
    if any(b.exists() for b in httpd_bins):
        score += MARKERS["has_httpd"]
        markers.append("has_httpd")

    return {
        "path": str(path.resolve()),
        "score": score,
        "markers": markers,
    }


def score_rootfs_candidates(extracted_dir: str | Path) -> dict[str, Any]:
    """Score all candidate rootfs directories under ``extracted_dir``.

    A directory is considered a candidate if it contains at least one of
    ``bin``, ``sbin``, ``etc``, ``lib``, or ``usr``.

    Returns:
        Dict with ``candidates`` (sorted by score desc), ``best``,
        ``extraction_confidence``, and ``threshold_met``.
    """
    root = Path(extracted_dir)
    if not root.exists():
        raise FileNotFoundError(f"Extracted directory not found: {root}")

    candidates: list[dict[str, Any]] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        # Treat the root itself as a candidate if it has typical top-level dirs.
        has_top_level = any(
            (root / name).is_dir() for name in ("bin", "sbin", "etc", "lib", "usr")
        )
        if has_top_level and root not in [Path(c["path"]) for c in candidates]:
            candidates.append(_score_directory(root))
        if any((child / name).is_dir() for name in ("bin", "sbin", "etc", "lib", "usr")):
            candidates.append(_score_directory(child))

    # Deduplicate by path.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for c in candidates:
        if c["path"] not in seen:
            seen.add(c["path"])
            unique.append(c)

    unique.sort(key=lambda x: x["score"], reverse=True)
    best = unique[0] if unique else None
    confidence = 0.0
    if best:
        if best["score"] >= 7:
            confidence = 1.0
        elif best["score"] >= 5:
            confidence = 0.7
        else:
            confidence = 0.3

    return {
        "candidates": unique,
        "best": best,
        "extraction_confidence": confidence,
        "threshold_met": best is not None and best["score"] >= 5,
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.firmware.rootfs_score <extracted_dir>")
        raise SystemExit(1)
    print(json.dumps(score_rootfs_candidates(sys.argv[1]), indent=2))
