"""JSON file read/write helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> Any:
    """Load JSON from a file."""
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path: str | Path, data: Any, *, indent: int = 2) -> None:
    """Save ``data`` to a JSON file atomically."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent, ensure_ascii=False)
        fh.write("\n")
    tmp.replace(target)
