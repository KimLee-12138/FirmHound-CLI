"""JSON/YAML file read/write helpers."""

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


def load_yaml(path: str | Path) -> Any:
    """Load YAML from a file."""
    import yaml

    with Path(path).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def save_yaml(path: str | Path, data: Any) -> None:
    """Save ``data`` to a YAML file atomically."""
    import yaml

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)
    tmp.replace(target)
