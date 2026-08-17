"""Load JSON Schemas and validate documents against them.

All schemas live in ``schemas/`` at the project root. This module resolves
that directory relative to the repository root so that validation works from
any working directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema


_REGISTRY: dict[str, dict[str, Any]] | None = None


def _repo_root() -> Path:
    """Return the repository root directory.

    The root is located by walking up from this file until ``pyproject.toml``
    is found.
    """
    here = Path(__file__).resolve().parent
    for parent in [here, *here.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    msg = "Could not locate repository root (no pyproject.toml found)"
    raise RuntimeError(msg)


def schema_dir() -> Path:
    """Return the ``schemas/`` directory."""
    return _repo_root() / "schemas"


def load_schema(name: str) -> dict[str, Any]:
    """Load a JSON Schema by short name, e.g. ``task_card``.

    The file is resolved as ``schemas/{name}.schema.json``.
    """
    path = schema_dir() / f"{name}.schema.json"
    if not path.exists():
        msg = f"Schema not found: {path}"
        raise FileNotFoundError(msg)
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def get_registry() -> dict[str, dict[str, Any]]:
    """Return a cached dict mapping schema short names to schema objects."""
    global _REGISTRY  # noqa: PLW0603
    if _REGISTRY is not None:
        return _REGISTRY

    registry: dict[str, dict[str, Any]] = {}
    for path in sorted(schema_dir().glob("*.schema.json")):
        short = path.stem.replace(".schema", "")
        registry[short] = load_schema(short)
    _REGISTRY = registry
    return registry


def validate(document: Any, *, schema_name: str) -> None:
    """Validate ``document`` against the named schema.

    Raises:
        jsonschema.ValidationError: If the document is invalid.
        FileNotFoundError: If the schema does not exist.
    """
    schema = load_schema(schema_name)
    jsonschema.validate(instance=document, schema=schema)


def validate_all_examples() -> list[tuple[str, Exception]]:
    """Validate every file in ``schemas/examples/``.

    Returns a list of ``(example_file, exception)`` for failures. An empty list
    means all examples passed.
    """
    failures: list[tuple[str, Exception]] = []
    examples_dir = schema_dir() / "examples"
    if not examples_dir.exists():
        return failures

    for path in sorted(examples_dir.glob("*.example.json")):
        stem = path.stem
        # example filename convention: {schema_name}.example.json
        schema_name = stem.replace(".example", "")
        try:
            with path.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
            validate(doc, schema_name=schema_name)
        except Exception as exc:  # noqa: BLE001
            failures.append((str(path), exc))
    return failures


if __name__ == "__main__":
    failures = validate_all_examples()
    if failures:
        for path, exc in failures:
            print(f"FAIL {path}: {exc}")
        raise SystemExit(1)
    print(f"All {len(list(schema_dir().glob('*.schema.json')))} schemas and examples are valid.")
