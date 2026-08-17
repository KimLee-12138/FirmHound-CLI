"""Unit tests for JSON Schema definitions and examples."""

import json
from pathlib import Path

import pytest

from fsa.schemas.loader import get_registry, validate, validate_all_examples


@pytest.mark.parametrize("schema_name", sorted(get_registry()))
def test_example_validates(schema_name: str, tmp_path: str) -> None:
    """Each schema must have a matching example that validates."""
    example_path = (
        Path(__file__).resolve().parent.parent.parent
        / "schemas"
        / "examples"
        / f"{schema_name}.example.json"
    )
    assert example_path.exists(), f"Missing example for schema {schema_name}"
    with example_path.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    validate(doc, schema_name=schema_name)


def test_all_examples_validate() -> None:
    """No example should fail validation."""
    failures = validate_all_examples()
    assert not failures, failures
