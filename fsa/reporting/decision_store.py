"""Decision store: persistent decision records per run."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fsa.reporting.store_base import RunLayout
from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json


class DecisionStore:
    """Store decision records as individual JSON files."""

    def __init__(self, run_id: str, run_root: str | Path) -> None:
        self.layout = RunLayout(run_id, run_root)

    def add(
        self,
        *,
        stage: str,
        observation: str,
        options: list[str],
        selected: str,
        reason: str,
        confidence: float,
        next_stage: str,
        actor: str = "rule",
        inputs: list[str] | None = None,
        decision_id: str | None = None,
    ) -> dict[str, Any]:
        """Add a decision record and persist it."""
        decision_id = decision_id or f"dec-{uuid.uuid4().hex[:12]}"
        record = {
            "decision_id": decision_id,
            "stage": stage,
            "inputs": inputs or [],
            "observation": observation,
            "options": options,
            "selected": selected,
            "reason": reason,
            "confidence": confidence,
            "next_stage": next_stage,
            "actor": actor,
        }
        validate(record, schema_name="decision")
        save_json(self.layout.decision_path(decision_id), record)
        return record

    def get(self, decision_id: str) -> dict[str, Any] | None:
        """Load a single decision record."""
        path = self.layout.decision_path(decision_id)
        if not path.exists():
            return None
        return load_json(path)

    def list_all(self) -> list[dict[str, Any]]:
        """Load all decisions for the run."""
        records: list[dict[str, Any]] = []
        if not self.layout.decision_dir.exists():
            return records
        for path in sorted(self.layout.decision_dir.glob("*.json")):
            records.append(load_json(path))
        return records
