"""Evidence store: persistent, indexed evidence items per run."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fsa.reporting.store_base import RunLayout
from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json


class EvidenceStore:
    """Store evidence items as individual JSON files and provide lookups."""

    def __init__(self, run_id: str, run_root: str | Path) -> None:
        self.layout = RunLayout(run_id, run_root)

    def add(
        self,
        *,
        run_id: str,
        stage: str,
        type: str,  # noqa: A002
        observation: str,
        tool: str,
        tool_version: str = "unknown",
        source_file: str | None = None,
        command: str | None = None,
        artifact_path: str | None = None,
        fact_status: str = "confirmed",
        supports: list[str] | None = None,
        contradicts: list[str] | None = None,
        evidence_id: str | None = None,
    ) -> dict[str, Any]:
        """Add a new evidence item and persist it."""
        evidence_id = evidence_id or f"ev-{uuid.uuid4().hex[:12]}"
        item = {
            "evidence_id": evidence_id,
            "run_id": run_id,
            "stage": stage,
            "type": type,
            "source_file": source_file,
            "command": command,
            "tool": tool,
            "tool_version": tool_version,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "artifact_path": artifact_path,
            "observation": observation,
            "fact_status": fact_status,
            "supports": supports or [],
            "contradicts": contradicts or [],
        }
        validate(item, schema_name="evidence")
        save_json(self.layout.evidence_path(evidence_id), item)
        return item

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        """Load a single evidence item."""
        path = self.layout.evidence_path(evidence_id)
        if not path.exists():
            return None
        return load_json(path)

    def list_all(self) -> list[dict[str, Any]]:
        """Load all evidence items for the run."""
        items: list[dict[str, Any]] = []
        if not self.layout.evidence_dir.exists():
            return items
        for path in sorted(self.layout.evidence_dir.glob("*.json")):
            items.append(load_json(path))
        return items

    def find_supporting(self, target_id: str) -> list[dict[str, Any]]:
        """Return evidence items that support ``target_id``."""
        return [item for item in self.list_all() if target_id in item.get("supports", [])]
