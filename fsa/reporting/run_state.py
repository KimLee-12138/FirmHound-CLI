"""Run state persistence."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fsa.reporting.store_base import RunLayout
from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json


@dataclass
class TokenUsage:
    """Token usage counters for a run."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "calls": self.calls,
        }

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> TokenUsage:
        return cls(**data)


class RunState:
    """Read/write run state under the canonical run directory layout."""

    VALID_STATUSES = {"running", "paused", "done", "aborted"}

    def __init__(self, run_id: str, run_root: str | Path) -> None:
        self.run_id = run_id
        self.layout = RunLayout(run_id, run_root)
        self.layout.root.mkdir(parents=True, exist_ok=True)
        self._path = self.layout.run_state
        self._state: dict[str, Any] = self._initial_state()

    def _initial_state(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "task_card_ref": str(self.layout.task_card),
            "current_stage": "init",
            "completed_stages": [],
            "failed_stages": [],
            "retry_count": {},
            "artifacts": {},
            "decisions": [],
            "token_usage": TokenUsage().to_dict(),
            "status": "running",
            "resume_token": f"resume-{self.run_id}-init",
        }

    def load(self) -> dict[str, Any]:
        """Load existing run state from disk."""
        if self._path.exists():
            self._state = load_json(self._path)
        return self._state

    def save(self) -> None:
        """Persist current run state after schema validation."""
        validate(self._state, schema_name="run_state")
        save_json(self._path, self._state)

    def set_stage(self, stage: str) -> None:
        """Set current stage and update resume token."""
        self._state["current_stage"] = stage
        self._state["resume_token"] = f"resume-{self.run_id}-{stage}"
        self.save()

    def complete_stage(self, stage: str) -> None:
        """Mark a stage as completed."""
        completed: list[str] = self._state.setdefault("completed_stages", [])
        if stage not in completed:
            completed.append(stage)
        self.save()

    def fail_stage(self, stage: str) -> None:
        """Mark a stage as failed."""
        failed: list[str] = self._state.setdefault("failed_stages", [])
        if stage not in failed:
            failed.append(stage)
        self.save()

    def add_artifact(self, name: str, path: str | Path) -> None:
        """Register an artifact path."""
        self._state.setdefault("artifacts", {})[name] = str(path)
        self.save()

    def add_decision(self, decision_id: str) -> None:
        """Register a decision reference."""
        decisions: list[str] = self._state.setdefault("decisions", [])
        if decision_id not in decisions:
            decisions.append(decision_id)
        self.save()

    def add_token_usage(self, prompt: int = 0, completion: int = 0, calls: int = 0) -> None:
        """Add token usage counters."""
        usage = self._state.setdefault("token_usage", TokenUsage().to_dict())
        usage["prompt_tokens"] = usage.get("prompt_tokens", 0) + prompt
        usage["completion_tokens"] = usage.get("completion_tokens", 0) + completion
        usage["calls"] = usage.get("calls", 0) + calls
        self.save()

    def set_status(self, status: str) -> None:
        """Set final or intermediate status."""
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        self._state["status"] = status
        self.save()

    def to_dict(self) -> dict[str, Any]:
        """Return current state as a dictionary."""
        return self._state

    @classmethod
    def create(cls, run_root: str | Path, run_id: str | None = None) -> RunState:
        """Create a new run state with a generated or supplied run id."""
        run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        instance = cls(run_id, run_root)
        instance.save()
        return instance

    @classmethod
    def resume(cls, run_id: str, run_root: str | Path) -> RunState:
        """Resume an existing run state."""
        instance = cls(run_id, run_root)
        instance.load()
        return instance
