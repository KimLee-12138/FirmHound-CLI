"""Human-in-the-loop injection points."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fsa.reporting.evidence_store import EvidenceStore
from fsa.utils.jsonio import save_json


class HumanGate:
    """Allow operators to inject evidence or override verdicts mid-run."""

    def __init__(self, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir)
        self.evidence_store = EvidenceStore(run_dir)

    def inject_evidence(
        self,
        evidence_type: str,
        content: str,
        source: str = "human_input",
        stage: str = "unknown",
    ) -> dict[str, Any]:
        """Create an evidence entry from human input and store it."""
        evidence = {
            "evidence_id": self.evidence_store.next_id(),
            "type": evidence_type,
            "source": source,
            "stage": stage,
            "observation": content,
            "fact_status": "confirmed",
            "supports": [],
            "contradicts": [],
        }
        self.evidence_store.append(evidence)
        return evidence

    def override_verdict(self, candidate_id: str, verdict: str, reason: str) -> dict[str, Any]:
        """Record a human verdict override."""
        override = {
            "candidate_id": candidate_id,
            "verdict": verdict,
            "reason": reason,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        path = self.run_dir / "state" / "human_overrides.json"
        overrides: list[dict[str, Any]] = []
        if path.exists():
            from fsa.utils.jsonio import load_json

            overrides = load_json(path)
        overrides.append(override)
        save_json(path, overrides)
        return override

    def list_pending_questions(self) -> list[dict[str, Any]]:
        """Return open human_gate questions from run_state."""
        from fsa.utils.jsonio import load_json

        state_path = self.run_dir / "state" / "run_state.json"
        if not state_path.exists():
            return []
        state = load_json(state_path)
        return state.get("human_gate", {}).get("pending", [])
