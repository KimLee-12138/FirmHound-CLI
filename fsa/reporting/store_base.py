"""Canonical run directory layout shared by all persistence modules."""

from __future__ import annotations

from pathlib import Path


class RunLayout:
    """Defines the on-disk layout for a single analysis run."""

    def __init__(self, run_id: str, run_root: str | Path) -> None:
        self.run_id = run_id
        self.root = Path(run_root) / run_id
        self.root.mkdir(parents=True, exist_ok=True)

    @property
    def task_card(self) -> Path:
        return self.root / "task_card.json"

    @property
    def firmware_manifest(self) -> Path:
        return self.root / "firmware_manifest.json"

    @property
    def attack_surface(self) -> Path:
        return self.root / "attack_surface.json"

    @property
    def candidates(self) -> Path:
        return self.root / "candidates.json"

    @property
    def verdict(self) -> Path:
        return self.root / "verdict.json"

    @property
    def final_verdict(self) -> Path:
        return self.root / "final_verdict.json"

    @property
    def report(self) -> Path:
        return self.root / "report.md"

    @property
    def run_state(self) -> Path:
        return self.root / "run_state.json"

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def decision_dir(self) -> Path:
        return self.root / "decisions"

    @property
    def binaries_dir(self) -> Path:
        return self.root / "binaries"

    def evidence_path(self, evidence_id: str) -> Path:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        return self.evidence_dir / f"{evidence_id}.json"

    def decision_path(self, decision_id: str) -> Path:
        self.decision_dir.mkdir(parents=True, exist_ok=True)
        return self.decision_dir / f"{decision_id}.json"

    def binary_summary_path(self, binary_id: str) -> Path:
        d = self.binaries_dir / binary_id
        d.mkdir(parents=True, exist_ok=True)
        return d / "binary_summary.json"
