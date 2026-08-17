"""Tests for run state, evidence store, and decision store persistence."""

from pathlib import Path

from fsa.reporting.decision_store import DecisionStore
from fsa.reporting.evidence_store import EvidenceStore
from fsa.reporting.run_state import RunState
from fsa.reporting.store_base import RunLayout


def test_run_layout_paths(tmp_path: Path) -> None:
    """RunLayout creates expected subdirectories and paths."""
    layout = RunLayout("run-001", tmp_path)
    assert layout.root.exists()
    assert layout.task_card == layout.root / "task_card.json"
    assert layout.evidence_dir == layout.root / "evidence"
    assert layout.binary_summary_path("bin-1").parent.exists()


def test_run_state_create_and_update(tmp_path: Path) -> None:
    """RunState creates valid initial state and persists updates."""
    state = RunState.create(tmp_path, run_id="run-002")
    assert state.run_id == "run-002"
    assert state.to_dict()["status"] == "running"

    state.set_stage("surface")
    state.complete_stage("init")
    state.add_artifact("manifest", str(tmp_path / "run-002" / "firmware_manifest.json"))
    state.add_decision("dec-001")
    state.add_token_usage(prompt=100, completion=20, calls=1)

    reloaded = RunState.resume("run-002", tmp_path)
    data = reloaded.to_dict()
    assert data["current_stage"] == "surface"
    assert "init" in data["completed_stages"]
    assert "manifest" in data["artifacts"]
    assert "dec-001" in data["decisions"]
    assert data["token_usage"]["prompt_tokens"] == 100


def test_evidence_store(tmp_path: Path) -> None:
    """EvidenceStore persists items and supports lookup."""
    store = EvidenceStore("run-003", tmp_path)
    item = store.add(
        run_id="run-003",
        stage="surface",
        type="command_output",
        observation="Found pre-auth endpoint",
        tool="grep",
        supports=["surf-001"],
    )
    assert item["evidence_id"].startswith("ev-")
    loaded = store.get(item["evidence_id"])
    assert loaded is not None
    assert loaded["observation"] == "Found pre-auth endpoint"
    assert store.find_supporting("surf-001")[0]["evidence_id"] == item["evidence_id"]


def test_decision_store(tmp_path: Path) -> None:
    """DecisionStore persists records."""
    store = DecisionStore("run-004", tmp_path)
    record = store.add(
        stage="surface",
        observation="Pre-auth surface found",
        options=["continue", "skip"],
        selected="continue",
        reason="Worth deeper analysis",
        confidence=0.9,
        next_stage="binary",
    )
    assert record["decision_id"].startswith("dec-")
    loaded = store.get(record["decision_id"])
    assert loaded is not None
    assert loaded["selected"] == "continue"
    assert len(store.list_all()) == 1
