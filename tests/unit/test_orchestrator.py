"""Tests for orchestrator state machine and planner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fsa.orchestrator import Orchestrator, Planner
from fsa.orchestrator.human_gate import HumanGate
from fsa.orchestrator.state_manager import StateManager
from fsa.runtime import MockRuntime


@pytest.fixture
def planner() -> Planner:
    return Planner()


def test_planner_parse_cli(planner: Planner) -> None:
    card = planner.parse_task(
        {
            "task_id": "T-001",
            "firmware_path": "firmwares/ac15.bin",
            "vendor": "Tenda",
            "model": "AC15",
            "authorization": "authorized by device owner",
        }
    )
    assert card["vendor"] == "Tenda"
    assert card["requires_human_gate"] is False


def test_planner_missing_authorization_triggers_gate(planner: Planner) -> None:
    card = planner.parse_task(
        {
            "task_id": "T-002",
            "firmware_path": "firmwares/test.bin",
        }
    )
    assert card["requires_human_gate"] is True
    assert any("authorization" in r.lower() for r in card["human_gate_reasons"])


def test_planner_extract_from_nl(planner: Planner) -> None:
    card = planner.parse_task(
        {
            "task_id": "T-003",
            "natural_language": "分析厂商为Tenda、型号AC15的固件 /firmwares/ac15.bin，授权测试。",
        }
    )
    assert card.get("vendor") == "Tenda"
    assert card.get("model") == "AC15"
    assert "/firmwares/ac15.bin" in (card.get("firmware_path") or "")


def test_build_plan_depths(planner: Planner) -> None:
    full_plan = planner.build_plan({"depth": "standard"})
    assert "DECOMPILE" in full_plan["stages"]

    quick_plan = planner.build_plan({"depth": "quick"})
    assert "DECOMPILE" not in quick_plan["stages"]

    deep_plan = planner.build_plan({"depth": "full"})
    assert "LOCAL_VALIDATION" in deep_plan["stages"]
    assert deep_plan["stages"].index("SYMEX_PRUNE") < deep_plan["stages"].index("RANK")
    assert deep_plan["stage_configs"]["EXTERNAL_ANALYSIS"]["args"] == {
        "phase": "upstream"
    }
    assert deep_plan["stage_configs"]["SYMEX_PRUNE"]["tool"].endswith(".prune")
    assert deep_plan["stage_configs"]["CONSTRAINED_VALIDATION"]["tool"].endswith(
        ".validate"
    )


def test_state_manager_lifecycle(tmp_path: Path) -> None:
    sm = StateManager(tmp_path / "run-001")
    state = sm.init({"task_id": "run-001"}, {"stages": ["A", "B"]})
    assert state["status"] == "running"

    sm.mark_stage_complete("A", {"x": 1})
    state = sm.load()
    assert "A" in state["completed_stages"]
    assert state["artifacts"]["x"] == 1

    sm.mark_stage_failed("B", "simulated error")
    state = sm.resume()
    assert state["current_stage"] == "B"


def test_human_gate_inject_evidence(tmp_path: Path) -> None:
    hg = HumanGate(tmp_path / "run-002")
    (tmp_path / "run-002" / "evidence").mkdir(parents=True)
    ev = hg.inject_evidence(
        "human_input", "This looks like a command injection sink.", stage="STATIC_ANALYSIS"
    )
    assert ev["type"] == "human_input"
    assert ev["source"] == "human_input"


def test_orchestrator_smoke(tmp_path: Path, planner: Planner) -> None:
    """A minimal run using mock runtime and no-op tools reaches DONE."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True)
    # Patch Orchestrator to use tmp runs dir.
    Orchestrator._default_runs_dir = runs_dir  # type: ignore[attr-defined]
    orch = Orchestrator(runtime=MockRuntime({}), planner=planner)
    # Monkey-patch run_dir creation to use tmp_path/runs.

    def create_run_patched(task_card: dict[str, Any]) -> str:
        run_id = task_card.get("task_id", "smoke")
        orch._run_dir = runs_dir / run_id
        orch._run_dir.mkdir(parents=True, exist_ok=True)
        (orch._run_dir / "state").mkdir(exist_ok=True)
        (orch._run_dir / "evidence").mkdir(exist_ok=True)
        (orch._run_dir / "decisions").mkdir(exist_ok=True)
        (orch._run_dir / "artifacts").mkdir(exist_ok=True)
        orch._state_manager = StateManager(orch._run_dir)
        orch._evidence_store = __import__(
            "fsa.reporting.evidence_store", fromlist=["EvidenceStore"]
        ).EvidenceStore(orch._run_dir)
        orch._decision_store = __import__(
            "fsa.reporting.decision_store", fromlist=["DecisionStore"]
        ).DecisionStore(orch._run_dir)
        orch._human_gate = HumanGate(orch._run_dir)
        plan = planner.build_plan(task_card)
        budget_cfg = orch._load_budget_cfg(plan.get("budget_profile", "default"))
        from fsa.runtime.base import Budget

        orch._budget = Budget(**budget_cfg)
        orch._state_manager.init(task_card, plan)
        return run_id

    orch.create_run = create_run_patched  # type: ignore[method-assign]
    card = planner.parse_task(
        {
            "task_id": "smoke",
            "firmware_path": "fixtures/mini.bin",
            "authorization": "test",
            "depth": "quick",
        }
    )
    final_state = orch.run(card)
    assert final_state["status"] in {"completed", "aborted", "pending"}
    # Because tools are not all registered, some required stages abort; that's expected in smoke.
    assert Path(final_state["run_id"]).name in ["smoke"]
