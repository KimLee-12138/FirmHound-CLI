"""Orchestrator state machine and run lifecycle."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

from fsa.orchestrator.human_gate import HumanGate
from fsa.orchestrator.planner import Planner
from fsa.orchestrator.state_manager import StateManager
from fsa.reporting.decision_store import DecisionStore
from fsa.reporting.evidence_store import EvidenceStore
from fsa.runtime import AgentRuntime, Budget, load_runtime
from fsa.runtime.base import ToolResult
from fsa.runtime.tool_registry import ToolRegistry
from fsa.safety.policy_engine import PolicyEngine
from fsa.utils.jsonio import load_yaml


class Stage(str, Enum):
    """Canonical stage names."""

    INIT = "INIT"
    BASELINE = "BASELINE"
    UNPACK = "UNPACK"
    SURFACE = "SURFACE"
    BINARY_TRIAGE = "BINARY_TRIAGE"
    DECOMPILE = "DECOMPILE"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    RANK = "RANK"
    VERIFY_TOP_K = "VERIFY_TOP_K"
    LOCAL_VALIDATION = "LOCAL_VALIDATION"
    REPORT = "REPORT"
    DONE = "DONE"
    ABORTED = "ABORTED"


# Transition table: current stage -> (next_stage_on_success, fallback_stage_on_partial)
TRANSITIONS: dict[str, tuple[str, str | None]] = {
    Stage.INIT.value: (Stage.BASELINE.value, None),
    Stage.BASELINE.value: (Stage.UNPACK.value, None),
    Stage.UNPACK.value: (Stage.SURFACE.value, Stage.BINARY_TRIAGE.value),
    Stage.SURFACE.value: (Stage.BINARY_TRIAGE.value, None),
    Stage.BINARY_TRIAGE.value: (Stage.DECOMPILE.value, None),
    Stage.DECOMPILE.value: (Stage.STATIC_ANALYSIS.value, Stage.STATIC_ANALYSIS.value),
    Stage.STATIC_ANALYSIS.value: (Stage.RANK.value, None),
    Stage.RANK.value: (Stage.VERIFY_TOP_K.value, None),
    Stage.VERIFY_TOP_K.value: (Stage.REPORT.value, Stage.LOCAL_VALIDATION.value),
    Stage.LOCAL_VALIDATION.value: (Stage.REPORT.value, Stage.REPORT.value),
    Stage.REPORT.value: (Stage.DONE.value, None),
}


class Orchestrator:
    """Top-level controller for a firmware analysis run."""

    def __init__(
        self,
        runtime: AgentRuntime | None = None,
        tool_registry: ToolRegistry | None = None,
        planner: Planner | None = None,
        policy_engine: PolicyEngine | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.config = config or load_yaml(
            Path(__file__).parent.parent.parent / "config" / "dev.yaml"
        )
        self.runtime = runtime or load_runtime("mock")
        self.registry = tool_registry or ToolRegistry()
        self.planner = planner or Planner(self.config)
        self.policy = policy_engine or PolicyEngine.from_yaml()
        self._run_dir: Path | None = None
        self._state_manager: StateManager | None = None
        self._evidence_store: EvidenceStore | None = None
        self._decision_store: DecisionStore | None = None
        self._human_gate: HumanGate | None = None
        self._budget: Budget | None = None

    def create_run(self, task_card: dict[str, Any]) -> str:
        """Initialize a new run directory and state."""
        run_id = task_card.get("task_id", uuid.uuid4().hex[:12])
        self._run_dir = Path("runs") / run_id
        self._run_dir.mkdir(parents=True, exist_ok=True)
        (self._run_dir / "state").mkdir(exist_ok=True)
        (self._run_dir / "evidence").mkdir(exist_ok=True)
        (self._run_dir / "decisions").mkdir(exist_ok=True)
        (self._run_dir / "artifacts").mkdir(exist_ok=True)

        self._state_manager = StateManager(self._run_dir)
        self._evidence_store = EvidenceStore(self._run_dir)
        self._decision_store = DecisionStore(self._run_dir)
        self._human_gate = HumanGate(self._run_dir)

        plan = self.planner.build_plan(task_card)
        budget_profile = plan.get("budget_profile", "default")
        budget_cfg = self._load_budget_cfg(budget_profile)
        self._budget = Budget(**budget_cfg)

        self._state_manager.init(task_card, plan)
        self._log_decision(
            stage=Stage.INIT.value,
            options=["proceed", "abort"],
            selected="proceed",
            reason="Task parsed; plan generated.",
            confidence=1.0,
        )
        return run_id

    def _load_budget_cfg(self, profile: str) -> dict[str, int]:
        models_cfg = load_yaml(Path(__file__).parent.parent.parent / "config" / "models.yaml")
        budgets = models_cfg.get("budgets", {})
        cfg = budgets.get(profile, budgets.get("default", {}))
        return {
            "max_total_tokens": cfg.get("max_total_tokens", 100000),
            "max_tokens_per_stage": cfg.get("max_tokens_per_stage", 20000),
            "max_model_calls_per_stage": cfg.get("max_model_calls_per_stage", 50),
            "max_total_duration_seconds": cfg.get("max_total_duration_seconds", 3600),
        }

    def run(self, task_card: dict[str, Any]) -> dict[str, Any]:
        """Execute the full pipeline."""
        self.create_run(task_card)
        state = self._state_manager.load()  # type: ignore[union-attr]
        stages = state["plan"]["stages"]

        for stage in stages:
            if stage in {Stage.INIT.value, Stage.DONE.value}:
                continue
            state = self._execute_stage(stage)
            if state["status"] == "aborted":
                break

        return self._state_manager.load()  # type: ignore[union-attr]

    def resume(self, run_id: str) -> dict[str, Any]:
        """Resume a run from its last completed stage."""
        self._run_dir = Path("runs") / run_id
        self._state_manager = StateManager(self._run_dir)
        self._evidence_store = EvidenceStore(self._run_dir)
        self._decision_store = DecisionStore(self._run_dir)
        self._human_gate = HumanGate(self._run_dir)
        state = self._state_manager.resume()
        stages = state["plan"]["stages"]
        current = state["current_stage"]
        started = False
        for stage in stages:
            if stage == current:
                started = True
            if not started or stage in {Stage.INIT.value, Stage.DONE.value}:
                continue
            state = self._execute_stage(stage)
            if state["status"] == "aborted":
                break
        return self._state_manager.load()  # type: ignore[union-attr]

    def _execute_stage(self, stage: str) -> dict[str, Any]:
        """Run a single stage, handling success/partial/failure transitions."""
        state = self._state_manager.load()  # type: ignore[union-attr]
        state["current_stage"] = stage
        self._state_manager.save(state)  # type: ignore[union-attr]

        stage_cfg = state["plan"].get("stage_configs", {}).get(stage, {})
        tool_name = stage_cfg.get("tool")
        required = stage_cfg.get("required", True)

        self._log_decision(
            stage=stage,
            options=["execute", "skip", "abort"],
            selected="execute",
            reason=f"Entering stage {stage} with tool {tool_name}",
            confidence=1.0,
        )

        if tool_name is None:
            self._state_manager.mark_stage_complete(stage)  # type: ignore[union-attr]
            return self._state_manager.load()  # type: ignore[union-attr]

        try:
            result = self.registry.call(tool_name, {"run_dir": str(self._run_dir)})
        except Exception as exc:  # noqa: BLE001
            result = ToolResult(status="error", stderr=str(exc))

        if result.status == "success":
            next_stage, _ = TRANSITIONS.get(stage, (Stage.DONE.value, None))
            self._state_manager.mark_stage_complete(stage, result.output)  # type: ignore[union-attr]
        elif result.status == "partial":
            _, fallback = TRANSITIONS.get(stage, (Stage.DONE.value, None))
            if fallback and not required:
                self._log_decision(
                    stage=stage,
                    options=["retry", "fallback", "abort"],
                    selected="fallback",
                    reason=f"Stage {stage} returned partial; falling back to {fallback}",
                    confidence=0.5,
                )
                self._state_manager.mark_stage_complete(stage, result.output)  # type: ignore[union-attr]
            else:
                self._state_manager.mark_stage_failed(stage, result.stderr or "partial failure")  # type: ignore[union-attr]
                if required:
                    state = self._state_manager.load()  # type: ignore[union-attr]
                    state["status"] = "aborted"
                    self._state_manager.save(state)  # type: ignore[union-attr]
        else:
            self._state_manager.mark_stage_failed(stage, result.stderr or "failure")  # type: ignore[union-attr]
            if required:
                state = self._state_manager.load()  # type: ignore[union-attr]
                state["status"] = "aborted"
                self._state_manager.save(state)  # type: ignore[union-attr]

        return self._state_manager.load()  # type: ignore[union-attr]

    def _log_decision(
        self,
        stage: str,
        options: list[str],
        selected: str,
        reason: str,
        confidence: float,
    ) -> None:
        """Persist a decision entry."""
        self._decision_store.append(  # type: ignore[union-attr]
            {
                "decision_id": self._decision_store.next_id(),  # type: ignore[union-attr]
                "stage": stage,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "options": options,
                "selected": selected,
                "reason": reason,
                "confidence": confidence,
                "actor": "rule",
            }
        )
