"""Deterministic offline runtime with a backward-compatible ``MockRuntime`` alias."""

from __future__ import annotations

from typing import Any

from fsa.runtime.base import AgentRuntime, Budget, ModelReply, SkillResult, ToolResult
from fsa.runtime.skill_loader import SkillLoader
from fsa.safety.policy_engine import PolicyEngine, SafetyViolation


class OfflineRuleRuntime(AgentRuntime):
    """Offline runtime that never represents deterministic metadata as model output."""

    def ask_model(self, messages: list[dict[str, str]], budget: Budget) -> ModelReply:
        """Return an explicit degraded result; no inference is fabricated."""
        if not messages:
            content = "No input provided; no model inference was performed."
            return ModelReply(
                content=content,
                tokens_input=0,
                tokens_output=len(content) // 4,
                finish_reason="fallback",
                metadata={
                    "reviewer": "rule",
                    "status": "degraded",
                    "inference_performed": False,
                },
            )

        last = messages[-1].get("content", "")
        content = (
            "Model inference unavailable; no conclusion was generated. "
            "Use the deterministic pipeline artifacts for ranking, verification, and reporting."
        )

        return ModelReply(
            content=content,
            tokens_input=len(last) // 4,
            tokens_output=len(content) // 4,
            finish_reason="fallback",
            metadata={
                "reviewer": "rule",
                "status": "degraded",
                "inference_performed": False,
            },
        )

    def run_skill(self, skill_name: str, context: dict[str, Any]) -> SkillResult:
        """Load skill metadata without claiming the workflow was executed."""
        try:
            loader = SkillLoader()
            skill = loader.get(skill_name)
            return SkillResult(
                status="partial",
                deliverables={
                    "skill": skill_name,
                    "mode": "offline_metadata_only",
                    "title": skill.frontmatter.get("title", ""),
                    "workflow_steps": skill.workflow_steps(),
                    "fallbacks": skill.failure_fallbacks(),
                    "acceptance_criteria": skill.acceptance_criteria(),
                },
                evidence_refs=[],
            )
        except KeyError:
            return SkillResult(
                status="failed",
                deliverables={"skill": skill_name, "mode": "offline_metadata_only"},
                evidence_refs=[],
            )

    def call_tool(self, tool_name: str, args: dict[str, Any]) -> ToolResult:
        """Execute only the real policy check; refuse all other fake tool calls."""
        if tool_name != "policy_check":
            return ToolResult(
                status="error",
                output={
                    "status": "failed",
                    "tool": tool_name,
                    "reason": "offline runtime does not execute tools; use ToolRegistry",
                },
            )
        command = str(args.get("command", ""))
        try:
            PolicyEngine.from_yaml().check_command(command)
        except SafetyViolation as exc:
            return ToolResult(
                status="unsafe",
                output={"status": "failed", "allowed": False, "reason": str(exc)},
            )
        return ToolResult(
            status="success",
            output={"status": "ok", "allowed": True, "command_checked": True},
        )


# Compatibility for existing imports and test fixtures. Production config uses
# ``runtime.default=offline`` and therefore does not expose a mock execution mode.
MockRuntime = OfflineRuleRuntime
