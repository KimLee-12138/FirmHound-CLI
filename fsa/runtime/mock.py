"""Mock runtime: rule-based fallback when no model is available."""

from __future__ import annotations

import re
from typing import Any

from fsa.runtime.base import AgentRuntime, Budget, ModelReply, SkillResult, ToolResult


class MockRuntime(AgentRuntime):
    """Offline runtime that uses regex/heuristic rules instead of model calls."""

    def ask_model(self, messages: list[dict[str, str]], budget: Budget) -> ModelReply:
        """Return a rule-based reply based on the last user message."""
        if not messages:
            return ModelReply(content="No input provided.", tokens_input=0, tokens_output=4)

        last = messages[-1].get("content", "")
        lowered = last.lower()

        # Rule-based intent detection for common prompts.
        if "rank" in lowered or "sort" in lowered:
            content = "Mock ranking: candidates sorted by static score descending."
        elif "verify" in lowered or "confirm" in lowered:
            content = "Mock verifier: insufficient evidence, mark as high-confidence-candidate."
        elif "summarize" in lowered or "report" in lowered:
            content = "Mock summary: see structured output above."
        elif "extract" in lowered and "endpoint" in lowered:
            content = "Mock extraction: formXxx handlers found via string regex."
        else:
            content = "Mock response: no model available, using rule fallback."

        return ModelReply(
            content=content,
            tokens_input=len(last) // 4,
            tokens_output=len(content) // 4,
            finish_reason="mock",
            metadata={"reviewer": "mock"},
        )

    def run_skill(self, skill_name: str, context: dict[str, Any]) -> SkillResult:
        """Mock skill execution: return a placeholder success."""
        return SkillResult(
            status="success",
            deliverables={"skill": skill_name, "mode": "mock"},
            evidence_refs=[],
        )

    def call_tool(self, tool_name: str, args: dict[str, Any]) -> ToolResult:
        """Mock tool call: echo args back with a heuristic status."""
        status = "success"
        if tool_name == "policy_check":
            # Simple safety check simulation.
            cmd = str(args.get("command", ""))
            unsafe = any(x in cmd for x in ["rm -rf", "mkfs.", ">/dev/sd", "curl | sh"])
            status = "unsafe" if unsafe else "success"
        return ToolResult(status=status, output={"tool": tool_name, "args": args})
