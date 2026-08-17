"""Abstract base class for agent runtimes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Budget:
    """Token/call/time budget for a run or stage."""

    max_total_tokens: int = 100000
    max_tokens_per_stage: int = 20000
    max_model_calls_per_stage: int = 50
    max_total_duration_seconds: int = 3600
    total_tokens_used: int = 0
    total_calls: int = 0

    def can_spend(self, tokens: int, calls: int = 1) -> bool:
        """Check if a proposed spend fits within remaining budget."""
        if self.total_tokens_used + tokens > self.max_total_tokens:
            return False
        if calls > self.max_model_calls_per_stage:
            return False
        return True

    def spend(self, tokens: int, calls: int = 1) -> None:
        """Record spent tokens and calls."""
        self.total_tokens_used += tokens
        self.total_calls += calls

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_total_tokens": self.max_total_tokens,
            "max_tokens_per_stage": self.max_tokens_per_stage,
            "max_model_calls_per_stage": self.max_model_calls_per_stage,
            "max_total_duration_seconds": self.max_total_duration_seconds,
            "total_tokens_used": self.total_tokens_used,
            "total_calls": self.total_calls,
        }


@dataclass
class ModelReply:
    """Normalized reply from any model/runtime."""

    content: str
    role: str = "assistant"
    tokens_input: int = 0
    tokens_output: int = 0
    finish_reason: str = "stop"
    metadata: dict[str, Any] = field(default_factory=dict)

    def total_tokens(self) -> int:
        return self.tokens_input + self.tokens_output


@dataclass
class ToolResult:
    """Normalized tool call result."""

    status: str  # success / error / unsafe / timeout
    output: dict[str, Any] = field(default_factory=dict)
    stderr: str = ""
    duration_ms: int = 0


@dataclass
class SkillResult:
    """Normalized skill execution result."""

    status: str  # success / partial / failed / skipped
    deliverables: dict[str, Any] = field(default_factory=dict)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


class AgentRuntime(ABC):
    """Runtime-agnostic interface for the orchestrator."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    @abstractmethod
    def ask_model(self, messages: list[dict[str, str]], budget: Budget) -> ModelReply:
        """Send messages to the model and return a normalized reply."""

    @abstractmethod
    def run_skill(self, skill_name: str, context: dict[str, Any]) -> SkillResult:
        """Load and execute a skill from skills/ directory."""

    @abstractmethod
    def call_tool(self, tool_name: str, args: dict[str, Any]) -> ToolResult:
        """Call a registered tool by name."""

    def save_state(self, state: dict[str, Any]) -> None:
        """Optional hook to persist runtime-specific state."""
        return None
