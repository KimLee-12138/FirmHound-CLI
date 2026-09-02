"""OpenAI-compatible runtime adapter (DeepSeek/Qwen/GLM/Moonshot/...)."""

from __future__ import annotations

import os
from typing import Any

from fsa.runtime.base import AgentRuntime, Budget, ModelReply, SkillResult, ToolResult
from fsa.runtime.skill_loader import SkillLoader


class OpenAICompatibleRuntime(AgentRuntime):
    """Adapter for any OpenAI-compatible chat completion endpoint."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self.base_url = config.get("base_url", "https://api.openai.com/v1")
        self.model = config.get("model", "gpt-3.5-turbo")
        self.timeout = config.get("timeout", 60)
        self.max_retries = config.get("max_retries", 3)
        self.api_key_env = config.get("api_key_env", "OPENAI_API_KEY")
        self._client: Any | None = None

    def _get_client(self) -> Any:
        """Lazy-load openai client."""
        if self._client is None:
            try:
                import openai
            except ImportError as exc:
                raise RuntimeError("openai package not installed; run: pip install openai") from exc
            api_key = os.environ.get(self.api_key_env)
            self._client = openai.OpenAI(
                base_url=self.base_url,
                api_key=api_key,
                timeout=self.timeout,
                max_retries=self.max_retries,
            )
        return self._client

    def ask_model(self, messages: list[dict[str, str]], budget: Budget) -> ModelReply:
        """Call the chat completion endpoint and normalize the reply."""
        if not budget.can_spend(0, calls=1):
            return ModelReply(
                content="Budget exhausted; switching to rule fallback.",
                finish_reason="budget_exceeded",
                metadata={"reviewer": "rule", "inference_performed": False},
            )

        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
            )
            choice = response.choices[0]
            usage = response.usage
            reply = ModelReply(
                content=choice.message.content or "",
                role=choice.message.role,
                tokens_input=usage.prompt_tokens if usage else 0,
                tokens_output=usage.completion_tokens if usage else 0,
                finish_reason=choice.finish_reason or "stop",
                metadata={"model": self.model, "reviewer": "model"},
            )
            budget.spend(reply.total_tokens(), calls=1)
            return reply
        except Exception as exc:  # noqa: BLE001
            return ModelReply(
                content=f"Model call failed: {exc}",
                finish_reason="error",
                metadata={
                    "reviewer": "rule",
                    "inference_performed": False,
                    "error": str(exc),
                },
            )

    def run_skill(self, skill_name: str, context: dict[str, Any]) -> SkillResult:
        """Load skill metadata; runtime provides model calls while orchestrator executes."""
        try:
            loader = SkillLoader()
            skill = loader.get(skill_name)
            return SkillResult(
                status="success",
                deliverables={
                    "skill": skill_name,
                    "mode": "openai_compatible",
                    "title": skill.frontmatter.get("title", ""),
                    "workflow_steps": skill.workflow_steps(),
                },
            )
        except KeyError:
            return SkillResult(
                status="failed",
                deliverables={"skill": skill_name, "mode": "openai_compatible"},
            )

    def call_tool(self, tool_name: str, args: dict[str, Any]) -> ToolResult:
        """Tools are executed by the registry; runtime only provides model calls."""
        return ToolResult(status="success", output={"tool": tool_name, "args": args})
