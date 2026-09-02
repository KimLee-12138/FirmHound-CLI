"""Agent Runtime adapters and tool registry."""

from fsa.runtime.base import AgentRuntime, Budget, ModelReply, SkillResult, ToolResult
from fsa.runtime.mock import MockRuntime, OfflineRuleRuntime
from fsa.runtime.skill_loader import SkillLoader

__all__ = [
    "AgentRuntime",
    "Budget",
    "ModelReply",
    "SkillResult",
    "ToolResult",
    "MockRuntime",
    "OfflineRuleRuntime",
    "SkillLoader",
    "load_runtime",
]


def load_runtime(name: str, config: dict | None = None) -> AgentRuntime:
    """Factory: load a runtime by name from config/models.yaml."""
    from pathlib import Path

    from fsa.utils.jsonio import load_yaml

    if config is None:
        config = load_yaml(Path(__file__).parent.parent.parent / "config" / "models.yaml")

    runtimes = config.get("runtimes", {})
    if name not in runtimes:
        raise ValueError(f"Runtime '{name}' not found in config/models.yaml")

    runtime_cfg = runtimes[name]
    provider = runtime_cfg.get("provider")
    if provider in {"mock", "offline_rule"}:
        return OfflineRuleRuntime(runtime_cfg)
    if provider == "openai":
        from fsa.runtime.openai_compatible import OpenAICompatibleRuntime

        return OpenAICompatibleRuntime(runtime_cfg)
    raise ValueError(f"Unknown runtime provider: {provider}")
