"""Declarative tool registry with safety policy enforcement."""

from __future__ import annotations

import importlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from fsa.runtime.base import ToolResult
from fsa.safety.policy_engine import PolicyEngine


@dataclass
class ToolSpec:
    """Specification for a registered tool."""

    name: str
    module_path: str
    function_name: str
    description: str
    args_schema: dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)


class ToolRegistry:
    """Discover and call tools from YAML declarations."""

    def __init__(self, registry_dir: str | Path | None = None) -> None:
        self.registry_dir = (
            Path(registry_dir)
            if registry_dir
            else Path(__file__).parent.parent.parent / "tools" / "registry"
        )
        self._tools: dict[str, ToolSpec] = {}
        self._policy = PolicyEngine.from_yaml()
        self._load_registry()

    def _load_registry(self) -> None:
        """Load tool declarations from registry YAML files."""
        if not self.registry_dir.exists():
            return
        for path in self.registry_dir.rglob("*.yaml"):
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            for item in data.get("tools", []):
                spec = ToolSpec(
                    name=item["name"],
                    module_path=item["module_path"],
                    function_name=item["function_name"],
                    description=item.get("description", ""),
                    args_schema=item.get("args_schema", {}),
                    required_permissions=item.get("required_permissions", []),
                )
                self._tools[spec.name] = spec

    def register(self, spec: ToolSpec) -> None:
        """Register a tool programmatically."""
        self._tools[spec.name] = spec

    def list_tools(self) -> list[str]:
        """Return all registered tool names."""
        return sorted(self._tools.keys())

    def get(self, name: str) -> ToolSpec:
        """Fetch a tool spec by name."""
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not registered")
        return self._tools[name]

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        """Resolve and execute a tool, enforcing safety policy."""
        spec = self.get(name)

        # Safety gate for commands.
        if "command" in args:
            cmd = str(args["command"])
            policy_result = self._policy.evaluate_command(cmd)
            if not policy_result["allowed"]:
                return ToolResult(
                    status="unsafe",
                    output={},
                    stderr=f"Policy rejected command: {policy_result['reason']}",
                )

        start = time.time()
        try:
            module = importlib.import_module(spec.module_path)
            func: Callable[..., Any] = getattr(module, spec.function_name)
            output = func(**args)
            if not isinstance(output, dict):
                output = {"result": output}
            return ToolResult(
                status="success",
                output=output,
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                status="error",
                output={},
                stderr=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )
