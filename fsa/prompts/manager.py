"""Prompt template loading and rendering."""

from __future__ import annotations

import contextlib
import re
import string
from pathlib import Path
from typing import Any

import yaml


class PromptManager:
    """Load, index, and render prompt templates by stage and intent."""

    def __init__(self, templates_dir: str | Path | None = None) -> None:
        """Initialize prompt manager and load templates from disk."""
        self.templates_dir = (
            Path(templates_dir) if templates_dir else Path(__file__).parent / "templates"
        )
        self._templates: dict[str, dict[str, Any]] = {}
        self._load_templates()

    def _load_templates(self) -> None:
        """Load all YAML prompt manifests from the templates directory."""
        if not self.templates_dir.exists():
            return
        for path in sorted(self.templates_dir.rglob("*.yaml")):
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            for name, meta in data.get("prompts", {}).items():
                meta["_source"] = str(path)
                self._templates[name] = meta

    def list(self) -> list[str]:
        """Return all registered prompt names."""
        return sorted(self._templates.keys())

    def get(self, name: str) -> dict[str, Any]:
        """Return prompt metadata by name."""
        if name not in self._templates:
            raise KeyError(f"Prompt '{name}' not found")
        return self._templates[name]

    def render(self, name: str, variables: dict[str, Any] | None = None) -> str:
        """Render a prompt template with variables.

        Supports either a single ``template`` key or ``system`` + ``user`` keys.
        """
        meta = self.get(name)
        template = meta.get("template")
        if template is None:
            parts = []
            if meta.get("system"):
                parts.append(str(meta["system"]))
            if meta.get("user"):
                parts.append(str(meta["user"]))
            template = "\n\n".join(parts)
        variables = variables or {}

        # Support $var and ${var} style substitution.
        def replacer(match: re.Match[str]) -> str:
            key = match.group(1) or match.group(2)
            if key in variables:
                return str(variables[key])
            if key in meta.get("defaults", {}):
                return str(meta["defaults"][key])
            return match.group(0)

        rendered = re.sub(r"\$\{(\w+)\}|\$(\w+)", replacer, template)

        # Also support Python string.Template as a fallback for simple ${var}.
        with contextlib.suppress(ValueError):
            rendered = string.Template(rendered).safe_substitute(variables)

        return rendered

    def render_messages(
        self, name: str, variables: dict[str, Any] | None = None
    ) -> list[dict[str, str]]:
        """Render a prompt into OpenAI-style messages list."""
        meta = self.get(name)
        messages = []
        system = meta.get("system")
        if system:
            messages.append({"role": "system", "content": self._render_text(system, variables)})
        user = meta.get("user")
        if user:
            messages.append({"role": "user", "content": self._render_text(user, variables)})
        for msg in meta.get("messages", []):
            messages.append(
                {
                    "role": msg.get("role", "user"),
                    "content": self._render_text(msg.get("content", ""), variables),
                }
            )
        return messages

    def _render_text(self, text: str, variables: dict[str, Any] | None) -> str:
        """Render a single text block with variables."""
        variables = variables or {}

        def replacer(match: re.Match[str]) -> str:
            key = match.group(1) or match.group(2)
            return str(variables.get(key, match.group(0)))

        rendered = re.sub(r"\$\{(\w+)\}|\$(\w+)", replacer, text)
        with contextlib.suppress(ValueError):
            rendered = string.Template(rendered).safe_substitute(variables)
        return rendered

    def register(self, name: str, template: str, **meta: Any) -> None:
        """Register a prompt programmatically."""
        self._templates[name] = {"template": template, **meta}
