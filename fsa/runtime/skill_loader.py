"""Skill loader: discover and parse SKILL.md packages."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Skill:
    """Parsed skill package."""

    name: str
    path: Path
    frontmatter: dict[str, Any] = field(default_factory=dict)
    sections: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def section(self, title: str) -> str:
        """Return a section body by heading title (case-insensitive)."""
        return self.sections.get(title.lower(), "")

    def workflow_steps(self) -> list[str]:
        """Extract numbered or bulleted workflow steps from the '执行流程' section."""
        text = self.section("执行流程") or self.section("workflow")
        steps: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if re.match(r"^\d+[.．]\s+", line) or line.startswith(("- ", "* ")):
                steps.append(re.sub(r"^\d+[.．]\s+|^[-*]\s+", "", line))
        return steps

    def failure_fallbacks(self) -> list[dict[str, str]]:
        """Parse the '失败降级路径' table into structured rows."""
        text = self.section("失败降级路径") or self.section("fallback")
        rows: list[dict[str, str]] = []
        in_table = False
        for line in text.splitlines():
            if line.strip().startswith("|"):
                parts = [p.strip() for p in line.strip().split("|") if p.strip()]
                if parts == ["场景", "行为"]:
                    in_table = True
                    continue
                if in_table and len(parts) >= 2:
                    rows.append({"scenario": parts[0], "behavior": parts[1]})
        return rows

    def acceptance_criteria(self) -> list[str]:
        """Return bulleted acceptance criteria."""
        text = self.section("验收标准") or self.section("acceptance")
        return [
            re.sub(r"^[-*]\s+", "", line.strip())
            for line in text.splitlines()
            if line.strip().startswith(("- ", "* "))
        ]


class SkillLoader:
    """Discover and parse skills under a skills root directory."""

    def __init__(self, skills_dir: str | Path | None = None) -> None:
        """Initialize skill loader and discover SKILL.md packages."""
        self.skills_dir = (
            Path(skills_dir) if skills_dir else Path(__file__).parent.parent.parent / "skills"
        )
        self._skills: dict[str, Skill] = {}
        self._load_all()

    def _load_all(self) -> None:
        """Discover all SKILL.md files under the skills directory."""
        if not self.skills_dir.exists():
            return
        for path in sorted(self.skills_dir.rglob("SKILL.md")):
            skill = self._parse(path)
            self._skills[skill.name] = skill

    def _parse(self, path: Path) -> Skill:
        """Parse a single SKILL.md file."""
        raw = path.read_text(encoding="utf-8")
        frontmatter: dict[str, Any] = {}
        body = raw

        # Extract YAML frontmatter between --- fences.
        if raw.startswith("---"):
            _, fm_text, rest = raw.split("---", 2)
            try:
                frontmatter = yaml.safe_load(fm_text) or {}
            except yaml.YAMLError:
                frontmatter = {}
            body = rest

        # Determine skill name: frontmatter id > directory name.
        name = frontmatter.get("id") or path.parent.name

        # Split body into sections by ## headings.
        sections: dict[str, str] = {}
        current_title: str | None = None
        current_lines: list[str] = []
        for line in body.splitlines():
            match = re.match(r"^##\s+(.*)", line)
            if match:
                if current_title is not None:
                    sections[current_title.lower()] = "\n".join(current_lines).strip()
                current_title = match.group(1).strip()
                current_lines = []
            else:
                current_lines.append(line)
        if current_title is not None:
            sections[current_title.lower()] = "\n".join(current_lines).strip()

        return Skill(
            name=name,
            path=path,
            frontmatter=frontmatter,
            sections=sections,
            raw=raw,
        )

    def list_skills(self) -> list[str]:
        """Return all loaded skill names."""
        return sorted(self._skills.keys())

    def get(self, name: str) -> Skill:
        """Fetch a parsed skill by name."""
        if name not in self._skills:
            raise KeyError(f"Skill '{name}' not found")
        return self._skills[name]

    def find_by_tag(self, tag: str) -> list[Skill]:
        """Return skills whose frontmatter tags contain ``tag``."""
        return [
            skill for skill in self._skills.values() if tag in skill.frontmatter.get("tags", [])
        ]

    def reload(self) -> None:
        """Reload skills from disk."""
        self._skills.clear()
        self._load_all()
