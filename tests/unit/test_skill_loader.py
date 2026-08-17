"""Tests for skill loader."""

from __future__ import annotations

from fsa.runtime import MockRuntime, SkillLoader


def test_load_all_skills() -> None:
    loader = SkillLoader()
    skills = loader.list_skills()
    assert "01-unpack" in skills
    assert "02-attack-surface" in skills
    assert "04-audit-command-injection" in skills
    assert "04-audit-buffer-overflow" in skills
    assert "06-dynamic-qemu-service-bootstrap" in skills
    assert "05-candidate-verifier" in skills


def test_get_skill_metadata() -> None:
    loader = SkillLoader()
    skill = loader.get("05-candidate-verifier")
    assert skill.frontmatter.get("id") == "05-candidate-verifier"
    assert "候选漏洞反证审查" in skill.frontmatter.get("title", "")


def test_workflow_steps() -> None:
    loader = SkillLoader()
    skill = loader.get("05-candidate-verifier")
    steps = skill.workflow_steps()
    assert any("加载输入" in s for s in steps)
    assert any("10 问审查" in s for s in steps)


def test_failure_fallbacks() -> None:
    loader = SkillLoader()
    skill = loader.get("01-unpack")
    fallbacks = skill.failure_fallbacks()
    assert any("binwalk 无签名" in f["scenario"] for f in fallbacks)


def test_acceptance_criteria() -> None:
    loader = SkillLoader()
    skill = loader.get("02-attack-surface")
    criteria = skill.acceptance_criteria()
    assert any("formexeCommand" in c for c in criteria)


def test_audit_command_injection_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("04-audit-command-injection")
    assert "command_injection" in skill.frontmatter.get("tags", [])
    steps = skill.workflow_steps()
    assert any("入口定位" in s for s in steps)


def test_dynamic_qemu_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("06-dynamic-qemu-service-bootstrap")
    assert "qemu" in skill.frontmatter.get("tags", [])


def test_mock_runtime_run_skill() -> None:
    runtime = MockRuntime({})
    result = runtime.run_skill("05-candidate-verifier", {})
    assert result.status == "success"
    assert "workflow_steps" in result.deliverables
