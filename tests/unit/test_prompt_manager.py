"""Tests for prompt manager."""

from __future__ import annotations

from pathlib import Path

from fsa.prompts import PromptManager


def test_load_default_prompts() -> None:
    pm = PromptManager()
    assert "task_understanding" in pm.list()
    assert "verifier_review" in pm.list()


def test_render_simple_variables() -> None:
    pm = PromptManager()
    rendered = pm.render("task_understanding", {"firmware_path": "fw.bin", "vendor": "Tenda"})
    assert "fw.bin" in rendered
    assert "Tenda" in rendered


def test_render_defaults() -> None:
    pm = PromptManager()
    rendered = pm.render("task_understanding", {})
    assert "Firmware path:" in rendered


def test_render_messages() -> None:
    pm = PromptManager()
    messages = pm.render_messages("verifier_review", {"candidate_id": "cand-001"})
    assert any(m["role"] == "system" for m in messages)
    assert any("cand-001" in m["content"] for m in messages)


def test_register_prompt(tmp_path: Path) -> None:
    pm = PromptManager(tmp_path)
    pm.register("custom", "Hello ${name}!")
    assert "custom" in pm.list()
    assert pm.render("custom", {"name": "World"}) == "Hello World!"
