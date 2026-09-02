"""Tests for developer-facing helper commands."""

from __future__ import annotations

from pathlib import Path

from scripts import dev


def test_dev_smoke_uses_product_cli(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str] | str, *, cwd: Path | None = None) -> int:
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        return 0

    monkeypatch.setattr(dev, "run", fake_run)

    assert dev.cmd_smoke(object()) == 0

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:5] == [dev.PYTHON, "-m", "fsa.cli", "--config", "config/dev.yaml"]
    assert "analyze" in cmd
    assert "smoke" not in cmd
    assert "--authorization-holder" in cmd
