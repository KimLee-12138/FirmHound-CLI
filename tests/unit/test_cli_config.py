"""Tests for CLI configuration side effects."""

import os
from pathlib import Path

import pytest

from fsa.cli import _configure_tool_path
from fsa.utils.jsonio import save_yaml


def test_configure_tool_path_prepends_wsl_wrappers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Configured WSL tool wrappers are prepended to PATH."""
    wrappers = tmp_path / "tools" / "wsl_wrappers"
    wrappers.mkdir(parents=True)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config = config_dir / "dev.yaml"
    save_yaml(
        config,
        {
            "tools": {
                "use_wsl_wrappers": True,
                "wsl_wrappers": str(wrappers),
            }
        },
    )
    monkeypatch.setenv("PATH", "original")

    _configure_tool_path(config)

    assert os.environ["PATH"].split(os.pathsep)[0] == str(wrappers)


def test_configure_tool_path_ignores_disabled_wrappers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """PATH stays unchanged when WSL wrappers are disabled."""
    config = tmp_path / "dev.yaml"
    save_yaml(config, {"tools": {"use_wsl_wrappers": False}})
    monkeypatch.setenv("PATH", "original")

    _configure_tool_path(config)

    assert os.environ["PATH"] == "original"
