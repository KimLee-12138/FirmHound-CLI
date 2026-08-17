"""Safety policy engine tests (red-line cases)."""

from pathlib import Path

import pytest

from fsa.safety.policy_engine import PolicyEngine, SafetyViolation


@pytest.fixture
def engine(tmp_path: Path) -> PolicyEngine:
    """Build a policy engine that allows ``tmp_path`` and blocks a subpath."""
    policy = {
        "enforce": True,
        "abort_on_violation": True,
        "allowed_paths": [str(tmp_path / "runs")],
        "blocked_paths": [str(tmp_path / "runs" / "secrets")],
        "command_blacklist": [
            {"pattern": "^rm\\s+-[rf]+", "reason": "recursive delete"},
            {"pattern": "curl\\s+", "reason": "network fetch"},
        ],
        "network": {"allow_public": False, "allowed_hosts": ["localhost"]},
    }
    policy_file = tmp_path / "safety.yaml"
    import yaml

    with policy_file.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(policy, fh)
    return PolicyEngine(policy_file)


def test_allowed_path(engine: PolicyEngine, tmp_path: Path) -> None:
    """Paths under allowed roots pass."""
    engine.check_path(tmp_path / "runs" / "task_001")


def test_blocked_path(engine: PolicyEngine, tmp_path: Path) -> None:
    """Blocked subpaths raise."""
    with pytest.raises(SafetyViolation):
        engine.check_path(tmp_path / "runs" / "secrets" / "key.txt")


def test_outside_path(engine: PolicyEngine, tmp_path: Path) -> None:
    """Paths outside allowed roots raise."""
    with pytest.raises(SafetyViolation):
        engine.check_path(tmp_path / "outside")


def test_blacklisted_command(engine: PolicyEngine) -> None:
    """Blacklisted commands raise."""
    with pytest.raises(SafetyViolation):
        engine.check_command("rm -rf /")
    with pytest.raises(SafetyViolation):
        engine.check_command("curl http://example.com")


def test_allowed_command(engine: PolicyEngine) -> None:
    """Non-blacklisted commands pass."""
    engine.check_command("python tools/firmware/unpack.py runs/foo.bin")


def test_private_ip_allowed(engine: PolicyEngine) -> None:
    """Private IPs are allowed."""
    engine.check_host("192.168.1.1")


def test_public_ip_blocked(engine: PolicyEngine) -> None:
    """Public IPs are blocked by default."""
    with pytest.raises(SafetyViolation):
        engine.check_host("8.8.8.8")


def test_allowed_hostname(engine: PolicyEngine) -> None:
    """Explicitly allowed hostnames pass."""
    engine.check_host("localhost")


def test_is_within_allowed(engine: PolicyEngine, tmp_path: Path) -> None:
    """is_within_allowed reflects policy."""
    assert engine.is_within_allowed(tmp_path / "runs" / "x") is True
    assert engine.is_within_allowed(tmp_path / "outside") is False
