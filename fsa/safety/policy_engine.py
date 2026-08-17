"""Safety policy engine for commands, paths, and network targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from fsa.utils.netcheck import is_private_ip


class SafetyViolation(Exception):
    """Raised when an operation violates the configured safety policy."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"Safety violation ({rule}): {detail}")
        self.rule = rule
        self.detail = detail


@dataclass(frozen=True)
class Policy:
    """Loaded safety policy configuration."""

    enforce: bool
    abort_on_violation: bool
    allowed_paths: list[Path]
    blocked_paths: list[Path]
    command_blacklist: list[dict[str, str]]
    network_allow_public: bool
    network_allowed_hosts: set[str]
    model_limits: dict[str, Any]


class PolicyEngine:
    """Validate filesystem paths, shell commands, and network targets."""

    def __init__(self, policy_path: str | Path) -> None:
        self.policy_path = Path(policy_path)
        self.policy = self._load(self.policy_path)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> PolicyEngine:
        """Load policy from the default config/safety.yaml or a provided path."""
        if path is None:
            path = Path(__file__).parent.parent.parent / "config" / "safety.yaml"
        return cls(path)

    @staticmethod
    def _load(path: Path) -> Policy:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)

        repo_root = path.resolve().parent.parent

        def resolve_paths(entries: list[str]) -> list[Path]:
            out: list[Path] = []
            for entry in entries:
                p = Path(entry)
                if not p.is_absolute():
                    p = repo_root / p
                out.append(p.resolve())
            return out

        return Policy(
            enforce=raw.get("enforce", True),
            abort_on_violation=raw.get("abort_on_violation", True),
            allowed_paths=resolve_paths(raw.get("allowed_paths", [])),
            blocked_paths=resolve_paths(raw.get("blocked_paths", [])),
            command_blacklist=raw.get("command_blacklist", []),
            network_allow_public=raw.get("network", {}).get("allow_public", False),
            network_allowed_hosts=set(raw.get("network", {}).get("allowed_hosts", [])),
            model_limits=raw.get("model", {}),
        )

    def _check(self, rule: str, detail: str) -> None:
        if not self.policy.enforce:
            return
        if self.policy.abort_on_violation:
            raise SafetyViolation(rule, detail)

    def check_path(self, target: str | Path) -> None:
        """Ensure ``target`` is within an allowed path and not explicitly blocked."""
        target_resolved = Path(target).resolve()

        for blocked in self.policy.blocked_paths:
            if target_resolved == blocked or target_resolved.is_relative_to(blocked):
                self._check("blocked_path", str(target_resolved))
                return

        for allowed in self.policy.allowed_paths:
            if target_resolved == allowed or target_resolved.is_relative_to(allowed):
                return

        self._check("path_whitelist", str(target_resolved))

    def check_command(self, command: str) -> None:
        """Ensure ``command`` does not match any blacklisted pattern."""
        for rule in self.policy.command_blacklist:
            pattern = rule.get("pattern", "")
            reason = rule.get("reason", "blacklisted command")
            if re.search(pattern, command, re.IGNORECASE):
                self._check("command_blacklist", f"{command!r}: {reason}")
                return

    def check_host(self, host: str) -> None:
        """Ensure ``host`` is either an allowed host or a private IP."""
        if host in self.policy.network_allowed_hosts:
            return
        try:
            ipaddress.ip_address(host)
            if is_private_ip(host):
                return
        except ValueError:
            # Hostname: only allowed if explicitly listed.
            pass
        if self.policy.network_allow_public:
            return
        self._check("network_host", host)

    def is_within_allowed(self, target: str | Path) -> bool:
        """Return True if ``target`` is within an allowed path."""
        target_resolved = Path(target).resolve()
        for allowed in self.policy.allowed_paths:
            if target_resolved == allowed or target_resolved.is_relative_to(allowed):
                return True
        return False
