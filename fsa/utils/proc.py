"""Subprocess execution helpers with safety wrappers."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunResult:
    """Result of a controlled subprocess invocation."""

    command: str
    returncode: int
    stdout: str
    stderr: str
    status: str  # success | failed | timeout


def run_command(
    cmd: Sequence[str] | str,
    *,
    cwd: str | Path | None = None,
    timeout: float = 60.0,
    shell: bool = False,
) -> RunResult:
    """Run a command safely and return a structured result.

    This helper never raises on non-zero exit codes; instead it returns a
    ``RunResult`` with ``status == "failed"``. Timeouts are captured as
    ``status == "timeout"``.

    Args:
        cmd: Command and arguments as a list, or a string (split with shlex).
        cwd: Working directory for the child process.
        timeout: Maximum runtime in seconds.
        shell: If True, run through the shell (avoid unless required).
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    cmd = [str(c) for c in cmd]
    # On Windows, resolve executable through PATHEXT so .bat/.cmd wrappers work.
    if sys.platform == "win32" and cmd and not Path(cmd[0]).is_absolute():
        resolved = shutil.which(cmd[0])
        if resolved:
            cmd[0] = resolved
    command_str = shlex.join(cmd)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            shell=shell,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        status = "success" if proc.returncode == 0 else "failed"
        return RunResult(
            command=command_str,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            status=status,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            command=command_str,
            returncode=-1,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            status="timeout",
        )
