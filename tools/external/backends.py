"""Execution backends for external analyzers: local / wsl / docker.

All three backends funnel through :func:`fsa.utils.proc.run_command`, which never
raises on non-zero exits and converts timeouts into a structured result.

Safety notes:
* ``docker`` backend mounts only paths that were staged under the analyzer's
  workdir (``tmp/external/<tool>/<run_id>/``), which sits inside the
  ``./tmp`` path whitelist in ``config/safety.yaml``.
* ``wsl`` backend reuses the project's ``C:\\... -> /mnt/c/...`` translation so
  Windows host paths are usable inside the distro.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fsa.utils.proc import RunResult, run_command
from tools.external.base import to_wsl_path

WSL_DISTRO = "Ubuntu-22.04"


@dataclass
class BackendResult:
    """Normalized result of a backend invocation."""

    status: str  # ok | failed | timeout | missing
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    returncode: int = -1

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _from_run_result(res: RunResult) -> BackendResult:
    """Map a :class:`RunResult` onto :class:`BackendResult`."""
    if res.status == "timeout":
        return BackendResult("timeout", res.stdout, res.stderr, returncode=-1)
    if res.status == "success":
        return BackendResult("ok", res.stdout, res.stderr, returncode=res.returncode)
    return BackendResult("failed", res.stdout, res.stderr, returncode=res.returncode)


# --------------------------------------------------------------------------- #
# local
# --------------------------------------------------------------------------- #


def run_local(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 60.0,
) -> BackendResult:
    """Run a command on the host (Linux, or Windows with native tooling)."""
    if not cmd:
        return BackendResult("failed", stderr="empty command")
    if shutil.which(cmd[0]) is None and not Path(cmd[0]).is_absolute():
        return BackendResult("missing", stderr=f"executable not found: {cmd[0]}")
    return _from_run_result(run_command(cmd, cwd=cwd, timeout=timeout))


# --------------------------------------------------------------------------- #
# wsl
# --------------------------------------------------------------------------- #


def run_wsl(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 60.0,
    distro: str = WSL_DISTRO,
) -> BackendResult:
    """Run a command inside a WSL distro, translating host paths in arguments."""
    if shutil.which("wsl.exe") is None and shutil.which("wsl") is None:
        return BackendResult("missing", stderr="wsl executable not found")
    translated = [to_wsl_path(c) if ("/" in c or "\\" in c) else c for c in cmd]
    full = ["wsl", "-d", distro, "--"] + translated
    return _from_run_result(run_command(full, cwd=cwd, timeout=timeout))


# --------------------------------------------------------------------------- #
# docker
# --------------------------------------------------------------------------- #


def docker_available() -> tuple[bool, str]:
    """Return ``(available, detail)`` for the Docker daemon."""
    if shutil.which("docker") is None:
        return False, "docker executable not found"
    res = run_command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20.0)
    if res.status != "success":
        return False, (res.stderr or res.stdout or "docker daemon unreachable").strip()
    return True, (res.stdout or "").strip()


def docker_image_exists(image: str) -> bool:
    """Return True when ``image`` is present locally."""
    res = run_command(["docker", "image", "inspect", image], timeout=30.0)
    return res.status == "success"


def run_docker(
    image: str,
    cmd: list[str],
    *,
    mounts: dict[Path | str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = 60.0,
    memory: str | None = None,
    entrypoint: str | None = None,
    env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> BackendResult:
    """Run a command inside a throwaway container.

    Args:
        image: Image reference, e.g. ``smile0304/satc``.
        cmd: Command executed inside the container.
        mounts: Mapping of host path -> container path. Host paths are
            translated for Docker Desktop's WSL2 backend.
        memory: Optional hard memory limit, e.g. ``16g`` (Ghidra needs headroom).
        extra_args: Additional ``docker run`` flags appended before the image.
    """
    if not docker_image_exists(image):
        return BackendResult("missing", stderr=f"docker image not present: {image}")

    full: list[str] = ["docker", "run", "--rm"]
    for host, container in (mounts or {}).items():
        full += ["-v", f"{to_wsl_path(host)}:{container}"]
    if memory:
        full += ["--memory", memory]
    for key, value in (env or {}).items():
        full += ["-e", f"{key}={value}"]
    if entrypoint:
        full += ["--entrypoint", entrypoint]
    full += list(extra_args or [])
    full += [image]
    full += [str(c) for c in cmd]
    return _from_run_result(run_command(full, cwd=cwd, timeout=timeout))


def run_container_cmd(
    container: str,
    cmd: list[str],
    *,
    timeout: float = 60.0,
) -> BackendResult:
    """Execute a command inside an already-running container (``docker exec``)."""
    full = ["docker", "exec", container] + [str(c) for c in cmd]
    return _from_run_result(run_command(full, timeout=timeout))


BACKENDS: dict[str, Any] = {
    "local": run_local,
    "wsl": run_wsl,
    "docker": run_docker,
}
