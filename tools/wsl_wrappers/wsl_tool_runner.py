"""Dispatch Windows tool calls to WSL Ubuntu-22.04.

Each tool wrapper is a .bat file that invokes this script. Windows absolute paths
in arguments are translated to /mnt/<drive>/... so WSL tools can operate on them.

The WSL_UTF8=1 environment variable forces WSL to emit UTF-8 (instead of the
default codepage), which keeps stderr/stdout decodable on the Windows side.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

WSL_DISTRO = "Ubuntu-22.04"
WSL_PATH = (
    "/home/kimlee/.local/bin:/usr/local/sbin:/usr/local/bin:"
    "/usr/sbin:/usr/bin:/sbin:/bin"
)

_WIN_PATH_RE = re.compile(r"^([A-Za-z]):[/\\](.*)$")


def to_wsl_path(arg: str) -> str:
    """Translate a Windows absolute path to a WSL path, leave others unchanged."""
    m = _WIN_PATH_RE.match(arg)
    if not m:
        return arg
    drive = m.group(1).lower()
    rest = m.group(2).replace("\\", "/")
    return f"/mnt/{drive}/{rest}"


def shlex_quote(s: str) -> str:
    """Minimal POSIX shell quoting."""
    if not s:
        return "''"
    safe = re.compile(r"^[A-Za-z0-9_./=+:@%-]+$")
    if safe.match(s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: wsl_tool_runner.py <tool> [args...]", file=sys.stderr)
        return 2
    tool = sys.argv[1]
    args = [to_wsl_path(a) for a in sys.argv[2:]]
    quoted = " ".join(shlex_quote(a) for a in args)
    cmd = ["wsl", "-d", WSL_DISTRO, "--", "bash", "-lc", f"export PATH={WSL_PATH}; {tool} {quoted}"]

    env = os.environ.copy()
    env.setdefault("WSL_UTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
