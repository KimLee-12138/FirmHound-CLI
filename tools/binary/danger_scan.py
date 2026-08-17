"""Six-tier dangerous-function scanner for ELF imports (D/E/F/B/M/W).

The tier scheme follows the legacy SKILL1 module-4 classification and feeds
both the M4 triage score and the M5 static-audit sink matching:

* ``W`` — command execution (highest weight)
* ``B`` — buffer / memory copy (overflow potential)
* ``F`` — format string
* ``M`` — memory management
* ``E`` — environment variable access
* ``D`` — dangerous path / temp / permission APIs (lowest weight)

A cross-signal flag is set when a command-execution sink coexists with a
``sprintf``/``snprintf``-family function (the classic shell-command string
builder pattern seen in CVE-2017-17215 and CVE-2023-27021).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.binary.elf_read import iter_imports, load_elf

# name -> (tier, weight, category)
DANGER_FUNCTIONS: dict[str, tuple[str, int, str]] = {
    # W: command execution
    "system": ("W", 3, "command_execution"),
    "__system": ("W", 3, "command_execution"),
    "popen": ("W", 3, "command_execution"),
    "execl": ("W", 3, "command_execution"),
    "execlp": ("W", 3, "command_execution"),
    "execle": ("W", 3, "command_execution"),
    "execv": ("W", 3, "command_execution"),
    "execvp": ("W", 3, "command_execution"),
    "execve": ("W", 3, "command_execution"),
    "doSystemCmd": ("W", 3, "command_execution"),
    "lxmldbc_system": ("W", 3, "command_execution"),
    "alpha_system2": ("W", 3, "command_execution"),
    # B: buffer overflow (unbounded / length-sensitive copies)
    "strcpy": ("B", 3, "buffer_overflow"),
    "strcat": ("B", 3, "buffer_overflow"),
    "gets": ("B", 3, "buffer_overflow"),
    "sprintf": ("B", 3, "buffer_overflow"),
    "vsprintf": ("B", 3, "buffer_overflow"),
    "sscanf": ("B", 2, "buffer_overflow"),
    "strncpy": ("B", 2, "buffer_overflow"),
    "strncat": ("B", 2, "buffer_overflow"),
    "memcpy": ("B", 2, "buffer_overflow"),
    "memmove": ("B", 2, "buffer_overflow"),
    # F: format string
    "printf": ("F", 2, "format_string"),
    "fprintf": ("F", 2, "format_string"),
    "snprintf": ("F", 2, "format_string"),
    "vsnprintf": ("F", 2, "format_string"),
    "syslog": ("F", 2, "format_string"),
    # M: memory management
    "malloc": ("M", 1, "memory"),
    "calloc": ("M", 1, "memory"),
    "realloc": ("M", 1, "memory"),
    "free": ("M", 1, "memory"),
    "alloca": ("M", 1, "memory"),
    # E: environment
    "getenv": ("E", 1, "environment"),
    "setenv": ("E", 1, "environment"),
    "putenv": ("E", 1, "environment"),
    # D: dangerous path / temp / permission
    "access": ("D", 1, "dangerous"),
    "mktemp": ("D", 1, "dangerous"),
    "tmpnam": ("D", 1, "dangerous"),
    "chmod": ("D", 1, "dangerous"),
    "chown": ("D", 1, "dangerous"),
    "strtok": ("D", 1, "dangerous"),
}

# command-execution sinks that, combined with sprintf-family, mark a critical pattern.
_COMMAND_SINKS = {"system", "__system", "popen", "doSystemCmd", "lxmldbc_system", "alpha_system2"}
_FORMAT_BUILDERS = {"sprintf", "snprintf", "vsprintf", "vsnprintf"}


def scan_imports(imports: set[str] | list[str]) -> dict[str, Any]:
    """Scan a collection of import names and return the danger-scan report.

    This is the pure, unit-testable core; :func:`scan_dangerous_functions`
    wraps it with ELF import extraction.
    """
    hits: list[dict[str, Any]] = []
    tiers: dict[str, list[str]] = {t: [] for t in "DEFBMW"}
    total_weight = 0

    for name in sorted(imports):
        rule = DANGER_FUNCTIONS.get(name)
        if rule is None:
            continue
        tier, weight, category = rule
        hits.append({"function": name, "tier": tier, "weight": weight, "category": category})
        tiers[tier].append(name)
        total_weight += weight

    command_sinks = {name for name in imports if name in _COMMAND_SINKS}
    format_builders = {name for name in imports if name in _FORMAT_BUILDERS}
    critical = bool(command_sinks and format_builders)

    return {
        "hits": hits,
        "tiers": tiers,
        "critical": critical,
        "total_weight": total_weight,
    }


def scan_dangerous_functions(path: str | Path) -> dict[str, Any]:
    """Extract imports from an ELF and return the danger-scan report."""
    elf = load_elf(path)
    imports = set(iter_imports(elf)) if elf is not None else set()
    return scan_imports(imports)
