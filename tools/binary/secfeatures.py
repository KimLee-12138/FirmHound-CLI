"""Detect ELF security hardening features (NX / Canary / PIE / RELRO / Stripped).

Reimplements the ``checksec`` decision logic using :mod:`pyelftools` so it runs
without the external ``checksec`` or ``readelf`` binaries. Output aligns with
the ``security_features`` object in ``binary_summary.schema.json``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from tools.binary.elf_read import iter_symbols, load_elf

_PF_X = 0x1
_DF_1_NOW = 0x1

_CANARY_SYMBOLS = {"__stack_chk_fail", "__stack_chk_guard", "__stack_smash_handler"}


def _has_gnu_stack(elf: ELFFile) -> tuple[bool, bool]:
    """Return ``(present, executable)`` for the ``PT_GNU_STACK`` segment."""
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return True, bool(seg["p_flags"] & _PF_X)
    return False, False


def _has_relro(elf: ELFFile) -> bool:
    return any(seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments())


def _has_bind_now(elf: ELFFile) -> bool:
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is None:
        return False
    for tag in dynamic.iter_tags():
        d_tag = tag["d_tag"]
        if d_tag == "DT_BIND_NOW":
            return True
        if d_tag == "DT_FLAGS_1" and tag["d_val"] & _DF_1_NOW:
            return True
    return False


def _is_pie(elf: ELFFile) -> bool:
    return elf["e_type"] == "ET_DYN"


def _is_stripped(elf: ELFFile) -> bool:
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return True
    return symtab.num_symbols() == 0


def security_features(path: str | Path) -> dict[str, Any]:
    """Compute hardening features for an ELF.

    Returns a dict shaped like the ``security_features`` field of
    ``binary_summary.schema.json``. When the file is not a valid ELF, every
    field falls back to a conservative ``unknown``/``False`` value so the
    caller never crashes.
    """
    elf = load_elf(path)
    if elf is None:
        return {"nx": False, "canary": False, "pie": False, "relro": "unknown", "stripped": True}

    present, executable = _has_gnu_stack(elf)
    nx = present and not executable

    canary = any(sym in _CANARY_SYMBOLS for sym in iter_symbols(elf))

    relro = ("full" if _has_bind_now(elf) else "partial") if _has_relro(elf) else "none"

    return {
        "nx": nx,
        "canary": canary,
        "pie": _is_pie(elf),
        "relro": relro,
        "stripped": _is_stripped(elf),
    }
