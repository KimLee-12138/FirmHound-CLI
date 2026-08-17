"""Shared ELF reading helpers for the M4 binary tools.

All parsing is done with :mod:`pyelftools` so the tools run on Windows
without the Linux ``readelf``/``objdump``/``strings`` toolchain.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from elftools.elf.elffile import ELFFile

# Map pyelftools ``get_machine_arch()`` strings to canonical names (aligned
# with :mod:`tools.firmware.arch_detect`).
_ARCH_MAP: dict[str, str] = {
    "MIPS": "mips",
    "ARM": "arm",
    "x86": "i386",
    "x64": "x86_64",
    "AArch64": "aarch64",
    "PowerPC": "powerpc",
    "SPARC": "sparc",
}

# Sections whose raw bytes are scanned for printable ASCII strings.
_STRING_SECTIONS = {".rodata", ".data", ".strtab", ".dynstr", ".comment"}

_ASCII_PATTERN = re.compile(rb"[ -~]{4,}")


def load_elf(path: str | Path) -> ELFFile | None:
    """Open ``path`` as an ELF, returning ``None`` when it is not a valid ELF."""
    try:
        fh = Path(path).open("rb")  # noqa: SIM115 - handle stays open for lazy reads
    except OSError:
        return None
    try:
        return ELFFile(fh)
    except Exception:  # noqa: BLE001 - pyelftools raises on non-ELF input
        fh.close()
        return None


def canonical_arch(elf: ELFFile) -> str:
    """Return a canonical architecture string for an ELF (mipsel vs mips aware)."""
    machine = elf.get_machine_arch()
    base = _ARCH_MAP.get(machine, machine.lower())
    if base == "mips":
        return "mipsel" if elf.little_endian else "mips"
    return base


def iter_symbols(elf: ELFFile) -> Iterator[str]:
    """Yield every symbol name present in the ELF (dynsym and symtab)."""
    seen: set[str] = set()
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for sym in section.iter_symbols():
            name = sym.name
            if name and name not in seen:
                seen.add(name)
                yield name


def iter_imports(elf: ELFFile) -> Iterator[str]:
    """Yield imported function names (undefined symbols)."""
    seen: set[str] = set()
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for sym in section.iter_symbols():
            if sym["st_shndx"] == "SHN_UNDEF":
                name = sym.name
                if name and name not in seen:
                    seen.add(name)
                    yield name


def iter_strings(elf: ELFFile) -> Iterator[str]:
    """Yield printable ASCII strings (>=4 chars) from data-bearing sections."""
    seen: set[str] = set()
    for section in elf.iter_sections():
        if section.name not in _STRING_SECTIONS:
            continue
        try:
            data = section.data()
        except Exception:  # noqa: BLE001 - NOBITS sections have no data
            continue
        for match in _ASCII_PATTERN.finditer(data):
            text = match.group().decode("ascii", errors="ignore")
            if text not in seen:
                seen.add(text)
                yield text


def is_elf(path: str | Path) -> bool:
    """Return True if the file starts with the ELF magic."""
    try:
        with Path(path).open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False
