"""Build minimal ELF64 fixtures for the M4 tool unit tests.

:mod:`pyelftools` can read but not write ELF files, so this module hand-
assembles a minimal ELF64 little-endian binary with just enough structure for
the M4 readers: program headers (``PT_GNU_STACK`` / ``PT_GNU_RELRO``),
``.dynsym`` / ``.symtab`` with imports, an optional ``.dynamic`` section, and
``.rodata`` strings.
"""

from __future__ import annotations

import struct
from pathlib import Path

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

SHN_UNDEF = 0

STB_GLOBAL = 1
STT_FUNC = 2

DT_NULL = 0
DT_BIND_NOW = 24

PF_R = 4
PF_W = 2
PF_X = 1


def _ident() -> bytes:
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2  # 64-bit
    ident[5] = 1  # little-endian
    ident[6] = 1  # ELF version
    return bytes(ident)


def _elf_header(
    e_type: int,
    e_phoff: int,
    e_shoff: int,
    e_phnum: int,
    e_shnum: int,
    e_shstrndx: int,
) -> bytes:
    return struct.pack(
        "<16sHHIQQQIHHHHHH",
        _ident(),
        e_type,
        EM_X86_64,
        1,  # e_version
        0,  # e_entry
        e_phoff,
        e_shoff,
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        e_phnum,
        64,  # e_shentsize
        e_shnum,
        e_shstrndx,
    )


def _phdr(p_type: int, p_flags: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, p_flags, 0, 0, 0, 0, 0, 0)


def _shdr(
    sh_name: int,
    sh_type: int,
    sh_offset: int,
    sh_size: int,
    sh_link: int,
    sh_entsize: int,
) -> bytes:
    return struct.pack(
        "<IIQQQQIIQQ", sh_name, sh_type, 0, 0, sh_offset, sh_size, sh_link, 0, 1, sh_entsize
    )


def _sym(st_name: int, st_info: int, st_shndx: int) -> bytes:
    return struct.pack("<IBBHQQ", st_name, st_info, 0, st_shndx, 0, 0)


def _null_sym() -> bytes:
    return _sym(0, 0, 0)


def _strtab(names: list[str]) -> tuple[bytes, dict[str, int]]:
    data = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(data)
        data.extend(name.encode("ascii"))
        data.extend(b"\x00")
    return bytes(data), offsets


def build_elf64(
    *,
    e_type: int = ET_DYN,
    has_gnu_stack: bool = True,
    stack_executable: bool = False,
    has_relro: bool = True,
    bind_now: bool = False,
    has_symtab: bool = True,
    imports: list[str] | None = None,
    defined_syms: list[str] | None = None,
    rodata_strings: list[str] | None = None,
    canary: bool = False,
) -> bytes:
    """Assemble a minimal ELF64 file and return its bytes."""
    imports = list(imports or [])
    defined_syms = list(defined_syms or [])
    rodata_strings = list(rodata_strings or [])
    if canary:
        imports = [*imports, "__stack_chk_fail"]

    # Content blobs.
    dynstr, dyn_offsets = _strtab(imports)
    dynsym = _null_sym() + b"".join(
        _sym(dyn_offsets[n], (STB_GLOBAL << 4) | STT_FUNC, SHN_UNDEF) for n in imports
    )

    strtab, str_offsets = _strtab(defined_syms)
    symtab = _null_sym() + b"".join(
        _sym(str_offsets[n], (STB_GLOBAL << 4) | STT_FUNC, 1) for n in defined_syms
    )

    rodata = b"\x00".join(s.encode("ascii") for s in rodata_strings)
    if rodata:
        rodata += b"\x00"

    dynamic = b""
    if bind_now:
        dynamic = struct.pack("<QQ", DT_BIND_NOW, 0) + struct.pack("<QQ", DT_NULL, 0)

    # Build an ordered section plan: (name, type, data, link, entsize).
    plan: list[tuple[str, int, bytes, int, int]] = []
    plan.append((".dynstr", SHT_STRTAB, dynstr, 0, 0))
    plan.append((".dynsym", SHT_DYNSYM, dynsym, 0, 24))  # link patched below
    if has_symtab:
        plan.append((".strtab", SHT_STRTAB, strtab, 0, 0))
        plan.append((".symtab", SHT_SYMTAB, symtab, 0, 24))  # link patched below
    plan.append((".rodata", SHT_PROGBITS, rodata, 0, 0))
    if bind_now:
        plan.append((".dynamic", SHT_DYNAMIC, dynamic, 0, 16))

    # Section names string table (.shstrtab) covers every section name.
    all_names = [".shstrtab"] + [name for name, *_ in plan]
    shstrtab, shstr_offsets = _strtab(all_names)

    # Index map: null(0) + .shstrtab(1) + plan sections (2..n).
    idx: dict[str, int] = {}
    next_idx = 2
    for name, *_ in plan:
        idx[name] = next_idx
        next_idx += 1

    # Patch link fields: dynsym -> dynstr, symtab -> strtab, dynamic -> dynstr.
    patched: list[tuple[str, int, bytes, int, int]] = []
    for name, stype, data, _link, entsize in plan:
        link = 0
        if name in (".dynsym", ".dynamic"):
            link = idx[".dynstr"]
        elif name == ".symtab":
            link = idx[".strtab"]
        patched.append((name, stype, data, link, entsize))
    plan = patched

    # Program headers come right after the ELF header.
    phnum = int(has_gnu_stack) + int(has_relro)
    base = 64 + 56 * phnum

    # Assign file offsets for each section (starting right after the phdrs).
    offsets: list[int] = []
    cursor = base
    for _name, _stype, data, _link, _entsize in plan:
        offsets.append(cursor)
        cursor += len(data)

    # .shstrtab data sits after all plan-section data.
    shstrtab_off = cursor
    shoff = shstrtab_off + len(shstrtab)

    # Build section header table (null + .shstrtab + plan sections).
    shdrs = [_shdr(0, SHT_NULL, 0, 0, 0, 0)]
    shdrs.append(_shdr(shstr_offsets[".shstrtab"], SHT_STRTAB, shstrtab_off, len(shstrtab), 0, 0))
    for (name, stype, data, link, entsize), sec_off in zip(plan, offsets, strict=True):
        shdrs.append(_shdr(shstr_offsets[name], stype, sec_off, len(data), link, entsize))

    shnum = len(shdrs)
    shstrndx = 1

    section_data = b"".join(data for _n, _t, data, _l, _e in plan) + shstrtab
    section_table = b"".join(shdrs)

    phdrs: list[bytes] = []
    if has_gnu_stack:
        flags = (PF_R | PF_W) | (PF_X if stack_executable else 0)
        phdrs.append(_phdr(PT_GNU_STACK, flags))
    if has_relro:
        phdrs.append(_phdr(PT_GNU_RELRO, PF_R))

    header = _elf_header(e_type, 64, shoff, phnum, shnum, shstrndx)
    return header + b"".join(phdrs) + section_data + section_table


def write_elf64(path: str | Path, **kwargs: object) -> Path:
    """Write a minimal ELF64 to ``path`` and return it as a ``Path``."""
    target = Path(path)
    target.write_bytes(build_elf64(**kwargs))
    return target
