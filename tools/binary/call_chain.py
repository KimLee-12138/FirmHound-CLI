"""Lightweight call-chain recovery for stripped ARM32 ELF (no Ghidra).

DECOMPILE fallback that answers the questions the verifier needs for a
``command_injection``/``overflow`` candidate:

1. which code locations call a sink import (``system`` / ``doSystemCmd`` /
   ``popen`` / ``strcpy`` ...);
2. whether the *enclosing function* of that call site also calls a source API
   (``websGetVar`` / ``websGetVar64`` ...) -- same-function co-location;
3. which web handler name a function serves. Registration is recovered by a
   *generic* GoAhead pattern that does NOT depend on ``websFormDefine`` being a
   dynamic import (Tenda links it statically): scan every call site, and when
   the caller loads ``r0 = "formXxx..."`` (printable, ``form*``/``from*``) and
   ``r1 = <code address>`` immediately before the call, record
   ``name -> func_addr``. This yields the handler table even when the registrar
   itself is a local function.

Everything is pure Python (``pyelftools`` + ``capstone``). If a step is
inconclusive the module degrades honestly to an empty report -- it never
fabricates a chain.
"""

from __future__ import annotations

import bisect
import re
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs

from tools.binary.elf_read import load_elf

DEFAULT_SOURCE_APIS = (
    "websGetVar",
    "websGetVar64",
    "websGetVarLen",
    "httpdGetChar",
    "websDecodeUrl",
    "websGetQuery",
    "websGetRequest",
    "getenv",
)

DEFAULT_FILTER_APIS = (
    "strncmp",
    "strcmp",
    "atoi",
    "strlen",
    "sscanf",
    "strtol",
    "strtoul",
    "isalpha",
    "isdigit",
)

_FORM_NAME_RE = re.compile(r"^(form|from)[A-Za-z0-9_]{2,}$")
_WINDOW = 14


def _exec_sections(elf: Any) -> list[dict[str, Any]]:
    out = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_PROGBITS" and section["sh_flags"] & 0x4:
            data = section.data()
            if data:
                out.append({"name": section.name, "addr": section["sh_addr"], "data": data})
    return out


def _build_view(elf: Any) -> tuple[list[tuple[int, bytes]], list[tuple[int, int]]]:
    """One-time view of PROGBITS sections: (base, data) + (base, end) ranges."""
    sections: list[tuple[int, bytes]] = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_PROGBITS":
            data = section.data()
            if data:
                sections.append((section["sh_addr"], data))
    ranges = [(base, base + len(data)) for base, data in sections]
    return sections, ranges


def _read_at(view: list[tuple[int, bytes]], va: int, size: int) -> bytes | None:
    for base, data in view:
        off = va - base
        if 0 <= off <= len(data) - size:
            return data[off : off + size]
    return None


def _read_string(view: list[tuple[int, bytes]], va: int, max_len: int = 128) -> str | None:
    raw = _read_at(view, va, max_len)
    if raw is None:
        return None
    end = raw.find(b"\x00")
    if end < 0:
        return None
    text = raw[:end]
    if not text or not all(0x20 <= byte < 0x7F for byte in text):
        return None
    return text.decode("ascii", "ignore")


def _plt_map(elf: Any) -> dict[int, str]:
    """Map PLT stub start -> import name (ARM JUMP_SLOT order == PLT order)."""
    plt_sec = next((s for s in elf.iter_sections() if s.name == ".plt"), None)
    dynsym = elf.get_section_by_name(".dynsym")
    if plt_sec is None or dynsym is None:
        return {}
    slots: list[tuple[int, int]] = []
    for reloc_name in (".rel.plt", ".rela.plt"):
        reloc = elf.get_section_by_name(reloc_name)
        if reloc is None:
            continue
        for r in reloc.iter_relocations():
            if r["r_info_type"] in {2, 7, 21, 22}:
                slots.append((r["r_info_sym"], r["r_offset"]))
    if not slots:
        return {}
    slots.sort(key=lambda pair: pair[1])
    plt_base = plt_sec["sh_addr"]
    header = plt_sec["sh_size"] - 12 * len(slots)
    if header < 0:
        header = 16
    out: dict[int, str] = {}
    for i, (sym_index, _offset) in enumerate(slots):
        try:
            sym = dynsym.get_symbol(sym_index)
        except Exception:  # noqa: BLE001
            continue
        if sym is not None and sym.name:
            out[plt_base + header + i * 12] = sym.name
    return out


def _dest_reg(op_str: str) -> str:
    return op_str.split(",")[0].strip()


def _literal_values(
    view: list[tuple[int, bytes]], window: list[tuple[int, str, str]], reg: str
) -> list[int]:
    """Values loaded into ``reg`` within the window (ldr pc-relative/ADR/movw-movt)."""
    values: list[int] = []
    for addr, mnemonic, op_str in reversed(window):
        if _dest_reg(op_str) != reg:
            continue
        try:
            imm = int(re.search(r"#(0x[0-9a-fA-F]+|\d+)", op_str).group(1), 0)
        except (AttributeError, ValueError):
            imm = None
        if mnemonic == "ldr" and imm is not None and "[pc" in op_str:
            raw = _read_at(view, ((addr + 8) & ~3) + imm, 4)
            if raw is not None:
                values.append(struct.unpack("<I", raw)[0])
        elif mnemonic in {"add", "adr"} and imm is not None:
            values.append(((addr + 8) & ~3) + imm)
        elif mnemonic == "movw" and imm is not None:
            values.append(imm)
        elif mnemonic == "movt" and imm is not None and values:
            values[-1] |= imm << 16
        if len(values) >= 4:
            break
    return values


def recover_chains(
    elf_path: str | Path,
    sink_functions: list[str],
    source_apis: tuple[str, ...] = DEFAULT_SOURCE_APIS,
    filter_apis: tuple[str, ...] = DEFAULT_FILTER_APIS,
) -> dict[str, Any]:
    """Recover sink call sites + handler registrations for one ARM ELF.

    Returns:
        {"status": "ok" | "failed" | "unsupported-arch",
         "sink_callers": [{call_addr, func_addr, sink, same_func_source,
                           same_func_filters}],
         "registration": {handler: func_addr},
         "func_handlers": {func_addr: handler},   # reverse of registration
         "chains": [{handler|None, func_addr, sink, call_addr,
                     same_func_source}]}
    """
    elf = load_elf(elf_path)
    if elf is None:
        return {"status": "failed", "reason": "cannot load ELF"}
    if str(elf["e_machine"]) != "EM_ARM":
        return {"status": "unsupported-arch", "machine": str(elf["e_machine"])}

    sections = _exec_sections(elf)
    if not sections:
        return {"status": "failed", "reason": "no executable sections"}
    view, all_ranges = _build_view(elf)
    plt = _plt_map(elf)
    sinks = set(sink_functions)
    srcs = set(source_apis)
    filters = set(filter_apis)
    exec_ranges = [(s["addr"], s["addr"] + len(s["data"])) for s in sections]
    rodata_ranges = [
        (lo, hi) for lo, hi in all_ranges if not any(xlo <= lo and hi <= xhi for xlo, xhi in exec_ranges)
    ]

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    calls: list[dict[str, Any]] = []
    prologues: list[int] = []
    window: list[tuple[int, str, str]] = []

    for sec in sections:
        data = sec["data"]
        base = sec["addr"]
        pos = 0
        addr = base
        while pos <= len(data) - 4:
            chunk = data[pos : pos + 65536]
            decoded = list(md.disasm(chunk, addr))
            if not decoded:
                pos += 4
                addr += 4
                continue
            for insn in decoded:
                mnem = insn.mnemonic
                op_str = insn.op_str
                window.append((insn.address, mnem, op_str))
                if len(window) > _WINDOW:
                    window.pop(0)
                if mnem in {"bl", "blx"}:
                    target = None
                    if insn.operands and insn.operands[0].type == 2:
                        target = int(insn.operands[0].imm)
                    calls.append(
                        {
                            "addr": insn.address,
                            "target": target,
                            "name": plt.get(target) if target is not None else None,
                            "window": tuple(window),
                        }
                    )
                elif mnem == "push" and "lr" in op_str:
                    prologues.append(insn.address)
            last = decoded[-1]
            pos += (last.address - addr) + last.size
            addr = last.address + last.size

    if not calls:
        empty: dict[str, Any] = {
            "status": "ok",
            "sink_callers": [],
            "registration": {},
            "func_handlers": {},
            "chains": [],
        }
        return empty
    prologues.sort()

    # -- 1) sink call sites + enclosing function co-location ------------------ #
    named = [c for c in calls if c["name"]]
    sink_callers: list[dict[str, Any]] = []
    for ev in named:
        if ev["name"] not in sinks:
            continue
        idx = bisect.bisect_right(prologues, ev["addr"]) - 1
        func_addr = prologues[idx] if idx >= 0 else None
        rec: dict[str, Any] = {
            "call_addr": ev["addr"],
            "func_addr": func_addr,
            "sink": ev["name"],
            "same_func_source": False,
            "same_func_filters": [],
        }
        if func_addr is not None:
            end = prologues[idx + 1] if idx + 1 < len(prologues) else ev["addr"] + 0x2000
            for other in named:
                if func_addr <= other["addr"] < end:
                    if other["name"] in srcs:
                        rec["same_func_source"] = True
                    if other["name"] in filters:
                        rec["same_func_filters"].append(other["name"])
        sink_callers.append(rec)

    # -- 2) generic GoAhead registration: (r0="form*" str, r1=code addr) ------ #
    registration: dict[str, int] = {}
    seen_sites: set[int] = set()
    str_cache: dict[int, str] = {}
    for ev in calls:
        if ev["addr"] in seen_sites:
            continue
        r0_vals = _literal_values(view, ev["window"], "r0")
        name_value: str | None = None
        for va in r0_vals:
            if not any(lo <= va < hi for lo, hi in rodata_ranges):
                continue
            text = str_cache.get(va)
            if text is None:
                text = _read_string(view, va)
                if text is not None:
                    str_cache[va] = text
            if text and _FORM_NAME_RE.match(text):
                name_value = text
                break
        if name_value is None:
            continue
        r1_vals = _literal_values(view, ev["window"], "r1")
        func_value: int | None = None
        for va in r1_vals:
            if any(lo <= va < hi for lo, hi in exec_ranges):
                func_value = va
                break
        if func_value is None and r1_vals:
            func_value = r1_vals[0]
        if name_value and func_value is not None:
            seen_sites.add(ev["addr"])
            registration[name_value] = func_value
    func_handlers = {addr: name for name, addr in registration.items()}

    # -- 3) chains: registration handler whose function calls a sink ---------- #
    chains: list[dict[str, Any]] = []
    for caller in sink_callers:
        func_addr = caller.get("func_addr")
        if func_addr is None:
            continue
        handler = func_handlers.get(func_addr)
        chains.append(
            {
                "handler": handler,
                "func_addr": func_addr,
                "sink": caller["sink"],
                "call_addr": caller["call_addr"],
                "same_func_source": bool(caller.get("same_func_source")),
            }
        )

    return {
        "status": "ok",
        "sink_callers": sink_callers,
        "registration": registration,
        "func_handlers": func_handlers,
        "chains": chains,
    }


__all__ = ["recover_chains", "DEFAULT_SOURCE_APIS", "DEFAULT_FILTER_APIS"]
