"""Lightweight call-chain recovery for stripped ARM32 ELF (no Ghidra).

DECOMPILE fallback that answers the questions the verifier needs for a
``command_injection``/``overflow`` candidate:

1. which code locations call a sink import (``system`` / ``doSystemCmd`` /
   ``popen`` / ``strcpy`` ...);
2. whether the *enclosing function* of that call site also calls a source API
   (``websGetVar`` / ``websGetVar64`` ...) -- the same-function co-location
   signal that upgrades "binary imports a sink" into "one function reads a
   request value and then calls the sink";
3. whether a GoAhead registration table (``websFormDefine(name, func)`` /
   ``websAspDefine``) maps a handler name onto that function -- a real entry
   point, so a candidate's ``call_chain`` becomes [handler, sink-caller].

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

# ARM PLT layout used by GNU ld for ARM executables:
#   0x00: header (12 bytes padded to 16); 0x10: entry[0]; entry[i] at +12*i
_PLT_HEADER = 16
_PLT_ENTRY = 12

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


def _exec_sections(elf: Any) -> list[dict[str, Any]]:
    out = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_PROGBITS" and section["sh_flags"] & 0x4:
            data = section.data()
            if data:
                out.append({"name": section.name, "addr": section["sh_addr"], "data": data})
    return out


def _read_at(elf: Any, va: int, size: int) -> bytes | None:
    for section in elf.iter_sections():
        if section["sh_type"] != "SHT_PROGBITS":
            continue
        base = section["sh_addr"]
        if base <= va < base + section["sh_size"]:
            data = section.data()
            off = va - base
            if 0 <= off <= len(data) - size:
                return data[off : off + size]
    return None


def _read_string(elf: Any, va: int, max_len: int = 96) -> str | None:
    out = bytearray()
    for _ in range(max_len):
        one = _read_at(elf, va + len(out), 1)
        if one is None:
            return None
        byte = one[0]
        if byte == 0:
            break
        if not (0x20 <= byte < 0x7F):
            return None
        out.append(byte)
    text = bytes(out).decode("ascii", "ignore")
    return text if text else None


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
            if r["r_info_type"] in {2, 7, 21, 22}:  # JUMP_SLOT/GLOB_DAT (ARM/MIPS)
                slots.append((r["r_info_sym"], r["r_offset"]))
    if not slots:
        return {}
    slots.sort(key=lambda pair: pair[1])
    plt_base = plt_sec["sh_addr"]
    # Header size is not a fixed 16: derive it from (plt_size - N*entry).
    header = plt_sec["sh_size"] - _PLT_ENTRY * len(slots)
    if header < 0:
        header = _PLT_HEADER
    out: dict[int, str] = {}
    for i, (sym_index, _offset) in enumerate(slots):
        try:
            sym = dynsym.get_symbol(sym_index)
        except Exception:  # noqa: BLE001
            continue
        if sym is not None and sym.name:
            out[plt_base + header + i * _PLT_ENTRY] = sym.name
    return out


def _dest_reg(op_str: str) -> str:
    return op_str.split(",")[0].strip()


def _literal_loads(
    elf: Any, events: list[dict[str, Any]], reg: str
) -> list[int]:
    """Collect 32-bit values loaded into ``reg`` across the recent events.

    Handles ``ldr reg, [pc, #imm]`` (literal pool), ``add/adr reg, pc, #imm``
    and ``movw/movt`` register pairs.
    """
    values: list[int] = []
    for ev in reversed(events):
        if _dest_reg(ev["op_str"]) != reg:
            continue
        mnem = ev["mnemonic"]
        op_str = ev["op_str"]
        try:
            imm = int(re.search(r"#(0x[0-9a-fA-F]+|\d+)", op_str).group(1), 0)
        except (AttributeError, ValueError):
            imm = None
        if mnem == "ldr" and imm is not None and "[pc" in op_str:
            va = ((ev["addr"] + 8) & ~3) + imm
            raw = _read_at(elf, va, 4)
            if raw is not None:
                values.append(struct.unpack("<I", raw)[0])
        elif mnem in {"add", "adr"} and imm is not None:
            values.append(((ev["addr"] + 8) & ~3) + imm)
        elif mnem == "movw" and imm is not None:
            values.append(imm)
        elif mnem == "movt" and imm is not None and values:
            values[-1] |= imm << 16
        if len(values) >= 4:
            break
    return values


def recover_chains(
    elf_path: str | Path,
    sink_functions: list[str],
    source_apis: tuple[str, ...] = DEFAULT_SOURCE_APIS,
    filter_apis: tuple[str, ...] = DEFAULT_FILTER_APIS,
    register_symbols: tuple[str, ...] = ("websFormDefine", "websAspDefine"),
) -> dict[str, Any]:
    """Recover sink call sites + handler registrations for one ARM ELF.

    Returns:
        {"status": "ok" | "failed" | "unsupported-arch",
         "sink_callers": [{call_addr, func_addr, sink, same_func_source,
                           same_func_filters}],
         "registration": {handler: func_addr},
         "chains": [{handler, func_addr, sink, call_addr, same_func_source}]}
    """
    elf = load_elf(elf_path)
    if elf is None:
        return {"status": "failed", "reason": "cannot load ELF"}
    if str(elf["e_machine"]) != "EM_ARM":  # only ARM32 for now
        return {"status": "unsupported-arch", "machine": str(elf["e_machine"])}

    sections = _exec_sections(elf)
    if not sections:
        return {"status": "failed", "reason": "no executable sections"}
    plt = _plt_map(elf)
    sinks = set(sink_functions)
    regs = set(register_symbols)
    srcs = set(source_apis)
    filters = set(filter_apis)

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    events: list[dict[str, Any]] = []
    prologues: list[int] = []
    for sec in sections:
        data = sec["data"]
        base = sec["addr"]
        # Chunked linear sweep: capstone stops at the first undecodable word,
        # so resume 4 bytes past the failure until the section is exhausted.
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
                if mnem in {"bl", "blx"}:
                    target = None
                    if insn.operands and insn.operands[0].type == 2:
                        target = int(insn.operands[0].imm)
                    events.append(
                        {
                            "addr": insn.address,
                            "mnemonic": mnem,
                            "op_str": op_str,
                            "target": target,
                            "name": plt.get(target) if target is not None else None,
                            "is_call": True,
                        }
                    )
                else:
                    events.append(
                        {
                            "addr": insn.address,
                            "mnemonic": mnem,
                            "op_str": op_str,
                            "target": None,
                            "name": None,
                            "is_call": False,
                        }
                    )
                    if mnem == "push" and "lr" in op_str:
                        prologues.append(insn.address)
            last = decoded[-1]
            pos += (last.address - addr) + last.size
            addr = last.address + last.size
    prologues.sort()
    call_events = [e for e in events if e["is_call"] and e["name"]]

    # -- 1) sink call sites + enclosing function co-location ------------------ #
    sink_callers: list[dict[str, Any]] = []
    for ev in call_events:
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
            for other in call_events:
                if func_addr <= other["addr"] < end:
                    if other["name"] in srcs:
                        rec["same_func_source"] = True
                    if other["name"] in filters:
                        rec["same_func_filters"].append(other["name"])
        sink_callers.append(rec)

    # -- 2) handler registration: websFormDefine(name, func) ----------------- #
    registration: dict[str, int] = {}
    for i, ev in enumerate(events):
        if not ev["is_call"] or ev["name"] not in regs:
            continue
        window = events[max(0, i - 12) : i]
        r0_vals = _literal_loads(elf, window, "r0")
        r1_vals = _literal_loads(elf, window, "r1")
        name_value: str | None = None
        for va in r0_vals:
            text = _read_string(elf, va)
            if text and _FORM_NAME_RE.match(text):
                name_value = text
                break
        if name_value is None:
            continue
        func_value: int | None = None
        exec_ranges = [(s["addr"], s["addr"] + len(s["data"])) for s in sections]
        for va in r1_vals:
            if any(lo <= va < hi for lo, hi in exec_ranges):
                func_value = va
                break
        if func_value is None and r1_vals:
            func_value = r1_vals[0]
        if func_value is not None:
            registration[name_value] = func_value

    # -- 3) chains: registration handler whose function calls a sink ---------- #
    chains: list[dict[str, Any]] = []
    for handler, func_addr in registration.items():
        for caller in sink_callers:
            if caller.get("func_addr") == func_addr:
                chains.append(
                    {
                        "handler": handler,
                        "func_addr": func_addr,
                        "sink": caller["sink"],
                        "call_addr": caller["call_addr"],
                        "same_func_source": bool(caller.get("same_func_source")),
                    }
                )
                break

    return {
        "status": "ok",
        "sink_callers": sink_callers,
        "registration": registration,
        "chains": chains,
    }


__all__ = ["recover_chains", "DEFAULT_SOURCE_APIS", "DEFAULT_FILTER_APIS"]
