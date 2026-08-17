"""Unit tests for the M4 binary tools (secfeatures / danger_scan / elf_triage)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fixtures"))

from elf_builder import build_elf64, write_elf64  # noqa: E402

from tools.binary.danger_scan import scan_dangerous_functions, scan_imports
from tools.binary.elf_triage import triage_elf
from tools.binary.secfeatures import security_features


def _elf(tmp_path: Path, **kwargs: object) -> Path:
    return write_elf64(tmp_path / "sample.elf", **kwargs)


# ---------------------------------------------------------------------------
# secfeatures
# ---------------------------------------------------------------------------


def test_security_features_nx_pie_full_relro_not_stripped(tmp_path: Path) -> None:
    elf = _elf(
        tmp_path,
        e_type=3,  # ET_DYN => PIE
        stack_executable=False,  # NX on
        bind_now=True,  # full RELRO
        has_symtab=True,
        imports=["system"],
        defined_syms=["main"],
        canary=True,
    )
    feat = security_features(elf)
    assert feat["nx"] is True
    assert feat["canary"] is True
    assert feat["pie"] is True
    assert feat["relro"] == "full"
    assert feat["stripped"] is False


def test_security_features_executable_stack_partial_relro(tmp_path: Path) -> None:
    elf = _elf(
        tmp_path,
        e_type=2,  # ET_EXEC => non-PIE
        stack_executable=True,  # NX off
        bind_now=False,  # partial RELRO
        has_symtab=True,
        imports=[],
        defined_syms=["main"],
    )
    feat = security_features(elf)
    assert feat["nx"] is False
    assert feat["canary"] is False
    assert feat["pie"] is False
    assert feat["relro"] == "partial"
    assert feat["stripped"] is False


def test_security_features_stripped_no_relro(tmp_path: Path) -> None:
    elf = _elf(
        tmp_path,
        e_type=2,
        has_gnu_stack=True,
        has_relro=False,
        has_symtab=False,
        imports=["strcpy"],
    )
    feat = security_features(elf)
    assert feat["stripped"] is True
    assert feat["relro"] == "none"


def test_security_features_non_elf(tmp_path: Path) -> None:
    not_elf = tmp_path / "not_elf.bin"
    not_elf.write_bytes(b"MZ not an elf")
    feat = security_features(not_elf)
    assert feat["stripped"] is True
    assert feat["relro"] == "unknown"


# ---------------------------------------------------------------------------
# danger_scan
# ---------------------------------------------------------------------------


def test_scan_imports_cross_signal_critical() -> None:
    report = scan_imports({"system", "sprintf", "strcpy", "malloc"})
    assert report["critical"] is True
    assert report["tiers"]["W"] == ["system"]
    assert report["tiers"]["B"] == ["sprintf", "strcpy"]
    assert report["total_weight"] == 3 + 3 + 3 + 1  # system + sprintf + strcpy + malloc


def test_scan_imports_no_critical_without_format_builder() -> None:
    report = scan_imports({"system", "strcpy"})
    assert report["critical"] is False


def test_scan_dangerous_functions_from_elf(tmp_path: Path) -> None:
    elf = _elf(tmp_path, imports=["system", "sprintf", "getenv"], canary=True)
    report = scan_dangerous_functions(elf)
    assert report["critical"] is True
    assert set(report["tiers"]["W"]) == {"system"}
    assert "getenv" in report["tiers"]["E"]


# ---------------------------------------------------------------------------
# elf_triage
# ---------------------------------------------------------------------------


def test_triage_web_handler_network_and_danger(tmp_path: Path) -> None:
    elf = _elf(
        tmp_path,
        imports=["system", "sprintf", "socket", "recv"],
        rodata_strings=["/cgi-bin", "%s; %s"],
    )
    report = triage_elf(elf, startup_refs=1, attack_surface_refs=1)
    assert report["architecture"] == "x86_64"
    assert "network_imports" in report["reasons"]
    assert "web_handler_strings" in report["reasons"]
    assert "dangerous_imports" in report["reasons"]
    assert "startup_refs=1" in report["reasons"]
    assert "attack_surface_refs=1" in report["reasons"]
    assert 0.0 <= report["triage_score"] <= 1.0
    assert report["raw_score"] > 0


def test_triage_non_elf_zero_score(tmp_path: Path) -> None:
    not_elf = tmp_path / "plain.txt"
    not_elf.write_text("hello", encoding="utf-8")
    report = triage_elf(not_elf)
    assert report["triage_score"] == 0.0
    assert report["raw_score"] == 0
    assert report["architecture"] == "unknown"


def test_triage_score_capped_at_one(tmp_path: Path) -> None:
    elf = _elf(
        tmp_path,
        imports=["system", "sprintf", "socket"],
        rodata_strings=["/cgi-bin", "upnp"],
    )
    report = triage_elf(elf, startup_refs=10, attack_surface_refs=10)
    assert report["triage_score"] == 1.0


def test_build_elf64_round_trip() -> None:
    """The fixture builder itself produces a pyelftools-parseable ELF."""
    data = build_elf64(imports=["system"], defined_syms=["main"], rodata_strings=["abc"])
    assert data[:4] == b"\x7fELF"
    assert len(data) > 64
