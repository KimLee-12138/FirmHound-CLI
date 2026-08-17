"""Tests for the end-to-end rootfs analysis (unknown-firmware drill)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fixtures"))

from elf_builder import write_elf64  # noqa: E402

from scripts.run_e2e import analyze_rootfs


def _make_rootfs(tmp_path: Path) -> Path:
    """Build a minimal rootfs with an injected command-injection ELF and CGI."""
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "www" / "cgi-bin").mkdir(parents=True)
    (rootfs / "etc" / "init.d").mkdir(parents=True)

    # ELF with the sprintf+system+getenv command-injection import pattern.
    write_elf64(
        rootfs / "bin" / "httpd",
        imports=["system", "sprintf", "getenv"],
        defined_syms=["formexeCommand"],
        rodata_strings=["QUERY_STRING", "%s; reboot"],
    )

    # CGI with unfiltered QUERY_STRING reaching a shell.
    (rootfs / "www" / "cgi-bin" / "ping.cgi").write_text(
        '#!/bin/sh\neval "ping -c 4 $QUERY_STRING"\n', encoding="utf-8"
    )

    # A benign text file that must NOT produce a candidate.
    (rootfs / "www" / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    return rootfs


def test_analyze_detects_elf_command_injection(tmp_path: Path) -> None:
    rootfs = _make_rootfs(tmp_path)
    result = analyze_rootfs(rootfs)
    elf_candidates = [
        c for c in result["candidates"] if c["candidate_id"].startswith("e2e-elf-")
    ]
    assert elf_candidates, "expected an ELF command-injection candidate"
    cand = elf_candidates[0]
    assert cand["vuln_class_hypothesis"] == "command_injection"
    assert cand["sink"]["function"] == "system"
    assert cand["risk_level"] in ("HIGH", "CRITICAL")


def test_analyze_detects_cgi_command_injection(tmp_path: Path) -> None:
    rootfs = _make_rootfs(tmp_path)
    result = analyze_rootfs(rootfs)
    cgi_candidates = [
        c for c in result["candidates"] if c["candidate_id"].startswith("e2e-cgi-")
    ]
    assert cgi_candidates, "expected a CGI command-injection candidate"
    assert cgi_candidates[0]["sink"]["function"] == "eval"


def test_analyze_reports_binaries_and_endpoints(tmp_path: Path) -> None:
    rootfs = _make_rootfs(tmp_path)
    result = analyze_rootfs(rootfs)
    assert result["inventory"]["elf_count"] == 1
    assert result["endpoint_count"] >= 1
    assert len(result["binaries"]) == 1


def test_analyze_missing_rootfs_raises(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        analyze_rootfs(tmp_path / "does-not-exist")
