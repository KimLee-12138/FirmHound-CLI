"""Unit tests for firmware unpacking tools."""

from pathlib import Path

import pytest

from tools.firmware.arch_detect import detect_architecture
from tools.firmware.collect_info import collect_info
from tools.firmware.rootfs_score import score_rootfs_candidates
from tools.firmware.unpack import unpack


def _make_rootfs(path: Path, *, full: bool = True, extra_web: bool = False) -> None:
    """Create a fake rootfs tree for scoring tests."""
    (path / "bin").mkdir(parents=True)
    (path / "sbin").mkdir(parents=True)
    (path / "etc" / "init.d").mkdir(parents=True)
    (path / "lib").mkdir(parents=True)
    (path / "usr").mkdir(parents=True)
    (path / "bin" / "busybox").write_text("busybox", encoding="utf-8")
    (path / "etc" / "init.d" / "rcS").write_text("#!/bin/sh\n", encoding="utf-8")
    if full:
        (path / "www").mkdir(parents=True)
        (path / "usr" / "sbin").mkdir(parents=True)
        (path / "usr" / "sbin" / "httpd").write_text("httpd", encoding="utf-8")
    if extra_web:
        (path / "htdocs").mkdir(parents=True)


def test_rootfs_score_full(tmp_path: Path) -> None:
    """A full rootfs scores high and meets threshold."""
    root = tmp_path / "extracted" / "squashfs-root"
    _make_rootfs(root)
    result = score_rootfs_candidates(root.parent)
    assert result["best"]["path"] == str(root.resolve())
    assert result["best"]["score"] >= 7
    assert result["threshold_met"] is True
    assert result["extraction_confidence"] == 1.0


def test_rootfs_score_partial(tmp_path: Path) -> None:
    """A partial rootfs scores below threshold."""
    root = tmp_path / "extracted" / "squashfs-root"
    # Only create a minimal tree without busybox/initd/web/httpd.
    (root / "bin").mkdir(parents=True)
    (root / "sbin").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    (root / "lib").mkdir(parents=True)
    result = score_rootfs_candidates(root.parent)
    assert result["best"]["score"] < 5
    assert result["threshold_met"] is False
    assert result["extraction_confidence"] < 1.0


def test_collect_info_hashes(tmp_path: Path) -> None:
    """collect_info returns correct hashes and size."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"hello firmware")
    info = collect_info(fw)
    assert info["sha256"] == "836bdaaef7134e769cf2c51b1494bb1602a3975412f7893e8b153ce20bbf3acd"
    assert info["md5"] == "5d99b396caab4bfae4e25207b62b30e2"
    assert info["file_size"] == 14
    assert info["status"] == "success"


def test_collect_info_file_not_found(tmp_path: Path) -> None:
    """collect_info raises for missing firmware."""
    with pytest.raises(FileNotFoundError):
        collect_info(tmp_path / "missing.bin")


def test_unpack_missing_firmware(tmp_path: Path) -> None:
    """Unpack raises for missing firmware."""
    with pytest.raises(FileNotFoundError):
        unpack(tmp_path / "missing.bin", tmp_path / "out")


def test_unpack_carve_fallback(tmp_path: Path) -> None:
    """Unpack falls back to carving when no strategy matches."""
    fw = tmp_path / "fw.bin"
    # Fake squashfs magic at offset 16.
    data = b"A" * 16 + b"hsqs" + b"B" * 32
    fw.write_bytes(data)
    out = tmp_path / "out"
    result = unpack(fw, out)
    assert result["fallback"]["method"] == "carve_fallback"
    assert result["fallback"]["status"] == "partial"
    carved = list(out.glob("carved_*"))
    assert carved


def test_arch_detect_no_elf(tmp_path: Path) -> None:
    """arch_detect returns unknown when no ELF samples exist."""
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "hosts").write_text("127.0.0.1", encoding="utf-8")
    result = detect_architecture(root)
    assert result["architecture"] == "unknown"
    assert result["warning"] == "no ELF samples found"


def test_arch_detect_consistent_elf(tmp_path: Path) -> None:
    """arch_detect picks majority architecture from sampled ELF headers."""
    root = tmp_path / "rootfs"
    root.mkdir()
    elf = root / "bin" / "app"
    elf.parent.mkdir(parents=True)
    # Minimal valid 32-bit little-endian MIPS ELF header.
    header = (
        b"\x7fELF"  # magic (0-3)
        b"\x01"  # 32-bit (4)
        b"\x01"  # little-endian (5)
        b"\x01"  # ELF version (6)
        b"\x00"  # OS/ABI (7)
        + b"\x00" * 8  # pad to fill e_ident[16] (8-15)
        + b"\x01\x00"  # e_type = executable (16-17)
        + b"\x08\x00"  # e_machine = MIPS (18-19)
        + b"\x01\x00\x00\x00"  # e_version (20-23)
        + b"\x00\x10\x00\x00"  # e_entry (24-27)
        + b"\x34\x00\x00\x00"  # e_phoff (28-31)
        + b"\x00\x00\x00\x00"  # e_shoff (32-35)
        + b"\x00\x00\x00\x00"  # e_flags (36-39)
        + b"\x34\x00"  # e_ehsize (40-41)
        + b"\x20\x00"  # e_phentsize (42-43)
        + b"\x01\x00"  # e_phnum (44-45)
        + b"\x28\x00"  # e_shentsize (46-47)
        + b"\x00\x00"  # e_shnum (48-49)
        + b"\x00\x00"  # e_shstrndx (50-51)
    )
    elf.write_bytes(header + b"\x00" * 52)  # pad to >= 52 bytes for readelf
    result = detect_architecture(root)
    assert result["architecture"] == "mips"
    assert result["bits"] == "ELF32"
    assert result["endian"] == "little"
