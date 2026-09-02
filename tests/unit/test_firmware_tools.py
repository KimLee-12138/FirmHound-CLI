"""Unit tests for firmware unpacking tools."""

from pathlib import Path

import pytest

from fsa.utils.proc import RunResult
from tools.firmware.arch_detect import detect_architecture
from tools.firmware.collect_info import _binwalk_signatures, collect_info
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


def test_rootfs_score_vendor_ro_layout(tmp_path: Path) -> None:
    """Vendor readonly layouts such as etc_ro/webroot_ro score as rootfs."""
    root = tmp_path / "extracted" / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "sbin").mkdir(parents=True)
    (root / "etc_ro" / "init.d").mkdir(parents=True)
    (root / "lib").mkdir(parents=True)
    (root / "usr").mkdir(parents=True)
    (root / "webroot_ro").mkdir(parents=True)
    (root / "bin" / "busybox").write_text("busybox", encoding="utf-8")
    (root / "bin" / "httpd").write_text("httpd", encoding="utf-8")
    (root / "etc_ro" / "init.d" / "rcS").write_text("#!/bin/sh\n", encoding="utf-8")

    result = score_rootfs_candidates(root.parent)

    assert result["best"]["path"] == str(root.resolve())
    assert result["threshold_met"] is True
    assert "has_etc" in result["best"]["markers"]
    assert "has_web" in result["best"]["markers"]


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


def test_binwalk_parser_supports_classic_table(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Classic binwalk table output is parsed into offset signatures."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"firmware")

    monkeypatch.setattr("tools.firmware.collect_info.shutil.which", lambda name: "/bin/binwalk")
    monkeypatch.setattr(
        "tools.firmware.collect_info.run_command",
        lambda cmd, timeout=120: RunResult(
            command="binwalk",
            returncode=0,
            stdout=(
                "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
                "--------------------------------------------------------------------------------\n"
                "64            0x40            TRX firmware header\n"
                "1875608       0x1C9E98        Squashfs filesystem, little endian\n"
            ),
            stderr="",
            status="success",
        ),
    )

    signatures = _binwalk_signatures(fw)
    assert signatures == [
        {"offset": 64, "offset_hex": "0x40", "description": "TRX firmware header"},
        {
            "offset": 1875608,
            "offset_hex": "0x1C9E98",
            "description": "Squashfs filesystem, little endian",
        },
    ]


def test_unpack_extracts_carved_squashfs_slice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A carved inner SquashFS slice is retried with filesystem extractors."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 32)
    out = tmp_path / "out"

    def fake_which(name: str) -> str | None:
        if name in {"binwalk", "unsquashfs"}:
            return f"/bin/{name}"
        return None

    def fake_binwalk(path: Path) -> list[dict[str, object]]:
        return [{"offset": 0, "offset_hex": "0x0", "description": "custom encrypted header"}]

    def fake_run_command(cmd: list[str], timeout: int = 300) -> RunResult:
        extract_dir = Path(cmd[cmd.index("-d") + 1])
        _make_rootfs(extract_dir)
        return RunResult(
            command=" ".join(cmd),
            returncode=0,
            stdout="",
            stderr="",
            status="success",
        )

    monkeypatch.setattr("tools.firmware.collect_info.shutil.which", fake_which)
    monkeypatch.setattr("tools.firmware.unpack.shutil.which", fake_which)
    monkeypatch.setattr("tools.firmware.collect_info._binwalk_signatures", fake_binwalk)
    monkeypatch.setattr("tools.firmware.unpack.run_command", fake_run_command)

    result = unpack(fw, out)
    assert result["status"] == "success"
    assert result["fallback"]["status"] == "success"
    assert result["fallback"]["attempts"][0]["status"] == "extracted"
    assert score_rootfs_candidates(out)["threshold_met"] is True


def test_unpack_rejects_successful_empty_squashfs_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Extractor success without files is treated as failed."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"hsqs" + b"B" * 32)
    out = tmp_path / "out"

    def fake_which(name: str) -> str | None:
        if name in {"binwalk", "unsquashfs"}:
            return f"/bin/{name}"
        return None

    def fake_run_command(cmd: list[str], timeout: int = 300) -> RunResult:
        extract_dir = Path(cmd[cmd.index("-d") + 1])
        assert not extract_dir.exists()
        return RunResult(
            command=" ".join(cmd),
            returncode=0,
            stdout="",
            stderr="reported success but wrote nothing",
            status="success",
        )

    monkeypatch.setattr("tools.firmware.collect_info.shutil.which", fake_which)
    monkeypatch.setattr("tools.firmware.unpack.shutil.which", fake_which)
    monkeypatch.setattr(
        "tools.firmware.collect_info._binwalk_signatures",
        lambda path: [{"offset": 0, "offset_hex": "0x0", "description": "custom header"}],
    )
    monkeypatch.setattr("tools.firmware.unpack.run_command", fake_run_command)

    result = unpack(fw, out)
    extraction = result["fallback"]["attempts"][0]["extraction"]["attempts"][0]
    assert extraction["attempts"][0]["status"] == "failed"


def test_unpack_records_encrypted_openssl_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Encrypted OpenSSL-style payloads are recorded without noisy gzip carving."""
    fw = tmp_path / "encrypted.bin"
    fw.write_bytes(b"H" * 16 + b"Salted__12345678" + b"\x1f\x8b" + b"ciphertext")
    out = tmp_path / "out"

    monkeypatch.setattr("tools.firmware.collect_info.shutil.which", lambda name: "/bin/binwalk")
    monkeypatch.setattr("tools.firmware.unpack.shutil.which", lambda name: None)
    monkeypatch.setattr(
        "tools.firmware.collect_info._binwalk_signatures",
        lambda path: [
            {
                "offset": 16,
                "offset_hex": "0x10",
                "description": "OpenSSL encryption, salted, salt: 0x3132333435363738",
            }
        ],
    )

    result = unpack(fw, out)

    assert result["encrypted"]["status"] == "degraded"
    assert result["encrypted"]["attempts"][0]["format"] == "openssl-salted"
    assert Path(result["encrypted"]["attempts"][0]["slice"]).read_bytes().startswith(b"Salted__")
    assert result["fallback"]["attempts"] == []


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
