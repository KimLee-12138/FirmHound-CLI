"""Integration tests for M3 attack surface enumeration.

Uses synthetic rootfs fixtures that mimic the structure of known vulnerable
firmwares (Tenda AC15 formexeCommand, Huawei HG532e UPnP Upgrade).
"""

from __future__ import annotations

from pathlib import Path

from tools.web.build_attack_surface import build_attack_surface


def _elf_header() -> bytes:
    """Return a minimal valid 32-bit little-endian MIPS ELF header."""
    return (
        b"\x7fELF" + b"\x01\x01\x01\x00" + b"\x00" * 8
        + b"\x01\x00"  # e_type
        + b"\x08\x00"  # e_machine = MIPS
        + b"\x01\x00\x00\x00"
        + b"\x00\x10\x00\x00"
        + b"\x34\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x34\x00"
        + b"\x20\x00"
        + b"\x01\x00"
        + b"\x28\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )


def _make_ac15_like(root: Path) -> None:
    """Create a rootfs resembling Tenda AC15 (GoAhead formexeCommand)."""
    (root / "usr" / "sbin").mkdir(parents=True)
    (root / "www" / "goform").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    (root / "usr" / "sbin" / "httpd").write_bytes(
        _elf_header() + b"formexeCommand\x00websFormDefine\x00"
    )
    (root / "www" / "goform" / "formexeCommand").write_text("cgi", encoding="utf-8")
    (root / "etc" / "init.d" / "rcS").write_text(
        "#!/bin/sh\n/usr/sbin/httpd -h /www\n", encoding="utf-8"
    )


def _make_hg532e_like(root: Path) -> None:
    """Create a rootfs resembling Huawei HG532e (UPnP DevUpg.xml)."""
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    (root / "usr" / "bin" / "upnp").write_bytes(_elf_header())
    (root / "etc" / "init.d" / "rcS").write_text(
        "#!/bin/sh\n/usr/bin/upnp &\n", encoding="utf-8"
    )
    upnp_dir = root / "upnp"
    upnp_dir.mkdir(parents=True)
    (upnp_dir / "DevUpg.xml").write_text(
        '''<?xml version="1.0"?>
        <scpd>
          <actionList>
            <action>
              <name>Upgrade</name>
              <argumentList>
                <argument>
                  <name>NewDownloadURL</name>
                  <direction>in</direction>
                </argument>
                <argument>
                  <name>NewStatusURL</name>
                  <direction>in</direction>
                </argument>
              </argumentList>
            </action>
          </actionList>
        </scpd>
        ''',
        encoding="utf-8",
    )


def test_ac15_formexe_command(tmp_path: Path) -> None:
    """AC15-like rootfs must surface the formexeCommand endpoint."""
    root = tmp_path / "rootfs"
    _make_ac15_like(root)
    result = build_attack_surface(root, "run-ac15", tmp_path / "runs")
    routes = {s["route"] for s in result["surfaces"]}
    assert "/goform/formexeCommand" in routes


def test_hg532e_upnp_upgrade(tmp_path: Path) -> None:
    """HG532e-like rootfs must surface the UPnP Upgrade action."""
    root = tmp_path / "rootfs"
    _make_hg532e_like(root)
    result = build_attack_surface(root, "run-hg532e", tmp_path / "runs")
    upnp_surfaces = [s for s in result["surfaces"] if s["category"] == "upnp"]
    assert upnp_surfaces
    handlers = {s["handler"] for s in upnp_surfaces}
    assert "Upgrade" in handlers
