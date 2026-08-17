"""Unit tests for attack-surface enumeration tools (M3 front half)."""

from pathlib import Path

from tools.filesystem.inventory import inventory_rootfs
from tools.filesystem.startup_parse import parse_all_startup, parse_startup_script
from tools.web.webroot_enum import enumerate_webroot, find_webroots


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


def _make_rootfs(path: Path) -> None:
    """Create a representative fake rootfs."""
    (path / "bin").mkdir(parents=True)
    (path / "usr" / "sbin").mkdir(parents=True)
    (path / "etc" / "init.d").mkdir(parents=True)
    (path / "www" / "goform").mkdir(parents=True)
    (path / "etc" / "config").mkdir(parents=True)
    (path / "bin" / "busybox").write_bytes(_elf_header())
    (path / "usr" / "sbin" / "httpd").write_bytes(_elf_header())
    (path / "etc" / "init.d" / "rcS").write_text(
        "#!/bin/sh\n/usr/sbin/httpd -h /www\n/bin/busybox syslogd\n",
        encoding="utf-8",
    )
    (path / "www" / "goform" / "formexeCommand").write_text("cgi", encoding="utf-8")
    (path / "www" / "index.html").write_text("<html></html>", encoding="utf-8")
    (path / "www" / "style.css").write_text("body {}", encoding="utf-8")
    (path / "etc" / "config" / "system.conf").write_text("name=router", encoding="utf-8")
    (path / "etc" / "init.d" / "start.sh").write_text("#!/bin/sh\n", encoding="utf-8")


def test_inventory(tmp_path: Path) -> None:
    """inventory_rootfs correctly counts file types."""
    root = tmp_path / "rootfs"
    _make_rootfs(root)
    inv = inventory_rootfs(root)
    assert inv["elf_count"] == 2
    assert inv["script_count"] >= 1
    assert "etc/init.d/rcS" in inv["startup_script_paths"]
    assert "www" in inv["webroots"] or any("www" in w for w in inv["webroots"])


def test_startup_parse(tmp_path: Path) -> None:
    """parse_startup_script extracts service invocations."""
    script = tmp_path / "rcS"
    script.write_text(
        "#!/bin/sh\n/usr/sbin/httpd -h /www\n/bin/busybox syslogd\n",
        encoding="utf-8",
    )
    services = parse_startup_script(script)
    binaries = {s["binary"] for s in services}
    assert "/usr/sbin/httpd" in binaries
    assert "/bin/busybox" in binaries


def test_parse_all_startup(tmp_path: Path) -> None:
    """parse_all_startup groups services by binary name."""
    root = tmp_path / "rootfs"
    _make_rootfs(root)
    parsed = parse_all_startup(root)
    assert parsed["service_count"] >= 2
    assert "httpd" in parsed["grouped"]
    assert any("/www" in s["args"] for s in parsed["grouped"]["httpd"])


def test_webroot_enum(tmp_path: Path) -> None:
    """enumerate_webroot finds CGI endpoints and skips static assets."""
    webroot = tmp_path / "www"
    (webroot / "goform").mkdir(parents=True)
    (webroot / "goform" / "formexeCommand").write_text("cgi", encoding="utf-8")
    (webroot / "index.html").write_text("html", encoding="utf-8")
    (webroot / "style.css").write_text("css", encoding="utf-8")
    result = enumerate_webroot(webroot)
    routes = {e["route"] for e in result["endpoints"]}
    assert "/goform/formexeCommand" in routes
    assert "/index.html" in routes
    assert result["static_asset_count"] == 1


def test_find_webroots(tmp_path: Path) -> None:
    """find_webroots locates webroot directories."""
    root = tmp_path / "rootfs"
    (root / "www").mkdir(parents=True)
    (root / "usr" / "htdocs").mkdir(parents=True)
    webroots = find_webroots(root)
    names = {w.name for w in webroots}
    assert "www" in names
    assert "htdocs" in names
