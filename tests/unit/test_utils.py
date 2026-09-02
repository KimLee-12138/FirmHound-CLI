"""Unit tests for fsa.utils helpers."""

from pathlib import Path

from fsa.utils.hashing import md5_file, sha256_bytes, sha256_file
from fsa.utils.jsonio import load_json, save_json
from fsa.utils.netcheck import contains_private_ip, is_private_ip
from fsa.utils.proc import run_command


def test_sha256_file(tmp_path: Path) -> None:
    """SHA-256 of a known file should match."""
    f = tmp_path / "hello.txt"
    f.write_text("hello", encoding="utf-8")
    expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert sha256_file(f) == expected


def test_md5_file(tmp_path: Path) -> None:
    """MD5 of a known file should match."""
    f = tmp_path / "hello.txt"
    f.write_text("hello", encoding="utf-8")
    expected = "5d41402abc4b2a76b9719d911017c592"
    assert md5_file(f) == expected


def test_sha256_bytes() -> None:
    """SHA-256 of known bytes should match."""
    assert (
        sha256_bytes(b"hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_is_private_ip() -> None:
    """Private/reserved IPs are recognized; public IPs are not."""
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("224.0.0.1") is False
    assert is_private_ip("2001:4860:4860::8888") is False
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("not-an-ip") is False


def test_contains_private_ip() -> None:
    """Text scanning finds embedded private IPs."""
    assert contains_private_ip("server at 192.168.0.1:8080") is True
    assert contains_private_ip("server at 8.8.8.8") is False


def test_jsonio_roundtrip(tmp_path: Path) -> None:
    """save_json + load_json preserves data and writes final newline."""
    f = tmp_path / "data.json"
    payload = {"key": "value", "list": [1, 2, 3]}
    save_json(f, payload)
    assert load_json(f) == payload
    assert f.read_text(encoding="utf-8").endswith("\n")


def test_run_command_success() -> None:
    """run_command captures stdout and success status."""
    result = run_command(["python", "-c", "print('ok')"])
    assert result.status == "success"
    assert result.returncode == 0
    assert result.stdout.strip() == "ok"


def test_run_command_failure() -> None:
    """run_command returns failed status without raising."""
    result = run_command(["python", "-c", "import sys; sys.exit(1)"])
    assert result.status == "failed"
    assert result.returncode == 1


def test_run_command_timeout() -> None:
    """run_command returns timeout status for slow commands."""
    result = run_command(["python", "-c", "import time; time.sleep(10)"], timeout=0.1)
    assert result.status == "timeout"
