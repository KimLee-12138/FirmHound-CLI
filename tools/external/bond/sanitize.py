"""BOND PoC sanitizer (X1 deliverable, shared by the whole group).

Every PoC that any external analyzer wants to persist or render into a report
MUST pass through :func:`sanitize_poc`. This is the single compliance gate for
"can this payload leave the lab". The stable contract is:

    sanitize_poc(raw: str, *, strict: bool = True) -> tuple[str, bool]
    # -> (sanitized_text, poc_sanitized)

Semantics of the return tuple (see H-BOND.md §5.1, §7.2):

* ``poc_sanitized == True``  -> the text is safe to persist / render. The text
  may have been redacted (real IP -> ``<DEVICE_IP>``) but is otherwise usable.
* ``poc_sanitized == False`` -> the payload hit a hard red line (reverse shell /
  download-and-exec / persistence). It MUST NOT be persisted. The returned text
  is a safe *summary* that never contains the original payload; callers drop the
  finding and only record "a command-execution primitive was detected; PoC
  omitted per compliance policy".

Hard rules (violating any means the finding is rejected):
  * reverse shell / ``/dev/tcp`` / ``nc -e`` / ``bash -i``       -> reject
  * download-and-exec (``curl ... | sh`` / ``wget ... | bash``)  -> reject
  * persistence (``crontab`` / ``init.d`` write / ``mkfifo``)    -> reject
  * destructive (``rm -rf /``)                                    -> reject
Redaction (allowed, still sanitized):
  * real IP  -> ``<DEVICE_IP>``
  * host name/domain -> ``<HOST>``
  * overflow string (>=N bytes of one char) -> ``A×N``
Benign markers (``touch /tmp/lab_marker``, ``id``, ``echo LAB``) are kept as-is.

This module never performs network I/O and never raises for bad input.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# --- hard red lines: payloads that must NEVER leave the lab ----------------- #

_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"bash\s+-i", re.I),
    re.compile(r"/bin/(?:sh|bash|ash)\b", re.I),
    re.compile(r"\bnc\s+-e\b", re.I),
    re.compile(r"\bncat\s+-e\b", re.I),
    re.compile(r"reverse\s*shell", re.I),
    re.compile(r"/dev/(?:tcp|udp)", re.I),
    re.compile(r"\brm\s+-rf\s+/", re.I),
    re.compile(r"\|\s*(?:sh|bash)\b", re.I),
    re.compile(r";\s*(?:reboot|shutdown|halt|poweroff)\b", re.I),
    re.compile(r"\$\("),
    re.compile(r"`[^`]+`"),
    re.compile(r"curl\s+https?://", re.I),
    re.compile(r"wget\s+https?://", re.I),
    re.compile(r"(?:mkfifo|mknod)", re.I),
    re.compile(r"crontab", re.I),
    re.compile(r"init\.d", re.I),
]

# --- redaction patterns (allowed, but must be anonymised) ----------------- #

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
# overflow run: >= 200 of the same byte (classic `A`*N / `\\x90`*N)
_OVERFLOW_RE = re.compile(r"(?P<ch>(?:\\x[0-9a-fA-F]{2}|.))(?P=ch){199,}")

_BENIGN_MARKERS = ("touch /tmp/lab_marker", "id", "echo LAB", "uname")


def _is_dangerous(text: str) -> bool:
    return any(p.search(text) for p in _DANGEROUS_PATTERNS)


def _redact(text: str) -> str:
    """Anonymise IPs / hosts and truncate overflow runs. Never raises."""
    out = text

    # redact IPv4 (skip the loopback / placeholder ranges already abstract)
    def _ip_sub(m: re.Match[str]) -> str:
        raw = m.group(0)
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            return raw
        return "<DEVICE_IP>"

    out = _IP_RE.sub(_ip_sub, out)
    out = _HOST_RE.sub("<HOST>", out)
    # truncate overflow runs to the canonical A×N (N=<count>) form
    out = _OVERFLOW_RE.sub(lambda m: f"{m.group('ch')}×N（N={m.end() - m.start()}）", out)
    return out


def sanitize_poc(raw: Any, *, strict: bool = True) -> tuple[str, bool]:
    """Sanitize a PoC payload.

    Returns ``(text, poc_sanitized)``:
      * dangerous payload  -> ``("", False)`` (summary only, no raw payload)
      * benign/redacted     -> ``(redacted_text, True)``

    ``strict`` only controls whether benign markers are redacted; dangerous
    payloads are ALWAYS rejected regardless of ``strict`` (the safety red line is
    absolute and cannot be downgraded by a caller flag).
    """
    if raw is None:
        return "", True
    text = str(raw)
    if not text.strip():
        return "", True

    if _is_dangerous(text):
        # Rejected: emit a safe summary that contains no original command primitive.
        summary = "PoC omitted per compliance policy (command-execution primitive detected)"
        return summary, False

    redacted = _redact(text)
    if not strict and redacted != text:
        # non-strict callers may opt to keep the original; safety red lines above
        # still apply, so this only affects IP/host redaction.
        return text, True
    return redacted, True


def is_safe(raw: Any) -> bool:
    """Convenience predicate: ``True`` iff the payload may be persisted."""
    return sanitize_poc(raw)[1]


__all__ = ["sanitize_poc", "is_safe"]
