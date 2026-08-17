"""File hashing utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str | Path, chunk_size: int = 8192) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: str | Path, chunk_size: int = 8192) -> str:
    """Return the MD5 hex digest of a file."""
    h = hashlib.md5(usedforsecurity=False)
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of a byte string."""
    return hashlib.sha256(data).hexdigest()
