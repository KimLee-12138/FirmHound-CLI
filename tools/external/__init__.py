"""External analyzer adapters.

Concrete analyzers live in their own subpackages (``satc``, ``firmrec``,
``klee``, ``bond``) and are discovered through ``tools/registry/external.yaml``.
Importing this package must never require any external tool to be installed.
"""

from __future__ import annotations

from tools.external.base import (
    AnalysisContext,
    AnalyzerResult,
    ExternalAnalyzer,
    ProbeResult,
    RunOutcome,
    dedup_key,
    normalize_addr,
    normalize_binary_id,
    to_wsl_path,
)

__all__ = [
    "AnalysisContext",
    "AnalyzerResult",
    "ExternalAnalyzer",
    "ProbeResult",
    "RunOutcome",
    "dedup_key",
    "normalize_addr",
    "normalize_binary_id",
    "to_wsl_path",
]
