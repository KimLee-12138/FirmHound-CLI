"""SaTC adapter package.

Importing this module must never require Docker or SaTC to be present --
availability is decided at runtime by :meth:`SatcAnalyzer.probe`.
"""

from __future__ import annotations

from tools.external.satc.parser import (
    PARSER_VERSION,
    ParseStats,
    compute_confidence,
    parse_alert_file,
    parse_clustering,
    parse_ghidra_result,
    parse_satc_output,
)
from tools.external.satc.runner import SatcAnalyzer, build

__all__ = [
    "PARSER_VERSION",
    "ParseStats",
    "SatcAnalyzer",
    "build",
    "compute_confidence",
    "parse_alert_file",
    "parse_clustering",
    "parse_ghidra_result",
    "parse_satc_output",
]
