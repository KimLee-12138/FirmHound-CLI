"""M5 static-audit analysis tools (source/sink rules, dataflow, false-positive filter)."""

from tools.analysis.dataflow import assemble_chain, verify_variable_usage
from tools.analysis.fp_filter import apply_fp_filters
from tools.analysis.source_sink_rules import (
    classify_sink,
    classify_source,
    classify_validation,
    match_binary,
)

__all__ = [
    "assemble_chain",
    "verify_variable_usage",
    "apply_fp_filters",
    "classify_sink",
    "classify_source",
    "classify_validation",
    "match_binary",
]
