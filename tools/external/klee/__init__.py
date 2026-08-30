"""KLEE external analyzer: symbolic execution path feasibility (student G).

X1 (``harness_gen``) synthesises a C harness from a candidate's sink signature
and compiles it to LLVM bitcode. X2 (``prune``) is the false-positive guard:
an ``infeasible`` verdict is written as *counterevidence only* (never deletes a
candidate) and a prune-rate > 70% triggers a manual 5-sample audit.
"""

from tools.external.klee.harness_gen import (
    HARNESS_VERSION,
    HarnessSpec,
    compile_to_bc,
    generate_harness,
    render_harness,
    spec_from_candidate,
)
from tools.external.klee.parser import PARSER_VERSION, parse_klee_output
from tools.external.klee.prune import needs_manual_audit, prune_candidate
from tools.external.klee.runner import KleeAnalyzer, build

__all__ = [
    "KleeAnalyzer",
    "build",
    "HarnessSpec",
    "HARNESS_VERSION",
    "render_harness",
    "generate_harness",
    "compile_to_bc",
    "spec_from_candidate",
    "PARSER_VERSION",
    "parse_klee_output",
    "prune_candidate",
    "needs_manual_audit",
]
