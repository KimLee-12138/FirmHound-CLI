"""mini-BOND: constraint-directed fuzzing validation, self-implemented (Plan B).

Replaces BOND's original closed dependencies with in-house equivalents (H-BOND.md §4):
  * M1 ghidra_export  -- entry-point identification + reachable region (Ghidra headless)
  * M2 constraint     -- three-class x six-semantic path-constraint extraction
  * M3 template       -- LLM HTTP template generation with a rule-based fallback
  * scheduler         -- priority-ordered seed generation (no patched BooFuzz needed)

The methodology (entry-point recognition, reachable-region partitioning, constraint
extraction, priority mutation) is BOND's; the implementation is ours.
"""

from tools.external.bond.mini.constraint import (
    KLASS_ORDER,
    extract_constraints,
    parse_constraint_expr,
    priority_order,
)
from tools.external.bond.mini.ghidra_export import (
    export_cfg_cg,
    identify_entry_points,
)
from tools.external.bond.mini.scheduler import generate_seeds
from tools.external.bond.mini.template import generate_template

__all__ = [
    "export_cfg_cg",
    "identify_entry_points",
    "extract_constraints",
    "parse_constraint_expr",
    "priority_order",
    "generate_template",
    "generate_seeds",
    "KLASS_ORDER",
]
