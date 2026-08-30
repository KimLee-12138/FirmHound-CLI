"""BOND external analyzer package (student H).

Public surface used by the registry / adapter:
  * ``BondAnalyzer`` / ``build`` -- the analyzer entry point
  * ``sanitize_poc`` -- the group-wide PoC compliance gate (X1)
  * ``mini.*`` -- self-implemented constraint-directed fuzzing (X2)
"""

from tools.external.bond.runner import BondAnalyzer, build
from tools.external.bond.sanitize import sanitize_poc

__all__ = ["BondAnalyzer", "build", "sanitize_poc"]
