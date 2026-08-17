"""M4 binary triage and analysis tools (pure Python via pyelftools)."""

from tools.binary.danger_scan import DANGER_FUNCTIONS, scan_dangerous_functions
from tools.binary.elf_triage import triage_elf
from tools.binary.secfeatures import security_features

__all__ = [
    "DANGER_FUNCTIONS",
    "scan_dangerous_functions",
    "security_features",
    "triage_elf",
]
