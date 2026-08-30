"""FirmRec adapter package (external analyzer F).

FirmRec (CCS'24, seclab-fudan/FirmRec) is a *recurring-vulnerability* detector:
it finds variants of known vulnerabilities across firmware of the same vendor /
code lineage, using exploit-process-aware semantic signatures.

Because it *requires* known-vulnerability signatures, it is the only external
tool that must never participate in a blind benchmark run. See
``docs/external/F-FirmRec.md`` §4 and ``tools/external/base.py::RECURRENCE_ONLY_TOOLS``.
"""

from tools.external.firmrec.runner import FirmrecAnalyzer, build

__all__ = ["FirmrecAnalyzer", "build"]
