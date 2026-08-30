"""Convert our 9-CVE knowledge base into FirmRec's ``vuln_info`` signature format.

F-FirmRec.md §5.2 (X2) requires two ``vuln_info`` datasets:

  * **official** -- FirmRec's own sample ``inout/vuln_info/`` (verify by running
    the upstream sample first, then copy its shape).
  * **ours** -- derived from ``benchmarks/CVEs/<CVE>/`` (the 9 historical CVEs we
    use for methodology + regression, *not* the answer key for the live contest).

The upstream FirmRec repository ships its ``vuln_info`` as a JSON list of known
vulnerabilities. We mirror that shape with the fields our fixtures actually carry
(CVE id, device, vuln class, entry/source/sink, call chain, references).

IMPORTANT (academic-integrity gate, F-FirmRec.md §5.2): the benchmark fixtures use
*abstract* ``binary_id`` values (``bin-CVE-xxxx``), which are **not** real rootfs
paths. Every record we emit is flagged ``presumed=True`` so downstream consumers
never treat an inferred field as a verified fact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Canonical vuln classes shared with external_finding.schema.json.
_KNOWN_CLASSES = {
    "command_injection",
    "overflow",
    "path_traversal",
    "auth_bypass",
    "config_injection",
    "format_string",
    "other",
}


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def cve_dir_to_vuln_info(cve_dir: Path) -> dict[str, Any] | None:
    """Build one FirmRec ``vuln_info`` record from a single CVE fixture dir."""
    cve_dir = Path(cve_dir)
    candidate = _read_json(cve_dir / "candidate.json")
    verdict_doc = _read_json(cve_dir / "verdict.json")
    if not candidate:
        return None

    meta = candidate.get("metadata", {}) or {}
    cve_id = meta.get("cve_id") or candidate.get("candidate_id", "")
    sink = candidate.get("sink", {}) or {}
    entry = candidate.get("entry", {}) or {}
    source = candidate.get("source", {}) or {}

    verdict = "unknown"
    if isinstance(verdict_doc, dict):
        verdicts = verdict_doc.get("verdicts", []) or []
        if verdicts:
            verdict = str(verdicts[0].get("action", "unknown"))

    vuln_class = candidate.get("vuln_class_hypothesis") or "other"
    if vuln_class not in _KNOWN_CLASSES:
        vuln_class = "other"

    return {
        "cve_id": cve_id,
        "device": meta.get("device", ""),
        "vuln_class": vuln_class,
        "entry": {"function": entry.get("function", ""), "addr": str(entry.get("addr", ""))},
        "source": {"type": source.get("type", ""), "name": source.get("name", "")},
        "sink": {"function": sink.get("function", ""), "type": sink.get("type", "")},
        "call_chain": candidate.get("call_chain", []) or [],
        "verdict": verdict,
        "references": meta.get("references", []) or [],
        # Honesty flags -- see module docstring.
        "binary_id": candidate.get("binary_id", ""),  # abstract, NOT a real path
        "presumed": True,
    }


def collect_our_vuln_info(cve_root: str | Path) -> list[dict[str, Any]]:
    """Read every CVE under ``benchmarks/CVEs/`` into a vuln_info list."""
    cve_root = Path(cve_root)
    records: list[dict[str, Any]] = []
    if not cve_root.exists():
        return records
    for cve_dir in sorted(p for p in cve_root.iterdir() if p.is_dir()):
        rec = cve_dir_to_vuln_info(cve_dir)
        if rec:
            records.append(rec)
    return records


def stage_vuln_info(
    workdir: Path,
    *,
    cve_root: str | Path | None = None,
    source: str = "our",
) -> Path:
    """Write ``inout/vuln_info/vulns.json`` into the analyzer workdir.

    ``source="our"`` uses our 9-CVE knowledge base; ``source="official"`` is a
    placeholder path the student fills from the upstream FirmRec sample (the exact
    upstream schema is copied after a successful official-sample run).
    """
    workdir = Path(workdir)
    out_dir = workdir / "inout" / "vuln_info"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "vulns.json"

    if source == "official":
        # Filled by the student after running the official FirmRec sample; until
        # then we emit an empty-but-valid list so the pipeline does not crash.
        out_path.write_text("[]", encoding="utf-8")
        return out_path

    records = collect_our_vuln_info(cve_root) if cve_root else []
    out_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


__all__ = [
    "cve_dir_to_vuln_info",
    "collect_our_vuln_info",
    "stage_vuln_info",
]
