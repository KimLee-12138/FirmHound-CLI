"""Parse BOND artifacts into normalized ``external_finding`` documents (F3).

BOND (H-BOND.md §7.2) writes, per validated candidate:
  * ``Bond_result/action_find/``   -> entry-point recognition result
  * ``Bond_result/custom_analysis/`` -> path-constraint analysis
  * ``fuzz_log/fuzz_sent_log.txt``   -> the request sequence actually sent
  * crash / marker evidence          -> the sink was reached (validation)

This module turns each candidate directory into exactly one external finding carrying
the BOND-specific ``validation`` field:

  * crash evidence  -> ``validation.triggered=true, probe="crash"``
  * marker evidence -> ``validation.triggered=true, probe="marker"``
  * timeout marker  -> ``validation.triggered=null, probe="timeout"``
  * no evidence     -> ``validation.triggered=false, probe="none"`` (degrade, NOT reject)

Compliance gate (H-BOND.md §5.1, §7.2): the PoC request is passed through
:func:`tools.external.bond.sanitize.sanitize_poc`. When ``poc_sanitized`` is ``False``
the finding is **dropped entirely** -- never persisted, never rendered. This is asserted
by the unit tests.

Every reader is tolerant and never raises. ``PARSER_VERSION`` is stamped on findings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.external.base import normalize_addr
from tools.external.bond.sanitize import sanitize_poc

PARSER_VERSION = "bond-parser-v1"

# Markers we recognise inside fuzz_log/fuzz_sent_log.txt (case-insensitive).
_CRASH_RE = re.compile(r"TRIGGERED\s*:\s*crash", re.I)
_MARKER_RE = re.compile(r"TRIGGERED\s*:\s*marker", re.I)
_TIMEOUT_RE = re.compile(r"\bTIMEOUT\b", re.I)
_VERSION_RE = re.compile(r"VERSION\s*:\s*(.+)", re.I)
_SENT_RE = re.compile(r"^SENT\s*:\s*(.*)$", re.I)


@dataclass
class ParseStats:
    """Counters describing what the parser managed to interpret."""

    dirs_seen: int = 0
    findings: int = 0
    dropped_unsafe: int = 0
    limitations: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        if message not in self.limitations:
            self.limitations.append(message)


# --------------------------------------------------------------------------- #
# low-level readers (tolerant, never raise)
# --------------------------------------------------------------------------- #


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _entry_point_for(cand_dir: Path, candidate: dict[str, Any]) -> dict[str, Any]:
    ep_file = cand_dir / "Bond_result" / "action_find" / "entry.json"
    ep = _read_json(ep_file)
    if isinstance(ep, dict):
        return ep
    # fall back to the candidate's own entry_point metadata
    return candidate.get("entry_point") or {"type": "unknown"}


def _constraints_for(cand_dir: Path, candidate: dict[str, Any]) -> list[dict[str, Any]]:
    c_file = cand_dir / "Bond_result" / "custom_analysis" / "constraints.json"
    c = _read_json(c_file)
    if isinstance(c, list):
        return c
    return candidate.get("constraints") or []


def _scan_fuzz_log(cand_dir: Path) -> tuple[list[str], dict[str, Any]]:
    """Return ``(sent_requests, markers)`` from fuzz_log/fuzz_sent_log.txt.

    ``markers`` carries booleans: ``crash`` / ``marker`` / ``timeout`` and an optional
    ``version`` string.
    """
    log = cand_dir / "fuzz_log" / "fuzz_sent_log.txt"
    if not log.exists():
        return [], {"crash": False, "marker": False, "timeout": False, "version": None}
    text = _read_text(log)
    sent: list[str] = []
    crash = bool(_CRASH_RE.search(text))
    marker = bool(_MARKER_RE.search(text))
    timeout = bool(_TIMEOUT_RE.search(text))
    version = None
    mv = _VERSION_RE.search(text)
    if mv:
        version = mv.group(1).strip()
    for line in text.splitlines():
        m = _SENT_RE.match(line.strip())
        if m and m.group(1).strip():
            sent.append(m.group(1).strip())
    return sent, {"crash": crash, "marker": marker, "timeout": timeout, "version": version}


# --------------------------------------------------------------------------- #
# per-directory verdict
# --------------------------------------------------------------------------- #


def _validation_for(
    sent: list[str],
    markers: dict[str, Any],
    stats: ParseStats,
    cand_dir: Path,
) -> dict[str, Any]:
    """Decide the validation verdict and the (sanitized) PoC for a candidate dir."""
    if markers.get("crash"):
        probe = "crash"
        triggered: bool | None = True
    elif markers.get("marker"):
        probe = "marker"
        triggered = True
    elif markers.get("timeout"):
        probe = "timeout"
        triggered = None
    else:
        probe = "none"
        triggered = False

    # Pick the PoC request to sanitize: the last sent request (the one that reached
    # the sink on trigger, or the closest attempt otherwise).
    poc_raw = sent[-1] if sent else ""
    poc_text, poc_ok = sanitize_poc(poc_raw)
    if not poc_ok:
        # Hard red line hit: the PoC must not be persisted. The finding is dropped
        # by the caller; we record the reason here.
        stats.dropped_unsafe += 1
        stats.note(
            f"{cand_dir.name}: PoC blocked by sanitizer "
            "(command-execution primitive); finding dropped"
        )
        return {
            "triggered": triggered,
            "probe": probe,
            "poc_sanitized": False,
            "poc": "",
            "limitation": "poc blocked by compliance sanitizer",
        }

    limitation = ""
    if probe == "none":
        limitation = "bond: constrained fuzzing did not trigger; needs manual review (NEED_DYNAMIC)"
    elif probe == "timeout":
        limitation = "bond: fuzz timeout; feasibility undetermined"
    return {
        "triggered": triggered,
        "probe": probe,
        "poc_sanitized": True,
        "poc": poc_text,
        "limitation": limitation,
    }


def _confidence_for(verdict: dict[str, Any]) -> float:
    if verdict["probe"] == "crash" or verdict["probe"] == "marker":
        return 0.9
    if verdict["probe"] == "timeout":
        return 0.0
    return 0.2  # no trigger -> degrade, never reject


# --------------------------------------------------------------------------- #
# assembly
# --------------------------------------------------------------------------- #


def parse_bond_output(
    out_dir: Path,
    *,
    candidate_map: dict[str, dict[str, Any]],
    run_id: str,
    tool_version: str = "",
    duration_s: float = 0.0,
) -> tuple[list[dict[str, Any]], ParseStats]:
    """Walk ``out_dir/<cand_id>/`` and emit one finding per processed candidate.

    Args:
        out_dir: directory holding one subdir per candidate (each with Bond_result/ + fuzz_log/).
        candidate_map: ``{cand_id: candidate_summary}`` produced by ``runner.prepare``.
        run_id / tool_version / duration_s: pipeline metadata stamped on findings.

    Returns ``(findings, stats)``. Never raises for missing/malformed input.
    """
    stats = ParseStats()
    findings: list[dict[str, Any]] = []
    out = Path(out_dir)
    if not out.exists():
        stats.note(f"bond output directory missing: {out_dir}")
        return findings, stats

    subdirs = [d for d in sorted(out.iterdir()) if d.is_dir()]
    if not subdirs:
        stats.note("no bond candidate directories found")
        return findings, stats

    for d in subdirs:
        stats.dirs_seen += 1
        name = d.name
        candidate = candidate_map.get(name)
        if candidate is None:
            stats.note(f"{name}: no candidate_map entry; skipped")
            continue

        sent, markers = _scan_fuzz_log(d)
        verdict = _validation_for(sent, markers, stats, d)
        if not verdict.get("poc_sanitized"):
            # Compliance gate: drop the finding entirely.
            continue

        entry_point = _entry_point_for(d, candidate)
        constraints = _constraints_for(d, candidate)
        binary_id = str(candidate.get("binary_id") or "unknown")
        vuln_class = str(candidate.get("vuln_class") or "other")
        sink = candidate.get("sink") or {}
        sink_func = str(sink.get("function") or candidate.get("sink_func") or "")
        sink_addr = normalize_addr(sink.get("addr") if sink else None)
        sink_type = str(sink.get("type") or "unknown")
        validation = {
            "triggered": verdict["triggered"],
            "probe": verdict["probe"],
            "poc_sanitized": True,
        }
        if verdict.get("poc"):
            validation["poc"] = verdict["poc"]
        confidence = _confidence_for(verdict)
        slug = re.sub(r"[^A-Za-z0-9]+", "-", binary_id).strip("-") or "unknown"
        notes = f"parser={PARSER_VERSION}; probe={verdict['probe']}"
        if markers.get("version"):
            notes += f"; bond-version={markers['version']}"

        finding: dict[str, Any] = {
            "finding_id": f"bond-{slug}-{name}",
            "tool": "bond",
            "tool_version": tool_version or str(candidate.get("tool_version") or "unknown"),
            "run_id": run_id,
            "binary_id": binary_id,
            "vuln_class": vuln_class,
            "entry_point": entry_point,
            "source": candidate.get("source") or {"type": "unknown"},
            "sink": {"function": sink_func, "addr": sink_addr, "type": sink_type},
            "call_trace": candidate.get("call_trace") or [],
            "constraints": constraints,
            "validation": validation,
            "confidence": confidence,
            "status": "ok",
            "duration_s": round(duration_s, 1),
            "notes": notes,
        }
        if verdict.get("limitation"):
            finding["limitation"] = verdict["limitation"]
        findings.append(finding)
        stats.findings += 1

    if not findings and stats.dropped_unsafe == 0:
        stats.note("bond produced no findings across all candidates")
    return findings, stats


__all__ = ["PARSER_VERSION", "ParseStats", "parse_bond_output"]
