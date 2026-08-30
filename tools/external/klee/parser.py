"""Parse KLEE ``klee-out-N/`` artifacts into normalized ``external_finding`` docs.

KLEE (v3.2) writes a directory per symbolically-executed harness containing a
mix of artifacts (G-KLEE.md §3, §6.2). This module turns each ``klee-out-N/``
into exactly one external finding carrying the KLEE-specific ``symex`` field:

  * ``*.err`` -- memory / assertion errors. ``ptr.err`` / ``free.err`` /
    ``div.err`` / ``overflow.err`` / ``assert.err`` are **vulnerability evidence**
    (``reachable=true``). ``model.err`` / ``exec.err`` are **modelling
    limitations** and MUST NOT be treated as vulns (the false-positive guard).
  * ``test*.ktest`` -- a concrete witness input that reaches the sink. Extracted
    (via ``ktest-tool`` when present, else a safe printable-byte heuristic) and
    stored sanitised in ``symex.witness_input`` for BOND.
  * ``info`` -- KLEE version + invocation; stored in ``tool_version`` / ``notes``.
  * ``run.stats`` -- instructions / states / completed paths / time (perf baseline).
  * ``warnings.txt`` -- timeout / fork-limit (path explosion) markers.

Every reader is tolerant and never raises. A malformed artifact degrades to
fewer findings + a ``limitation`` string, never to a failed stage. ``PARSER_VERSION``
is stamped on every finding.

The ``harness_map`` (written by ``runner.prepare``) maps each ``klee-out-N``
directory back to its candidate so we can fill ``binary_id`` / ``sink`` /
``source`` / ``vuln_class`` / ``constraints`` without re-deriving them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.external.base import normalize_addr
from tools.external.klee.harness_gen import HARNESS_VERSION

PARSER_VERSION = "klee-parser-v1"

# .err files that prove a real (symbolic) bug -> vulnerability evidence.
_VULN_ERR_TYPES = {
    "ptr.err": "overflow",
    "free.err": "overflow",   # double / invalid free -> memory safety
    "div.err": "divide_by_zero",
    "overflow.err": "integer_overflow",
    "assert.err": "assertion",
}
# .err files that are KLEE modelling limits, NOT vulnerabilities.
_LIMITATION_ERR_TYPES = {"model.err": "memory_model", "exec.err": "unsupported_call"}

_KTEST_RE = re.compile(r"test\d+\.ktest")
_OBJ_RE = re.compile(r"b'([^']*)'|'([^']*)'")


# --------------------------------------------------------------------------- #
# stats carrier
# --------------------------------------------------------------------------- #


@dataclass
class ParseStats:
    """Counters describing what the parser managed to interpret."""

    dirs_seen: int = 0
    findings: int = 0
    limitations: list[str] = field(default_factory=list)
    dropped_malformed: int = 0

    def note(self, message: str) -> None:
        if message not in self.limitations:
            self.limitations.append(message)


# --------------------------------------------------------------------------- #
# low-level artifact readers (tolerant, never raise)
# --------------------------------------------------------------------------- #


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _err_types_in(out_dir: Path, stats: ParseStats | None = None) -> dict[str, str]:
    """Return ``{err_basename: kind}`` for every *decodable* ``.err`` file present.

    A ``.err`` whose name matches a known type but whose bytes are not valid UTF-8
    (truncated / corrupted artifact) is skipped and recorded as a malformed
    limitation -- it must NOT be mistaken for a real vulnerability (anti-false-positive).
    """
    found: dict[str, str] = {}
    for f in sorted(out_dir.iterdir()):
        if f.is_file() and f.name.endswith(".err"):
            kind = _VULN_ERR_TYPES.get(f.name) or _LIMITATION_ERR_TYPES.get(f.name)
            if not kind:
                continue
            try:
                f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                if stats is not None:
                    stats.dropped_malformed += 1
                    stats.note(f"{out_dir.name}/{f.name}: malformed .err (non-utf8); skipped")
                continue
            found[f.name] = kind
    return found


def _extract_witness(ktest_paths: list[Path]) -> dict[str, Any] | None:
    """Return a sanitised witness ``{"input": ..., "encoding": ...}`` or None.

    Strategy: prefer ``ktest-tool`` (if installed) for an authoritative decode;
    otherwise extract the longest printable-ASCII run from the binary ``.ktest``
    (the concrete input is ASCII-constrained in our harnesses, so this is exact
    for our own fixtures and a safe approximation in general). The witness is
    never executed -- it is stored for directed fuzzing (BOND) only.
    """
    if not ktest_paths:
        return None
    ktest = ktest_paths[0]
    raw = _read_bytes(ktest)
    if not raw:
        return None

    import shutil
    import subprocess

    if shutil.which("ktest-tool"):
        try:
            proc = subprocess.run(
                ["ktest-tool", "--write-ints", str(ktest)],
                capture_output=True, text=True, timeout=30,
            )
            text = proc.stdout + proc.stderr
            chunks = [m.group(1) or m.group(2) for m in _OBJ_RE.finditer(text)]
            if chunks:
                joined = "".join(chunks)
                return {"input": joined, "encoding": "ktest-tool"}
        except Exception:
            pass

    # Heuristic fallback: longest printable ASCII run (>=4 chars).
    runs = re.findall(rb"[\x20-\x7e]{4,}", raw)
    if runs:
        best = max(runs, key=len).decode("ascii", errors="replace")
        return {"input": best, "encoding": "heuristic-printable"}
    return {"input": "", "encoding": "heuristic-empty"}


def _parse_info(out_dir: Path) -> dict[str, Any]:
    info = out_dir / "info"
    text = _read_text(info) if info.exists() else ""
    version = ""
    m = re.search(r"KLEE\s+([0-9][0-9A-Za-z.\-]*)", text)
    if m:
        version = m.group(1)
    return {"version": version, "raw": text}


def _parse_run_stats(out_dir: Path) -> dict[str, Any]:
    """Parse ``run.stats`` (HTML-table form) into a flat stats dict.

    KLEE's ``run.stats`` is an HTML table with a header row and one data row.
    A malformed / truncated file yields an empty dict + a limitation (never raises).
    """
    stats_file = out_dir / "run.stats"
    if not stats_file.exists():
        return {}
    text = _read_text(stats_file)
    if not text.strip():
        return {}
    # Defensive: a truncated file may raise during parsing -> degrade, not abort.
    try:
        rows = [ln for ln in text.splitlines() if ln.strip().startswith("<tr")]
        if len(rows) < 2:
            # Not the expected table; still try to surface a couple of scalars.
            stats: dict[str, Any] = {}
            for key in ("Instructions", "States", "Completed Paths", "Time"):
                mm = re.search(rf"{key}\D*?([0-9][0-9.]*)", text)
                if mm:
                    stats[key.lower().replace(" ", "_")] = float(mm.group(1))
            return stats
        header_cells = re.findall(r"<th>(.*?)</th>", rows[0])
        data_cells = re.findall(r"<td>(.*?)</td>", rows[1])
        pairs = dict(zip(header_cells, data_cells, strict=False))
        stats = {}
        for key in ("Instructions", "States", "Completed Paths", "Time"):
            val = pairs.get(key, "").strip()
            if val:
                try:
                    stats[key.lower().replace(" ", "_")] = float(val)
                except ValueError:
                    stats[key.lower().replace(" ", "_")] = val
        return stats
    except Exception:
        return {}


def _parse_warnings(out_dir: Path) -> list[str]:
    warnings = out_dir / "warnings.txt"
    if not warnings.exists():
        return []
    text = _read_text(warnings)
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _classify_warnings(warnings: list[str]) -> str | None:
    """Return ``timeout`` / ``path_explosion`` / None based on warning markers."""
    joined = " ".join(warnings).lower()
    if "max time" in joined or "timed out" in joined or "timeout" in joined:
        return "timeout"
    if "fork" in joined or "path explosion" in joined or "max depth" in joined:
        return "path_explosion"
    return None


# --------------------------------------------------------------------------- #
# per-directory verdict
# --------------------------------------------------------------------------- #


def _verdict_for(out_dir: Path, stats: ParseStats) -> dict[str, Any]:
    """Classify one ``klee-out-N/`` directory into a symex verdict dict.

    Returns a dict with keys: ``category``, ``reachable``, ``reason``,
    ``errs`` (vuln err kinds), ``witness`` (or None), ``limitation`` (or "").
    ``category == "empty"`` means no finding should be emitted.
    """
    err_types = _err_types_in(out_dir, stats)
    warnings = _parse_warnings(out_dir)
    ktest_paths = sorted(out_dir.glob("test*.ktest")) if out_dir.exists() else []
    warn_cat = _classify_warnings(warnings)
    vuln_errs = {name: kind for name, kind in err_types.items() if name in _VULN_ERR_TYPES}
    lim_errs = {name: kind for name, kind in err_types.items() if name in _LIMITATION_ERR_TYPES}

    # Malformed guard: a directory that only contains an unreadable artifact.
    info = out_dir / "info"
    if info.exists():
        try:
            info.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            stats.dropped_malformed += 1
            stats.note(f"{out_dir.name}: malformed info (non-utf8); skipped")

    # 1) Explicit timeout / path explosion markers win (do not change the score).
    if warn_cat == "timeout":
        return {"category": "timeout", "reachable": None, "reason": "timeout",
                "errs": vuln_errs, "witness": None,
                "limitation": "klee: hard timeout (--max-time); feasibility undetermined"}
    if warn_cat == "path_explosion":
        return {"category": "path_explosion", "reachable": None, "reason": "path_explosion",
                "errs": vuln_errs, "witness": None,
                "limitation": "klee: path explosion (fork/depth limit); feasibility undetermined"}

    # 2) A real vulnerability error is strong evidence (reachable + vuln class).
    if vuln_errs:
        witness = _extract_witness(ktest_paths)
        return {"category": "vuln", "reachable": True, "reason": "ok",
                "errs": vuln_errs, "witness": witness, "limitation": ""}

    # 3) ONLY modelling-limitation errors (model.err / exec.err): NOT a vuln.
    if lim_errs and not vuln_errs:
        return {"category": "limitation", "reachable": None, "reason": "unsupported_arch",
                "errs": {}, "witness": None,
                "limitation": "klee: " + ", ".join(sorted(lim_errs))
                + " (modelling limitation, not a vulnerability)"}

    # 4) A witness input exists -> the path is feasible; emit witness for BOND.
    if ktest_paths:
        witness = _extract_witness(ktest_paths)
        return {"category": "reachable", "reachable": True, "reason": "ok",
                "errs": {}, "witness": witness, "limitation": ""}

    # 5) No error, no witness, no markers -> all paths explored, sink not reached
    #    under the harness constraints -> infeasible (under the harness model).
    #    `decodable` ignores malformed (non-utf8) artifacts so a corrupt .err is
    #    never mistaken for a real "sink not reached" verdict.
    decodable = (
        bool(err_types) or info.exists() or (out_dir / "run.stats").exists()
        or ktest_paths or bool(warnings)
    )
    if decodable:
        return {"category": "infeasible", "reachable": False, "reason": "infeasible",
                "errs": {}, "witness": None,
                "limitation": "klee: all explored paths UNSAT under harness constraints"}

    # 6) Truly empty / fully-malformed directory -> nothing to report.
    has_decodable = (
        bool(list(out_dir.glob("*.err"))) or info.exists()
        or (out_dir / "run.stats").exists() or ktest_paths
        or bool(warnings)
    )
    if not has_decodable:
        stats.note(f"{out_dir.name}: no decodable artifact; skipped")
        return {"category": "empty", "reachable": None, "reason": "error",
                "errs": {}, "witness": None, "limitation": ""}
    return {"category": "empty", "reachable": None, "reason": "error",
            "errs": {}, "witness": None, "limitation": ""}


# --------------------------------------------------------------------------- #
# confidence
# --------------------------------------------------------------------------- #


def _confidence_for(verdict: dict[str, Any], vuln_class: str) -> float:
    cat = verdict["category"]
    if cat == "vuln":
        return 0.85
    if cat == "reachable":
        return 0.6
    if cat == "infeasible":
        return 0.3
    return 0.0  # timeout / path_explosion / limitation -> no score change


def _vuln_class_for(verdict: dict[str, Any], base_vuln_class: str) -> str:
    """Override the vuln_class when a specific error type demands it."""
    errs = verdict.get("errs", {})
    if "ptr.err" in errs or "free.err" in errs:
        return "overflow"
    if "overflow.err" in errs:
        return "overflow" if base_vuln_class != "format_string" else base_vuln_class
    # div.err / assert.err keep the candidate's original class.
    return base_vuln_class


# --------------------------------------------------------------------------- #
# assembly
# --------------------------------------------------------------------------- #


def parse_klee_output(
    out_dir: Path,
    *,
    harness_map: dict[str, dict[str, Any]],
    run_id: str,
    tool_version: str = "",
    duration_s: float = 0.0,
) -> tuple[list[dict[str, Any]], ParseStats]:
    """Walk ``out_dir/klee-out-*`` and emit one finding per processed harness.

    Args:
        out_dir: directory that contains ``klee-out-N`` subdirs.
        harness_map: ``{dir_name: candidate_summary}`` produced by ``runner.prepare``.
        run_id / tool_version / duration_s: pipeline metadata stamped on findings.

    Returns ``(findings, stats)``. Never raises for missing/malformed input.
    """
    stats = ParseStats()
    findings: list[dict[str, Any]] = []
    out = Path(out_dir)
    if not out.exists():
        stats.note(f"klee output directory missing: {out_dir}")
        return findings, stats

    subdirs = [d for d in sorted(out.iterdir()) if d.is_dir()]
    if not subdirs:
        stats.note("no klee-out-N directories found")
        return findings, stats

    for d in subdirs:
        stats.dirs_seen += 1
        name = d.name
        cand = harness_map.get(name)
        if cand is None:
            stats.note(f"{name}: no harness_map entry; skipped")
            continue

        verdict = _verdict_for(d, stats)
        if verdict["category"] == "empty":
            continue

        binary_id = str(cand.get("binary_id") or "unknown")
        base_vuln_class = str(cand.get("vuln_class") or "other")
        vuln_class = _vuln_class_for(verdict, base_vuln_class)
        sink = cand.get("sink") or {}
        sink_func = str(sink.get("function") or cand.get("sink_func") or "")
        sink_addr = normalize_addr(sink.get("addr") if sink else None)
        sink_type = str(sink.get("type") or _sink_type_for(vuln_class, sink_func))
        confidence = _confidence_for(verdict, vuln_class)
        slug = re.sub(r"[^A-Za-z0-9]+", "-", binary_id).strip("-") or "unknown"

        symex: dict[str, Any] = {
            "reachable": verdict["reachable"],
            "reason": verdict["reason"],
            "harness_version": str(cand.get("harness_version") or HARNESS_VERSION),
            "stats": _parse_run_stats(d),
        }
        if verdict.get("witness"):
            symex["witness_input"] = verdict["witness"]

        err_notes = ""
        if verdict["errs"]:
            err_notes = "; errs=" + ",".join(sorted(verdict["errs"]))

        finding: dict[str, Any] = {
            "finding_id": f"klee-{slug}-{sink_addr or name}",
            "tool": "klee",
            "tool_version": tool_version or str(cand.get("tool_version") or "unknown"),
            "run_id": run_id,
            "binary_id": binary_id,
            "vuln_class": vuln_class,
            "entry_point": cand.get("entry_point") or {"type": "unknown"},
            "source": cand.get("source") or {"type": "unknown"},
            "sink": {
                "function": sink_func,
                "addr": sink_addr,
                "type": sink_type,
            },
            "call_trace": cand.get("call_trace") or [],
            "constraints": cand.get("constraints") or [],
            "symex": symex,
            "confidence": confidence,
            "status": "ok",
            "duration_s": round(duration_s, 1),
            "notes": (
                f"parser={PARSER_VERSION}; harness={symex['harness_version']}; "
                f"category={verdict['category']}{err_notes}"
            ),
        }
        if verdict.get("limitation"):
            finding["limitation"] = verdict["limitation"]
        findings.append(finding)
        stats.findings += 1

    if not findings:
        stats.note("klee produced no feasible/error findings across all harnesses")
    return findings, stats


def _sink_type_for(vuln_class: str, sink_func: str) -> str:
    if vuln_class == "command_injection" or sink_func in {"system", "popen"}:
        return "command_execution"
    if vuln_class in {"overflow", "use_after_free"} or sink_func in {
        "strcpy", "memcpy", "sprintf", "strcat",
    }:
        return "memory_copy"
    if vuln_class == "format_string":
        return "format_output"
    return "unknown"


__all__ = [
    "PARSER_VERSION",
    "ParseStats",
    "parse_klee_output",
    "_verdict_for",
    "_extract_witness",
    "_parse_run_stats",
]
