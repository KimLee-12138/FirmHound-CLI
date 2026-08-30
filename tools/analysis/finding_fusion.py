"""FUSION stage: merge main-track candidates with external-analyzer findings.

This module is the shared contract that lets the four external analyzers (SaTC,
FirmRec, KLEE, BOND) plug into the main track. It is deliberately conservative:

  * **Deduplicate** external findings across tools by ``(binary_id, sink_addr,
    vuln_class)`` -- the same sink found by two tools stays one record.
  * **Cross-validate** against the main track. If the main track already reported
    the same ``binary_id + vuln_class + sink_addr``, the external finding is
    *not* ``external_only`` (it corroborates, which still raises confidence).
  * **Flag external_only** when the main track missed it -- this is the metric
    the benchmark cares about (SaTC/KLEE/BOND hits the main track did not make).
  * **Converge into ``unified_candidates.json``** (teacher's §3.2 matrix):
      - a main candidate corroborated by an external tool gets its
        ``conclusion_category`` bumped to ``high-confidence-candidate`` and an
        ``external corroboration`` evidence entry appended;
      - an ``external_only`` finding is materialised as a **new candidate**
        tagged ``external_only: true`` so it flows into KLEE/BOND downstream.
  * **Enforce FirmRec blind-run isolation**: any finding carrying ``matched_cve``
    (FirmRec signature match) is marked ``blind_isolated`` and kept out of the
    external_only delta so it can never inflate a blind benchmark's score.

The function never raises; a run with no external output degrades to an empty
fused list and a benign summary.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fsa.utils.jsonio import save_json
from tools.external.base import normalize_addr

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{4,}")

# conclusion_category values that already count as "corroborated enough".
_STRONG_CATS = {"confirmed-issue", "high-confidence-candidate"}


def _main_keys(run_dir: Path) -> tuple[set[tuple[str, str, str]], set[str]]:
    """Collect (binary_id, sink_addr, vuln_class) keys + all sink addrs.

    Scans the main-track artifacts (verdicts.json, analysis.json,
    candidates.json) for anything that looks like a vuln_class / sink address so
    we can decide whether an external finding was already known.
    """
    keys: set[tuple[str, str, str]] = set()
    addrs: set[str] = set()
    candidates: list[dict[str, Any]] = []

    for name in ("verdicts.json", "analysis.json", "candidates.json", "attack_surface.json"):
        path = run_dir / name
        if not path.exists():
            path = run_dir / "artifacts" / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            if "verdicts" in data:
                candidates.extend(data["verdicts"])
            if "candidates" in data:
                candidates.extend(data["candidates"])
            if "findings" in data:
                candidates.extend(data["findings"])
        elif isinstance(data, list):
            candidates.extend(data)

    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        binary = str(cand.get("binary_id", "") or "")
        vuln = str(cand.get("vuln_class", "") or "")
        # Sink address may live in sink.addr or in supporting_evidence strings.
        sink = cand.get("sink") or {}
        addr = normalize_addr(sink.get("addr")) if isinstance(sink, dict) else ""
        if addr:
            addrs.add(addr)
        for ev in cand.get("supporting_evidence", []) or []:
            for m in _ADDR_RE.findall(str(ev)):
                addrs.add(normalize_addr(m))
        if binary and vuln and addr:
            keys.add((binary, addr, vuln))
        # Also capture plain sink-addr-only keys for looser matching.
        if addr:
            keys.add(("", addr, vuln))

    return keys, addrs


def _fused_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    sink = finding.get("sink") or {}
    addr = normalize_addr(sink.get("addr")) if isinstance(sink, dict) else ""
    return (
        str(finding.get("binary_id", "")),
        addr,
        str(finding.get("vuln_class", "")),
    )


def _process_findings(
    findings: list[dict[str, Any]],
    main_keys: set[tuple[str, str, str]],
    main_addrs: set[str],
    *,
    force_blind_isolated: bool = False,
) -> tuple[list[dict[str, Any]], int, int]:
    """Dedupe + cross-validate a batch of external findings.

    Returns ``(processed, external_only_count, blind_isolated_count)``. Pure
    helper so the recurrence split (F-FirmRec.md §4.3) can reuse the same logic.
    """
    seen: set[tuple[str, str, str]] = set()
    fused: list[dict[str, Any]] = []
    external_only = 0
    blind_isolated = 0

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = _fused_key(finding)
        if key in seen:
            continue
        seen.add(key)

        sink = finding.get("sink") or {}
        addr = normalize_addr(sink.get("addr")) if isinstance(sink, dict) else ""

        is_blind = force_blind_isolated or bool(finding.get("matched_cve"))
        is_ext_only = (key not in main_keys) and (addr not in main_addrs)

        # FirmRec blind-run isolation: matched_cve findings must not count toward
        # the external_only delta of a blind benchmark (they carry prior knowledge).
        if is_blind:
            is_ext_only = False
            blind_isolated += 1

        if is_ext_only:
            external_only += 1

        out = dict(finding)
        out["external_only"] = is_ext_only
        out["blind_isolated"] = is_blind
        fused.append(out)

    return fused, external_only, blind_isolated


# --------------------------------------------------------------------------- #
# Convergence semantics (teacher's §3.2 cross-validation matrix)
# --------------------------------------------------------------------------- #


def _load_main_candidates(run_dir: Path) -> list[dict[str, Any]]:
    """Load genuine main-track candidates (never a previously fused set).

    Candidates tagged ``external_only`` (created by an earlier fusion) are
    skipped so re-running ``fuse()`` stays idempotent.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for name in ("candidates.json", "verdicts.json", "analysis.json"):
        path = run_dir / name
        if not path.exists():
            path = run_dir / "artifacts" / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            items = data.get("candidates") or data.get("verdicts") or data.get("findings") or []
        elif isinstance(data, list):
            items = data
        else:
            continue
        for it in items:
            if not isinstance(it, dict) or not it.get("candidate_id"):
                continue
            if it.get("external_only"):
                continue
            cid = str(it["candidate_id"])
            if cid in seen:
                continue
            seen.add(cid)
            out.append(it)
    return out


def _match_main(
    finding: dict[str, Any], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return the main candidates corroborated by ``finding``.

    Strict on any dimension both sides specify (binary / vuln_class / sink addr),
    tolerant when one side is missing that dimension. Requires at least one
    shared dimension so an all-empty finding never matches everything.
    """
    fbin = str(finding.get("binary_id", "") or "")
    fvuln = str(finding.get("vuln_class", "") or "")
    faddr = normalize_addr((finding.get("sink") or {}).get("addr") if finding.get("sink") else None)
    out: list[dict[str, Any]] = []
    for c in candidates:
        cbin = str(c.get("binary_id", "") or "")
        cvuln = str(c.get("vuln_class_hypothesis", "") or "")
        sink = c.get("sink") or {}
        caddr = normalize_addr(sink.get("addr")) if isinstance(sink, dict) else ""
        if fbin and cbin and fbin != cbin:
            continue
        if fvuln and cvuln and fvuln != cvuln:
            continue
        if faddr and caddr and faddr != caddr:
            continue
        if not (fbin == cbin or fvuln == cvuln or faddr == caddr):
            continue
        out.append(c)
    return out


def _apply_corroboration(cand: dict[str, Any], finding: dict[str, Any]) -> None:
    """§3.2 row 1: dual-track corroboration bumps confidence on the main candidate."""
    if cand.get("conclusion_category") not in _STRONG_CATS:
        cand["conclusion_category"] = "high-confidence-candidate"
    ev = f"external corroboration:{finding.get('tool', '?')}:{finding.get('finding_id', '?')}"
    evidence = cand.setdefault("evidence", [])
    if ev not in evidence:
        evidence.append(ev)
    corr = cand.setdefault("corroborated_by", [])
    fid = finding.get("finding_id")
    if fid and fid not in corr:
        corr.append(fid)
    cand["cross_validation"] = "both"


def _finding_to_candidate(finding: dict[str, Any]) -> dict[str, Any]:
    """§3.2 row 3: turn an external-only finding into a NEW main-track candidate.

    The synthesized dict conforms to ``candidate.schema.json`` (all required
    fields) so downstream stages (KLEE / BOND / RANK / VERIFY) can consume it
    unchanged.
    """
    sink = finding.get("sink") or {}
    trace = finding.get("call_trace") or []
    source = finding.get("source") or {"type": "unknown", "name": "unknown"}
    entry = finding.get("entry_point") or {}
    try:
        confidence = float(finding.get("confidence", 0.5) or 0.5)
    except (TypeError, ValueError):
        confidence = 0.5
    risk_score = max(0, min(30, round(confidence * 30)))
    risk_level = (
        "CRITICAL"
        if risk_score >= 24
        else "HIGH"
        if risk_score >= 18
        else "MEDIUM"
        if risk_score >= 12
        else "LOW"
    )
    src_type = str(source.get("type", ""))
    return {
        "candidate_id": f"ext-{finding.get('finding_id', 'external')}",
        "surface_id": "external",
        "binary_id": finding.get("binary_id", ""),
        "entry": {
            "function": entry.get("path") or entry.get("type") or "unknown",
            "type": entry.get("type", "unknown"),
            "method": entry.get("method", ""),
        },
        "source": source,
        "transform": [],
        "validation": [],
        "authorization": {"required": False, "evidence": []},
        "sink": {
            "function": sink.get("function", "unknown"),
            "type": sink.get("type", "unknown"),
            "addr": sink.get("addr", ""),
        },
        "call_chain": [t.get("func") for t in trace if t.get("func")]
        or [sink.get("function", "")],
        "user_control": "full" if src_type.startswith(("http", "soap", "socket")) else "partial",
        "vuln_class_hypothesis": finding.get("vuln_class", "other"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "evidence": [
            f"external:{finding.get('tool', '?')}:{finding.get('finding_id', '?')}: "
            f"{finding.get('binary_id', '')} {sink.get('addr', '')} {sink.get('function', '')}"
        ],
        "counterevidence": [],
        "conclusion_category": "high-confidence-candidate" if confidence >= 0.7 else "observation",
        "decisive_missing_fact": None,
        "status": "new",
        "external_only": True,
        "cross_validation": "external_only",
        "source_finding_id": finding.get("finding_id"),
        "tool": finding.get("tool"),
    }


def fuse(run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Deduplicate + cross-validate external findings for ``run_dir``.

    Reads ``<run_dir>/artifacts/external_findings/*.json`` (per-tool outputs
    written by the adapters) plus the combined ``all.json``. Writes:
      * ``<run_dir>/artifacts/unified_candidates.json`` -- the **merged** candidate
        set (main candidates + external-only candidates), consumed by KLEE / BOND
        downstream (teacher §3.2).
      * ``<run_dir>/artifacts/external_findings/fused.json`` -- the main fused
        findings (SaTC / KLEE / BOND), used by the benchmark as external evidence.
      * ``<run_dir>/artifacts/external_findings/recurrence_findings.json`` --
        FirmRec-only recurring detections, kept **separate** so they never leak
        into ``unified_candidates`` / the blind benchmark (F-FirmRec.md §4.3).
    Returns a summary dict (wrapped into a success ToolResult by the registry).
    """
    run_dir = Path(run_dir)
    ext_dir = run_dir / "artifacts" / "external_findings"
    ext_dir.mkdir(parents=True, exist_ok=True)

    findings: list[dict[str, Any]] = []
    per_tool: dict[str, int] = {}

    if ext_dir.exists():
        for f in sorted(ext_dir.glob("*.json")):
            if f.name in {"fused.json", "all.json", "recurrence_findings.json"}:
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(data, dict) and "findings" in data:
                tool_findings = data["findings"] or []
            elif isinstance(data, list):
                tool_findings = data
            else:
                tool_findings = []
            per_tool[f.stem] = len(tool_findings)
            findings.extend(tool_findings)

    main_candidates = _load_main_candidates(run_dir)
    main_keys, main_addrs = _main_keys(run_dir)

    # Split: FirmRec is the only recurrence-only tool and must be isolated.
    recurrence = [f for f in findings if isinstance(f, dict) and f.get("tool") == "firmrec"]
    main_external = [f for f in findings if isinstance(f, dict) and f.get("tool") != "firmrec"]

    fused_main, external_only, _ = _process_findings(main_external, main_keys, main_addrs)
    recurrence_processed, _, blind_isolated = _process_findings(
        recurrence, main_keys, main_addrs, force_blind_isolated=True
    )

    # -- convergence: build the unified candidate set (teacher §3.2) ---------- #
    unified: list[dict[str, Any]] = [dict(c) for c in main_candidates]
    index_by_id = {str(c["candidate_id"]): c for c in unified}
    seen_ext: set[str] = set()
    corroborated = 0
    external_new = 0

    for finding in fused_main:
        matches = _match_main(finding, main_candidates)
        if matches:
            for m in matches:
                target = index_by_id.get(str(m.get("candidate_id")))
                if target is None:
                    continue
                before = target.get("conclusion_category")
                _apply_corroboration(target, finding)
                if before != target.get("conclusion_category"):
                    corroborated += 1
        else:
            cand = _finding_to_candidate(finding)
            key = cand["candidate_id"]
            if key in seen_ext:
                continue
            seen_ext.add(key)
            unified.append(cand)
            external_new += 1

    summary = {
        "total_external": len(main_external),
        "fused": len(fused_main),
        "external_only": external_only,
        "blind_isolated": blind_isolated,
        "recurrence": len(recurrence_processed),
        "per_tool": per_tool,
        "unified": {
            "main": len(main_candidates),
            "corroborated": corroborated,
            "external_only_new": external_new,
            "total": len(unified),
        },
    }

    save_json(ext_dir / "fused.json", {"summary": summary, "findings": fused_main})
    save_json(
        ext_dir / "recurrence_findings.json",
        {
            "summary": {
                "recurrence": len(recurrence_processed),
                "blind_isolated": blind_isolated,
            },
            "findings": recurrence_processed,
        },
    )
    save_json(
        run_dir / "artifacts" / "unified_candidates.json",
        {"summary": summary["unified"], "candidates": unified},
    )

    return {
        "status": "ok",
        "summary": summary,
        "artifacts": {
            "fused": str(ext_dir / "fused.json"),
            "recurrence": str(ext_dir / "recurrence_findings.json"),
            "unified": str(run_dir / "artifacts" / "unified_candidates.json"),
        },
    }


__all__ = ["fuse", "_process_findings", "_load_main_candidates", "_finding_to_candidate"]
