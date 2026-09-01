"""Parse SaTC raw output into normalized ``external_finding`` documents.

SaTC lays out its results like this (NSSL-SJTU/SaTC README)::

    <output>/
      keyword_extract_result/
        simple/API_simple.result            frontend API names
        simple/Prar_simple.result           frontend parameter names
        detail/API_detail.result            API name -> file:line
        detail/Prar_detail.result           param name -> file:line
        detail/api_split.result             composite-keyword splits
        detail/Clustering_result_v2.result  keyword <-> border binary match
        detail/File_detail.result           frontend file inventory
        detail/from_bin_add_para.result     params recovered from binaries
        detail/Not_Analysise_JS_File.result JS files that were skipped
        info.txt
      ghidra_extract_result/
        <bin>/<bin>_ref2sink_cmdi.result    command-injection sinks + paths
        <bin>/<bin>_ref2sink_cmdi.result-alter2
        <bin>/<bin>_ref2sink_bof.result     buffer-overflow sinks + paths
      result-<bin>-<script>-<rand>.txt      final alerts (Alert Address)

Parsing strategy
----------------
The exact line grammar differs between SaTC releases (the official Docker image
is built from an older commit than the current repository). Rather than betting
on one grammar, the parser uses several tolerant patterns per file type, records
``limitations`` for anything it cannot interpret, and never raises: a malformed
artifact degrades to fewer findings, never to a failed stage.

``PARSER_VERSION`` is stamped onto every finding so a later calibration pass can
tell which findings came from which parser generation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.external.base import normalize_addr, normalize_binary_id

PARSER_VERSION = "satc-parser-v1"

# Command-execution sinks -> command_injection
_CMDI_SINKS = {
    "system",
    "__system",
    "popen",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "execve",
    "doSystemCmd",
    "lxmldbc_system",
    "alpha_system2",
    "twsystem",
}
# Memory-copy sinks -> overflow
_BOF_SINKS = {
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "memcpy",
    "gets",
    "scanf",
    "sscanf",
    "wcscpy",
    "lstrcpy",
}
_ALL_SINKS = _CMDI_SINKS | _BOF_SINKS

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
_HEXWORD_RE = re.compile(r"\b[0-9a-fA-F]{6,8}\b")
_KV_SPLIT_RE = re.compile(r"[:=]\s*|\t+|\s{2,}")
_ALERT_RE = re.compile(r"alert[ _-]?address\D{0,16}(0x[0-9a-fA-F]+|\d+)", re.I)


@dataclass
class ParseStats:
    """Counters describing what the parser managed to interpret."""

    files_seen: list[str] = field(default_factory=list)
    unparsed_lines: int = 0
    limitations: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        if message not in self.limitations:
            self.limitations.append(message)


# --------------------------------------------------------------------------- #
# low-level readers (all tolerant, none raise)
# --------------------------------------------------------------------------- #


def _read_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()


def _is_blank_or_noise(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped in {"-", "--", "None", "null", "[]"}


def parse_simple_list(path: Path, stats: ParseStats | None = None) -> list[str]:
    """Parse ``API_simple.result`` / ``Prar_simple.result``: one token per line."""
    out: list[str] = []
    for raw in _read_lines(path):
        line = raw.strip()
        if _is_blank_or_noise(line):
            continue
        # Tolerate "name<TAB>count" or "name: count" shapes.
        head = re.split(r"[\t:]", line, maxsplit=1)[0].strip()
        head = head.strip("\"'`[],")
        if head:
            out.append(head)
    if stats:
        stats.files_seen.append(path.name)
    return out


def parse_detail_map(path: Path, stats: ParseStats | None = None) -> dict[str, list[str]]:
    """Parse ``API_detail.result`` / ``Prar_detail.result``: name -> evidence hits."""
    mapping: dict[str, list[str]] = {}
    for raw in _read_lines(path):
        line = raw.strip()
        if _is_blank_or_noise(line):
            continue
        parts = [p.strip() for p in _KV_SPLIT_RE.split(line, maxsplit=1) if p.strip()]
        if len(parts) < 2:
            if stats:
                stats.unparsed_lines += 1
            continue
        key = parts[0].strip("\"'`[],")
        if key:
            mapping.setdefault(key, []).append(parts[1])
    if stats:
        stats.files_seen.append(path.name)
    return mapping


def parse_clustering(path: Path, stats: ParseStats | None = None) -> list[dict[str, Any]]:
    """Parse ``Clustering_result_v2.result``: keyword <-> border binary matches.

    This is the highest-value artifact: it is the front-end-keyword to
    back-end-binary mapping our main track cannot produce.
    """
    rows: list[dict[str, Any]] = []
    for raw in _read_lines(path):
        line = raw.strip()
        if _is_blank_or_noise(line):
            continue
        addrs = _ADDR_RE.findall(line) or _HEXWORD_RE.findall(line)
        parts = [p.strip().strip("\"'`[],") for p in re.split(r"[\t|,]", line) if p.strip()]
        if not parts:
            continue
        keyword = parts[0]
        binary = ""
        for candidate in parts[1:]:
            if "/" in candidate or candidate.endswith((".cgi", ".bin", ".so")):
                binary = candidate
                break
        if not binary and len(parts) > 1:
            binary = parts[1]
        rows.append(
            {
                "keyword": keyword,
                "binary": binary,
                "addr": normalize_addr(addrs[0]) if addrs else "",
                "raw": line,
            }
        )
    if stats:
        stats.files_seen.append(path.name)
    return rows


def parse_ghidra_result(
    path: Path, vuln_class: str, stats: ParseStats | None = None
) -> list[dict[str, Any]]:
    """Parse ``<bin>_ref2sink_{cmdi,bof}.result`` (and the ``-alter2`` variant).

    Each interpretable line yields a sink address plus the ordered addresses that
    form the call path. Lines without any address are skipped and counted.
    """
    findings: list[dict[str, Any]] = []
    for raw in _read_lines(path):
        line = raw.strip()
        if _is_blank_or_noise(line):
            continue
        addrs = _ADDR_RE.findall(line) or _HEXWORD_RE.findall(line)
        if not addrs:
            if stats:
                stats.unparsed_lines += 1
            continue
        sink_func = next((s for s in _ALL_SINKS if re.search(rf"\b{s}\b", line)), "")
        if not sink_func:
            # Fall back to the last identifier that looks like a call target.
            idents = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\b", line)
            sink_func = idents[-1] if idents else ""
        trace = [normalize_addr(a) for a in addrs]
        findings.append(
            {
                "sink": {"function": sink_func, "addr": normalize_addr(addrs[-1])},
                "call_trace": [{"addr": a} for a in trace],
                "vuln_class": vuln_class,
                "raw": line,
            }
        )
    if stats:
        stats.files_seen.append(path.name)
    return findings


def parse_alert_file(path: Path, stats: ParseStats | None = None) -> list[dict[str, Any]]:
    """Parse ``result-<bin>-<script>-<rand>.txt``: the final alert list.

    Alert addresses are the primary key of a SaTC finding, so this file wins when
    the same sink appears in several artifacts.
    """
    alerts: list[dict[str, Any]] = []
    for raw in _read_lines(path):
        line = raw.strip()
        if _is_blank_or_noise(line):
            continue
        match = _ALERT_RE.search(line)
        if match:
            addr = normalize_addr(match.group(1))
        else:
            addrs = _ADDR_RE.findall(line) or _HEXWORD_RE.findall(line)
            if not addrs:
                if stats:
                    stats.unparsed_lines += 1
                continue
            addr = normalize_addr(addrs[-1])
        sink_func = next((s for s in _ALL_SINKS if re.search(rf"\b{s}\b", line)), "")
        alerts.append({"sink": {"function": sink_func, "addr": addr}, "raw": line})
    if stats:
        stats.files_seen.append(path.name)
    return alerts


# --------------------------------------------------------------------------- #
# high-level assembly
# --------------------------------------------------------------------------- #


def _vuln_class_for(script: str, sink_func: str) -> str:
    if "bof" in script.lower():
        return "overflow"
    if "cmdi" in script.lower():
        return "command_injection"
    if sink_func in _CMDI_SINKS:
        return "command_injection"
    if sink_func in _BOF_SINKS:
        return "overflow"
    return "other"


def _sink_type_for(sink_func: str) -> str:
    if sink_func in _CMDI_SINKS:
        return "command_execution"
    if sink_func in _BOF_SINKS:
        return "memory_copy"
    return "unknown"


def compute_confidence(
    *,
    has_alert_addr: bool,
    taint_check: bool,
    trace_len: int,
    clustered: bool,
) -> float:
    """Explainable confidence score (see docs/external/E-SaTC.md §6.3)."""
    score = 0.3
    if has_alert_addr:
        score += 0.25
    if taint_check:
        score += 0.20
    if trace_len >= 2:
        score += 0.15
    if clustered:
        score += 0.10
    if not has_alert_addr:
        score = min(score, 0.6)
    return round(min(score, 1.0), 2)


def parse_satc_output(
    output_dir: Path,
    *,
    rootfs: Path,
    run_id: str,
    taint_check: bool = False,
    tool_version: str = "",
    duration_s: float = 0.0,
) -> tuple[list[dict[str, Any]], ParseStats]:
    """Walk a SaTC output tree and emit normalized findings.

    Returns ``(findings, stats)``. Never raises for missing or malformed input.
    """
    stats = ParseStats()
    findings: list[dict[str, Any]] = []
    if not output_dir or not Path(output_dir).exists():
        stats.note(f"output directory missing: {output_dir}")
        return findings, stats

    out = Path(output_dir)
    kw_detail_dir = out / "keyword_extract_result" / "detail"
    kw_simple_dir = out / "keyword_extract_result" / "simple"
    ghidra_dir = out / "ghidra_extract_result"

    # 1-9: keyword extraction artifacts (context / evidence).
    api_simple = parse_simple_list(kw_simple_dir / "API_simple.result", stats)
    prar_simple = parse_simple_list(kw_simple_dir / "Prar_simple.result", stats)
    parse_detail_map(kw_detail_dir / "API_detail.result", stats)
    prar_detail = parse_detail_map(kw_detail_dir / "Prar_detail.result", stats)
    clustering = parse_clustering(kw_detail_dir / "Clustering_result_v2.result", stats)
    parse_detail_map(kw_detail_dir / "File_detail.result", stats)
    from_bin = parse_simple_list(kw_detail_dir / "from_bin_add_para.result", stats)
    skipped_js = parse_simple_list(kw_detail_dir / "Not_Analysise_JS_File.result", stats)
    parse_detail_map(kw_detail_dir / "api_split.result", stats)

    if skipped_js:
        stats.note(f"{len(skipped_js)} JS file(s) not analysed by SaTC")

    # Keyword -> binary map, used to attribute findings and to feed A1.
    keyword_to_binary: dict[str, str] = {
        row["keyword"]: row["binary"] for row in clustering if row["keyword"] and row["binary"]
    }
    clustered_keywords = set(keyword_to_binary)

    # 10-11: ghidra per-binary results, keyed by (binary, sink addr).
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for bin_dir in (
        sorted(p for p in ghidra_dir.iterdir() if p.is_dir()) if ghidra_dir.exists() else []
    ):
        binary_id = (
            normalize_binary_id(rootfs, rootfs / bin_dir.name)
            if (rootfs / bin_dir.name).exists()
            else bin_dir.name
        )
        for result_file in sorted(bin_dir.iterdir()):
            if not result_file.is_file() or ".result" not in result_file.name:
                continue
            script = (
                "ref2sink_cmdi"
                if "cmdi" in result_file.name
                else "ref2sink_bof"
                if "bof" in result_file.name
                else "other"
            )
            for item in parse_ghidra_result(result_file, script, stats):
                addr = item["sink"]["addr"]
                key = (binary_id, addr)
                existing = by_key.get(key)
                # Prefer the entry that already carries trace information.
                if existing is None or len(item["call_trace"]) > len(existing["call_trace"]):
                    by_key[key] = {
                        "binary_id": binary_id,
                        "sink": item["sink"],
                        "call_trace": item["call_trace"],
                        "vuln_class": _vuln_class_for(script, item["sink"]["function"]),
                        "raw_ref": str(result_file.relative_to(out)),
                    }

    # 12: final alert files override / add sink addresses.
    alert_addrs: dict[tuple[str, str], bool] = {}
    for alert_file in sorted(out.glob("result-*.txt")):
        match = re.match(
            r"result-(?P<bin>.+?)-(?P<script>.+?)-(?P<rand>[A-Za-z0-9]+)\.txt$", alert_file.name
        )
        script = match.group("script") if match else ""
        bin_hint = match.group("bin") if match else ""
        for alert in parse_alert_file(alert_file, stats):
            addr = alert["sink"]["addr"]
            if not addr:
                continue
            matched_key = None
            for bin_id, sink_addr in by_key:
                if sink_addr == addr:
                    matched_key = (bin_id, sink_addr)
                    break
            if matched_key is None:
                binary_id = (
                    normalize_binary_id(rootfs, rootfs / bin_hint)
                    if (rootfs / bin_hint).exists()
                    else bin_hint
                )
                matched_key = (binary_id, addr)
                by_key[matched_key] = {
                    "binary_id": binary_id,
                    "sink": alert["sink"],
                    "call_trace": [],
                    "vuln_class": _vuln_class_for(script, alert["sink"]["function"]),
                    "raw_ref": alert_file.name,
                }
            alert_addrs[matched_key] = True

    # Source keywords: prefer clustered ones, fall back to the simple list.
    if clustered_keywords:
        source_names = sorted(clustered_keywords)[:8]
    else:
        source_names = sorted({*prar_simple, *from_bin})[:8]

    for (binary_id, addr), entry in sorted(by_key.items()):
        sink_func = entry["sink"]["function"]
        has_alert = alert_addrs.get((binary_id, addr), False)
        vuln_class = entry["vuln_class"]
        trace = entry["call_trace"]
        # Attribute keywords to this binary when the clustering says so.
        own_keywords = [
            k for k, b in keyword_to_binary.items() if b == binary_id or b.endswith(binary_id)
        ]
        params = own_keywords[:8] or source_names
        confidence = compute_confidence(
            has_alert_addr=has_alert,
            taint_check=taint_check,
            trace_len=len(trace),
            clustered=bool(own_keywords),
        )
        evidence: list[str] = []
        if entry.get("raw_ref"):
            evidence.append(f"satc_raw:{entry['raw_ref']}")
        if params:
            evidence.append(f"satc_keyword:{','.join(params[:4])}")
        for name in params[:3]:
            if name in prar_detail:
                evidence.append(f"satc_prar:{name}@{prar_detail[name][0]}")

        slug = re.sub(r"[^A-Za-z0-9]+", "-", binary_id).strip("-") or "unknown"
        findings.append(
            {
                "finding_id": f"satc-{slug}-{addr or sink_func or 'na'}",
                "tool": "satc",
                "tool_version": tool_version or "unknown",
                "run_id": run_id,
                "binary_id": binary_id,
                "vuln_class": vuln_class,
                "entry_point": {
                    "type": "http" if api_simple else "unknown",
                    "params": params,
                },
                "source": {
                    "type": "http_param" if params else "unknown",
                    "name": params[0] if params else "",
                    "evidence": "; ".join(evidence[:3]),
                },
                "sink": {
                    "function": sink_func,
                    "addr": addr,
                    "type": _sink_type_for(sink_func),
                },
                "call_trace": trace,
                "confidence": confidence,
                "status": "ok",
                "raw_ref": entry.get("raw_ref", ""),
                "duration_s": round(duration_s, 1),
                "notes": (
                    f"parser={PARSER_VERSION}; taint_check={taint_check}; "
                    f"alert={has_alert}; keywords={len(params)}"
                ),
            }
        )

    if not findings:
        stats.note(
            "no findings produced; check whether keyword_extract_result / "
            "ghidra_extract_result contain data for this firmware"
        )
    return findings, stats
