"""End-to-end firmware static-analysis run against an extracted rootfs.

This is the "unknown firmware" drill: given only an extracted rootfs (from a
synthetic firmware built by ``scripts/e2e/build_firmware.sh``), the pipeline
must discover the injected command-injection vulnerability with no prior
knowledge of its location or CVE.

Stages:

    inventory → webroot enum → startup parse → ELF triage + danger scan
               → command-injection detection (ELF + CGI) → risk score → report

Usage::

    python scripts/run_e2e.py --rootfs C:/temp/fw_demo/rootfs
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from fsa.utils.jsonio import save_json
from tools.analysis.risk_score import rank_candidates
from tools.binary.danger_scan import scan_dangerous_functions
from tools.binary.elf_read import is_elf
from tools.binary.elf_triage import triage_elf
from tools.binary.secfeatures import security_features
from tools.filesystem.inventory import inventory_rootfs
from tools.filesystem.startup_parse import parse_all_startup
from tools.web.webroot_enum import enumerate_webroot, find_webroots

# Command-execution + format-builder imports that form the classic
# sprintf → system injection pattern (CVE-2017-17215, CVE-2023-27021).
_COMMAND_SINKS = {"system", "__system", "popen", "doSystemCmd", "lxmldbc_system", "alpha_system2"}
_FORMAT_BUILDERS = {"sprintf", "snprintf", "vsprintf", "vsnprintf"}
_ENV_SOURCES = {"getenv", "websGetVar", "UPnPGetArgumentValue"}

# CGI command-injection patterns (unfiltered user input into shell).
_CGI_DANGER_MARKERS = [
    "eval",
    "$QUERY_STRING",
    "$(",
    "`",
    "system(",
    "exec(",
]


def _find_elf_binaries(rootfs: Path) -> list[Path]:
    return [p for p in sorted(rootfs.rglob("*")) if p.is_file() and is_elf(p)]


def _scan_elf(rootfs: Path, path: Path) -> dict[str, Any]:
    triage = triage_elf(path)
    danger = scan_dangerous_functions(path)
    sec = security_features(path)
    return {
        "binary_id": str(path.relative_to(rootfs)),
        "path": str(path),
        "architecture": triage["architecture"],
        "security_features": sec,
        "danger": danger,
        "triage_score": triage["triage_score"],
        "network_imports": triage["network_imports"],
    }


def _detect_elf_command_injection(rootfs: Path, path: Path) -> dict[str, Any] | None:
    """Detect the sprintf/system command-injection pattern in an ELF's imports."""
    from tools.binary.elf_read import iter_imports, iter_strings, load_elf

    elf = load_elf(path)
    if elf is None:
        return None
    imports = set(iter_imports(elf))
    strings = list(iter_strings(elf))

    sinks = imports & _COMMAND_SINKS
    builders = imports & _FORMAT_BUILDERS
    sources = imports & _ENV_SOURCES

    if not (sinks and (builders or sources)):
        return None

    # Look for an env-var / query-string hint that is attacker-controlled.
    all_text = " ".join(strings)
    network_hint = any(
        h in all_text
        for h in ("QUERY_STRING", "HTTP_", "NewDownloadURL", "NewStatusURL", "SOAPAction")
    )
    source: dict[str, Any] = (
        {"type": "http_query", "name": "QUERY_STRING"}
        if network_hint
        else {"type": "environment", "name": next(iter(sources), "getenv")}
    )

    # Surface the real command template (e.g. "%s; reboot") as transform evidence.
    cmd_template = next((s for s in strings if "%s" in s or "%d" in s), None)
    transform_detail = cmd_template if cmd_template else "user input spliced into shell command"

    candidate: dict[str, Any] = {
        "candidate_id": f"e2e-elf-{path.name}",
        "surface_id": f"e2e-surf-{path.name}",
        "binary_id": str(path.relative_to(rootfs)),
        "entry": {"function": "handler", "addr": ""},
        "source": source,
        "transform": [{"type": "concat", "detail": transform_detail}],
        "validation": [],
        "authorization": {"required": False, "evidence": []},
        "sink": {"function": next(iter(sinks)), "type": "command_execution"},
        "call_chain": ["handler", next(iter(sinks))],
        "user_control": "full",
        "vuln_class_hypothesis": "command_injection",
        "evidence": [f"import:{s}" for s in sorted(sinks | builders | sources)],
        "counterevidence": [],
        "conclusion_category": "high-confidence-candidate",
        "decisive_missing_fact": None,
        "status": "analyzing",
        "_signals": {
            "sinks": sorted(sinks),
            "builders": sorted(builders),
            "sources": sorted(sources),
            "network_hint": network_hint,
        },
    }
    return candidate


def _detect_cgi_command_injection(rootfs: Path, path: Path) -> dict[str, Any] | None:
    """Detect unfiltered user input reaching a shell in a CGI script."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    lowered = content.lower()
    markers = [m for m in _CGI_DANGER_MARKERS if m in content or m in lowered]
    # Require both a shell-danger marker and an external-input hint.
    has_shell = any(m in lowered for m in ("eval", "system(", "exec(", "`", "$("))
    has_input = "$query_string" in lowered or "query_string" in lowered or "http_" in lowered
    if not (has_shell and has_input):
        return None

    return {
        "candidate_id": f"e2e-cgi-{path.name}",
        "surface_id": f"e2e-surf-{path.name}",
        "binary_id": str(path.relative_to(rootfs)),
        "entry": {"function": "cgi_handler", "addr": ""},
        "source": {"type": "http_query", "name": "QUERY_STRING"},
        "transform": [{"type": "concat", "detail": "user input interpolated into shell command"}],
        "validation": [],
        "authorization": {"required": False, "evidence": []},
        "sink": {"function": "eval", "type": "command_execution"},
        "call_chain": ["cgi_handler", "eval"],
        "user_control": "full",
        "vuln_class_hypothesis": "command_injection",
        "evidence": [f"cgi-pattern:{m}" for m in markers],
        "counterevidence": [],
        "conclusion_category": "high-confidence-candidate",
        "decisive_missing_fact": None,
        "status": "analyzing",
        "_signals": {"markers": markers},
    }


def analyze_rootfs(rootfs_dir: str | Path) -> dict[str, Any]:
    """Run the full static-analysis chain over an extracted rootfs."""
    rootfs = Path(rootfs_dir).resolve()
    if not rootfs.exists():
        raise FileNotFoundError(f"rootfs not found: {rootfs}")

    inventory = inventory_rootfs(rootfs)
    startup = parse_all_startup(rootfs)

    webroots = find_webroots(rootfs)
    endpoints: list[dict[str, Any]] = []
    for webroot in webroots:
        endpoints.extend(enumerate_webroot(webroot)["endpoints"])

    binaries = [_scan_elf(rootfs, p) for p in _find_elf_binaries(rootfs)]

    candidates: list[dict[str, Any]] = []
    for path in _find_elf_binaries(rootfs):
        cand = _detect_elf_command_injection(rootfs, path)
        if cand:
            candidates.append(cand)

    # CGI scripts under webroot (and any cgi-bin dir).
    cgi_roots = list(webroots)
    for cgi_root in cgi_roots:
        for path in sorted(cgi_root.rglob("*")):
            if path.is_file() and ".cgi" in path.name.lower():
                cand = _detect_cgi_command_injection(rootfs, path)
                if cand:
                    candidates.append(cand)

    ranked = rank_candidates(candidates) if candidates else []

    return {
        "rootfs": str(rootfs),
        "inventory": {
            "elf_count": inventory.get("elf_count"),
            "script_count": inventory.get("script_count"),
            "startup_script_count": inventory.get("startup_script_count"),
        },
        "startup_services": startup.get("services", []),
        "webroot_count": len(webroots),
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "binaries": binaries,
        "candidates": ranked,
    }


def render_report(result: dict[str, Any]) -> str:
    """Render the end-to-end result as Markdown."""
    lines = [
        "# 固件端到端静态分析报告",
        "",
        f"- rootfs: `{result['rootfs']}`",
        f"- ELF 二进制: {result['inventory'].get('elf_count')}",
        f"- 脚本数: {result['inventory'].get('script_count')}",
        f"- 启动脚本: {result['inventory'].get('startup_script_count')}",
        f"- Web 端点: {result['endpoint_count']}",
        f"- 检出候选: {len(result['candidates'])}",
        "",
        "## 1. 二进制 triage",
        "",
        "| 二进制 | 架构 | triage | 危险命中 |",
        "|--------|------|--------|----------|",
    ]
    for b in result["binaries"]:
        danger = b["danger"]
        hits = ", ".join(h["function"] for h in danger["hits"]) or "—"
        lines.append(
            f"| {b['binary_id']} | {b['architecture']} | {b['triage_score']:.2f} | {hits} |"
        )
    lines.append("")
    lines.append("## 2. 检出候选（命令注入）")
    lines.append("")
    lines.append("| 候选 | 二进制 | Sink | 分数 | 等级 |")
    lines.append("|------|--------|------|------|------|")
    for c in result["candidates"]:
        sink = (c.get("sink") or {}).get("function", "?")
        lines.append(
            f"| {c['candidate_id']} | {c['binary_id']} | {sink} "
            f"| {c['risk_score']} | {c['risk_level']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run end-to-end static analysis on a rootfs.")
    parser.add_argument("--rootfs", default="C:/temp/fw_demo/rootfs")
    parser.add_argument("--out-dir", default="runs/e2e")
    args = parser.parse_args()

    result = analyze_rootfs(args.rootfs)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / "analysis.json", result)
    report = render_report(result)
    (out_dir / "report.md").write_text(report, encoding="utf-8")

    print(report)
    print(f"\nArtifacts written to {out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
