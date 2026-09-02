"""Synthetic benchmark runner for the deterministic scoring/verifier chain.

Wires the M5→M6→M7 chain together:

    candidate → risk_score → rank → select_top → verify (10-question falsification)
              → verdicts → report

Reads only the CVE benchmark fixtures, runs scoring + ranking + verifier, and writes
a human-readable Markdown report plus machine-readable JSON artifacts.

Usage::

    python scripts/run_pipeline.py --benchmark-fixtures [--out-dir runs/pipeline]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fsa.orchestrator.verifier import CandidateVerifier  # noqa: E402
from fsa.utils.jsonio import save_json  # noqa: E402
from tools.analysis.finding_fusion import fuse  # noqa: E402
from tools.analysis.risk_score import rank_candidates, select_top  # noqa: E402
from tools.external.bond.validate import execute_validation  # noqa: E402
from tools.external.klee.prune import execute_prune  # noqa: E402
from tools.external.run_all import run_all  # noqa: E402

BENCHMARK_DIR = REPO_ROOT / "benchmarks" / "CVEs"

_ACTION_LABEL = {
    "ACCEPT": "采纳",
    "DOWNGRADE": "降级",
    "REJECT": "拒绝",
    "NEED_DYNAMIC": "需动态验证",
}


def load_benchmark() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load all benchmark candidates and merge their attack surfaces."""
    candidates: list[dict[str, Any]] = []
    surfaces: list[dict[str, Any]] = []
    for path in sorted(BENCHMARK_DIR.glob("*/")):
        cve_id = path.name
        with (path / "candidate.json").open(encoding="utf-8") as fh:
            candidate = json.load(fh)
        candidate["_cve_id"] = cve_id
        candidates.append(candidate)

        with (path / "attack_surface.json").open(encoding="utf-8") as fh:
            surface = json.load(fh)
        surfaces.extend(surface.get("surfaces", []))
    return candidates, {"surfaces": surfaces}


def _metadata(candidate: dict[str, Any]) -> dict[str, str]:
    meta = candidate.get("metadata", {})
    return {
        "cve_id": meta.get("cve_id", candidate.get("_cve_id", "")),
        "device": meta.get("device", ""),
        "reporter": meta.get("reporter", ""),
    }


def run_pipeline(
    candidates: list[dict[str, Any]],
    attack_surface: dict[str, Any],
    run_dir: str | Path,
    *,
    top_k: int = 5,
    depth: str = "standard",
    config_path: str | None = None,
    blind: bool = True,
) -> dict[str, Any]:
    """Run the baseline or full dual-track pipeline and return its result."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = run_dir / "artifacts"
    state_dir = run_dir / "state"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    save_json(artifacts_dir / "candidates.json", {"candidates": candidates})
    save_json(artifacts_dir / "attack_surface.json", attack_surface)
    save_json(state_dir / "task_card.json", {"blind": blind, "depth": depth})

    external: dict[str, Any] = {
        "status": "skipped",
        "limitation": "depth=standard; external analyzer track not requested",
    }
    working_candidates = candidates
    if depth == "full":
        upstream = run_all(run_dir, config_path, phase="upstream")
        fusion = fuse(run_dir, config_path)
        symex = execute_prune(run_dir, config_path)
        unified_path = artifacts_dir / "unified_candidates.json"
        if unified_path.exists():
            try:
                working_candidates = json.loads(unified_path.read_text(encoding="utf-8")).get(
                    "candidates", candidates
                )
            except (OSError, json.JSONDecodeError):
                working_candidates = candidates
        external = {
            "status": "ok"
            if upstream.get("status") == "ok" or symex.get("status") == "ok"
            else "degraded",
            "upstream": upstream,
            "fusion": fusion,
            "symex": symex,
        }

    ranked = rank_candidates(working_candidates)
    top = select_top(ranked, limit=top_k, keep_diversity=True)

    verifier = CandidateVerifier(run_dir)
    verdicts = verifier.review(top, attack_surface)

    if depth == "full":
        unified_path = artifacts_dir / "unified_candidates.json"
        if unified_path.exists():
            try:
                unified_doc = json.loads(unified_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                unified_doc = {}
            unified_doc["candidates"] = ranked
            save_json(unified_path, unified_doc)
        bond = execute_validation(run_dir, config_path)
        external["bond"] = bond
        if bond.get("status") == "ok" and bond.get("metrics", {}).get("applied", 0):
            updated = json.loads(unified_path.read_text(encoding="utf-8")).get("candidates", ranked)
            ranked = rank_candidates(updated)
            top = select_top(ranked, limit=top_k, keep_diversity=True)
            verdicts = verifier.review(top, attack_surface)

    result = {
        "status": "ok",
        "run_dir": str(run_dir),
        "depth": depth,
        "blind": blind,
        "total_candidates": len(ranked),
        "top_k": len(top),
        "ranking": [
            {
                "rank": i,
                "candidate_id": c.get("candidate_id"),
                "risk_score": c.get("risk_score"),
                "risk_level": c.get("risk_level"),
                "vuln_class_hypothesis": c.get("vuln_class_hypothesis"),
                **_metadata(c),
            }
            for i, c in enumerate(ranked, start=1)
        ],
        "verdicts": verdicts,
        "external": external,
    }
    return result


def render_report(result: dict[str, Any]) -> str:
    """Render the pipeline result as Markdown."""
    verdicts = result["verdicts"]["verdicts"]
    by_action: dict[str, int] = {}
    for v in verdicts:
        by_action[v["action"]] = by_action.get(v["action"], 0) + 1

    lines = [
        "# 固件漏洞静态分析流水线报告",
        "",
        f"- 候选总数：{result['total_candidates']}",
        f"- 进入 Verifier 的 Top-K：{result['top_k']}",
        "- 裁决统计："
        + "、".join(f"{_ACTION_LABEL.get(a, a)} {n}" for a, n in sorted(by_action.items())),
        "",
        "## 1. 风险评分排序",
        "",
        "| Rank | CVE | 设备 | 队员 | 类型 | 分数 | 等级 |",
        "|------|-----|------|------|------|------|------|",
    ]
    for item in result["ranking"]:
        lines.append(
            f"| {item['rank']} | {item['cve_id']} | {item['device']} | {item['reporter']} "
            f"| {item['vuln_class_hypothesis']} | {item['risk_score']} | {item['risk_level']} |"
        )
    lines.append("")
    lines.append("## 2. Verifier 反证审查（10 问）")
    lines.append("")
    lines.append("| 候选 | 裁决 | 原分 → 修正分 | 反证理由 |")
    lines.append("|------|------|--------------|----------|")
    for v in verdicts:
        counter = "；".join(v["counterevidence"]) or "—"
        lines.append(
            f"| {v['candidate_id']} | {_ACTION_LABEL.get(v['action'], v['action'])} "
            f"| {v['original_score']:.0f} → {v['revised_score']:.0f} | {counter} |"
        )
    lines.append("")
    lines.append("### 裁决口径")
    lines.append("")
    lines.append("- 采纳(ACCEPT)：确认为漏洞（confirmed-issue / high-confidence-candidate）。")
    lines.append("- 降级(DOWNGRADE)：存在认证、过滤、调用链等削弱因素，分数下调。")
    lines.append("- 拒绝(REJECT)：source 非真实外部输入 / 不可控 / 未达 sink / 仅调试功能。")
    lines.append("- 需动态验证(NEED_DYNAMIC)：静态证据不足，需 M8 本地仿真补证。")
    lines.append("")
    external = result.get("external") or {}
    lines.extend(
        [
            "## 21. 外部工具交叉验证",
            "",
            f"- 外部轨状态：{external.get('status', 'skipped')}",
        ]
    )
    if result.get("depth") != "full":
        lines.append("- 本次为 standard 深度，SaTC / KLEE / BOND / FirmRec 均未参与。")
    else:
        upstream = external.get("upstream") or {}
        symex = external.get("symex") or {}
        bond = external.get("bond") or {}
        fusion = external.get("fusion") or {}
        lines.extend(
            [
                f"- 上游外部分析：{upstream.get('status', 'skipped')}，"
                f"findings={upstream.get('findings', 0)}",
                f"- 汇聚：external_only={fusion.get('summary', {}).get('external_only', 0)}，"
                f"recurrence={fusion.get('summary', {}).get('recurrence', 0)}",
                f"- KLEE：{symex.get('status', 'skipped')}，"
                f"prune_rate={symex.get('metrics', {}).get('prune_rate', 0.0)}",
                f"- BOND：{bond.get('status', 'skipped')}，"
                f"confirmed={bond.get('metrics', {}).get('confirmed', 0)}",
                "- FirmRec 结论依赖已知漏洞签名，独立保存，不计入 Blind Benchmark 指标。",
                "- 仅允许已脱敏 (`poc_sanitized=true`) 的验证证据进入结论。",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run benchmark fixtures only; use `fsa analyze` for product analysis."
    )
    parser.add_argument(
        "--benchmark-fixtures",
        action="store_true",
        help="Acknowledge this command processes known-CVE fixtures, not submitted firmware.",
    )
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "runs" / "pipeline"))
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--depth", choices=["standard", "full"], default="standard")
    parser.add_argument("--config", default=None)
    parser.add_argument(
        "--blind",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Force recurrence-only tools out of benchmark results (default: true).",
    )
    args = parser.parse_args()
    if not args.benchmark_fixtures:
        parser.error(
            "this is a benchmark-only harness; pass --benchmark-fixtures or use `fsa analyze`"
        )

    candidates, attack_surface = load_benchmark()
    result = run_pipeline(
        candidates,
        attack_surface,
        args.out_dir,
        top_k=args.top_k,
        depth=args.depth,
        config_path=args.config,
        blind=args.blind,
    )

    out_dir = Path(args.out_dir)
    save_json(out_dir / "ranking.json", result["ranking"])
    save_json(out_dir / "verdicts.json", result["verdicts"])
    report = render_report(result)
    (out_dir / "report.md").write_text(report, encoding="utf-8")

    sys.stdout.write(report)
    sys.stdout.write(f"\n\nArtifacts written to {out_dir}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
