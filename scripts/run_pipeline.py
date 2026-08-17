"""End-to-end static-analysis pipeline demo.

Wires the M5→M6→M7 chain together:

    candidate → risk_score → rank → select_top → verify (10-question falsification)
              → verdicts → report

Reads the CVE benchmark fixtures as its input (a stand-in for a real M5
candidate set), runs scoring + ranking + verifier, and writes a human-readable
Markdown report plus machine-readable JSON artifacts.

Usage::

    python scripts/run_pipeline.py [--out-dir runs/pipeline]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from fsa.orchestrator.verifier import CandidateVerifier
from fsa.utils.jsonio import save_json
from tools.analysis.risk_score import rank_candidates, select_top

REPO_ROOT = Path(__file__).resolve().parent.parent
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
) -> dict[str, Any]:
    """Run scoring → ranking → selection → verification and return the result."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    ranked = rank_candidates(candidates)
    top = select_top(ranked, limit=top_k, keep_diversity=True)

    verifier = CandidateVerifier(run_dir)
    verdicts = verifier.review(top, attack_surface)

    result = {
        "run_dir": str(run_dir),
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
        f"- 裁决统计："
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
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the static-analysis pipeline demo.")
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "runs" / "pipeline"))
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args()

    candidates, attack_surface = load_benchmark()
    result = run_pipeline(candidates, attack_surface, args.out_dir, top_k=args.top_k)

    out_dir = Path(args.out_dir)
    save_json(out_dir / "ranking.json", result["ranking"])
    save_json(out_dir / "verdicts.json", result["verdicts"])
    report = render_report(result)
    (out_dir / "report.md").write_text(report, encoding="utf-8")

    print(report)
    print(f"\nArtifacts written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
