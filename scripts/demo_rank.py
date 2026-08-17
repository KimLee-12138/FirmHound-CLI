"""Demo runner: score and rank the CVE benchmark candidates.

Reads every ``benchmarks/CVEs/<CVE>/candidate.json`` (the M5 output ground
truth), runs the M6 ten-dimension scorer, ranks the results, and writes a
human-readable Markdown ranking plus a machine-readable JSON summary.

Usage::

    python scripts/demo_rank.py [--out-dir runs/demo]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.analysis.risk_score import rank_candidates

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = REPO_ROOT / "benchmarks" / "CVEs"


def load_candidates() -> list[dict]:
    candidates: list[dict] = []
    for path in sorted(BENCHMARK_DIR.glob("*/candidate.json")):
        with path.open(encoding="utf-8") as fh:
            candidate = json.load(fh)
        candidate["_cve_id"] = path.parent.name
        candidates.append(candidate)
    return candidates


def _metadata(candidate: dict) -> dict:
    meta = candidate.get("metadata", {})
    return {
        "cve_id": meta.get("cve_id", candidate.get("_cve_id", "")),
        "device": meta.get("device", ""),
        "reporter": meta.get("reporter", ""),
    }


def render_markdown(ranked: list[dict]) -> str:
    lines = [
        "# M6 风险评分排序报告（CVE Benchmark）",
        "",
        "对 9 个历史 CVE 复现候选执行 10 维评分（P-I-U-D-C-S-W-K-V-T，满分 30），按风险降序排列。",
        "",
        "| Rank | CVE | 设备 | 队员 | 类型 | 分数 | 等级 |",
        "|------|-----|------|------|------|------|------|",
    ]
    for i, candidate in enumerate(ranked, start=1):
        meta = _metadata(candidate)
        lines.append(
            f"| {i} | {meta['cve_id']} | {meta['device']} | {meta['reporter']} "
            f"| {candidate.get('vuln_class_hypothesis', '')} "
            f"| {candidate['risk_score']} | {candidate['risk_level']} |"
        )
    lines.append("")
    lines.append("### 评分维度说明")
    lines.append("")
    lines.append(
        "- 每维 0–3：P 预认证可达 / I 输入来源 / U 用户可控 / D 危险函数可达 / C 字符串拼接 / "
        "S Shell 上下文 / W 文件写入 / K 配置持久化 / V 输入验证(反向) / T 可测试性。"
    )
    lines.append("- 阈值：≥24 CRITICAL、18–23 HIGH、12–17 MEDIUM、<12 LOW（仅归档）。")
    lines.append("- 每维评分均引用证据 ID，无证据维度记 0 并标注。")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Score and rank CVE benchmark candidates.")
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "runs" / "demo"))
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ranked = rank_candidates(load_candidates())

    summary = [
        {
            "rank": i,
            "candidate_id": c.get("candidate_id"),
            "risk_score": c["risk_score"],
            "risk_level": c["risk_level"],
            "vuln_class_hypothesis": c.get("vuln_class_hypothesis"),
            **_metadata(c),
        }
        for i, c in enumerate(ranked, start=1)
    ]

    json_path = out_dir / "ranking.json"
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    md_path = out_dir / "ranking.md"
    md_path.write_text(render_markdown(ranked), encoding="utf-8")

    print(render_markdown(ranked))
    print(f"\nJSON: {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
