"""Build an evidence ledger for one candidate or an entire run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.utils.jsonio import load_json, save_json
from tools.analysis.risk_score import score_candidate


def _load_optional(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return load_json(path)


def _load_candidates(run_dir: Path) -> list[dict[str, Any]]:
    for name in ("unified_candidates.json", "ranking.json", "candidates.json"):
        data = _load_optional(run_dir / "artifacts" / name, {})
        if isinstance(data, dict) and isinstance(data.get("candidates"), list):
            return data["candidates"]
        if isinstance(data, list):
            return data
    return []


def _load_verdicts(run_dir: Path) -> list[dict[str, Any]]:
    data = _load_optional(run_dir / "artifacts" / "verdict.json", {})
    verdicts = data.get("verdicts", []) if isinstance(data, dict) else []
    return verdicts if isinstance(verdicts, list) else []


def _load_state(run_dir: Path) -> dict[str, Any]:
    return _load_optional(run_dir / "state" / "run_state.json", {})


def _load_decisions(run_dir: Path) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for path in sorted((run_dir / "decisions").glob("*.json")):
        data = _load_optional(path, {})
        if isinstance(data, dict):
            decisions.append(data)
    state = _load_state(run_dir)
    for item in state.get("decisions", []) if isinstance(state, dict) else []:
        if isinstance(item, dict):
            decisions.append(item)
    return decisions


def _candidate_by_id(candidates: list[dict[str, Any]], candidate_id: str) -> dict[str, Any] | None:
    for candidate in candidates:
        if candidate.get("candidate_id") == candidate_id:
            return candidate
    return None


def _verdict_by_candidate(
    verdicts: list[dict[str, Any]], candidate_id: str
) -> dict[str, Any] | None:
    for verdict in verdicts:
        if verdict.get("candidate_id") == candidate_id:
            return verdict
    return None


def _candidate_summary(candidate: dict[str, Any], verdict: dict[str, Any] | None) -> dict[str, Any]:
    scoring = score_candidate(candidate)
    return {
        "candidate_id": candidate.get("candidate_id"),
        "class": candidate.get("vuln_class_hypothesis"),
        "risk_score": candidate.get("risk_score", scoring["risk_score"]),
        "risk_level": candidate.get("risk_level", scoring["risk_level"]),
        "entry": candidate.get("entry", {}),
        "source": candidate.get("source", {}),
        "sink": candidate.get("sink", {}),
        "call_chain": candidate.get("call_chain", []),
        "authorization": candidate.get("authorization", {}),
        "validation": candidate.get("validation", []),
        "evidence": candidate.get("evidence", []),
        "counterevidence": candidate.get("counterevidence", []),
        "risk_dimensions": candidate.get("risk_dimensions", scoring["dimensions"]),
        "verdict": verdict or {},
        "next_step": _next_step(candidate, verdict),
    }


def _next_step(candidate: dict[str, Any], verdict: dict[str, Any] | None) -> str:
    action = (verdict or {}).get("action")
    if action == "ACCEPT":
        return "整理复现证据、影响范围和修复建议；对外披露前需再次确认授权与影响边界。"
    if action == "REJECT":
        return "保留为反证样本，后续用于优化误报过滤规则。"
    if action == "DOWNGRADE":
        return "补充缺失的外部输入、调用链、认证或过滤证据后再重新评分。"
    if action == "NEED_DYNAMIC" or candidate.get("decisive_missing_fact"):
        return "在隔离实验室中进行无害动态验证，优先证明入口可达和 sink 可触发。"
    return "继续进行反证审查，避免仅凭静态 source/sink 共现确认漏洞。"


def build_evidence_ledger(
    run_dir: str | Path,
    *,
    candidate_id: str | None = None,
    limit: int | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build and optionally persist an evidence ledger for a run."""
    run = Path(run_dir).resolve()
    if not run.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run}")
    candidates = _load_candidates(run)
    verdicts = _load_verdicts(run)
    selected = candidates
    if candidate_id:
        candidate = _candidate_by_id(candidates, candidate_id)
        if candidate is None:
            raise ValueError(f"candidate not found: {candidate_id}")
        selected = [candidate]
    elif limit is not None and limit > 0:
        selected = candidates[:limit]

    ledger = {
        "status": "ok",
        "run_id": run.name,
        "candidate_filter": candidate_id,
        "limit": limit,
        "state": {
            "status": _load_state(run).get("status"),
            "current_stage": _load_state(run).get("current_stage"),
        },
        "candidate_count": len(candidates),
        "ledger_count": len(selected),
        "candidates": [
            _candidate_summary(item, _verdict_by_candidate(verdicts, str(item.get("candidate_id"))))
            for item in selected
        ],
        "decisions": _load_decisions(run),
        "artifacts": {
            "report": str(run / "report.md") if (run / "report.md").is_file() else "",
            "final_verdict": str(run / "final_verdict.json")
            if (run / "final_verdict.json").is_file()
            else "",
        },
    }
    if output_path:
        save_json(output_path, ledger)
    return ledger


def render_ledger_markdown(ledger: dict[str, Any]) -> str:
    """Render a compact Markdown explanation for human review."""
    lines = [
        f"# 漏洞证据账本 — {ledger.get('run_id')}",
        "",
        f"- 状态：{ledger.get('status')}",
        f"- 候选总数：{ledger.get('candidate_count')}",
        f"- 本次解释候选数：{ledger.get('ledger_count')}",
        "",
    ]
    for candidate in ledger.get("candidates", []):
        verdict = candidate.get("verdict", {})
        lines.extend(
            [
                f"## {candidate.get('candidate_id')}",
                "",
                f"- 类型：{candidate.get('class')}",
                f"- 风险：{candidate.get('risk_score')} / {candidate.get('risk_level')}",
                f"- Source：`{candidate.get('source')}`",
                f"- Sink：`{candidate.get('sink')}`",
                f"- 调用链：`{candidate.get('call_chain')}`",
                f"- 裁决：{verdict.get('action', '未裁决')}",
                f"- 下一步：{candidate.get('next_step')}",
                "",
                "### 支持证据",
                "",
            ]
        )
        evidence = candidate.get("evidence", [])
        lines.extend([f"- {item}" for item in evidence] or ["- 暂无"])
        lines.extend(["", "### 反证", ""])
        counter = candidate.get("counterevidence", [])
        lines.extend([f"- {item}" for item in counter] or ["- 暂无"])
        lines.extend(["", "### 十维评分", ""])
        for dim in candidate.get("risk_dimensions", []):
            lines.append(
                f"- {dim.get('key')} {dim.get('name')}：{dim.get('score')}，{dim.get('note')}"
            )
        lines.append("")
    return "\n".join(lines)
