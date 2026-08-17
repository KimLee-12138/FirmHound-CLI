"""M6 ten-dimension risk scoring and candidate ranking.

Implements the P-I-U-D-C-S-W-K-V-T scoring model (each 0-3, max 30) from the
legacy SKILL2 section 10 table. Scoring is evidence-driven: every dimension
must reference an evidence ID (or a structural field), and dimensions with no
evidence score 0 with an explicit note.

Thresholds: >=24 CRITICAL, 18-23 HIGH, 12-17 MEDIUM, <12 LOW (archive only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Dimension key -> (display name, order).
DIMENSIONS: list[tuple[str, str]] = [
    ("P", "预认证可达性"),
    ("I", "输入来源"),
    ("U", "用户可控性"),
    ("D", "危险函数可达"),
    ("C", "字符串拼接"),
    ("S", "Shell 上下文"),
    ("W", "文件写入"),
    ("K", "配置持久化"),
    ("V", "输入验证(反向)"),
    ("T", "可测试性"),
]

# Direct network-facing input source types (score 3 for dimension I).
_NETWORK_SOURCES = {
    "http_param",
    "http_header",
    "http_query",
    "http_cookie",
    "http_body",
    "header",
    "body",
    "soap_arg",
    "soap_param",
    "soap",
    "socket_buffer",
    "socket_buf",
    "file_upload",
}

# Internal config / environment source types (score 2 for dimension I).
_CONFIG_SOURCES = {"config_import", "environment", "config", "nvram"}

# Command-execution sinks confirming a shell context (score 3 for dimension S).
_SHELL_SINKS = {
    "system",
    "__system",
    "popen",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "execve",
}

# Strong validation kinds (score 0 for the reverse-scored dimension V).
_STRONG_VALIDATION = {"escape", "whitelist", "path_normalize", "type_limit"}
# Weak validation kinds (score 2 for dimension V).
_WEAK_VALIDATION = {"blacklist", "length_check"}

_CRITICAL = 24
_HIGH = 18
_MEDIUM = 12


@dataclass
class DimensionScore:
    """A single dimension's score with its evidence references."""

    key: str
    name: str
    score: int
    evidence: list[str] = field(default_factory=list)
    note: str = ""


def _level(total: int) -> str:
    if total >= _CRITICAL:
        return "CRITICAL"
    if total >= _HIGH:
        return "HIGH"
    if total >= _MEDIUM:
        return "MEDIUM"
    return "LOW"


def _evidence_ids(candidate: dict[str, Any], *keywords: str) -> list[str]:
    """Return candidate evidence IDs matching any keyword, else a field marker."""
    ids = [e for e in candidate.get("evidence", []) if any(k in e.lower() for k in keywords)]
    return ids or [f"<field:{keywords[0]}>"]


def _score_preauth(candidate: dict[str, Any]) -> DimensionScore:
    auth = candidate.get("authorization") or {}
    required = auth.get("required")
    if required is False:
        return DimensionScore(
            "P", "预认证可达性", 3, _evidence_ids(candidate, "auth", "preauth"), "确认预认证"
        )
    if required is True:
        return DimensionScore("P", "预认证可达性", 0, _evidence_ids(candidate, "auth"), "需认证")
    return DimensionScore("P", "预认证可达性", 1, [], "认证状态未知，保守记 1")


def _score_input(candidate: dict[str, Any]) -> DimensionScore:
    source = candidate.get("source") or {}
    source_type = source.get("type", "")
    if source_type in _NETWORK_SOURCES:
        return DimensionScore(
            "I", "输入来源", 3, _evidence_ids(candidate, "source"), "直接网络输入"
        )
    if source_type in _CONFIG_SOURCES:
        return DimensionScore(
            "I", "输入来源", 2, _evidence_ids(candidate, "source"), "文件系统/配置输入"
        )
    if source_type:
        return DimensionScore(
            "I", "输入来源", 1, _evidence_ids(candidate, "source"), "间接/内部输入"
        )
    return DimensionScore("I", "输入来源", 0, [], "无外部输入，无证据")


def _score_user_control(candidate: dict[str, Any]) -> DimensionScore:
    control = candidate.get("user_control", "none")
    mapping = {"full": 3, "partial": 2, "none": 0}
    score = mapping.get(control, 0)
    note = {"full": "完全可控", "partial": "部分可控", "none": "不可控"}.get(control, "未知")
    return DimensionScore(
        "U", "用户可控性", score, _evidence_ids(candidate, "control", "source"), note
    )


def _score_reachability(candidate: dict[str, Any]) -> DimensionScore:
    sink = candidate.get("sink") or {}
    chain = candidate.get("call_chain") or []
    if sink.get("function") and chain:
        return DimensionScore(
            "D",
            "危险函数可达",
            3,
            _evidence_ids(candidate, "sink", "call", "flow"),
            "调用链到 sink 确认可达",
        )
    if sink.get("function"):
        return DimensionScore(
            "D", "危险函数可达", 2, _evidence_ids(candidate, "sink"), "仅字符串证据，无调用链"
        )
    return DimensionScore("D", "危险函数可达", 0, [], "无可达危险函数，无证据")


def _score_concat(candidate: dict[str, Any]) -> DimensionScore:
    transform = candidate.get("transform") or []
    concat = [t for t in transform if t.get("type") == "concat"]
    if not concat:
        return DimensionScore("C", "字符串拼接", 0, [], "无拼接")
    detail = " ".join(t.get("detail", "") for t in concat).lower()
    raw_markers = ("raw", "原始", "直接", "passed to shell", "concatenat", "拼接")
    fmt_markers = ("%s", "%d", "%x", "%p", "format")
    if any(m in detail for m in raw_markers):
        return DimensionScore(
            "C", "字符串拼接", 3, _evidence_ids(candidate, "transform", "concat"), "原始拼接"
        )
    if any(m in detail for m in fmt_markers):
        return DimensionScore(
            "C", "字符串拼接", 2, _evidence_ids(candidate, "transform", "concat"), "格式化含输入"
        )
    return DimensionScore("C", "字符串拼接", 1, _evidence_ids(candidate, "transform"), "固定格式")


def _score_shell(candidate: dict[str, Any]) -> DimensionScore:
    sink = candidate.get("sink") or {}
    func = sink.get("function", "")
    if sink.get("type") == "command_execution" and func in _SHELL_SINKS:
        return DimensionScore(
            "S",
            "Shell 上下文",
            3,
            _evidence_ids(candidate, "sink", "system"),
            "确认 Shell (system/exec)",
        )
    if sink.get("type") == "command_execution":
        return DimensionScore(
            "S",
            "Shell 上下文",
            2,
            _evidence_ids(candidate, "sink"),
            "厂商封装命令执行，很可能 Shell",
        )
    return DimensionScore("S", "Shell 上下文", 0, [], "无 Shell 上下文")


def _score_file_write(candidate: dict[str, Any]) -> DimensionScore:
    sink = candidate.get("sink") or {}
    detail = (sink.get("detail") or "").lower()
    if sink.get("type") == "filesystem":
        if any(m in detail for m in ("script", "shell", "任意", ".sh")):
            return DimensionScore(
                "W", "文件写入", 3, _evidence_ids(candidate, "write", "file"), "任意/Shell 脚本写入"
            )
        return DimensionScore(
            "W", "文件写入", 2, _evidence_ids(candidate, "write", "file"), "配置文件写入"
        )
    return DimensionScore("W", "文件写入", 0, [], "无写入")


def _score_persistence(candidate: dict[str, Any]) -> DimensionScore:
    source = candidate.get("source") or {}
    if source.get("type") in _CONFIG_SOURCES and candidate.get("user_control") == "full":
        return DimensionScore(
            "K",
            "配置持久化",
            3,
            _evidence_ids(candidate, "config", "persist"),
            "直接配置注入+持久化",
        )
    if source.get("type") in _CONFIG_SOURCES:
        return DimensionScore(
            "K", "配置持久化", 2, _evidence_ids(candidate, "config"), "可控配置键"
        )
    return DimensionScore("K", "配置持久化", 0, [], "无配置持久化")


def _score_validation(candidate: dict[str, Any]) -> DimensionScore:
    validations = candidate.get("validation") or []
    if not validations:
        return DimensionScore("V", "输入验证(反向)", 3, ["<field:validation-empty>"], "无任何验证")
    kinds = {v.get("kind", "") for v in validations if isinstance(v, dict)}
    if kinds & _STRONG_VALIDATION:
        return DimensionScore(
            "V", "输入验证(反向)", 0, _evidence_ids(candidate, "valid", "filter"), "强验证"
        )
    if kinds & _WEAK_VALIDATION:
        return DimensionScore(
            "V", "输入验证(反向)", 2, _evidence_ids(candidate, "valid", "filter"), "弱/最小验证"
        )
    return DimensionScore(
        "V", "输入验证(反向)", 1, _evidence_ids(candidate, "valid"), "白/黑名单验证"
    )


def _score_testability(candidate: dict[str, Any]) -> DimensionScore:
    source = candidate.get("source") or {}
    source_type = source.get("type", "")
    socket_sources = {"socket_buffer", "socket_buf"}
    if source_type in _NETWORK_SOURCES and source_type not in socket_sources:
        return DimensionScore(
            "T", "可测试性", 3, _evidence_ids(candidate, "source"), "简单 HTTP/网络请求"
        )
    if source_type in socket_sources:
        return DimensionScore(
            "T", "可测试性", 2, _evidence_ids(candidate, "source"), "需 QEMU 仿真"
        )
    return DimensionScore("T", "可测试性", 1, [], "需 Ghidra+QEMU")


_SCORERS = [
    _score_preauth,
    _score_input,
    _score_user_control,
    _score_reachability,
    _score_concat,
    _score_shell,
    _score_file_write,
    _score_persistence,
    _score_validation,
    _score_testability,
]


def score_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    """Score a single candidate and return the full report.

    Returns a dict with ``candidate_id``, ``risk_score`` (0-30),
    ``risk_level``, and ``dimensions`` (a list of dimension dicts, each with
    ``key``, ``name``, ``score``, ``evidence`` and ``note``).
    """
    dims = [fn(candidate) for fn in _SCORERS]
    total = sum(d.score for d in dims)
    return {
        "candidate_id": candidate.get("candidate_id", ""),
        "risk_score": total,
        "risk_level": _level(total),
        "dimensions": [
            {"key": d.key, "name": d.name, "score": d.score, "evidence": d.evidence, "note": d.note}
            for d in dims
        ],
    }


def _apply_score(candidate: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``candidate`` with ``risk_score``/``risk_level`` set."""
    report = score_candidate(candidate)
    out = dict(candidate)
    out["risk_score"] = report["risk_score"]
    out["risk_level"] = report["risk_level"]
    out["risk_dimensions"] = report["dimensions"]
    return out


def rank_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score and sort candidates by risk score (descending), stable by id."""
    scored = [_apply_score(c) for c in candidates]
    scored.sort(key=lambda c: (-c["risk_score"], c.get("candidate_id", "")))
    return scored


def select_top(
    candidates: list[dict[str, Any]],
    *,
    limit: int = 5,
    keep_diversity: bool = True,
) -> list[dict[str, Any]]:
    """Select the Top-K candidates for the Verifier, preserving class diversity.

    Selection strategy (from the M6 plan): <=5 -> all; 6-20 -> Top-5; >20 ->
    Top-3 plus one representative per additional ``vuln_class_hypothesis``.
    """
    ranked = rank_candidates(candidates)
    n = len(ranked)
    if n <= limit:
        return ranked

    selected: list[dict[str, Any]] = []
    seen_classes: set[str] = set()
    if keep_diversity:
        # First pass: take one of each vulnerability class in score order.
        for c in ranked:
            cls = c.get("vuln_class_hypothesis", "other")
            if cls not in seen_classes:
                selected.append(c)
                seen_classes.add(cls)
            if len(selected) >= limit:
                return selected
        # Second pass: fill remaining slots by score order.
        for c in ranked:
            if c not in selected:
                selected.append(c)
            if len(selected) >= limit:
                break
    else:
        selected = ranked[:limit]
    return selected
