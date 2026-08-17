"""Top-K candidate verifier: falsification-first review (M7)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fsa.reporting.evidence_store import EvidenceStore
from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json

CONCLUSION_CATEGORIES = {
    "confirmed-issue",
    "high-confidence-candidate",
    "false-positive",
    "unknown",
    "observation",
}

ACCEPT_ACTIONS = {"confirmed-issue", "high-confidence-candidate"}


@dataclass
class Verdict:
    """Single candidate verdict."""

    candidate_id: str
    action: str
    original_score: float
    revised_score: float
    reasons: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    counterevidence: list[str] = field(default_factory=list)
    reviewer: str = "rule"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict matching verdict.schema.json."""
        return {
            "candidate_id": self.candidate_id,
            "action": self.action,
            "original_score": self.original_score,
            "revised_score": self.revised_score,
            "reasons": self.reasons,
            "supporting_evidence": self.supporting_evidence,
            "counterevidence": self.counterevidence,
            "reviewer": self.reviewer,
        }


class CandidateVerifier:
    """Falsification-first reviewer for vulnerability candidates."""

    # Canonical 10-question checklist (M7).
    QUESTIONS = [
        "source_is_real_external_input",
        "user_controllable",
        "reaches_real_sink",
        "encoding_or_whitelist_present",
        "call_chain_reachable",
        "handler_actually_starts",
        "authentication_required",
        "debug_only_or_disabled",
        "build_or_platform_conditions",
        "contradictory_evidence_exists",
    ]

    def __init__(
        self,
        run_dir: str | Path,
        evidence_store: EvidenceStore | None = None,
        reviewer: str = "rule",
    ) -> None:
        """Initialize verifier with run directory and optional evidence store."""
        self.run_dir = Path(run_dir)
        self.evidence_store = evidence_store or EvidenceStore(self.run_dir)
        self.reviewer = reviewer
        self.run_id = self.run_dir.name

    def review(
        self,
        candidates: list[dict[str, Any]],
        attack_surface: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run the 10-question checklist over candidates and produce verdicts."""
        verdicts: list[dict[str, Any]] = []
        for candidate in candidates:
            verdict = self._review_one(candidate, attack_surface or {})
            verdicts.append(verdict.to_dict())

        result = {
            "run_id": self.run_id,
            "reviewer": self.reviewer,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verdicts": verdicts,
        }
        validate(result, schema_name="verdict")
        return result

    def review_and_save(
        self,
        candidates: list[dict[str, Any]],
        attack_surface: dict[str, Any] | None = None,
        path: str | Path | None = None,
    ) -> Path:
        """Run review and persist verdicts.json."""
        result = self.review(candidates, attack_surface)
        out_path = Path(path) if path else self.run_dir / "verdicts.json"
        save_json(out_path, result)
        return out_path

    def _review_one(self, candidate: dict[str, Any], attack_surface: dict[str, Any]) -> Verdict:
        """Apply falsification rules to a single candidate."""
        candidate_id = candidate.get("candidate_id", "unknown")
        original_score = float(candidate.get("risk_score", 0))
        original_category = candidate.get("conclusion_category", "unknown")
        reasons: list[str] = []
        supporting = list(candidate.get("evidence", []))
        counter = list(candidate.get("counterevidence", []))

        # 10-question evaluation.
        answers = self._answer_questions(candidate, attack_surface)

        # Rule-based verdict derivation.
        action, revised_score, final_category = self._derive_verdict(
            candidate, answers, original_score, original_category, reasons
        )

        # Evidence-based reasons.
        if answers["source_is_real_external_input"] is False:
            reasons.append("Source is not a real external input (e.g., constant or config key).")
            counter.append("source-not-external")
        if answers["user_controllable"] is False:
            reasons.append("User control over the source is not demonstrated.")
            counter.append("user-control-missing")
        if answers["reaches_real_sink"] is False:
            reasons.append(
                "Sink reachability is not confirmed by call chain or decompile evidence."
            )
            counter.append("sink-unreachable")
        if answers["encoding_or_whitelist_present"] is True:
            reasons.append("Encoding/whitelist/filter present; exploitation may be mitigated.")
            counter.append("filter-present")
        if answers["call_chain_reachable"] is False:
            reasons.append("Call chain from entry to sink is not demonstrated.")
            counter.append("call-chain-missing")
        if answers["handler_actually_starts"] is False:
            reasons.append("Handler binary or daemon is not evidenced in startup scripts.")
            counter.append("handler-not-started")
        if answers["authentication_required"] is True:
            reasons.append(
                "Route requires authentication; reduces exploitability unless paired "
                "with auth bypass."
            )
            counter.append("auth-required")
        if answers["debug_only_or_disabled"] is True:
            reasons.append(
                "Functionality is debug-only or compile-time disabled in release builds."
            )
            counter.append("debug-only")
        if answers["build_or_platform_conditions"] is True:
            reasons.append("Exploitability depends on build-time or platform-specific conditions.")
            counter.append("conditional-exploit")
        if answers["contradictory_evidence_exists"] is True:
            reasons.append("Contradictory evidence exists in the evidence store.")
            counter.append("contradictory-evidence")

        if not reasons:
            reasons.append("No defeating counter-evidence found under the 10-question checklist.")

        return Verdict(
            candidate_id=candidate_id,
            action=action,
            original_score=original_score,
            revised_score=revised_score,
            reasons=reasons,
            supporting_evidence=supporting,
            counterevidence=counter,
            reviewer=self.reviewer,
        )

    def _answer_questions(
        self, candidate: dict[str, Any], attack_surface: dict[str, Any]
    ) -> dict[str, bool | None]:
        """Answer the 10 falsification questions heuristically."""
        source = candidate.get("source", {}) or {}
        sink = candidate.get("sink", {}) or {}
        auth = candidate.get("authorization", {}) or {}
        transform = candidate.get("transform", []) or []
        validation = candidate.get("validation", []) or []
        call_chain = candidate.get("call_chain", []) or []
        evidence = candidate.get("evidence", []) or []
        counterevidence = candidate.get("counterevidence", []) or []

        # 1. Source is real external input.
        source_type = source.get("type", "")
        external_source = source_type in {
            "http_param",
            "http_header",
            "http_cookie",
            "url_path",
            "soap_argument",
            "upnp_argument",
            "socket_input",
            "config_file",
        }

        # 2. User controllable.
        user_control = candidate.get("user_control", "none")
        controllable = user_control in {"partial", "full"}

        # 3. Reaches real sink.
        sink_type = sink.get("type", "")
        sink_function = sink.get("function", "")
        real_sink = bool(sink_type or sink_function)

        # 4. Encoding or whitelist present.
        has_filter = any(
            t.get("type") in {"encode", "escape", "whitelist", "sanitize", "filter"}
            for t in transform
        ) or any(v.get("type") in {"length_check", "regex_match", "blacklist"} for v in validation)

        # 5. Call chain reachable.
        reachable = len(call_chain) >= 2

        # 6. Handler actually starts.
        surface_id = candidate.get("surface_id", "")
        surfaces = attack_surface.get("surfaces", []) if attack_surface else []
        surface = next((s for s in surfaces if s.get("surface_id") == surface_id), {})
        startup_evidence = surface.get("startup_evidence", []) or []
        handler_starts = bool(startup_evidence) or surface.get("confidence", 0.0) >= 0.5

        # 7. Authentication required.
        auth_required = auth.get("required", False)

        # 8. Debug only / disabled.
        handler = (surface.get("handler") or "").lower()
        debug_only = any(
            kw in handler or kw in sink_function.lower()
            for kw in ("debug", "test", "diag", "trace")
        )

        # 9. Build/platform conditions.
        conditional = any(
            t.get("type") in {"conditional", "platform_specific", "compile_flag"} for t in transform
        )

        # 10. Contradictory evidence exists.
        contradictory = bool(counterevidence) or self._has_contradictory_evidence(evidence)

        return {
            "source_is_real_external_input": external_source,
            "user_controllable": controllable,
            "reaches_real_sink": real_sink,
            "encoding_or_whitelist_present": has_filter,
            "call_chain_reachable": reachable,
            "handler_actually_starts": handler_starts,
            "authentication_required": auth_required,
            "debug_only_or_disabled": debug_only,
            "build_or_platform_conditions": conditional,
            "contradictory_evidence_exists": contradictory,
        }

    def _derive_verdict(
        self,
        candidate: dict[str, Any],
        answers: dict[str, bool | None],
        original_score: float,
        original_category: str,
        reasons: list[str],
    ) -> tuple[str, float, str]:
        """Derive verdict action and revised score from answers."""
        # False-positive defeating conditions.
        if answers["source_is_real_external_input"] is False:
            return "REJECT", max(0.0, original_score - 20), "false-positive"
        if answers["user_controllable"] is False and original_category not in {
            "observation",
            "unknown",
        }:
            return "REJECT", max(0.0, original_score - 15), "false-positive"
        if answers["reaches_real_sink"] is False:
            return "REJECT", max(0.0, original_score - 20), "false-positive"
        if answers["debug_only_or_disabled"] is True:
            return "REJECT", max(0.0, original_score - 18), "false-positive"

        # Downgrade conditions.
        if answers["encoding_or_whitelist_present"] is True:
            revised = max(0.0, original_score - 8)
            return (
                "DOWNGRADE",
                revised,
                "high-confidence-candidate" if revised >= 18 else "observation",
            )
        if answers["authentication_required"] is True:
            revised = max(0.0, original_score - 6)
            return (
                "DOWNGRADE",
                revised,
                "high-confidence-candidate" if revised >= 18 else "observation",
            )
        if answers["call_chain_reachable"] is False:
            revised = max(0.0, original_score - 10)
            return (
                "DOWNGRADE",
                revised,
                "high-confidence-candidate" if revised >= 18 else "unknown",
            )
        if answers["handler_actually_starts"] is False:
            revised = max(0.0, original_score - 10)
            return (
                "DOWNGRADE",
                revised,
                "high-confidence-candidate" if revised >= 18 else "unknown",
            )
        if answers["build_or_platform_conditions"] is True:
            revised = max(0.0, original_score - 5)
            return (
                "DOWNGRADE",
                revised,
                "high-confidence-candidate" if revised >= 18 else "observation",
            )
        if answers["contradictory_evidence_exists"] is True:
            revised = max(0.0, original_score - 8)
            return (
                "DOWNGRADE",
                revised,
                "high-confidence-candidate" if revised >= 18 else "unknown",
            )

        # Strong confirmation.
        if original_category == "confirmed-issue" and all(
            answers[q] is not False
            for q in [
                "source_is_real_external_input",
                "user_controllable",
                "reaches_real_sink",
                "call_chain_reachable",
            ]
        ):
            return "ACCEPT", original_score, "confirmed-issue"

        # Default: keep as high-confidence candidate if score warrants.
        if original_score >= 18:
            return "ACCEPT", original_score, "high-confidence-candidate"

        # Insufficient evidence for a confident conclusion.
        return "NEED_DYNAMIC", original_score, "unknown"

    def _has_contradictory_evidence(self, evidence_ids: list[str]) -> bool:
        """Check evidence store for entries that contradict these evidence IDs."""
        try:
            all_evidence = self.evidence_store.list_all()
        except Exception:  # noqa: BLE001
            return False
        evidence_set = set(evidence_ids)
        for ev in all_evidence:
            contradicts = set(ev.get("contradicts", []))
            if contradicts & evidence_set:
                return True
        return False

    def load_candidates(self, path: str | Path) -> list[dict[str, Any]]:
        """Load candidates from a JSON file or array."""
        data = load_json(Path(path))
        if isinstance(data, dict):
            return data.get("candidates", [])
        return data

    def load_attack_surface(self, path: str | Path) -> dict[str, Any]:
        """Load attack_surface.json."""
        return load_json(Path(path))
