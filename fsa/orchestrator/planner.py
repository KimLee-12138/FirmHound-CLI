"""Task parsing and plan generation."""

from __future__ import annotations

import contextlib
import re
import zipfile
from pathlib import Path
from typing import Any

from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json


class Planner:
    """Parse task inputs and generate execution plans."""

    DEFAULT_STAGES = [
        "INIT",
        "BASELINE",
        "UNPACK",
        "SURFACE",
        "BINARY_TRIAGE",
        "DECOMPILE",
        "STATIC_ANALYSIS",
        "RANK",
        "VERIFY_TOP_K",
        "REPORT",
        "DONE",
    ]

    QUICK_STAGES = [
        "INIT",
        "BASELINE",
        "UNPACK",
        "SURFACE",
        "BINARY_TRIAGE",
        "STATIC_ANALYSIS",
        "RANK",
        "VERIFY_TOP_K",
        "REPORT",
        "DONE",
    ]

    # Full depth: main track + the full external-analyzer track. Every external
    # stage is required=False, so a disabled/missing analyzer degrades to a no-op
    # and the run still reaches DONE. This is the F7 degradation safety net.
    FULL_STAGES = [
        "INIT",
        "BASELINE",
        "UNPACK",
        "SURFACE",
        "BINARY_TRIAGE",
        "DECOMPILE",
        "STATIC_ANALYSIS",
        "EXTERNAL_ANALYSIS",
        "FUSION",
        "SYMEX_PRUNE",
        "RANK",
        "VERIFY_TOP_K",
        "LOCAL_VALIDATION",
        "CONSTRAINED_VALIDATION",
        "REPORT",
        "DONE",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def parse_task(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize CLI args / natural language / zip package into a task_card."""
        raw_refs: list[dict[str, str]] = []
        if input_data.get("natural_language"):
            raw_refs.append({"type": "text", "value": input_data["natural_language"]})
        if input_data.get("firmware_path"):
            raw_refs.append({"type": "file", "value": input_data["firmware_path"]})
        if input_data.get("task_package"):
            raw_refs.append({"type": "archive_member", "value": input_data["task_package"]})

        auth_raw = input_data.get("authorization") or {}
        if isinstance(auth_raw, str):
            auth = {
                "holder": auth_raw,
                "scope": "analysis-only",
                "allow_emulation": False,
                "network_isolation": True,
            }
        else:
            auth = {
                "holder": auth_raw.get("holder", ""),
                "scope": auth_raw.get("scope", "analysis-only"),
                "allow_emulation": auth_raw.get("allow_emulation", False),
                "network_isolation": auth_raw.get("network_isolation", True),
            }

        task_card: dict[str, Any] = {
            "task_id": input_data.get("task_id", "auto"),
            "raw_input_refs": raw_refs,
            "objective": input_data.get("objective", "firmware_vuln_hunt"),
            "firmware_path": input_data.get("firmware_path", ""),
            "vendor": input_data.get("vendor"),
            "model": input_data.get("model"),
            "version": input_data.get("version"),
            "depth": input_data.get("depth", "standard"),
            "constraints": input_data.get("constraints", []),
            "success_criteria": input_data.get(
                "success_criteria", ["identify high-confidence vulnerabilities"]
            ),
            "authorization": auth,
            "requires_human_gate": False,
            "human_gate_reasons": [],
        }
        if input_data.get("rootfs_path"):
            task_card["rootfs_path"] = input_data["rootfs_path"]

        # If natural_language is provided, extract slots heuristically.
        nl = input_data.get("natural_language", "")
        if nl:
            task_card = self._extract_from_nl(nl, task_card)

        # If a task package zip is provided, unpack and inspect.
        package = input_data.get("task_package")
        if package:
            task_card = self._extract_from_package(package, task_card)

        # Mandatory slot checks.
        if not task_card.get("firmware_path") and not input_data.get("firmware_url"):
            task_card["firmware_path"] = "pending_human_input"
            task_card["requires_human_gate"] = True
            task_card["human_gate_reasons"].append("Missing firmware_path or firmware_url")

        if not auth.get("holder"):
            task_card["requires_human_gate"] = True
            task_card["human_gate_reasons"].append("Missing authorization holder")

        validate(task_card, schema_name="task_card")
        return task_card

    def _extract_from_nl(self, text: str, card: dict[str, Any]) -> dict[str, Any]:
        """Heuristic slot extraction from Chinese/English natural language."""
        # Path extraction: quoted paths or common extensions.
        path_re = re.compile(
            r"['\"]([^'\"]+\.(?:bin|trx|chk|img|fw))['\"]|([\w\-/\\]+\.(?:bin|trx|chk|img|fw))",
            re.I,
        )
        for m in path_re.finditer(text):
            card["firmware_path"] = m.group(1) or m.group(2)
            break

        # Vendor / model patterns.
        vendor_patterns = [
            re.compile(r"厂商[是为:]?\s*([\w\-]+)", re.I),
            re.compile(r"vendor[\s:=]+([\w\-]+)", re.I),
        ]
        for pat in vendor_patterns:
            m = pat.search(text)
            if m:
                card["vendor"] = m.group(1)
                break

        model_patterns = [
            re.compile(r"型号[是为:]?\s*([A-Za-z0-9\-]+)", re.I),
            re.compile(r"model[\s:=]+([A-Za-z0-9\-]+)", re.I),
        ]
        for pat in model_patterns:
            m = pat.search(text)
            if m:
                card["model"] = m.group(1)
                break

        # Depth keywords.
        if any(k in text.lower() for k in ("快速", "quick", "粗略")):
            card["depth"] = "quick"
        elif any(k in text.lower() for k in ("深度", "deep", "full", "完整")):
            card["depth"] = "full"

        # Authorization keywords.
        if any(k in text for k in ("授权", "authorization", "本人负责", "自有设备")):
            card["authorization"] = {
                "holder": "user-declared",
                "scope": "analysis-only",
                "allow_emulation": False,
                "network_isolation": True,
            }

        return card

    def _extract_from_package(
        self, package_path: str | Path, card: dict[str, Any]
    ) -> dict[str, Any]:
        """Inspect a zip task package and attach discovered files."""
        path = Path(package_path)
        if not path.exists():
            return card

        extracted = path.parent / "extracted_package"
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(extracted)

        for child in extracted.rglob("*"):
            if child.is_file():
                rel = str(child.relative_to(extracted))
                card["attachments"].append(rel)
                # Treat first .bin/.chk/.img as firmware if not already set.
                if not card.get("firmware_path") and child.suffix.lower() in {
                    ".bin",
                    ".chk",
                    ".img",
                    ".trx",
                    ".fw",
                }:
                    card["firmware_path"] = str(child)
                # Treat first .txt as readme.
                if child.suffix.lower() == ".txt" and not card.get("readme_text"):
                    with contextlib.suppress(OSError):
                        card["readme_text"] = child.read_text(encoding="utf-8", errors="ignore")
        return card

    def build_plan(self, task_card: dict[str, Any]) -> dict[str, Any]:
        """Generate a stage plan from a task_card."""
        depth = task_card.get("depth", "standard")
        if depth == "quick":
            stages = list(self.QUICK_STAGES)
        elif depth == "full":
            stages = list(self.FULL_STAGES)
        else:  # "standard" and anything else -> main track only, no external stages
            stages = list(self.DEFAULT_STAGES)

        config_path = self.config.get("_config_path")
        external_args = {"config_path": config_path} if config_path else {}

        plan: dict[str, Any] = {
            "stages": stages,
            "stage_configs": {
                "UNPACK": {
                    "tool": "tools.firmware.unpack",
                    "required": True,
                    "args": {
                        "temp_root": self.config.get("paths", {}).get("temp", ""),
                        "safety_config": self.config.get("safety", {}).get("config", ""),
                    },
                },
                "SURFACE": {"tool": "tools.web.build_attack_surface", "required": True},
                "BINARY_TRIAGE": {
                    "tool": "tools.binary.triage",
                    "required": True,
                    "args": {
                        "max_binaries": self.config.get("analysis", {}).get("max_binaries", 500),
                        "max_strings_per_binary": self.config.get("analysis", {}).get(
                            "max_strings_per_binary", 200
                        ),
                    },
                },
                "DECOMPILE": {"tool": "tools.binary.decompile", "required": False},
                "STATIC_ANALYSIS": {"tool": "tools.audit.static", "required": True},
                # External track (all required=False).
                "EXTERNAL_ANALYSIS": {
                    "tool": "tools.external.run_all",
                    "required": False,
                    "args": {
                        "phase": "upstream",
                        **external_args,
                    },
                },
                "FUSION": {
                    "tool": "tools.analysis.finding_fusion",
                    "required": False,
                    "args": external_args,
                },
                "SYMEX_PRUNE": {
                    "tool": "tools.external.klee.prune",
                    "required": False,
                    "args": external_args,
                },
                "CONSTRAINED_VALIDATION": {
                    "tool": "tools.external.bond.validate",
                    "required": False,
                    "args": external_args,
                },
                "RANK": {"tool": "tools.audit.rank", "required": True},
                "VERIFY_TOP_K": {
                    "tool": "tools.audit.verify",
                    "required": True,
                    "args": {"top_k": self.config.get("analysis", {}).get("verify_top_k", 5)},
                },
                "LOCAL_VALIDATION": {"tool": "tools.emu.validate", "required": False},
                "REPORT": {"tool": "tools.report.generate", "required": True},
            },
            "success_criteria": {
                "min_confidence": 0.6,
                "max_false_positives": 5,
            },
            "budget_profile": "quick" if depth == "quick" else "default",
        }
        return plan

    def save_task_card(self, task_card: dict[str, Any], run_dir: str | Path) -> Path:
        """Save task_card.json into a run directory."""
        path = Path(run_dir) / "state" / "task_card.json"
        validate(task_card, schema_name="task_card")
        save_json(path, task_card)
        return path

    def save_plan(self, plan: dict[str, Any], run_dir: str | Path) -> Path:
        """Save plan.json into a run directory."""
        path = Path(run_dir) / "state" / "plan.json"
        save_json(path, plan)
        return path
