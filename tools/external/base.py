"""Shared adapter contract for external analyzers (SaTC / FirmRec / KLEE / BOND).

This module is the *contract* that lets four people work in parallel: as long as
every analyzer implements :class:`ExternalAnalyzer`, the orchestrator, the
fusion layer and the reporting layer never need to know which tool produced a
finding.

Design rules (non-negotiable, see docs/external/README.md §3.3):

1. ``probe()`` must never raise. A raising probe takes down the whole pipeline.
2. ``execute()`` catches every exception. A missing tool degrades to
   ``status="skipped"`` or ``"failed"`` plus a ``limitation`` string; it never
   aborts the run.
3. The main pipeline must never ``import`` a concrete analyzer directly. It goes
   through ``ToolRegistry.call()`` / ``run_all()`` only.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fsa.schemas.loader import validate

SCHEMA_NAME = "external_finding"

# Tools that require a known-vulnerability signature and therefore must never
# participate in a blind benchmark run. See docs/external/F-FirmRec.md §4.
RECURRENCE_ONLY_TOOLS = frozenset({"firmrec"})


# --------------------------------------------------------------------------- #
# Shared normalization helpers
# --------------------------------------------------------------------------- #

_WIN_PATH_RE = re.compile(r"^[A-Za-z]:[/\\].*$")


def normalize_binary_id(rootfs: Path, path: Path | str) -> str:
    """Return a rootfs-relative, POSIX-normalized binary id.

    ALL four analyzers must use this so the fusion layer can join external
    findings against ``candidate.binary_id``.
    """
    p = Path(path)
    try:
        rel = p.relative_to(rootfs)
    except ValueError:
        # Already relative, or outside the rootfs: fall back to the raw string.
        rel = p
    return rel.as_posix().lstrip("./")


def normalize_addr(addr: str | int | None) -> str:
    """Normalize an address to lowercase hex without leading zeros.

    ``0x0040A1B0`` -> ``0x40a1b0``. Returns ``""`` for empty input so callers can
    build stable ``finding_id`` / dedup keys.
    """
    if addr is None:
        return ""
    if isinstance(addr, int):
        return hex(addr)
    text = str(addr).strip()
    if not text or text in {"-", "n/a", "None", "null"}:
        return ""
    try:
        value = int(text, 16) if text.lower().startswith("0x") else int(text, 16)
    except ValueError:
        return text.lower()
    return hex(value)


def to_wsl_path(arg: str | Path) -> str:
    """Translate a Windows absolute path to its WSL ``/mnt/<drive>/...`` form."""
    text = str(arg).replace("\\", "/")
    if _WIN_PATH_RE.match(text):
        drive = text[0].lower()
        return f"/mnt/{drive}/{text[2:].lstrip('/')}"
    return text


# --------------------------------------------------------------------------- #
# Data carriers
# --------------------------------------------------------------------------- #


@dataclass
class AnalysisContext:
    """Everything an external analyzer needs, resolved by the orchestrator."""

    run_id: str
    rootfs_dir: Path
    workdir: Path  # tmp/external/<tool>/<run_id>/ (inside the safety whitelist)
    firmware_path: Path | None = None
    attack_surface: dict[str, Any] = field(default_factory=dict)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    timeout_s: int = 1800
    config: dict[str, Any] = field(default_factory=dict)

    def output_dir(self, name: str) -> Path:
        """Return (and create) a per-invocation output directory."""
        out = self.workdir / "out" / name
        out.mkdir(parents=True, exist_ok=True)
        return out


@dataclass
class ProbeResult:
    """Availability probe outcome. Constructed instead of raising."""

    available: bool
    version: str = ""
    backend: str = ""
    missing: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class RunOutcome:
    """Result of a single analyzer invocation."""

    status: str  # ok | skipped | failed | timeout | unsafe
    stdout_path: Path | None = None
    stderr: str = ""
    duration_s: float = 0.0
    limitation: str = ""
    outputs: list[Path] = field(default_factory=list)


@dataclass
class AnalyzerResult:
    """What :meth:`ExternalAnalyzer.execute` returns to the pipeline."""

    tool: str
    status: str  # ok | skipped | failed | timeout | unsafe
    findings: list[dict[str, Any]] = field(default_factory=list)
    limitation: str = ""
    duration_s: float = 0.0
    dropped: int = 0  # findings rejected by schema validation
    probe: ProbeResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "findings": self.findings,
            "limitation": self.limitation,
            "duration_s": self.duration_s,
            "dropped": self.dropped,
            "probe": {
                "available": self.probe.available if self.probe else False,
                "version": self.probe.version if self.probe else "",
                "backend": self.probe.backend if self.probe else "",
                "missing": self.probe.missing if self.probe else [],
                "notes": self.probe.notes if self.probe else "",
            },
        }


# --------------------------------------------------------------------------- #
# The contract
# --------------------------------------------------------------------------- #


class ExternalAnalyzer(ABC):
    """Uniform interface every external analyzer implements."""

    name: str = ""

    # -- to be implemented by each analyzer -------------------------------- #

    @abstractmethod
    def probe(self) -> ProbeResult:
        """Detect whether the tool is usable. MUST NOT raise."""

    @abstractmethod
    def prepare(self, ctx: AnalysisContext) -> Path:
        """Stage inputs into ``ctx.workdir``. Return the prepared input root."""

    @abstractmethod
    def run(self, ctx: AnalysisContext) -> RunOutcome:
        """Execute the tool under a hard timeout. MUST NOT let timeouts hang."""

    @abstractmethod
    def parse(self, ctx: AnalysisContext, outcome: RunOutcome) -> list[dict[str, Any]]:
        """Parse raw artifacts into normalized finding dicts."""

    # -- shared implementation --------------------------------------------- #

    def normalize(
        self, findings: list[dict[str, Any]], *, strict: bool = False
    ) -> tuple[list[dict[str, Any]], int]:
        """Validate findings against ``external_finding.schema.json``.

        Invalid findings are dropped rather than propagated: one malformed
        artifact must not poison the whole fusion layer.

        Returns:
            ``(valid_findings, dropped_count)``
        """
        valid: list[dict[str, Any]] = []
        dropped = 0
        for finding in findings:
            try:
                validate(finding, schema_name=SCHEMA_NAME)
            except Exception as exc:  # noqa: BLE001 - validation must never raise out
                dropped += 1
                if strict:
                    raise
                self._last_error = str(exc)
                continue
            valid.append(finding)
        return valid, dropped

    def execute(self, ctx: AnalysisContext) -> AnalyzerResult:
        """Single entry point used by the pipeline. Catches everything."""
        try:
            probe = self.probe()
        except Exception as exc:  # noqa: BLE001
            return AnalyzerResult(
                tool=self.name,
                status="failed",
                limitation=f"probe raised {type(exc).__name__}: {exc}",
            )

        if not probe.available:
            return AnalyzerResult(
                tool=self.name,
                status="skipped",
                probe=probe,
                limitation=f"tool unavailable; missing: {probe.missing or probe.notes}",
            )

        try:
            ctx.workdir.mkdir(parents=True, exist_ok=True)
            self.prepare(ctx)
            outcome = self.run(ctx)
        except Exception as exc:  # noqa: BLE001
            return AnalyzerResult(
                tool=self.name,
                status="failed",
                probe=probe,
                limitation=f"{type(exc).__name__}: {exc}",
            )

        if outcome.status != "ok":
            return AnalyzerResult(
                tool=self.name,
                status=outcome.status,
                probe=probe,
                limitation=outcome.limitation or f"run status={outcome.status}",
                duration_s=outcome.duration_s,
            )

        try:
            raw_findings = self.parse(ctx, outcome)
        except Exception as exc:  # noqa: BLE001
            return AnalyzerResult(
                tool=self.name,
                status="failed",
                probe=probe,
                limitation=f"parse raised {type(exc).__name__}: {exc}",
                duration_s=outcome.duration_s,
            )

        findings, dropped = self.normalize(raw_findings)
        return AnalyzerResult(
            tool=self.name,
            status="ok",
            findings=findings,
            limitation="" if findings else "tool ran but produced no findings",
            duration_s=outcome.duration_s,
            dropped=dropped,
            probe=probe,
        )


def dedup_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    """Stable dedup key shared by the fusion layer."""
    return (
        str(finding.get("binary_id", "")),
        normalize_addr(finding.get("sink", {}).get("addr") if finding.get("sink") else None),
        str(finding.get("vuln_class", "")),
    )
