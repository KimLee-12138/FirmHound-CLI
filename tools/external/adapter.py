"""Registry-facing adapters for external analyzers.

These functions are what ``tools/registry/external.yaml`` points at. The
orchestrator calls them with ``{"run_dir": ...}`` (and an optional
``config_path``). Each function:

  * loads the merged ``external`` config from ``config/dev.yaml`` (or a custom
    path),
  * skips cleanly when the tool is disabled or unavailable -- a skipped tool
    must never abort the pipeline,
  * resolves the firmware rootfs for the run,
  * builds the analyzer with :func:`tools.external.<tool>.runner.build`,
  * executes it through the :class:`ExternalAnalyzer` contract,
  * persists normalized findings to
    ``<run_dir>/artifacts/external_findings/<tool>.json``,
  * returns a plain dict (the :class:`ToolRegistry` wraps it into a *success*
    ``ToolResult``, so a skipped analyzer degrades instead of failing).

Importing this module must never require Docker, SaTC, or any other external
tool to be installed.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

from fsa.utils.jsonio import save_json
from tools.external.base import RECURRENCE_ONLY_TOOLS, AnalysisContext

EXTERNAL_TOOLS = ("satc", "firmrec", "klee", "bond")


# --------------------------------------------------------------------------- #
# config + rootfs resolution
# --------------------------------------------------------------------------- #


def _repo_config_path() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "config" / "dev.yaml"


def _load_global_external(config_path: str | None = None) -> dict[str, Any]:
    """Return the ``external:`` mapping from config, or ``{}`` if absent."""
    candidates: list[Path] = []
    if config_path:
        candidates.append(Path(config_path))
    candidates.append(_repo_config_path())
    for path in candidates:
        if not path.exists():
            continue
        try:
            import yaml

            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
        ext = data.get("external", {}) or {}
        if isinstance(ext, dict):
            return ext
    return {}


def _run_context(run_dir: Path) -> dict[str, Any]:
    """Derive per-run context that gates external tools.

    Currently only ``blind`` matters: a blind benchmark run must not load any
    recurrence-only tool (FirmRec), because those tools require known-vuln
    signatures and would leak ground truth into the benchmark (F-FirmRec.md §4).
    The flag is read from ``<run_dir>/state/task_card.json`` when present.
    """
    blind = False
    tc = run_dir / "state" / "task_card.json"
    if tc.exists():
        try:
            import json

            card = json.loads(tc.read_text(encoding="utf-8"))
            blind = bool(card.get("blind", False))
        except Exception:
            blind = False
    return {"blind": blind}


def _resolve_external_config(external: dict[str, Any], run_ctx: dict[str, Any]) -> dict[str, Any]:
    """Apply per-run gates to the ``external:`` config mapping.

    On a *blind* run, every recurrence-only tool (FirmRec) is force-disabled so
    it can never participate in a blind benchmark. Returns a *new* mapping; the
    caller treats a tool whose ``enabled`` flipped to False here as FORCED_DISABLE
    (and records it in the result ``limitation``).

    This is the tested entry point for F-FirmRec.md §4.4 isolation test #1.
    """
    resolved: dict[str, Any] = {}
    for key, value in (external or {}).items():
        resolved[key] = dict(value) if isinstance(value, dict) else value
    if run_ctx.get("blind"):
        for tool in RECURRENCE_ONLY_TOOLS:
            tc = resolved.get(tool)
            if isinstance(tc, dict) and tc.get("enabled"):
                tc = dict(tc)
                tc["enabled"] = False
                tc["force_disabled_reason"] = (
                    "blind run: recurrence-only tool requires known-vuln signatures "
                    "and would leak ground truth into the benchmark"
                )
                resolved[tool] = tc
    return resolved


def _tool_cfg(global_ext: dict[str, Any], tool: str) -> dict[str, Any]:
    """Effective config for one tool: per-tool keys + inherited globals."""
    cfg: dict[str, Any] = dict(global_ext.get(tool, {}) or {})
    # The top-level switch is a hard gate, not a default value.  A per-tool
    # switch must never bypass ``external.enabled=false``.
    cfg["enabled"] = bool(global_ext.get("enabled", False)) and bool(cfg.get("enabled", False))
    cfg.setdefault("workdir", global_ext.get("workdir", "./tmp/external"))
    cfg.setdefault("timeout_s", global_ext.get("timeout_s", 3600))
    return cfg


def _load_candidates(run_dir: Path) -> list[dict[str, Any]]:
    """Load the candidate set for external analyzers.

    Prefers the FUSION output ``unified_candidates.json`` (main + external-only
    candidates merged), falling back to the raw main-track ``candidates.json``
    when fusion has not run yet. This is what makes KLEE / BOND see the
    external-only hits that the convergence layer materialised.
    """
    for name in ("unified_candidates.json", "candidates.json"):
        path = run_dir / "artifacts" / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and isinstance(data.get("candidates"), list):
            return data["candidates"]
        if isinstance(data, list):
            return data
    return []


def _resolve_rootfs(run_dir: Path, cfg: dict[str, Any]) -> Path | None:
    """Locate the extracted firmware rootfs for a run.

    Order: explicit config path -> the UNPACK stage's immutable
    ``artifacts/rootfs.json`` descriptor -> legacy in-run rootfs directory.
    The resolver deliberately never guesses from a global ``tmp/unpacked`` directory,
    because that can silently analyze a different run's firmware.
    """
    if cfg.get("rootfs_dir"):
        p = Path(str(cfg["rootfs_dir"]))
        if p.exists():
            return p

    descriptor = run_dir / "artifacts" / "rootfs.json"
    if descriptor.is_file():
        try:
            data = json.loads(descriptor.read_text(encoding="utf-8"))
            selected = Path(str(data.get("rootfs_path") or ""))
            if selected.is_dir():
                return selected.resolve()
        except (OSError, ValueError):
            return None

    art_rootfs = run_dir / "artifacts" / "rootfs"
    if art_rootfs.exists():
        return art_rootfs.resolve()
    return None


def _build_analyzer(tool: str, cfg: dict[str, Any]):
    """Import ``tools.external.<tool>.runner.build`` and construct the analyzer.

    Returns ``None`` when the analyzer module is not present yet (it belongs to
    another student's workstream).
    """
    module_name = f"tools.external.{tool}.runner"
    try:
        mod = importlib.import_module(module_name)
        factory = mod.build
    except Exception:
        return None
    try:
        return factory(cfg)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# core single-tool runner (shared by every registry entry)
# --------------------------------------------------------------------------- #


def _run_tool(tool: str, run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Run one external analyzer and persist its findings.

    Always returns a dict, never raises. A disabled/unavailable tool yields a
    ``skipped`` status so the orchestrator stage degrades instead of aborting.
    """
    run_dir = Path(run_dir)
    global_ext = _load_global_external(config_path)
    run_ctx = _run_context(run_dir)
    originally_enabled = bool((global_ext.get(tool, {}) or {}).get("enabled", False))
    global_ext = _resolve_external_config(global_ext, run_ctx)
    cfg = _tool_cfg(global_ext, tool)

    # Blind-run gate: a recurrence-only tool (FirmRec) that was enabled in config
    # is force-disabled on a blind run. This is the academic-integrity firewall of
    # F-FirmRec.md §4 -- it must never abort the pipeline, just degrade to skipped.
    if (
        run_ctx.get("blind")
        and tool in RECURRENCE_ONLY_TOOLS
        and not cfg.get("enabled", False)
        and originally_enabled
    ):
        return {
            "status": "skipped",
            "tool": tool,
            "findings": [],
            "dropped": 0,
            "limitation": (
                "FORCED_DISABLE: blind run detected; firmrec requires known-vuln "
                "signatures and is excluded from the benchmark by policy"
            ),
        }

    if not cfg.get("enabled", False):
        return {
            "status": "skipped",
            "tool": tool,
            "findings": [],
            "dropped": 0,
            "limitation": (
                f"external.{tool}.enabled=false (or external.enabled=false) "
                f"in config; tool did not run"
            ),
        }

    analyzer = _build_analyzer(tool, cfg)
    if analyzer is None:
        return {
            "status": "skipped",
            "tool": tool,
            "findings": [],
            "dropped": 0,
            "limitation": (
                f"analyzer module tools.external.{tool}.runner not available "
                f"(owned by another student workstream)"
            ),
        }

    rootfs = _resolve_rootfs(run_dir, cfg)
    if rootfs is None:
        return {
            "status": "skipped",
            "tool": tool,
            "findings": [],
            "dropped": 0,
            "limitation": "could not locate an extracted firmware rootfs for this run",
        }

    workdir = Path(str(cfg.get("workdir", "./tmp/external"))) / tool / run_dir.name
    ctx = AnalysisContext(
        run_id=run_dir.name,
        rootfs_dir=rootfs,
        candidates=_load_candidates(run_dir),
        workdir=workdir,
        timeout_s=int(cfg.get("timeout_s", 3600)),
        config=cfg,
    )
    ctx.attack_surface = ctx.attack_surface or {}

    result = analyzer.execute(ctx)

    out_dir = run_dir / "artifacts" / "external_findings"
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / f"{tool}.json", result.to_dict())

    return result.to_dict()


# --------------------------------------------------------------------------- #
# per-tool registry entries (one name per analyzer)
# --------------------------------------------------------------------------- #


def run_satc(run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Registry entry: ``tools.external.satc``."""
    return _run_tool("satc", run_dir, config_path)


def run_firmrec(run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Registry entry: ``tools.external.firmrec`` (owned by student F)."""
    return _run_tool("firmrec", run_dir, config_path)


def run_klee(run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Registry entry: ``tools.external.klee`` (owned by student G)."""
    return _run_tool("klee", run_dir, config_path)


def run_bond(run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Registry entry: ``tools.external.bond`` (owned by student H)."""
    return _run_tool("bond", run_dir, config_path)


__all__ = [
    "EXTERNAL_TOOLS",
    "_load_global_external",
    "_tool_cfg",
    "_resolve_rootfs",
    "_build_analyzer",
    "_run_tool",
    "_run_context",
    "_resolve_external_config",
    "run_satc",
    "run_firmrec",
    "run_klee",
    "run_bond",
]
