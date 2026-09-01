"""EXTERNAL_ANALYSIS stage scheduler: run every enabled external analyzer.

This is the single entry point for the ``EXTERNAL_ANALYSIS`` orchestrator stage.
It fans out to each enabled analyzer (SaTC / FirmRec / KLEE / BOND) -- each runs
independently and degrades to ``skipped`` on its own -- then merges their
persisted findings into one combined document.

The function never raises; a run where every tool is disabled still returns a
benign ``skipped`` summary so the pipeline proceeds to the fusion stage.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fsa.utils.jsonio import save_json
from tools.external.adapter import EXTERNAL_TOOLS, _load_global_external, _run_tool

UPSTREAM_TOOLS = ("satc", "firmrec")


def run_tool(tool: str, run_dir: str | Path, config_path: str | None = None) -> dict[str, Any]:
    """Run a single external analyzer (re-export of the adapter core runner)."""
    return _run_tool(tool, run_dir, config_path)


def run_all(
    run_dir: str | Path,
    config_path: str | None = None,
    phase: str = "all",
) -> dict[str, Any]:
    """Run all *enabled* external analyzers and merge their outputs.

    Returns a dict with ``status`` (ok | skipped), ``per_tool`` results, and the
    combined finding count. Persists:
      * ``<run_dir>/artifacts/external_findings/<tool>.json`` (per tool, done by adapter)
      * ``<run_dir>/artifacts/external_findings/all.json`` (combined)
    """
    run_dir = Path(run_dir)
    global_ext = _load_global_external(config_path)
    selected = UPSTREAM_TOOLS if phase == "upstream" else EXTERNAL_TOOLS
    if phase not in {"all", "upstream"}:
        return {
            "status": "failed",
            "tools": [],
            "findings": 0,
            "per_tool": {},
            "limitation": f"unsupported external analyzer phase: {phase}",
        }
    enabled = [
        t
        for t in selected
        if global_ext.get("enabled", False) and (global_ext.get(t, {}) or {}).get("enabled", False)
    ]

    if not enabled:
        return {
            "status": "skipped",
            "tools": [],
            "findings": 0,
            "per_tool": {},
            "phase": phase,
            "limitation": "all selected external analyzers disabled in config",
        }

    per_tool: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=min(len(enabled), 4)) as pool:
        futures = {pool.submit(_run_tool, tool, run_dir, config_path): tool for tool in enabled}
        for future in futures:
            tool = futures[future]
            try:
                per_tool[tool] = future.result()
            except Exception as exc:  # noqa: BLE001 - one tool must not poison the batch
                per_tool[tool] = {
                    "status": "failed",
                    "tool": tool,
                    "findings": [],
                    "limitation": f"run_all caught: {type(exc).__name__}: {exc}",
                }

    total_findings = sum(len(r.get("findings", [])) for r in per_tool.values())
    combined = {
        "status": "ok",
        "tools": enabled,
        "findings": total_findings,
        "per_tool": per_tool,
        "phase": phase,
    }

    out_dir = run_dir / "artifacts" / "external_findings"
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / "all.json", combined)

    return combined


__all__ = ["UPSTREAM_TOOLS", "run_tool", "run_all"]
