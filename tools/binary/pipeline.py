"""Executable ELF triage and honest decompilation-fallback stages."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fsa.schemas.loader import validate
from fsa.utils.hashing import sha256_file
from fsa.utils.jsonio import save_json
from tools.analysis.source_sink_rules import match_binary
from tools.binary.elf_read import iter_imports, iter_strings, load_elf
from tools.binary.elf_triage import triage_elf
from tools.binary.secfeatures import security_features
from tools.filesystem.inventory import inventory_rootfs
from tools.filesystem.startup_parse import parse_all_startup
from tools.pipeline_context import load_artifact, resolve_rootfs, run_path, save_artifact


def _binary_id(relative_path: str) -> str:
    return f"bin-{hashlib.sha256(relative_path.encode()).hexdigest()[:12]}"


def execute_triage(
    run_dir: str,
    max_binaries: int = 500,
    max_strings_per_binary: int = 200,
) -> dict[str, Any]:
    """Inventory and statically summarize real ELF files from the selected rootfs."""
    rootfs = resolve_rootfs(run_dir)
    inventory = inventory_rootfs(rootfs)
    startup = parse_all_startup(rootfs)
    surfaces = load_artifact(run_dir, "attack_surface.json", {"surfaces": []})
    surface_rows = surfaces.get("surfaces", []) if isinstance(surfaces, dict) else []
    summaries: list[dict[str, Any]] = []

    for relative in inventory["elf_paths"][:max_binaries]:
        path = rootfs / relative
        basename = path.name
        startup_refs = len(startup.get("grouped", {}).get(basename, []))
        surface_refs = sum(
            1 for surface in surface_rows if Path(str(surface.get("binary") or "")).name == basename
        )
        elf = load_elf(path)
        if elf is None:
            continue
        imports = sorted(iter_imports(elf))
        strings = list(iter_strings(elf))[:max_strings_per_binary]
        triage = triage_elf(
            path,
            startup_refs=startup_refs,
            attack_surface_refs=surface_refs,
        )
        summary: dict[str, Any] = {
            "binary_id": _binary_id(relative),
            "path": relative,
            "sha256": sha256_file(path),
            "architecture": triage["architecture"],
            "security_features": security_features(path),
            "imports": imports,
            "strings_summary": {
                "sample": strings,
                "sample_count": len(strings),
                "truncated": len(strings) >= max_strings_per_binary,
            },
            "functions": [],
            "network_functions": triage["network_imports"],
            "sources": [],
            "sinks": [],
            "auth_functions": [],
            "validation_functions": [],
            "triage_score": triage["triage_score"],
            "decompile_status": "fallback",
            "triage_reasons": triage["reasons"],
            "danger": triage["danger"],
            "startup_refs": startup_refs,
            "attack_surface_refs": surface_refs,
        }
        matches = match_binary(summary)
        summary["sources"] = sorted({item["type"] for item in matches["sources"]})
        summary["sinks"] = sorted({item["function"] for item in matches["sinks"]})
        summary["validation_functions"] = sorted({item["api"] for item in matches["validations"]})
        validate(summary, schema_name="binary_summary")
        summaries.append(summary)
        save_json(
            run_path(run_dir) / "binaries" / summary["binary_id"] / "binary_summary.json",
            summary,
        )

    payload = {
        "rootfs": str(rootfs),
        "inventory": inventory,
        "startup": startup,
        "summaries": summaries,
        "truncated": len(inventory["elf_paths"]) > max_binaries,
    }
    artifact = save_artifact(run_dir, "binary_summaries.json", payload)
    status = "degraded" if payload["truncated"] else "ok"
    return {
        "status": status,
        "binary_count": len(summaries),
        "inventory_elf_count": inventory["elf_count"],
        "binary_summaries": str(artifact),
    }


def execute_decompile(run_dir: str) -> dict[str, Any]:
    """Record the pyelftools fallback when no configured decompiler is present."""
    payload = load_artifact(run_dir, "binary_summaries.json")
    if not isinstance(payload, dict):
        return {"status": "failed", "reason": "binary triage artifact is missing"}
    return {
        "status": "degraded",
        "reason": "no decompiler backend configured; symbol/string fallback retained",
        "fallback": "pyelftools",
        "binary_count": len(payload.get("summaries", [])),
    }
