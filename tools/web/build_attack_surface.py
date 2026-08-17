"""Build attack_surface.json by combining M3 enumeration tools."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fsa.reporting.store_base import RunLayout
from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from tools.filesystem.inventory import inventory_rootfs
from tools.filesystem.startup_parse import parse_all_startup
from tools.web.auth_matrix import classify_auth
from tools.web.handler_extract import extract_handlers
from tools.web.upnp_parse import find_upnp_xmls, parse_upnp_xml
from tools.web.webroot_enum import enumerate_webroot, find_webroots


def _surface_id() -> str:
    return f"surf-{uuid.uuid4().hex[:8]}"


def _evidence_id() -> str:
    return f"ev-{uuid.uuid4().hex[:8]}"


def build_attack_surface(
    rootfs_dir: str | Path,
    run_id: str,
    run_root: str | Path,
) -> dict[str, Any]:
    """Enumerate attack surfaces from a rootfs and write attack_surface.json.

    Args:
        rootfs_dir: Extracted rootfs directory.
        run_id: Run identifier.
        run_root: Parent directory for run artifacts.

    Returns:
        Dict matching ``attack_surface.schema.json``.
    """
    root = Path(rootfs_dir)
    if not root.exists():
        raise FileNotFoundError(f"Rootfs not found: {root}")

    layout = RunLayout(run_id, run_root)
    surfaces: list[dict[str, Any]] = []

    # Webroot enumeration.
    for webroot in find_webroots(root):
        enum = enumerate_webroot(webroot)
        for ep in enum["endpoints"]:
            surface_id = _surface_id()
            auth = classify_auth(ep["route"], None, None, None)
            surfaces.append(
                {
                    "surface_id": surface_id,
                    "category": "web" if ep["suffix"] in {".html", ".htm"} else "cgi",
                    "protocol": "http",
                    "binary": None,
                    "route": ep["route"],
                    "handler": ep["file"],
                    "input_sources": ["http_param"],
                    "auth_hint": auth.hint,
                    "startup_evidence": [],
                    "reachability_hint": "LAN web admin",
                    "confidence": auth.confidence,
                    "evidence_ids": [_evidence_id()],
                }
            )

    # Binary handler extraction for all ELF binaries.
    inv = inventory_rootfs(root)
    for elf_rel in inv["elf_paths"]:
        elf_path = root / elf_rel
        extracted = extract_handlers(elf_path)
        for form in extracted["goahead_forms"]:
            surface_id = _surface_id()
            auth = classify_auth(form["route"], elf_path, form["handler"], None)
            surfaces.append(
                {
                    "surface_id": surface_id,
                    "category": "cgi",
                    "protocol": "http",
                    "binary": str(elf_path.relative_to(root).as_posix()),
                    "route": form["route"],
                    "handler": form["handler"],
                    "input_sources": ["http_param"],
                    "auth_hint": auth.hint,
                    "startup_evidence": [],
                    "reachability_hint": "LAN web admin (handler in binary)",
                    "confidence": 0.85 if extracted["goahead_registered"] else 0.6,
                    "evidence_ids": [_evidence_id()],
                }
            )

    # UPnP surfaces.
    for xml_path in find_upnp_xmls(root):
        parsed = parse_upnp_xml(xml_path)
        for action in parsed["actions"]:
            if not action["inputs"]:
                continue
            surface_id = _surface_id()
            surfaces.append(
                {
                    "surface_id": surface_id,
                    "category": "upnp",
                    "protocol": "soap",
                    "binary": None,
                    "route": f"/upnp/{Path(xml_path).name}",
                    "handler": action["name"],
                    "input_sources": ["soap_arg"],
                    "auth_hint": "preauth",
                    "startup_evidence": [],
                    "reachability_hint": "LAN UPnP",
                    "confidence": 0.9 if action["high_impact"] else 0.7,
                    "evidence_ids": [_evidence_id()],
                }
            )

    # Startup-driven daemon surfaces.
    startup = parse_all_startup(root)
    for name, services in startup["grouped"].items():
        if name in {"httpd", "goahead"}:
            continue
        if len(services) == 0:
            continue
        surface_id = _surface_id()
        evidence = [f"{s['source_file']}:{s['line']}" for s in services[:3]]
        surfaces.append(
            {
                "surface_id": surface_id,
                "category": "daemon",
                "protocol": "unknown",
                "binary": services[0]["binary"],
                "route": None,
                "handler": name,
                "input_sources": ["socket_buf"],
                "auth_hint": "unknown",
                "startup_evidence": evidence,
                "reachability_hint": "started at boot",
                "confidence": 0.6,
                "evidence_ids": [_evidence_id()],
            }
        )

    attack_surface = {
        "run_id": run_id,
        "firmware_path": str(root.resolve()),
        "surfaces": surfaces,
    }
    validate(attack_surface, schema_name="attack_surface")
    save_json(layout.attack_surface, attack_surface)
    return attack_surface


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 4:
        print("Usage: python -m tools.web.build_attack_surface <rootfs> <run_id> <run_root>")
        raise SystemExit(1)
    result = build_attack_surface(sys.argv[1], sys.argv[2], sys.argv[3])
    print(json.dumps(result, indent=2))
