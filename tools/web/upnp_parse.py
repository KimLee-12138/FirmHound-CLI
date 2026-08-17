"""Parse UPnP service description XML files.

Extracts actions, direction=in arguments, and flags high-impact operations.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


HIGH_IMPACT_ACTIONS = {
    "upgrade",
    "update",
    "reboot",
    "factoryreset",
    "restore",
    "setpersistent",
    "configure",
}


def parse_upnp_xml(xml_path: str | Path) -> dict[str, Any]:
    """Parse a UPnP SCPD XML file and extract actions with input args."""
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"UPnP XML not found: {path}")

    text = path.read_text(encoding="utf-8", errors="ignore")
    # Strip namespaces for simpler ElementTree traversal.
    text = re.sub(r'xmlns="[^"]+"', "", text)

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return {
            "file": str(path.resolve()),
            "actions": [],
            "error": str(exc),
        }

    actions: list[dict[str, Any]] = []
    for action_elem in root.findall(".//action"):
        name_elem = action_elem.find("name")
        if name_elem is None or name_elem.text is None:
            continue
        action_name = name_elem.text

        inputs: list[dict[str, str]] = []
        for arg in action_elem.findall("argumentList/argument"):
            direction_elem = arg.find("direction")
            name_arg = arg.find("name")
            related = arg.find("relatedStateVariable")
            if (
                direction_elem is not None
                and direction_elem.text == "in"
                and name_arg is not None
                and name_arg.text
            ):
                inputs.append({
                    "name": name_arg.text,
                    "related_state_variable": related.text if related is not None else None,
                })

        is_high_impact = any(hia in action_name.lower() for hia in HIGH_IMPACT_ACTIONS)
        actions.append({
            "name": action_name,
            "inputs": inputs,
            "high_impact": is_high_impact,
            "input_count": len(inputs),
        })

    return {
        "file": str(path.resolve()),
        "actions": actions,
        "action_count": len(actions),
    }


def find_upnp_xmls(rootfs_dir: str | Path) -> list[Path]:
    """Find likely UPnP service XML files in a rootfs."""
    root = Path(rootfs_dir)
    candidates: list[Path] = []
    for path in root.rglob("*.xml"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "<actionList>" in text:
            candidates.append(path)
    return candidates


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.web.upnp_parse <upnp_xml>")
        raise SystemExit(1)
    print(json.dumps(parse_upnp_xml(sys.argv[1]), indent=2))
