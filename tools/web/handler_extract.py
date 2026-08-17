"""Extract embedded endpoints from ELF binaries.

Covers GoAhead formXxx/fromXxx handlers, generic .cgi strings, URL route
strings, and HTTP_ environment variable references.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from fsa.utils.proc import run_command


def _extract_strings_python(path: Path, min_len: int = 5) -> list[str]:
    """Extract printable ASCII strings from a file without external tools."""
    try:
        data = path.read_bytes()
    except OSError:
        return []
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    return [m.decode("ascii", errors="ignore") for m in re.findall(pattern, data)]


def _extract_strings(path: Path, min_len: int = 5) -> list[str]:
    """Extract strings, preferring the external ``strings`` tool if available."""
    if shutil.which("strings") is not None:
        result = run_command(["strings", f"-n{min_len}", str(path)])
        if result.status == "success":
            return result.stdout.splitlines()
    return _extract_strings_python(path, min_len)


# GoAhead form handlers: formXxx / fromXxx naming convention (case-insensitive head).
GOAHEAD_RE = re.compile(r"\b(form|from)([A-Za-z0-9_]{2,})\b")
# Generic CGI references.
CGI_RE = re.compile(r"([A-Za-z0-9_/-]+\.cgi)")
# URL route strings starting with / and looking like paths.
ROUTE_RE = re.compile(r"(/[A-Za-z0-9_/-]{2,40})")
# HTTP_ environment variable strings.
HTTP_ENV_RE = re.compile(r"\b(HTTP_[A-Z_]+)\b")
# Registration function presence indicates GoAhead usage.
GOAHEAD_REGISTER = re.compile(r"\b(websFormDefine|websAspDefine)\b")


def extract_handlers(binary_path: str | Path) -> dict[str, Any]:
    """Extract endpoint evidence from a single binary.

    Returns a dict with detected handler lists and metadata.
    """
    path = Path(binary_path)
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    strings = _extract_strings(path)
    text = "\n".join(strings)

    goahead_forms: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in GOAHEAD_RE.finditer(text):
        full = match.group(0)
        if full in seen:
            continue
        seen.add(full)
        route = f"/goform/{full}"
        goahead_forms.append(
            {
                "handler": full,
                "route": route,
                "category": "goahead_form",
                "evidence": full,
            }
        )

    cgi_hits: list[dict[str, Any]] = []
    seen_cgi: set[str] = set()
    for match in CGI_RE.finditer(text):
        route = match.group(1)
        if route in seen_cgi:
            continue
        seen_cgi.add(route)
        cgi_hits.append(
            {
                "handler": path.name,
                "route": route,
                "category": "cgi_string",
                "evidence": route,
            }
        )

    routes: list[dict[str, Any]] = []
    seen_routes: set[str] = set()
    for match in ROUTE_RE.finditer(text):
        route = match.group(1)
        if route in seen_routes or route.count("/") < 2:
            continue
        seen_routes.add(route)
        routes.append(
            {
                "handler": path.name,
                "route": route,
                "category": "url_route_string",
                "evidence": route,
            }
        )

    http_env = sorted(set(HTTP_ENV_RE.findall(text)))
    goahead_registered = bool(GOAHEAD_REGISTER.search(text))

    return {
        "binary": str(path.resolve()),
        "goahead_registered": goahead_registered,
        "goahead_forms": goahead_forms,
        "cgi_strings": cgi_hits,
        "url_routes": routes,
        "http_env_vars": http_env,
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.web.handler_extract <binary>")
        raise SystemExit(1)
    print(json.dumps(extract_handlers(sys.argv[1]), indent=2))
