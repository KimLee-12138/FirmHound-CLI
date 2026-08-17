"""Source / Sink / Validation / Authorization rule library (M5).

Solidifies the legacy command-injection five-step method and the protocol
parsing six-step method into a machine-usable rule table. Vendor-specific
wrappers (D-Link ``doSystemCmd``/``lxmldbc_system``, Tenda ``alpha_system2``,
``websGetVar``, ``getenv("QUERY_STRING")``) are encoded as dictionaries so they
are matched without hardcoding in the dataflow layer.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Sources: external input channels an attacker can influence.
# ---------------------------------------------------------------------------
SOURCE_RULES: list[dict[str, Any]] = [
    {
        "name": "http_param",
        "kind": "http_param",
        "patterns": ["websGetVar", "$_GET", "$_POST", "arg[", "ngx.var", "request.get"],
    },
    {
        "name": "http_header",
        "kind": "http_header",
        "patterns": [
            "HTTP_COOKIE",
            "HTTP_USER_AGENT",
            "SOAPAction",
            "Content-Length",
            "Authorization",
        ],
    },
    {
        "name": "http_query",
        "kind": "http_query",
        "patterns": ['getenv("QUERY_STRING")', "QUERY_STRING", "query_string"],
    },
    {
        "name": "http_cookie",
        "kind": "http_cookie",
        "patterns": ["COOKIE", "get_cookie", "cookie"],
    },
    {
        "name": "soap_param",
        "kind": "soap_param",
        "patterns": ["NewDownloadURL", "NewStatusURL", "direction=in", "soap", "SOAPAction"],
    },
    {
        "name": "socket_buffer",
        "kind": "socket_buffer",
        "patterns": ["recv", "recvfrom", "recvmsg", "read(", "fgets", "readline"],
    },
    {
        "name": "file_upload",
        "kind": "file_upload",
        "patterns": ["multipart/form-data", "upload", "write_file"],
    },
    {
        "name": "config_import",
        "kind": "config_import",
        "patterns": ["config_get", "nvram_get", "flash_get", "uci_get"],
    },
    {
        "name": "environment",
        "kind": "environment",
        "patterns": ["getenv", "environ"],
    },
]

# ---------------------------------------------------------------------------
# Sinks: four categories, each with a list of API names to match.
# ---------------------------------------------------------------------------
SINK_RULES: dict[str, dict[str, Any]] = {
    "command_execution": {
        "patterns": [
            "system", "__system", "popen", "execl", "execlp", "execle", "execv",
            "execvp", "execve", "doSystemCmd", "lxmldbc_system", "alpha_system2",
            "unlink", "sprintf_system",
        ],
    },
    "memory_safety": {
        "patterns": [
            "strcpy",
            "strcat",
            "sprintf",
            "vsprintf",
            "gets",
            "memcpy",
            "strncpy",
            "strncat",
            "sscanf",
        ],
    },
    "filesystem": {
        "patterns": ["fwrite", "write", "open", "fopen", "chmod", "chown", "rename", "symlink"],
    },
    "format_string": {
        "patterns": ["printf", "fprintf", "snprintf", "vsnprintf", "syslog"],
    },
}

# ---------------------------------------------------------------------------
# Validation: filters applied between source and sink.
# ---------------------------------------------------------------------------
VALIDATION_RULES: dict[str, list[str]] = {
    "length_check": ["strlen", "sizeof", "strnlen", "check_len"],
    "whitelist": ["strcmp", "strncmp", "in_array", "is_valid", "allowed"],
    "blacklist": ["strstr", "strchr", "strtok", "str_replace", "preg_replace", "filter"],
    "escape": ["escapeshellarg", "escapeshellcmd", "addslashes", "htmlspecialchars", "quote"],
    "path_normalize": ["realpath", "dirname", "basename", "canonicalize"],
    "type_limit": ["atoi", "strtol", "is_numeric", "isdigit"],
}


def _match(name: str, patterns: list[str]) -> bool:
    lowered = name.lower()
    return any(p.lower() in lowered for p in patterns)


def classify_source(name: str) -> dict[str, Any] | None:
    """Classify a function/string name as an input source, or ``None``."""
    for rule in SOURCE_RULES:
        if _match(name, rule["patterns"]):
            return {"type": rule["kind"], "name": rule["name"]}
    return None


def classify_sink(name: str) -> dict[str, Any] | None:
    """Classify a function name as a sink, or ``None``."""
    for category, rule in SINK_RULES.items():
        if _match(name, rule["patterns"]):
            return {"function": name, "type": category}
    return None


def classify_validation(name: str) -> str | None:
    """Classify a function name as a validation kind, or ``None``."""
    for kind, patterns in VALIDATION_RULES.items():
        if _match(name, patterns):
            return kind
    return None


def match_binary(binary_summary: dict[str, Any]) -> dict[str, Any]:
    """Extract sources / sinks / validations / auth markers from a binary summary.

    Operates on the ``binary_summary.schema.json`` shape produced by M4, using
    its ``imports``, ``strings_summary``, ``functions`` and ``auth_functions``
    fields. No ELF file access required, so it is trivially unit-testable.
    """
    imports = binary_summary.get("imports", [])
    strings = _flatten_strings(binary_summary)
    functions = binary_summary.get("functions", [])
    auth_functions = set(binary_summary.get("auth_functions", []))
    validation_functions = set(binary_summary.get("validation_functions", []))

    sources: list[dict[str, Any]] = []
    for name in imports:
        classified = classify_source(name)
        if classified:
            sources.append({"api": name, **classified})
    for text in strings:
        classified = classify_source(text)
        if classified:
            sources.append({"string": text, **classified})

    sinks: list[dict[str, Any]] = []
    for name in imports:
        classified = classify_sink(name)
        if classified:
            sinks.append(classified)

    validations: list[dict[str, Any]] = []
    for name in imports:
        kind = classify_validation(name)
        if kind:
            validations.append({"api": name, "kind": kind})

    auth_markers: list[str] = []
    for func in functions:
        if func.get("is_auth") or func.get("name") in auth_functions:
            auth_markers.append(func.get("name", ""))

    return {
        "sources": sources,
        "sinks": sinks,
        "validations": validations,
        "auth_markers": sorted(set(auth_markers)),
        "validation_functions": sorted(validation_functions),
    }


def _flatten_strings(binary_summary: dict[str, Any]) -> list[str]:
    """Collect strings from a binary summary's ``strings_summary``."""
    summary = binary_summary.get("strings_summary", {})
    out: list[str] = []
    for value in summary.values():
        if isinstance(value, list):
            out.extend(str(v) for v in value)
        elif isinstance(value, str):
            out.append(value)
    return out
