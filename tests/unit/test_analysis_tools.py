"""Unit tests for the M5 analysis tools (source_sink_rules / dataflow / fp_filter)."""

from __future__ import annotations

from tools.analysis.dataflow import assemble_chain, verify_variable_usage
from tools.analysis.fp_filter import apply_fp_filters
from tools.analysis.source_sink_rules import (
    classify_sink,
    classify_source,
    classify_validation,
    match_binary,
)

# ---------------------------------------------------------------------------
# source_sink_rules
# ---------------------------------------------------------------------------


def test_classify_source_http_param() -> None:
    result = classify_source("websGetVar")
    assert result is not None
    assert result["type"] == "http_param"


def test_classify_source_soap() -> None:
    result = classify_source("NewDownloadURL")
    assert result is not None
    assert result["type"] == "soap_param"


def test_classify_source_unknown() -> None:
    assert classify_source("definitely_not_a_source") is None


def test_classify_sink_command_execution() -> None:
    result = classify_sink("doSystemCmd")
    assert result is not None
    assert result["type"] == "command_execution"


def test_classify_sink_memory_safety() -> None:
    result = classify_sink("strcpy")
    assert result is not None
    assert result["type"] == "memory_safety"


def test_classify_validation_whitelist() -> None:
    assert classify_validation("strcmp") == "whitelist"


def test_match_binary_extracts_sources_and_sinks() -> None:
    summary = {
        "imports": ["system", "sprintf", "websGetVar", "strcpy"],
        "strings_summary": {"command_templates": ["%s; %s"], "dangerous_api": ["system"]},
        "functions": [{"name": "check_auth", "is_auth": True}],
        "auth_functions": [],
        "validation_functions": [],
    }
    result = match_binary(summary)
    assert any(s["type"] == "command_execution" for s in result["sinks"])
    assert any(s["type"] == "http_param" for s in result["sources"])
    assert result["auth_markers"] == ["check_auth"]


# ---------------------------------------------------------------------------
# dataflow
# ---------------------------------------------------------------------------


def test_assemble_chain_http_template() -> None:
    chain = assemble_chain(
        {"function": "formexeCommand"},
        {"type": "http_param", "name": "cmd"},
        {"function": "system", "type": "command_execution"},
    )
    assert chain["protocol"] == "http"
    assert chain["call_chain"][0] == "request"
    assert chain["call_chain"][-1] == "shell_execute"
    assert chain["has_filter"] is False


def test_assemble_chain_with_validations_marks_filter() -> None:
    chain = assemble_chain(
        {"function": "formexeCommand"},
        {"type": "http_param", "name": "cmd"},
        {"function": "system", "type": "command_execution"},
        validations=[{"api": "strcmp", "kind": "whitelist"}],
    )
    assert chain["has_filter"] is True
    assert all(layer["filter"] for layer in chain["layers"] if layer["role"] == "transform")


def test_assemble_chain_socket_variant() -> None:
    chain = assemble_chain(
        None,
        {"type": "socket_buffer", "name": "recvfrom"},
        {"function": "strcpy", "type": "memory_safety"},
        protocol="socket",
    )
    assert chain["protocol"] == "socket"
    assert chain["call_chain"][-1] == "sink"


def test_verify_variable_usage_ok() -> None:
    functions = [
        {"name": "formexeCommand", "strings": ["cmd = websGetVar"], "is_source": True},
        {"name": "do_system", "strings": ["system(cmd)"], "is_source": False},
    ]
    result = verify_variable_usage(functions, "cmd")
    assert result["ok"] is True
    assert result["defined"] is True
    assert result["used"] is True


def test_verify_variable_usage_missing_use() -> None:
    functions = [
        {"name": "formexeCommand", "strings": ["cmd = websGetVar"], "is_source": True},
    ]
    result = verify_variable_usage(functions, "cmd")
    assert result["defined"] is True
    assert result["used"] is False
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# fp_filter
# ---------------------------------------------------------------------------


def _candidate(**overrides: object) -> dict:
    base = {
        "candidate_id": "cand-1",
        "binary_id": "httpd",
        "entry": {"function": "formexeCommand"},
        "source": {"type": "http_param", "name": "cmd"},
        "transform": [{"type": "concat", "detail": "%s; %s"}],
        "sink": {"function": "system", "type": "command_execution"},
        "user_control": "full",
        "conclusion_category": "high-confidence-candidate",
    }
    base.update(overrides)
    return base


def test_fp_filter_cli_tool_excluded() -> None:
    result = apply_fp_filters(_candidate(binary_id="busybox"), binary_path="/bin/busybox")
    assert result["excluded"] is True
    assert "cli_tool" in result["rules"]
    assert result["suggested_category"] == "false-positive"


def test_fp_filter_command_template_without_input() -> None:
    candidate = _candidate(transform=[{"type": "concat", "detail": "static only"}])
    result = apply_fp_filters(candidate)
    assert result["excluded"] is True
    assert "command_template_without_input" in result["rules"]


def test_fp_filter_internal_ipc_downgrade() -> None:
    candidate = _candidate(
        source={"type": "config_import", "name": "nvram_get"},
        user_control="none",
    )
    result = apply_fp_filters(candidate)
    assert "internal_ipc_only" in result["rules"]


def test_fp_filter_no_external_entry() -> None:
    candidate = _candidate(entry={"function": "orphan_handler"})
    surface = {"endpoints": [{"handler": "formexeCommand"}]}
    result = apply_fp_filters(candidate, attack_surface=surface)
    assert "no_reachable_external_entry" in result["rules"]


def test_fp_filter_no_rules_for_clean_candidate() -> None:
    candidate = _candidate(binary_id="httpd", entry={"function": "formexeCommand"})
    surface = {"endpoints": [{"handler": "formexeCommand"}]}
    result = apply_fp_filters(candidate, attack_surface=surface)
    assert result["excluded"] is False
    assert result["rules"] == []
