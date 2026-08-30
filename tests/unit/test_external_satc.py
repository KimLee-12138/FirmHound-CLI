"""Unit tests for the SaTC parser across its six required branches.

These tests NEVER invoke the real SaTC binary or Docker. They only parse the
committed fixtures under ``tools/external/satc/fixtures/`` (see E-SaTC.md F4).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fsa.schemas.loader import validate
from tools.external.base import normalize_addr
from tools.external.satc.parser import (
    PARSER_VERSION,
    compute_confidence,
    parse_satc_output,
)

FIXTURES = Path(__file__).resolve().parents[2] / "tools" / "external" / "satc" / "fixtures"


def _parse(name: str, **kw):
    return parse_satc_output(FIXTURES / name, rootfs=FIXTURES / name, run_id="ut", **kw)


def _assert_valid(findings):
    for f in findings:
        validate(f, schema_name="external_finding")


# --- Branch 1: normal ----------------------------------------------------- #
def test_normal_parses_cmdi_and_bof_with_alert():
    findings, stats = _parse("normal", taint_check=True)
    assert findings, "normal fixture should yield findings"
    vuln_classes = {f["vuln_class"] for f in findings}
    assert "command_injection" in vuln_classes
    assert "overflow" in vuln_classes
    # At least one finding carries a real alert address.
    assert any(f["sink"].get("addr") for f in findings)
    # Findings must be schema-valid external_findings.
    _assert_valid(findings)
    # Parser version is stamped.
    assert all(PARSER_VERSION in f.get("notes", "") for f in findings)


# --- Branch 2: empty file -------------------------------------------------- #
def test_empty_file_yields_no_findings_no_raise():
    findings, stats = _parse("empty")
    assert findings == []
    # No exception == pass.


# --- Branch 3: malformed lines -------------------------------------------- #
def test_malformed_lines_are_skipped_not_crashing():
    findings, stats = _parse("malformed")
    # The line with an address still parses; the noise/garbage lines are skipped.
    assert stats.unparsed_lines >= 1
    _assert_valid(findings)  # whatever parsed must still be valid


# --- Branch 4: no alert --------------------------------------------------- #
def test_no_alert_yields_empty_ok():
    findings, stats = _parse("no_alert")
    assert findings == []
    # status semantics live in the runner; the parser itself just returns [].


# --- Branch 5: timeout-truncated ------------------------------------------ #
def test_truncated_result_parses_available_partial():
    findings, stats = _parse("truncated")
    assert len(findings) >= 1
    _assert_valid(findings)


# --- Branch 6: version diff (alternate grammar) --------------------------- #
def test_version_diff_alternate_grammar_parses():
    findings, stats = _parse("v2", taint_check=False)
    assert findings, "v2 (self-built image grammar) should still parse"
    assert any(f["vuln_class"] == "command_injection" for f in findings)
    _assert_valid(findings)


# --- Confidence formula sanity -------------------------------------------- #
def test_compute_confidence_bounds_and_formula():
    # No alert -> capped at 0.6.
    no_alert = compute_confidence(
        has_alert_addr=False, taint_check=True, trace_len=3, clustered=True
    )
    assert no_alert <= 0.6
    # With alert: full formula sums to 1.0 and is capped at 1.0.
    with_alert = compute_confidence(
        has_alert_addr=True, taint_check=True, trace_len=2, clustered=True
    )
    assert with_alert == 1.0
    assert with_alert <= 1.0


def test_normalize_addr_is_stable():
    assert normalize_addr("0x0040A1B0") == "0x40a1b0"
    assert normalize_addr("0x40a1b0") == "0x40a1b0"
    assert normalize_addr(None) == ""
