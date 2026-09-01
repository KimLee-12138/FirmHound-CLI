"""Unit tests for the ExternalAnalyzer base contract.

Covers the two hard guarantees from E-SaTC.md F4:
  * ``execute()`` must catch any exception from probe/prepare/run/parse and return
    ``status="failed"`` instead of propagating (so a broken tool never aborts the
    pipeline).
  * ``normalize()`` must drop schema-invalid findings and count them.
"""

from __future__ import annotations

from pathlib import Path

from tools.external.base import (
    AnalysisContext,
    AnalyzerResult,
    ExternalAnalyzer,
    ProbeResult,
    RunOutcome,
)


class _BoomAtPrepare(ExternalAnalyzer):
    name = "boom_prepare"

    def probe(self) -> ProbeResult:
        return ProbeResult(available=True)

    def prepare(self, ctx: AnalysisContext) -> Path:
        raise RuntimeError("prepare exploded")

    def run(self, ctx: AnalysisContext) -> RunOutcome:
        raise AssertionError("should not reach run")

    def parse(self, ctx: AnalysisContext, outcome: RunOutcome):
        raise AssertionError("should not reach parse")


class _BoomAtParse(ExternalAnalyzer):
    name = "boom_parse"

    def probe(self) -> ProbeResult:
        return ProbeResult(available=True)

    def prepare(self, ctx: AnalysisContext) -> Path:
        return Path("/tmp")

    def run(self, ctx: AnalysisContext) -> RunOutcome:
        return RunOutcome(status="ok")

    def parse(self, ctx: AnalysisContext, outcome: RunOutcome):
        raise ValueError("parse exploded")


def _ctx() -> AnalysisContext:
    return AnalysisContext(run_id="ut", rootfs_dir=Path("/tmp/rootfs"), workdir=Path("/tmp/work"))


def test_execute_catches_prepare_exception():
    res = _BoomAtPrepare().execute(_ctx())
    assert isinstance(res, AnalyzerResult)
    assert res.status == "failed"
    assert "prepare exploded" in res.limitation


def test_execute_catches_parse_exception():
    res = _BoomAtParse().execute(_ctx())
    assert res.status == "failed"
    assert "parse exploded" in res.limitation


def test_execute_skips_when_probe_unavailable():
    class _Unavailable(ExternalAnalyzer):
        name = "unavail"

        def probe(self) -> ProbeResult:
            return ProbeResult(available=False, missing=["image:x"])

        def prepare(self, ctx):
            raise AssertionError("prepare should not run")

        def run(self, ctx):
            raise AssertionError("run should not run")

        def parse(self, ctx, outcome):
            raise AssertionError("parse should not run")

    res = _Unavailable().execute(_ctx())
    assert res.status == "skipped"
    assert res.probe is not None and res.probe.available is False


def test_normalize_drops_invalid_findings_and_counts():
    class _Holder(ExternalAnalyzer):
        name = "holder"

        def probe(self):
            return ProbeResult(available=True)

        def prepare(self, ctx):
            return Path("/tmp")

        def run(self, ctx):
            return RunOutcome(status="ok")

        def parse(self, ctx, outcome):
            # One valid, one missing required fields.
            return [
                {
                    "finding_id": "ok-1",
                    "tool": "satc",
                    "binary_id": "bin/httpd",
                    "vuln_class": "command_injection",
                    "source": {"type": "unknown", "name": ""},
                    "sink": {"function": "system", "addr": "0x10"},
                    "confidence": 0.5,
                    "status": "ok",
                    "run_id": "ut",
                },
                {"binary_id": "bin/x"},  # missing most required fields
            ]

    res = _Holder().execute(_ctx())
    assert res.status == "ok"
    assert len(res.findings) == 1
    assert res.dropped == 1
