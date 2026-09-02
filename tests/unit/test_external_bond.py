"""BOND integration tests (H-BOND.md §8.3 / §8.4): parser branches + safety gate + mini.

The transport test touches loopback only. Safety-gate tests assert that a non-private
target yields ``status="unsafe"`` with ZERO outbound artifacts.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fsa.utils.proc import RunResult
from tools.external.base import AnalysisContext
from tools.external.bond.mini import ghidra_export
from tools.external.bond.mini.ghidra_export import export_cfg_cg, identify_entry_points
from tools.external.bond.mini.scheduler import generate_seeds
from tools.external.bond.mini.template import generate_template
from tools.external.bond.parser import parse_bond_output
from tools.external.bond.runner import BondAnalyzer

FIX = Path(__file__).resolve().parents[2] / "tools" / "external" / "bond" / "fixtures" / "raw"


def _candidate_map() -> dict[str, dict]:
    sink = {"function": "system", "addr": "0x40c318", "type": "command_execution"}
    base = {
        "binary_id": "sbin/httpd",
        "vuln_class": "command_injection",
        "sink": sink,
        "source": {"type": "taint"},
        "entry_point": {"keyword": "SetWan", "func": "0x40a1b0", "type": "websFormDefine"},
        "call_trace": [],
        "constraints": [
            {"param": "Save", "semantic": "string_eq", "expr": "=='1'", "klass": "mandatory"},
            {"param": "Mode", "semantic": "string_eq", "expr": "=='General'", "klass": "mandatory"},
        ],
    }
    return {f"cand-{i}": dict(base) for i in range(6)}


# --------------------------------------------------------------------------- #
# parser: six artifact classes (F3)
# --------------------------------------------------------------------------- #


def test_parse_all_six_branches() -> None:
    findings, stats = parse_bond_output(
        FIX,
        candidate_map=_candidate_map(),
        run_id="r1",
        tool_version="mini-0.1",
    )
    assert len(findings) == 6, stats.limitations

    # cand-0: marker triggered
    markers = [f for f in findings if f["validation"]["probe"] == "marker"]
    assert len(markers) == 1
    assert markers[0]["validation"]["triggered"] is True
    assert markers[0]["validation"]["poc_sanitized"] is True

    # cand-3: timeout -> triggered None
    timeouts = [f for f in findings if f["validation"]["probe"] == "timeout"]
    assert len(timeouts) == 1
    assert timeouts[0]["validation"]["triggered"] is None

    # cand-5: crash + version diff noted
    crashes = [f for f in findings if f["validation"]["probe"] == "crash"]
    assert len(crashes) == 1
    assert "bond-version" in crashes[0]["notes"]

    # cand-1 / cand-2 / cand-4: no trigger (degrade, not reject)
    nones = [f for f in findings if f["validation"]["probe"] == "none"]
    assert len(nones) == 3
    for f in nones:
        assert f["validation"]["triggered"] is False
        assert "NEED_DYNAMIC" in f["limitation"]


def test_parse_drops_unsafe_poc() -> None:
    """A triggered finding whose PoC is a command primitive must be dropped."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "cand-9"
        (d / "fuzz_log").mkdir(parents=True)
        (d / "fuzz_log" / "fuzz_sent_log.txt").write_text(
            "SENT: ;reboot\nTRIGGERED:marker\n", encoding="utf-8"
        )
        cmap = {"cand-9": _candidate_map()["cand-0"]}
        findings, stats = parse_bond_output(
            Path(td),
            candidate_map=cmap,
            run_id="r",
            tool_version="t",
        )
    assert findings == []  # dropped, never persisted
    assert stats.dropped_unsafe == 1


# --------------------------------------------------------------------------- #
# mini modules
# --------------------------------------------------------------------------- #


def test_identify_entry_points_backward() -> None:
    cg = {
        "functions": {
            "0xdispatch": {"name": "handleSetWan", "strings": ['websFormDefine("SetWan", fn)']},
            "0xmid": {"name": "setWanInner", "strings": []},
            "0xsink": {"name": "system", "strings": []},
        },
        "callgraph": {"0xdispatch": ["0xmid"], "0xmid": ["0xsink"]},
    }
    eps = identify_entry_points(cg, "0xsink")
    assert len(eps) == 1
    assert eps[0]["keyword"] == "SetWan"
    assert eps[0]["type"] == "websFormDefine"
    assert "0xsink" in eps[0]["reachable_region"]


def test_generate_template_is_deterministic() -> None:
    cand = {
        "vuln_class": "command_injection",
        "entry_point": {"keyword": "SetWan"},
        "sink_func": "system",
        "constraints": [],
    }
    tpl = generate_template(cand)
    assert tpl["source"] == "deterministic-rule"
    assert tpl["method"] == "GET"
    assert "SetWan" in tpl["entry_point"]


def test_generate_seeds_priority() -> None:
    constraints = [
        {"param": "Server", "semantic": "net_format", "expr": "ipv4", "klass": "none"},
        {"param": "Save", "semantic": "string_eq", "expr": "=='1'", "klass": "mandatory"},
    ]
    seeds = generate_seeds(constraints, n_variants=3)
    assert len(seeds) == 3
    # every seed satisfies the mandatory param
    assert all("Save=1" in s for s in seeds)


# --------------------------------------------------------------------------- #
# safety gate (H-BOND.md §8.4, hard requirement)
# --------------------------------------------------------------------------- #


def _ctx(tmp_path: Path, candidates: list[dict]) -> AnalysisContext:
    return AnalysisContext(
        run_id="r",
        rootfs_dir=tmp_path,
        workdir=tmp_path / "work",
        candidates=candidates,
    )


def test_public_ip_target_aborts(tmp_path: Path) -> None:
    """Non-private target -> unsafe, zero outbound artifacts."""
    cfg = {
        "target": "emulation",
        "target_ip": "8.8.8.8",
        "authorized": True,
        "local_lab": True,
        "baseline_ready": True,
    }
    ana = BondAnalyzer(cfg)
    ctx = _ctx(
        tmp_path,
        [{"binary_id": "b", "vuln_class": "x", "sink": {"addr": "0x1"}, "entry_point": {}}],
    )
    # gate itself must refuse
    gate = ana.check_safety()
    assert gate.allowed is False
    assert not gate.gates["private_network"]
    # the pipeline always prepares before running; prepare writes the map, the gate
    # still fires inside run() with zero outbound artifacts.
    ana.prepare(ctx)
    out = ana.run(ctx)
    assert out.status == "unsafe"
    assert not any((ctx.workdir / "out").glob("**/fuzz_sent_log.txt"))


def test_unauthorized_aborts() -> None:
    cfg = {
        "target": "emulation",
        "target_ip": "192.168.1.1",
        "authorized": False,
        "local_lab": True,
        "baseline_ready": True,
    }
    ana = BondAnalyzer(cfg)
    gate = ana.check_safety()
    assert gate.allowed is False
    assert not gate.gates["authorized"]


def test_no_baseline_aborts() -> None:
    cfg = {
        "target": "emulation",
        "target_ip": "192.168.1.1",
        "authorized": True,
        "local_lab": True,
        "baseline_ready": False,
    }
    ana = BondAnalyzer(cfg)
    gate = ana.check_safety()
    assert gate.allowed is False
    assert not gate.gates["baseline_ready"]


def test_simulation_mode_is_excluded_from_production_findings(tmp_path: Path) -> None:
    """Simulation mode must skip instead of materialising no-trigger findings."""
    cfg = {
        "target": "emulation",
        "target_ip": "192.168.1.1",
        "authorized": True,
        "local_lab": True,
        "baseline_ready": True,
        "simulate": True,
    }
    ana = BondAnalyzer(cfg)
    ctx = _ctx(
        tmp_path,
        [
            {
                "binary_id": "sbin/httpd",
                "vuln_class": "command_injection",
                "sink": {"function": "system", "addr": "0x40c318"},
                "entry_point": {"keyword": "SetWan"},
                "constraints": [],
            }
        ],
    )
    result = ana.execute(ctx)
    assert result.status == "skipped"
    assert result.findings == []
    assert "simulation" in result.limitation


def test_real_emulation_probe_can_produce_marker_evidence(tmp_path: Path, monkeypatch) -> None:
    cfg = {
        "target": "emulation",
        "target_ip": "192.168.1.1",
        "authorized": True,
        "local_lab": True,
        "baseline_ready": True,
        "simulate": False,
        "trigger_marker": "LAB_MARKER",
        "probe_parameter": "diagnostic",
    }
    ana = BondAnalyzer(cfg)
    monkeypatch.setattr(ana, "_emulation_reachable", lambda: (True, ""))
    monkeypatch.setattr(
        ana,
        "_send_http_probe",
        lambda method, endpoint, seed: {
            "status": "ok",
            "request": f"{method} {endpoint}?{seed}",
            "http_status": 200,
            "response_sha256": "a" * 64,
            "triggered": "diagnostic=" in seed,
        },
    )
    ctx = _ctx(
        tmp_path,
        [
            {
                "binary_id": "sbin/httpd",
                "vuln_class_hypothesis": "command_injection",
                "sink": {"function": "system", "addr": "0x40c318"},
                "entry_point": {"keyword": "SetWan"},
                "constraints": [],
            }
        ],
    )
    result = ana.execute(ctx)
    assert result.status == "ok"
    assert result.findings
    assert result.findings[0]["validation"]["triggered"] is True
    assert result.findings[0]["vuln_class"] == "command_injection"


def test_builtin_http_transport_observes_real_loopback_marker() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"LAB_MARKER")

        def log_message(self, _format: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ana = BondAnalyzer(
            {
                "target_ip": "127.0.0.1",
                "target_port": server.server_port,
                "simulate": False,
                "trigger_marker": "LAB_MARKER",
            }
        )
        assert ana._emulation_reachable() == (True, "")
        result = ana._send_http_probe("GET", "/goform/Test", "diagnostic=1")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["status"] == "ok"
    assert result["http_status"] == 200
    assert result["triggered"] is True
    assert len(result["response_sha256"]) == 64


def test_ghidra_export_missing_tool_is_degraded(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "httpd"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setattr(ghidra_export.shutil, "which", lambda _name: None)
    result = export_cfg_cg(binary, tmp_path / "graph.json")
    assert result["status"] == "degraded"
    assert result["available"] is False


def test_ghidra_export_executes_and_loads_real_artifact(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "httpd"
    binary.write_bytes(b"\x7fELF")
    output = tmp_path / "graph.json"
    monkeypatch.setattr(ghidra_export.shutil, "which", lambda _name: "analyzeHeadless")

    def fake_run(command, timeout):
        assert "ExportCfgCg.java" in command
        assert timeout == 900
        output.write_text(
            '{"functions":{"0x1":{"name":"handler","strings":[]}},' '"callgraph":{"0x1":[]}}',
            encoding="utf-8",
        )
        return RunResult("analyzeHeadless", 0, "", "", "success")

    monkeypatch.setattr(ghidra_export, "run_command", fake_run)
    result = export_cfg_cg(binary, output)
    assert result["status"] == "ok"
    assert result["available"] is True
    assert result["functions"]["0x1"]["name"] == "handler"
