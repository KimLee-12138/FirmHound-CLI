"""BOND adapter: constraint-directed fuzzing validation (student H).

BOND (H-BOND.md) closes the gap between *suspected* and *confirmed* in our pipeline.
It consumes the candidates that survived KLEE's symbolic pruning (``symex.reachable``
== True), extracts constraints, schedules bounded probes and validates them against an
explicitly authorized emulated HTTP target. A finding is confirmed only when the real
response contains the configured marker.

Safety model (H-BOND.md §5, non-negotiable):
  * The target MUST be ``emulation`` only. Before any network activity the four hard
    gates in :mod:`tools.emulation.safety_gate` are evaluated. A non-private target IP,
    missing authorization, a non-lab context, or a missing baseline => ``status="unsafe"``
    and ZERO outbound traffic. This is asserted by the unit tests.
  * Every PoC that would be persisted passes :func:`tools.external.bond.sanitize.sanitize_poc`;
    a blocked payload is dropped (never written, never rendered).

The mini implementation uses a built-in HTTP transport and can optionally consume a
real Ghidra CFG/callgraph export. Missing Ghidra or an unreachable emulator is reported
as an honest limitation; no synthetic graph or simulated finding enters the result.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from tools.emulation.safety_gate import evaluate_gate
from tools.external.base import AnalysisContext, ExternalAnalyzer, ProbeResult, RunOutcome
from tools.external.bond.mini.constraint import extract_constraints
from tools.external.bond.mini.ghidra_export import export_cfg_cg, identify_entry_points
from tools.external.bond.mini.scheduler import generate_seeds
from tools.external.bond.mini.template import generate_template
from tools.external.bond.parser import parse_bond_output
from tools.external.bond.sanitize import sanitize_poc


class BondAnalyzer(ExternalAnalyzer):
    """Constraint-directed fuzzing runner validating external candidates."""

    name = "bond"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        # Safety-relevant knobs (all default to the SAFE posture: emulation only).
        self.target: str = str(cfg.get("target", "emulation"))
        self.target_ip: str = str(cfg.get("target_ip", ""))
        self.authorized: bool = bool(cfg.get("authorized", False))
        self.local_lab: bool = bool(cfg.get("local_lab", True))
        self.baseline_ready: bool = bool(cfg.get("baseline_ready", False))
        # Fuzzing knobs.
        self.max_seeds: int = int(cfg.get("max_seeds", 8))
        self.simulate: bool = bool(cfg.get("simulate", True))
        self.ghidra: bool = bool(cfg.get("use_ghidra", cfg.get("ghidra", False)))
        self.target_port: int = int(cfg.get("target_port", 80))
        self.request_timeout_s: float = float(cfg.get("request_timeout_s", 5.0))
        self.trigger_marker: str = str(cfg.get("trigger_marker", ""))
        self.probe_parameter: str = str(cfg.get("probe_parameter", ""))
        self.probe_value: str = str(cfg.get("probe_value", "echo LAB_MARKER"))

    # -- probe ------------------------------------------------------------- #

    def probe(self) -> ProbeResult:
        """Probe the built-in safe HTTP transport. Never claims simulation is real."""
        if self.target != "emulation":
            return ProbeResult(
                available=False,
                backend="none",
                missing=["emulation-only"],
                notes="BOND target must be 'emulation'; real-device fuzzing is forbidden",
            )
        if self.simulate:
            return ProbeResult(
                available=False,
                backend="simulation-disabled",
                missing=["simulation mode (set external.bond.simulate=false)"],
                notes=(
                    "simulation mode is a test fixture only and is excluded from "
                    "production findings"
                ),
            )
        return ProbeResult(
            available=True,
            version=_MINI_VERSION,
            backend="builtin-safe-http",
            notes="constraint scheduler with isolated HTTP transport",
        )

    # -- safety gate ------------------------------------------------------- #

    def check_safety(self, target_ip: str | None = None) -> Any:
        """Evaluate the four hard gates; returns a GateResult (never raises)."""
        ip = target_ip or self.target_ip
        return evaluate_gate(
            authorized=self.authorized,
            local_lab=self.local_lab,
            target_ip=ip,
            baseline_ready=self.baseline_ready,
        )

    # -- prepare ----------------------------------------------------------- #

    def prepare(self, ctx: AnalysisContext) -> Path:
        """Select KLEE-surviving candidates and record a candidate_map.json.

        BOND prefers candidates KLEE proved reachable (``symex.reachable == True``);
        if none survive, it falls back to all candidates (still attempts, honest degrade).
        """
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "out").mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "logs").mkdir(parents=True, exist_ok=True)

        candidates = list(ctx.candidates or [])
        reachable = [c for c in candidates if _klee_reachable(c)]
        chosen = reachable if reachable else candidates

        candidate_map: dict[str, dict[str, Any]] = {}
        for i, cand in enumerate(chosen):
            sink = cand.get("sink") or {}
            candidate_map[f"cand-{i}"] = {
                "binary_id": str(cand.get("binary_id") or "unknown"),
                "vuln_class": str(
                    cand.get("vuln_class") or cand.get("vuln_class_hypothesis") or "other"
                ),
                "sink": {
                    "function": str(sink.get("function") or cand.get("sink_func") or ""),
                    "addr": str(sink.get("addr") or ""),
                    "type": str(sink.get("type") or ""),
                },
                "source": cand.get("source") or {"type": "unknown"},
                "entry_point": cand.get("entry_point") or {"type": "unknown"},
                "call_trace": cand.get("call_trace") or [],
                "constraints": extract_constraints(cand),
            }
        (ctx.workdir / "candidate_map.json").write_text(
            json.dumps(candidate_map, indent=2), encoding="utf-8"
        )
        # Record the chosen target posture for audit (IP redacted by the gate itself).
        (ctx.workdir / "target.json").write_text(
            json.dumps(
                {
                    "target": self.target,
                    "authorized": self.authorized,
                    "local_lab": self.local_lab,
                    "baseline_ready": self.baseline_ready,
                    "target_ip_set": bool(self.target_ip),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return ctx.workdir

    # -- run --------------------------------------------------------------- #

    def run(self, ctx: AnalysisContext) -> RunOutcome:
        started = time.time()
        candidate_map = self._load_candidate_map(ctx)
        if not candidate_map:
            return RunOutcome(
                status="ok",
                duration_s=0.0,
                outputs=[],
                limitation="no candidates to validate with BOND",
            )

        # SAFETY GATE: evaluate before any network activity. A failing gate aborts
        # with ZERO outbound traffic (no Bond_result / fuzz_log are written).
        gate = self.check_safety()
        if not gate.allowed:
            return RunOutcome(
                status="unsafe",
                duration_s=time.time() - started,
                outputs=[],
                limitation=gate.reason or "ABORT_DYNAMIC_VALIDATION",
            )
        if self.simulate:
            return RunOutcome(
                status="skipped",
                duration_s=time.time() - started,
                outputs=[],
                limitation="simulation mode does not emit production findings",
            )

        out_root = ctx.workdir / "out"
        out_root.mkdir(parents=True, exist_ok=True)
        emulation_ok, reachability = self._emulation_reachable()
        if not emulation_ok:
            return RunOutcome(
                status="skipped",
                duration_s=time.time() - started,
                outputs=[],
                limitation=reachability,
            )

        triggered = 0
        sent = 0
        for dir_name, candidate in candidate_map.items():
            cand_dir = out_root / dir_name
            cand_dir.mkdir(parents=True, exist_ok=True)
            metrics = self._drive_one(ctx, cand_dir, candidate)
            triggered += int(metrics["triggered"])
            sent += int(metrics["sent"])

        duration = time.time() - started
        limitation = "" if triggered else f"{sent} real probes sent; no trigger marker observed"
        return RunOutcome(
            status="ok",
            duration_s=duration,
            outputs=[out_root],
            limitation=limitation,
        )

    def _drive_one(
        self,
        ctx: AnalysisContext,
        cand_dir: Path,
        candidate: dict[str, Any],
    ) -> dict[str, int]:
        """Run mini-BOND over one candidate and write BOND artifacts.

        This method runs only after the safety gate and reachability check. It records
        only requests actually attempted, and never fabricates a trigger.
        """
        (cand_dir / "Bond_result" / "action_find").mkdir(parents=True, exist_ok=True)
        (cand_dir / "Bond_result" / "custom_analysis").mkdir(parents=True, exist_ok=True)
        (cand_dir / "fuzz_log").mkdir(parents=True, exist_ok=True)

        # M1 entry point: use a real Ghidra graph when enabled; otherwise retain only
        # entry metadata already supported by upstream evidence.
        sink_addr = str(candidate.get("sink", {}).get("addr") or "")
        entries: list[dict[str, Any]] = []
        ghidra_result: dict[str, Any] | None = None
        if self.ghidra:
            binary = (ctx.rootfs_dir / str(candidate.get("binary_id") or "")).resolve()
            try:
                binary.relative_to(ctx.rootfs_dir.resolve())
            except ValueError:
                ghidra_result = {
                    "status": "failed",
                    "available": False,
                    "limitation": "candidate binary escapes the selected rootfs",
                }
            else:
                graph_path = cand_dir / "Bond_result" / "action_find" / "cfg_cg.json"
                ghidra_result = export_cfg_cg(binary, graph_path)
                if ghidra_result.get("available"):
                    entries = identify_entry_points(ghidra_result, sink_addr)
            (cand_dir / "Bond_result" / "action_find" / "ghidra_status.json").write_text(
                json.dumps(ghidra_result, indent=2), encoding="utf-8"
            )
        default_ep = candidate.get("entry_point") or {"type": "unknown"}
        entry_point = entries[0] if entries else default_ep
        (cand_dir / "Bond_result" / "action_find" / "entry.json").write_text(
            json.dumps(entry_point, indent=2), encoding="utf-8"
        )

        # M2 constraints
        drive_candidate = dict(candidate)
        drive_candidate["entry_point"] = entry_point
        constraints = extract_constraints(drive_candidate)
        (cand_dir / "Bond_result" / "custom_analysis" / "constraints.json").write_text(
            json.dumps(constraints, indent=2), encoding="utf-8"
        )

        # M3 template + scheduler seeds
        template = generate_template(drive_candidate)
        n_var = max(1, self.max_seeds // 3 or 1)
        seeds = generate_seeds(constraints, n_variants=n_var)
        if self.probe_parameter and self.trigger_marker:
            seeds.append(urlencode({self.probe_parameter: self.probe_value}))
        lines = [f"VERSION: BOND mini {_MINI_VERSION}"]
        method = template.get("method", "GET")
        ep = template.get("entry_point", "/")
        sent = 0
        triggered = 0
        for s in seeds:
            probe = self._send_http_probe(str(method), str(ep), s)
            if not probe.get("request"):
                lines.append(f"ERROR: {probe.get('limitation', 'probe rejected')}")
                continue
            safe_request, safe = sanitize_poc(str(probe.get("request", "")))
            if not safe:
                lines.append("REJECTED: compliance sanitizer blocked generated request")
                continue
            sent += 1
            lines.append(f"SENT: {safe_request}")
            if probe["status"] == "timeout":
                lines.append("TIMEOUT")
            elif probe["status"] == "ok":
                lines.append(
                    f"RESPONSE: status={probe['http_status']} sha256={probe['response_sha256']}"
                )
            else:
                lines.append(f"ERROR: {probe.get('limitation', 'probe failed')}")
            if probe.get("triggered"):
                triggered += 1
                lines.append("TRIGGERED:marker")
                break
        (cand_dir / "fuzz_log" / "fuzz_sent_log.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        return {"sent": sent, "triggered": triggered}

    def _emulation_reachable(self) -> tuple[bool, str]:
        """Confirm a TCP listener exists after all safety gates have passed."""
        if not self.target_ip or not 1 <= self.target_port <= 65535:
            return False, "emulation target_ip/target_port is not configured"
        try:
            with socket.create_connection(
                (self.target_ip, self.target_port), timeout=self.request_timeout_s
            ):
                return True, ""
        except OSError as exc:
            return False, f"emulation HTTP endpoint unreachable: {type(exc).__name__}"

    def _send_http_probe(self, method: str, endpoint: str, seed: str) -> dict[str, Any]:
        """Send one bounded request to the authorized private emulation endpoint."""
        method = method.upper()
        if method not in {"GET", "POST"}:
            return {"status": "failed", "request": "", "limitation": "unsupported method"}
        if "://" in endpoint or any(char in endpoint for char in ("\r", "\n", "\\")):
            return {"status": "failed", "request": "", "limitation": "unsafe endpoint"}
        endpoint_parts = urlsplit(endpoint)
        if (
            not endpoint_parts.path.startswith("/")
            or endpoint_parts.netloc
            or endpoint_parts.fragment
        ):
            return {"status": "failed", "request": "", "limitation": "unsafe endpoint"}
        seed_params = parse_qsl(seed, keep_blank_values=True)
        endpoint_params = parse_qsl(endpoint_parts.query, keep_blank_values=True)
        if method == "GET":
            query = urlencode([*endpoint_params, *seed_params])
            path = endpoint_parts.path + (f"?{query}" if query else "")
        else:
            existing_query = urlencode(endpoint_params)
            path = endpoint_parts.path + (f"?{existing_query}" if existing_query else "")
        encoded = urlencode(seed_params)
        body = encoded if method == "POST" else None
        request_line = f"{method} {path}"
        connection = http.client.HTTPConnection(
            self.target_ip, self.target_port, timeout=self.request_timeout_s
        )
        try:
            headers = (
                {"Content-Type": "application/x-www-form-urlencoded"} if method == "POST" else {}
            )
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(4096)
        except TimeoutError:
            return {"status": "timeout", "request": request_line, "triggered": False}
        except (OSError, http.client.HTTPException) as exc:
            return {
                "status": "failed",
                "request": request_line,
                "triggered": False,
                "limitation": type(exc).__name__,
            }
        finally:
            connection.close()
        marker = self.trigger_marker.encode("utf-8") if self.trigger_marker else b""
        return {
            "status": "ok",
            "request": request_line,
            "http_status": response.status,
            "response_sha256": hashlib.sha256(response_body).hexdigest(),
            "triggered": bool(marker and marker in response_body),
        }

    # -- parse ------------------------------------------------------------- #

    def parse(self, ctx: AnalysisContext, outcome: RunOutcome) -> list[dict[str, Any]]:
        candidate_map = self._load_candidate_map(ctx)
        if not candidate_map:
            return []
        findings, stats = parse_bond_output(
            ctx.workdir / "out",
            candidate_map=candidate_map,
            run_id=ctx.run_id,
            tool_version=_MINI_VERSION,
            duration_s=outcome.duration_s,
        )
        if stats.limitations:
            outcome.limitation = "; ".join(sorted(set(stats.limitations))[:5])
        return findings

    # -- helpers ----------------------------------------------------------- #

    def _load_candidate_map(self, ctx: AnalysisContext) -> dict[str, dict[str, Any]]:
        path = ctx.workdir / "candidate_map.json"
        if not path.exists():
            return {}
        with contextlib.suppress(Exception):
            return json.loads(path.read_text(encoding="utf-8")) or {}
        return {}


_MINI_VERSION = "mini-0.1"


def _klee_reachable(candidate: dict[str, Any]) -> bool:
    """True if KLEE (G) judged this candidate's path reachable."""
    symex = candidate.get("symex") or {}
    if isinstance(symex, dict) and symex.get("reachable") is True:
        return True
    # also accept an explicit flag some callers set
    return bool(candidate.get("klee_reachable"))


def build(config: dict[str, Any] | None = None) -> BondAnalyzer:
    """Factory used by ``tools/registry/external.yaml``."""
    return BondAnalyzer(config)


__all__ = ["BondAnalyzer", "build", "_MINI_VERSION"]
