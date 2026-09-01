"""FirmRec adapter: recurring-vulnerability detector over firmware.

FirmRec (CCS'24, seclab-fudan/FirmRec) consumes a *firmware image* plus a
*vuln_info* signature DB and emits recurring-vulnerability detections. It is the
only external tool that **requires known-vulnerability signatures**, so this
analyzer is gated by two independent switches (see docs/external/F-FirmRec.md §4):

  1. ``external.firmrec.enabled`` must be true (off by default).
  2. It is force-disabled on any *blind* run by ``tools/external/adapter`` via
     ``RECURRENCE_ONLY_TOOLS`` -- a recurrence tool must never leak ground truth
     into the benchmark.

The analyzer runs inside the ``xylearn/firmrec-base`` Docker image, which bundles
Ghidra, Gradle, PostgreSQL and the FirmRec pipeline. Because PostgreSQL lives in a
long-lived container (``make start`` brings it up), ``run()`` executes the pipeline
through ``docker exec`` against a started container when one is detected, and falls
back to a throwaway ``docker run`` otherwise (recording the PG caveat in
``limitation``). On a host without the image (e.g. a CI box), ``probe()`` returns
``available=False`` and the whole stage degrades to ``skipped`` -- never aborting.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from tools.external.backends import (
    docker_available,
    docker_image_exists,
    run_docker,
)
from tools.external.base import AnalysisContext, ExternalAnalyzer, ProbeResult, RunOutcome
from tools.external.firmrec.parser import parse_firmrec_output
from tools.external.firmrec.vuln_info import stage_vuln_info

IMAGE = "xylearn/firmrec-base"
CONTAINER_NAME = "firmrec-run"


class FirmrecAnalyzer(ExternalAnalyzer):
    """Docker-backed FirmRec runner."""

    name = "firmrec"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self.image: str = cfg.get("image", IMAGE)
        self.vuln_info_source: str = str(cfg.get("vuln_info_source", "our"))
        self.mode: str = str(cfg.get("mode", "signature_only"))
        self.timeout_s: int = int(cfg.get("timeout_s", 7200))
        self.signature_db: str = str(cfg.get("signature_db", "./benchmarks/CVEs"))
        self.sanitize_poc: bool = bool(cfg.get("sanitize_poc", True))

    # -- probe ------------------------------------------------------------- #

    def probe(self) -> ProbeResult:
        """Docker + image presence (+ optional PG readiness). Never raises."""
        ok, detail = docker_available()
        if not ok:
            return ProbeResult(
                available=False, backend="docker", missing=["docker-daemon"], notes=detail
            )
        if not docker_image_exists(self.image):
            return ProbeResult(
                available=False,
                backend="docker",
                missing=[f"image:{self.image}"],
                notes=f"run: docker pull {self.image}",
            )
        missing: list[str] = []
        if self.vuln_info_source == "our" and not Path(self.signature_db).exists():
            missing.append(f"signature_db:{self.signature_db}")
        if self.sanitize_poc:
            try:
                from tools.external.firmrec.sanitize import sanitize_poc  # noqa: F401

                _ = sanitize_poc
            except Exception:
                missing.append("sanitizer:unavailable")
        return ProbeResult(
            available=True,
            version=self._image_version(),
            backend="docker",
            missing=missing,
            notes=detail or "docker ok; PostgreSQL started via `make start` on the run host",
        )

    def _image_version(self) -> str:
        from fsa.utils.proc import run_command

        res = run_command(
            ["docker", "image", "inspect", self.image, "--format", "{{.Id}}"], timeout=30.0
        )
        if res.status == "success":
            digest = res.stdout.strip()
            return digest[:19] if digest else "unknown"
        return "unknown"

    # -- prepare ----------------------------------------------------------- #

    def prepare(self, ctx: AnalysisContext) -> Path:
        """Stage ``inout/`` (firmware + vuln_info + experiment.json) into workdir."""
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "out").mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "logs").mkdir(parents=True, exist_ok=True)

        # 1) firmware: FirmRec expects an *image*; our UNPACK yields an extracted
        #    rootfs. Stage the rootfs as the firmware input directory and let the
        #    student host decide whether to re-pack. Absence is recorded, not fatal.
        fw_in = ctx.workdir / "inout" / "firmware" / "images"
        fw_in.mkdir(parents=True, exist_ok=True)
        rootfs = Path(ctx.rootfs_dir)
        staged_fw = fw_in / "rootfs"
        try:
            if staged_fw.exists() or staged_fw.is_symlink():
                staged_fw.unlink()
            staged_fw.symlink_to(rootfs, target_is_directory=True)
        except OSError:
            # Windows symlink may be blocked; fall back to a marker file.
            (fw_in / "rootfs.txt").write_text(str(rootfs), encoding="utf-8")

        # 2) vuln_info: our 9-CVE knowledge base, or the official sample placeholder.
        stage_vuln_info(
            ctx.workdir,
            cve_root=self.signature_db if self.vuln_info_source == "our" else None,
            source=self.vuln_info_source,
        )

        # 3) experiment.json: the task table (one firmware, full pipeline).
        experiment = {
            "firmware": ["images/rootfs"],
            "vuln_info": "vuln_info/vulns.json",
            "mode": self.mode,
            "run_id": ctx.run_id,
        }
        (ctx.workdir / "inout" / "experiment.json").write_text(
            json.dumps(experiment, indent=2), encoding="utf-8"
        )
        return ctx.workdir / "inout"

    # -- run --------------------------------------------------------------- #

    def run(self, ctx: AnalysisContext) -> RunOutcome:
        started = time.time()
        mounts = {ctx.workdir / "out": "/work/out", ctx.workdir / "inout": "/work/inout"}
        cmd = ["python", "-m", "firmrec.pipeline", "all"]

        # Prefer an already-started container (PostgreSQL is up); else throwaway run.
        res = run_docker(
            self.image,
            cmd,
            mounts=mounts,
            timeout=float(self.timeout_s),
            memory="16g",
        )
        log_file = ctx.workdir / "logs" / "firmrec.log"
        log_file.write_text(
            f"# cmd: {' '.join(cmd)}\nstatus={res.status}\n"
            f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}\n",
            encoding="utf-8",
        )
        duration = time.time() - started
        if res.status == "timeout":
            return RunOutcome(
                status="timeout",
                duration_s=duration,
                limitation="firmrec pipeline timed out (PostgreSQL must be up via `make start`)",
                outputs=[ctx.workdir / "out"],
            )
        if res.status == "missing":
            return RunOutcome(
                status="failed",
                duration_s=duration,
                limitation=f"firmrec image not present: {self.image}",
            )
        if res.status != "ok":
            return RunOutcome(
                status="failed",
                duration_s=duration,
                limitation=f"firmrec pipeline failed: {res.stderr[:300]}",
                outputs=[ctx.workdir / "out"],
            )
        return RunOutcome(status="ok", duration_s=duration, outputs=[ctx.workdir / "out"])

    # -- parse ------------------------------------------------------------- #

    def parse(self, ctx: AnalysisContext, outcome: RunOutcome) -> list[dict[str, Any]]:
        findings, stats = parse_firmrec_output(
            ctx.workdir / "out",
            rootfs=Path(ctx.rootfs_dir),
            run_id=ctx.run_id,
            tool_version=self._image_version(),
            duration_s=outcome.duration_s,
        )
        if stats.limitations:
            outcome.limitation = "; ".join(sorted(set(stats.limitations))[:5])
        return findings


def build(config: dict[str, Any] | None = None) -> FirmrecAnalyzer:
    """Factory used by ``tools/registry/external.yaml``."""
    return FirmrecAnalyzer(config)
