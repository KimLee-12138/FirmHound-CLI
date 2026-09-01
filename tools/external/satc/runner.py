"""SaTC adapter: run the (shared-keyword aware) taint checker over a rootfs.

SaTC consumes an *already extracted* firmware rootfs, which is exactly what our
``UNPACK`` stage produces, so no format conversion is needed on input.

The analyzer runs up to four Ghidra-script configurations per firmware:

    ref2sink_cmdi   command-injection sinks reachable from shared keywords
    ref2sink_bof    buffer-overflow sinks reachable from shared keywords
    ref2share       shared-data *write* parameters (nvram_set / setenv / ...)
    share2sink      shared-data *read*  parameters -> sink (needs ref2share)

The last pair is the capability our main track does not have at all: cross
-process taint, i.e. data written to nvram/env by one binary and later read into
a sink by another.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from tools.external.backends import docker_available, docker_image_exists, run_docker
from tools.external.base import (
    AnalysisContext,
    ExternalAnalyzer,
    ProbeResult,
    RunOutcome,
)
from tools.external.satc.parser import parse_satc_output

IMAGE = "smile0304/satc"

# Script -> whether it needs the output of a previous run.
SCRIPT_ORDER = ["ref2sink_cmdi", "ref2sink_bof", "ref2share"]
NEEDS_REF2SHARE = "share2sink"


class SatcAnalyzer(ExternalAnalyzer):
    """Docker-backed SaTC runner."""

    name = "satc"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self.image: str = cfg.get("image", IMAGE)
        self.taint_check: bool = bool(cfg.get("taint_check", True))
        self.timeout_s: int = int(cfg.get("timeout_s", 3600))
        self.max_bins: int = int(cfg.get("max_bins", 3))
        self.memory: str = str(cfg.get("memory", "16g"))
        self.scripts: list[str] = list(cfg.get("scripts", SCRIPT_ORDER))
        self.enable_share2sink: bool = bool(cfg.get("enable_share2sink", True))

    # -- probe ------------------------------------------------------------- #

    def probe(self) -> ProbeResult:
        """Docker + image presence. Never raises."""
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
        return ProbeResult(
            available=True, version=self._image_version(), backend="docker", notes=detail
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
        """Stage the rootfs for container mounting.

        The rootfs is mounted read-only in place (no copy) because extracted
        firmware trees are large. Symlink breakage is recorded rather than
        repaired -- SaTC runs inside Linux where they resolve correctly.
        """
        rootfs = Path(ctx.rootfs_dir)
        if not rootfs.exists():
            raise FileNotFoundError(f"rootfs not found: {rootfs}")
        (ctx.workdir / "out").mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "logs").mkdir(parents=True, exist_ok=True)

        staged = ctx.workdir / "rootfs_marker.json"
        staged.write_text(
            '{"rootfs": "%s", "max_bins": %d}' % (rootfs.as_posix(), self.max_bins),
            encoding="utf-8",
        )
        return rootfs

    def _pick_border_binaries(self, ctx: AnalysisContext) -> list[str]:
        """Choose border binaries from the attack surface, else let SaTC decide."""
        surfaces = (ctx.attack_surface or {}).get("surfaces", [])
        seen: list[str] = []
        for surface in surfaces:
            binary = surface.get("binary")
            if binary and binary not in seen:
                seen.append(binary)
            if len(seen) >= self.max_bins:
                break
        return seen

    # -- run --------------------------------------------------------------- #

    def run(self, ctx: AnalysisContext) -> RunOutcome:
        rootfs = Path(ctx.rootfs_dir)
        started = time.time()
        logs: list[str] = []
        ran_any = False
        timed_out = False

        border_bins = self._pick_border_binaries(ctx)
        bin_args: list[list[str]] = (
            [["-b", b] for b in border_bins] if border_bins else [["-l", str(self.max_bins)]]
        )

        for script in self.scripts:
            for idx, bin_arg in enumerate(bin_args):
                out_dir = ctx.output_dir(f"{script}-{idx}")
                cmd = [
                    "python",
                    "satc.py",
                    "-d",
                    "/work/rootfs",
                    "-o",
                    "/work/out",
                    "--ghidra_script",
                    script,
                ]
                if self.taint_check:
                    cmd.append("--taint_check")
                cmd += bin_arg

                res = run_docker(
                    self.image,
                    cmd,
                    mounts={rootfs: "/work/rootfs", out_dir: "/work/out"},
                    timeout=float(self.timeout_s),
                    memory=self.memory,
                )
                log_file = ctx.workdir / "logs" / f"{script}-{idx}.log"
                log_file.write_text(
                    f"# cmd: {' '.join(cmd)}\nstatus={res.status}\n"
                    f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}\n",
                    encoding="utf-8",
                )
                logs.append(f"{script}-{idx}:{res.status}")
                if res.status in {"ok", "failed"}:
                    ran_any = True
                if res.status == "timeout":
                    timed_out = True

        # share2sink consumes the ref2share output.
        if self.enable_share2sink:
            ref2share_out = ctx.workdir / "out" / "ref2share-0"
            if (ref2share_out).exists():
                out_dir = ctx.output_dir("share2sink-0")
                cmd = [
                    "python",
                    "satc.py",
                    "-d",
                    "/work/rootfs",
                    "-o",
                    "/work/out",
                    "--ghidra_script",
                    NEEDS_REF2SHARE,
                    "--ref2share_result",
                    "/work/ref2share",
                ]
                if self.taint_check:
                    cmd.append("--taint_check")
                cmd += bin_args[0]
                res = run_docker(
                    self.image,
                    cmd,
                    mounts={
                        rootfs: "/work/rootfs",
                        out_dir: "/work/out",
                        ref2share_out: "/work/ref2share",
                    },
                    timeout=float(self.timeout_s),
                    memory=self.memory,
                )
                logs.append(f"share2sink-0:{res.status}")
                ran_any = ran_any or res.status in {"ok", "failed"}

        duration = time.time() - started
        if not ran_any:
            return RunOutcome(
                status="timeout" if timed_out else "failed",
                duration_s=duration,
                limitation=f"no SaTC invocation completed; runs={','.join(logs) or 'none'}",
            )
        if timed_out:
            return RunOutcome(
                status="timeout",
                duration_s=duration,
                limitation=f"partial: some invocations timed out; runs={','.join(logs)}",
            )
        return RunOutcome(status="ok", duration_s=duration, outputs=[ctx.workdir / "out"])

    # -- parse ------------------------------------------------------------- #

    def parse(self, ctx: AnalysisContext, outcome: RunOutcome) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        limitations: list[str] = []
        for out_dir in (
            sorted((ctx.workdir / "out").iterdir()) if (ctx.workdir / "out").exists() else []
        ):
            if not out_dir.is_dir():
                continue
            partial, stats = parse_satc_output(
                out_dir,
                rootfs=Path(ctx.rootfs_dir),
                run_id=ctx.run_id,
                taint_check=self.taint_check,
                tool_version=self._image_version(),
                duration_s=outcome.duration_s,
            )
            limitations.extend(stats.limitations)
            findings.extend(partial)

        if limitations:
            outcome.limitation = "; ".join(sorted(set(limitations))[:5])
        return findings


def build(config: dict[str, Any] | None = None) -> SatcAnalyzer:
    """Factory used by ``tools/registry/external.yaml``."""
    return SatcAnalyzer(config)
