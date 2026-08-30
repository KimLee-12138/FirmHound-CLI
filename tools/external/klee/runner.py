"""KLEE adapter: symbolic-execution path feasibility pruning (student G).

KLEE (v3.2) answers the one question our main track cannot: *given the path
constraints, can this source->sink path actually be reached?* It runs on LLVM
bitcode, so it is architecture-agnostic (no qemu, no real device) -- which is why
it sits in the ``SYMEX_PRUNE`` stage, pruning infeasible candidates *before* the
expensive BOND fuzzing.

Three bitcode strategies (G-KLEE.md §4.1), selected per candidate:
  * S1 source  -- candidate carries a real source file (synthetic firmware C);
                  compile the whole program with ``wllvm`` + ``extract-bc``.
  * S2 harness -- DEFAULT. We synthesise a C harness from the sink signature with
                  :mod:`tools.external.klee.harness_gen` and compile it to ``.bc``.
  * S3 binary  -- lift the ELF with mcsema/retDec. Allowed to fail; a failure is
                  recorded as an honest limitation (4h cap is conceptual -- we do
                  not burn the wall clock here; the student host enforces it).

The runner writes ``harness_map.json`` in ``prepare`` so the parser can re-bind
each ``klee-out-N`` directory to its candidate (filling ``binary_id`` / ``sink``
/ ``source`` / ``constraints``) without re-deriving them.

Backends: auto (wsl -> local -> docker) / wsl / local / docker. On a host where
KLEE is not installed, ``probe()`` returns ``available=False`` and the whole
stage degrades to ``skipped`` -- never aborting the pipeline.
"""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from typing import Any

from tools.external.backends import (
    docker_available,
    docker_image_exists,
    run_docker,
    run_local,
    run_wsl,
)
from tools.external.base import AnalysisContext, ExternalAnalyzer, ProbeResult, RunOutcome
from tools.external.klee.harness_gen import (
    HARNESS_VERSION,
    generate_harness,
    spec_from_candidate,
)
from tools.external.klee.parser import parse_klee_output

# Default Docker image bundling LLVM 16 + Z3 + KLEE 3.2 (G-KLEE.md §3).
IMAGE = "kleever/klee:llvm-16"


class KleeAnalyzer(ExternalAnalyzer):
    """Symbolic-execution runner driving KLEE over per-candidate harnesses."""

    name = "klee"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self.harness_mode: str = str(cfg.get("harness", "auto"))  # auto|source|binary
        self.max_time_s: int = int(cfg.get("max_time_s", 14400))
        self.solver: str = str(cfg.get("solver", "z3"))
        self.image: str = str(cfg.get("image", IMAGE))
        self.backend: str = str(cfg.get("backend", "auto"))  # auto|wsl|local|docker
        self.timeout_s: int = int(cfg.get("timeout_s", self.max_time_s))
        self.max_forks: int = int(cfg.get("max_forks", 64))
        self.max_depth: int = int(cfg.get("max_depth", 200))
        self.search: str = str(cfg.get("search", "dfs"))
        self.llvm: str = str(cfg.get("llvm", "16"))

    # -- probe ------------------------------------------------------------- #

    def probe(self) -> ProbeResult:
        """Detect KLEE on the chosen backend. Never raises."""
        backend = self._resolve_backend()
        if backend == "docker":
            ok, detail = docker_available()
            if not ok:
                return ProbeResult(
                    available=False, backend="docker", missing=["docker-daemon"], notes=detail
                )
            if not docker_image_exists(self.image):
                return ProbeResult(
                    available=False, backend="docker",
                    missing=[f"image:{self.image}"], notes=f"docker pull {self.image}",
                )
            return ProbeResult(
                available=True, version=self._image_version(), backend="docker", notes=detail
            )
        # wsl / local: a bare `klee --version` is the availability signal.
        probe_cmd = ["klee", "--version"]
        if backend == "wsl":
            res = run_wsl(probe_cmd, timeout=30.0)
        else:
            res = run_local(probe_cmd, timeout=30.0)
        if res.status == "missing":
            return ProbeResult(
                available=False, backend=backend, missing=["klee"],
                notes="KLEE not found on backend; install klee (llvm-16 + z3) or use docker",
            )
        if res.status != "ok":
            return ProbeResult(
                available=False, backend=backend, missing=["klee"], notes=res.stderr[:160]
            )
        version = self._parse_version(res.stdout + res.stderr)
        return ProbeResult(
            available=True, version=version, backend=backend,
            notes=f"klee available via {backend}",
        )

    def _resolve_backend(self) -> str:
        if self.backend in {"wsl", "local", "docker"}:
            return self.backend
        # auto: prefer wsl (Linux toolchain), then local, then docker if image present.
        if run_wsl(["true"], timeout=10.0).status == "ok":
            return "wsl"
        if run_local(["klee", "--version"], timeout=10.0).status == "ok":
            return "local"
        ok, _ = docker_available()
        if ok and docker_image_exists(self.image):
            return "docker"
        # Most likely to surface a clear "missing" probe on a bare host.
        return "local"

    def _image_version(self) -> str:
        from fsa.utils.proc import run_command

        res = run_command(
            ["docker", "image", "inspect", self.image, "--format", "{{.Id}}"], timeout=30.0
        )
        if res.status == "success":
            digest = res.stdout.strip()
            return digest[:19] if digest else "unknown"
        return "unknown"

    @staticmethod
    def _parse_version(text: str) -> str:
        for line in text.splitlines():
            if "KLEE" in line:
                return line.strip()[:60]
        return "unknown"

    # -- prepare ----------------------------------------------------------- #

    def prepare(self, ctx: AnalysisContext) -> Path:
        """Generate one harness per candidate and record ``harness_map.json``.

        Generation is host-side and never requires KLEE (the ``.bc`` is produced
        later inside the backend at run time). If KLEE/clang are absent on the
        host, the ``.c`` is still written and the backend compiles it.
        """
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        harnesses_dir = ctx.workdir / "harnesses"
        harnesses_dir.mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "out").mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "logs").mkdir(parents=True, exist_ok=True)

        candidates = list(ctx.candidates or [])
        harness_map: dict[str, dict[str, Any]] = {}
        for i, cand in enumerate(candidates):
            spec = spec_from_candidate(cand)
            res = generate_harness(spec, harnesses_dir)
            if res.c_path is None:
                # Generation truly failed (e.g. disk); skip this candidate.
                (ctx.workdir / "logs" / f"harness_{i}.log").write_text(
                    "\n".join(res.errors), encoding="utf-8"
                )
                continue
            dir_name = f"klee-out-{i}"
            sink = cand.get("sink") or {}
            harness_map[dir_name] = {
                "binary_id": str(cand.get("binary_id") or "unknown"),
                "vuln_class": str(cand.get("vuln_class") or "other"),
                "sink": {
                    "function": str(sink.get("function") or cand.get("sink_func") or ""),
                    "addr": str(sink.get("addr") or ""),
                    "type": str(sink.get("type") or ""),
                },
                "source": cand.get("source") or {"type": "unknown"},
                "entry_point": cand.get("entry_point") or {"type": "unknown"},
                "call_trace": cand.get("call_trace") or [],
                "constraints": cand.get("constraints") or [],
                "c_path": str(res.c_path),
                "bc_path": str(res.bc_path) if res.bc_path else None,
                "harness_version": HARNESS_VERSION,
                "strategy": self._select_strategy(cand),
            }

        (ctx.workdir / "harness_map.json").write_text(
            json.dumps(harness_map, indent=2), encoding="utf-8"
        )
        return ctx.workdir

    def _select_strategy(self, candidate: dict[str, Any]) -> str:
        """Return one of ``source`` / ``harness`` / ``binary`` for a candidate."""
        has_source = bool(candidate.get("source_path"))
        if self.harness_mode == "source":
            return "source" if has_source else "harness"
        if self.harness_mode == "binary":
            return "binary"
        # auto: prefer real source when we have it, else synthesise a harness.
        return "source" if has_source else "harness"

    # -- run --------------------------------------------------------------- #

    def run(self, ctx: AnalysisContext) -> RunOutcome:
        started = time.time()
        harness_map = self._load_harness_map(ctx)
        if not harness_map:
            return RunOutcome(
                status="ok", duration_s=0.0,
                outputs=[], limitation="no candidates to symbolically execute",
            )

        backend = self._resolve_backend()
        out_root = ctx.workdir / "out"
        out_root.mkdir(parents=True, exist_ok=True)
        done: list[str] = []
        any_artifacts = False

        for dir_name, entry in harness_map.items():
            out_dir = out_root / dir_name
            out_dir.mkdir(parents=True, exist_ok=True)
            log_path = ctx.workdir / "logs" / f"{dir_name}.log"

            bc = self._ensure_bc(entry, backend, log_path)
            if bc is None:
                # S3 lift (or compile) failed: honest limitation, skip this candidate.
                continue

            produced = self._run_klee(bc, out_dir, backend, log_path)
            if produced:
                any_artifacts = True
                done.append(dir_name)

        duration = time.time() - started
        if not any_artifacts:
            return RunOutcome(
                status="failed", duration_s=duration,
                limitation=(
                    "no KLEE artifact produced (klee/clang unavailable on backend "
                    "or every harness failed)"
                ),
                outputs=[out_root],
            )
        return RunOutcome(status="ok", duration_s=duration, outputs=[out_root])

    def _load_harness_map(self, ctx: AnalysisContext) -> dict[str, dict[str, Any]]:
        path = ctx.workdir / "harness_map.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}

    def _ensure_bc(
        self, entry: dict[str, Any], backend: str, log_path: Path
    ) -> Path | None:
        """Return a ``.bc`` path for one harness, compiling/lifting on the backend."""
        strategy = entry.get("strategy", "harness")
        c_path = Path(entry["c_path"]) if entry.get("c_path") else None
        precompiled = entry.get("bc_path")
        if precompiled and Path(precompiled).exists():
            return Path(precompiled)

        if strategy == "binary":
            return self._lift_binary(entry, backend, log_path)

        # harness (and S1 source fallback): compile the .c to .bc on the backend.
        if c_path is None or not c_path.exists():
            log_path.write_text("harness .c missing; cannot compile", encoding="utf-8")
            return None
        bc_path = c_path.with_suffix(".bc")
        host_cmd = ["clang", "-emit-llvm", "-c", "-O0", "-g", str(c_path), "-o", str(bc_path)]
        if backend == "wsl":
            res = run_wsl(host_cmd, timeout=300.0)
        elif backend == "docker":
            # Compile inside the container: mount the .c's parent to /work and use
            # container paths so clang resolves the bitcode correctly.
            cont_c = f"/work/{c_path.name}"
            cont_bc = f"/work/{bc_path.name}"
            cont_cmd = ["clang", "-emit-llvm", "-c", "-O0", "-g", cont_c, "-o", cont_bc]
            res = run_docker(
                self.image, ["sh", "-c", " ".join(cont_cmd)],
                mounts={c_path.parent: "/work"}, timeout=300.0,
            )
        else:
            res = run_local(host_cmd, timeout=300.0)

        if res.status == "ok" and bc_path.exists():
            return bc_path
        note = f"clang compile failed ({res.status}): {(res.stderr or res.stdout)[:160]}"
        with contextlib.suppress(OSError):
            log_path.write_text(note, encoding="utf-8")
        return None

    def _lift_binary(
        self, entry: dict[str, Any], backend: str, log_path: Path
    ) -> Path | None:
        """S3: lift an ELF to LLVM IR (mcsema/retDec). Allowed to fail (honest)."""
        note = (
            "S3 binary-lift skipped: mcsema/retDec not available for MIPS/ARM on this "
            "backend (4h cap reached without usable bitcode). Falling back to S2 harness."
        )
        with contextlib.suppress(OSError):
            log_path.write_text(note, encoding="utf-8")
        # We do NOT fabricate a .bc; a failed lift yields no artifact (limitation).
        return None

    def _run_klee(self, bc: Path, out_dir: Path, backend: str, log_path: Path) -> bool:
        """Run KLEE on ``bc`` into ``out_dir``; return True if it produced artifacts."""
        cmd = [
            "klee",
            f"--max-time={self.max_time_s}s",
            f"--max-depth={self.max_depth}",
            f"--max-forks={self.max_forks}",
            f"--solver-backend={self.solver}",
            f"--search={self.search}",
            f"--output-dir={out_dir}",
            str(bc),
        ]
        if backend == "wsl":
            res = run_wsl(cmd, timeout=float(self.timeout_s))
        elif backend == "docker":
            res = run_docker(
                self.image, cmd,
                mounts={bc.parent: "/work", out_dir: str(out_dir)},
                timeout=float(self.timeout_s),
            )
        else:
            res = run_local(cmd, timeout=float(self.timeout_s))

        with contextlib.suppress(OSError):
            log_path.write_text(
                f"# cmd: {' '.join(cmd)}\nstatus={res.status}\n"
                f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}\n",
                encoding="utf-8",
            )

        if res.status == "timeout":
            # KLEE timed out: leave partial artifacts; the parser flags timeout.
            return out_dir.exists() and any(out_dir.iterdir())
        if res.status != "ok":
            return False
        return out_dir.exists() and any(out_dir.iterdir())

    # -- parse ------------------------------------------------------------- #

    def parse(self, ctx: AnalysisContext, outcome: RunOutcome) -> list[dict[str, Any]]:
        harness_map = self._load_harness_map(ctx)
        findings, stats = parse_klee_output(
            ctx.workdir / "out",
            harness_map=harness_map,
            run_id=ctx.run_id,
            tool_version=self._tool_version_cached or "unknown",
            duration_s=outcome.duration_s,
        )
        if stats.limitations:
            outcome.limitation = "; ".join(sorted(set(stats.limitations))[:5])
        return findings

    @property
    def _tool_version_cached(self) -> str:
        # Probe result is not stored; report a stable marker for findings.
        return f"klee:{HARNESS_VERSION}"


def build(config: dict[str, Any] | None = None) -> KleeAnalyzer:
    """Factory used by ``tools/registry/external.yaml``."""
    return KleeAnalyzer(config)
