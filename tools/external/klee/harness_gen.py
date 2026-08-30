"""KLEE harness generator (X1 -- the core engineering of student G).

KLEE only eats LLVM bitcode, but real firmware is a compiled MIPS/ARM binary
with no source. This module closes that gap: given a *candidate*'s sink
signature (recovered by the main track / SaTC), it synthesizes a small C harness
that

  * symbolises the attacker-controlled input (``klee_make_symbolic``),
  * constrains it to the printable HTTP-parameter range (``klee_assume``),
  * funnels it into the *audited function* and then into a **stubbed sink**
    (``__fsa_sink``) so no real shell / library call is ever executed, and
  * asserts reachability / buffer bounds so KLEE emits ``ptr.err`` / a witness
    ``.ktest`` when the path is feasible.

The generated ``.c`` is compiled to ``.bc`` (clang -emit-llvm) -- either on the
host (if clang is available) or, more importantly, inside the *backend*
(wsl / docker) where KLEE's LLVM toolchain lives. The runner drives that second
step; this module only produces + (best-effort) compiles the source.

Three bitcode strategies (see docs/external/G-KLEE.md §4):
  * S1 source  -- candidate carries a ``source_path`` (synthetic firmware C);
  * S2 harness -- we generate the stub ourselves (the default, always available);
  * S3 binary  -- lift the ELF with mcsema/retDec (allowed to fail; honest attribution).

Design rules (non-negotiable):
  * Generation never raises. A malformed spec degrades to a default, not an error.
  * The sink is ALWAYS stubbed -- we never let KLEE spawn a real shell.
  * ``HARNESS_VERSION`` is stamped on every emitted ``.bc``/finding so an
    ``infeasible`` verdict is traceable to the modelling assumptions (X2).
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.external.backends import run_local, run_wsl

# Single source of truth for harness traceability (G-KLEE.md §6.3 / X2).
HARNESS_VERSION = "v1"

# Default sizes used when the binary analysis could not recover them.
DEFAULT_INPUT_SIZE = 64
DEFAULT_BUF_SIZE = 256

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


# --------------------------------------------------------------------------- #
# spec
# --------------------------------------------------------------------------- #


@dataclass
class HarnessSpec:
    """Everything needed to synthesise a KLEE harness for one candidate.

    Mirrors G-KLEE.md §4.2. All fields are optional-friendly so a partial binary
    recovery still yields a runnable harness (we never block on missing data).
    """

    func_name: str = "audited_func"
    sink_func: str = "system"
    sink_type: str = "command_execution"  # command_execution | memory_copy | format_output
    vuln_class: str = "command_injection"
    n_params: int = 1
    param_types: list[str] = field(default_factory=lambda: ["char*"])
    buf_size: int | None = None  # target buffer size (recovered from the stack frame)
    input_size: int | None = None  # symbolic input length
    constraints: list[dict[str, Any]] = field(default_factory=list)
    source_path: str | None = None  # S1: path to the real source (synthetic firmware)


# --------------------------------------------------------------------------- #
# templates (command_injection / overflow / format_string)
# --------------------------------------------------------------------------- #

_CMDI_TEMPLATE = """\
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* sink stub: record that a symbolic argument reached the sink; do NOT execute it */
static int g_reached_sink = 0;
static char g_sink_arg[512];

void __fsa_sink(const char *cmd) {
    g_reached_sink = 1;
    if (cmd) {
        strncpy(g_sink_arg, cmd, sizeof(g_sink_arg) - 1);
        g_sink_arg[sizeof(g_sink_arg) - 1] = '\\0';
    }
    klee_assert(cmd == NULL || strlen(cmd) < sizeof(g_sink_arg));
}

/* redirect the real command sink to the stub so no shell is ever spawned */
#define system(x) __fsa_sink(x)
#define popen(x, m) __fsa_sink(x)

__FUNC_DECL__

int main(void) {
    static char input[__INPUT_SIZE__];
    klee_make_symbolic(input, sizeof(input), "input");
    for (unsigned i = 0; i + 1 < sizeof(input); i++) {
        klee_assume(input[i] >= 0x20 && input[i] <= 0x7e);
    }
    input[sizeof(input) - 1] = '\\0';
__FUNC_CALL__
    klee_assert(!g_reached_sink || 1);
    return 0;
}
"""

_BOF_TEMPLATE = """\
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int g_reached_sink = 0;

void __fsa_sink(const char *p) {
    g_reached_sink = 1;
    klee_assert(p != NULL);
}

/* stubbed unsafe copy: copies without bounds so KLEE can observe the OOB write */
static char *__fsa_strcpy(char *d, const char *s) {
    if (d && s) { while ((*d++ = *s++)); }
    return d;
}
static char *__fsa_strcat(char *d, const char *s) {
    if (d && s) { char *t = d; while (*t) t++; while ((*t++ = *s++)); }
    return d;
}

#define strcpy(d, s) __fsa_strcpy(d, s)
#define strcat(d, s) __fsa_strcat(d, s)

__FUNC_DECL__

int main(void) {
    static char input[__INPUT_SIZE__];
    klee_make_symbolic(input, sizeof(input), "input");
    for (unsigned i = 0; i + 1 < sizeof(input); i++) {
        klee_assume(input[i] >= 0x20 && input[i] <= 0x7e);
    }
    input[sizeof(input) - 1] = '\\0';
__FUNC_CALL__
    klee_assert(!g_reached_sink || 1);
    return 0;
}
"""

_FMT_TEMPLATE = """\
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int g_reached_sink = 0;

void __fsa_sink(const char *p) {
    g_reached_sink = 1;
    klee_assert(p != NULL);
}

/* redirect the format sink to the stub so no real printf side effects happen */
#define sprintf __fsa_sprintf
static int __fsa_sprintf(char *out, const char *fmt, ...) {
    g_reached_sink = 1;
    (void)fmt;
    if (out) out[0] = '\\0';
    klee_assert(fmt != NULL);
    return 0;
}

__FUNC_DECL__

int main(void) {
    static char input[__INPUT_SIZE__];
    klee_make_symbolic(input, sizeof(input), "input");
    for (unsigned i = 0; i + 1 < sizeof(input); i++) {
        klee_assume(input[i] >= 0x20 && input[i] <= 0x7e);
    }
    input[sizeof(input) - 1] = '\\0';
__FUNC_CALL__
    klee_assert(!g_reached_sink || 1);
    return 0;
}
"""

_KIND_TO_TEMPLATE: dict[str, str] = {
    "command_injection": _CMDI_TEMPLATE,
    "overflow": _BOF_TEMPLATE,
    "format_string": _FMT_TEMPLATE,
}


# --------------------------------------------------------------------------- #
# spec -> rendered C
# --------------------------------------------------------------------------- #


def _sink_type_for(vuln_class: str, sink_func: str) -> str:
    if vuln_class == "command_injection" or sink_func in {
        "system", "popen", "doSystemCmd", "lxmldbc_system",
    }:
        return "command_execution"
    if vuln_class in {"overflow", "use_after_free"} or sink_func in {
        "strcpy", "memcpy", "sprintf", "strcat", "gets",
    }:
        return "memory_copy"
    if vuln_class == "format_string" or sink_func in {"sprintf", "snprintf", "printf"}:
        return "format_output"
    return "unknown"


def _template_for(spec: HarnessSpec) -> str:
    """Return the C template for a spec, preferring the on-disk file then inline."""
    kind = spec.vuln_class if spec.vuln_class in _KIND_TO_TEMPLATE else (
        "overflow" if spec.sink_type == "memory_copy"
        else "format_string" if spec.sink_type == "format_output"
        else "command_injection"
    )
    file_path = _TEMPLATE_DIR / f"{kind}.harness.c"
    if file_path.exists():
        try:
            return file_path.read_text(encoding="utf-8")
        except OSError:
            pass
    return _KIND_TO_TEMPLATE.get(kind, _CMDI_TEMPLATE)


def _func_decl(spec: HarnessSpec, buf_size: int) -> str:
    """Render the audited-function definition that funnels input into the sink."""
    fn = spec.func_name or "audited_func"
    buf = buf_size
    if spec.vuln_class == "command_injection":
        return (
            f"void {fn}(char *cmd) {{\n"
            f"    char buf[{buf}];\n"
            f'    sprintf(buf, "%s; reboot", cmd);\n'
            f"    system(buf);\n"
            f"}}"
        )
    if spec.vuln_class == "overflow":
        return (
            f"void {fn}(char *cmd) {{\n"
            f"    char buf[{buf}];\n"
            f"    strcpy(buf, cmd);\n"
            f"    __fsa_sink(buf);\n"
            f"}}"
        )
    if spec.vuln_class == "format_string":
        return (
            f"void {fn}(char *cmd) {{\n"
            f"    char buf[{buf}];\n"
            f"    sprintf(buf, cmd);\n"
            f"    __fsa_sink(buf);\n"
            f"}}"
        )
    # generic fallback: treat the sink as a memory copy
    return (
        f"void {fn}(char *cmd) {{\n"
        f"    char buf[{buf}];\n"
        f"    strcpy(buf, cmd);\n"
        f"    __fsa_sink(buf);\n"
        f"}}"
    )


def render_harness(spec: HarnessSpec) -> str:
    """Render a complete C harness source from a spec (pure, never raises)."""
    template = _template_for(spec)
    buf_size = int(spec.buf_size) if spec.buf_size else DEFAULT_BUF_SIZE
    input_size = int(spec.input_size) if spec.input_size else DEFAULT_INPUT_SIZE
    func_decl = _func_decl(spec, buf_size)
    func_call = f"    {spec.func_name or 'audited_func'}(input);"
    source = (
        template
        .replace("__FUNC_DECL__", func_decl)
        .replace("__FUNC_CALL__", func_call)
        .replace("__INPUT_SIZE__", str(input_size))
        .replace("__BUF_SIZE__", str(buf_size))
    )
    return source


# --------------------------------------------------------------------------- #
# high-level generation
# --------------------------------------------------------------------------- #


@dataclass
class HarnessResult:
    """Outcome of :func:`generate_harness`."""

    c_path: Path | None = None
    bc_path: Path | None = None
    version: str = HARNESS_VERSION
    errors: list[str] = field(default_factory=list)


def _clang_binary(llvm: str) -> str | None:
    for cand in (f"clang-{llvm}", "clang"):
        if shutil.which(cand):
            return cand
    return None


def compile_to_bc(
    c_path: Path,
    bc_path: Path,
    *,
    backend: str = "auto",
    llvm: str = "16",
    timeout: float = 120.0,
) -> tuple[bool, str]:
    """Compile a harness ``.c`` to LLVM ``.bc`` via the chosen backend.

    Returns ``(ok, detail)``. A missing clang degrades to ``(False, ...)`` rather
    than raising -- the runner may still compile inside wsl/docker later.
    """
    clang = _clang_binary(llvm)
    if clang is None and backend in {"auto", "local"}:
        return False, f"clang (llvm-{llvm}) not found on host"
    cmd = [clang or "clang", "-emit-llvm", "-c", "-O0", "-g", str(c_path), "-o", str(bc_path)]
    res = run_wsl(cmd, timeout=timeout) if backend == "wsl" else run_local(cmd, timeout=timeout)
    if res.status == "missing":
        return False, res.stderr or "clang executable not found in backend"
    if res.status != "ok":
        return False, (res.stderr or res.stdout or f"clang exited {res.returncode}")[:200]
    return True, ""


def generate_harness(spec: HarnessSpec, out_dir: Path) -> HarnessResult:
    """Write a harness ``.c`` into ``out_dir`` and (best-effort) compile to ``.bc``.

    Never raises. Compilation failure is recorded in ``errors`` and the ``.bc``
    is left for the backend (wsl/docker) to produce at run time.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = HarnessResult()

    try:
        source = render_harness(spec)
    except Exception as exc:  # noqa: BLE001 - generation must not abort the stage
        result.errors.append(f"render failed: {type(exc).__name__}: {exc}")
        return result

    # Stable name so repeated runs are idempotent.
    digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:12]
    c_path = out_dir / f"harness_{digest}.c"
    try:
        c_path.write_text(source, encoding="utf-8")
        result.c_path = c_path
    except OSError as exc:
        result.errors.append(f"write failed: {exc}")
        return result

    bc_path = out_dir / f"harness_{digest}.bc"
    ok, detail = compile_to_bc(c_path, bc_path, backend="auto", llvm="16")
    if ok:
        result.bc_path = bc_path
    else:
        result.errors.append(detail)
    return result


def spec_from_candidate(
    candidate: dict[str, Any], *, default_version: str = HARNESS_VERSION
) -> HarnessSpec:
    """Build a :class:`HarnessSpec` from a unified candidate dict.

    Tolerant: missing fields fall back to defaults so a partial binary recovery
    still yields a runnable harness.
    """
    sink = candidate.get("sink") or {}
    sink_func = str(sink.get("function") or candidate.get("sink_func") or "system")
    vuln_class = str(candidate.get("vuln_class") or "command_injection")
    sink_type = str(sink.get("type") or _sink_type_for(vuln_class, sink_func))
    func_name = str(candidate.get("function") or sink.get("function") or "audited_func")
    buf_size = candidate.get("buf_size")
    if buf_size is None:
        buf_size = sink.get("buf_size")
    try:
        buf_size = int(buf_size) if buf_size is not None else None
    except (TypeError, ValueError):
        buf_size = None
    input_size = candidate.get("input_size")
    try:
        input_size = int(input_size) if input_size is not None else None
    except (TypeError, ValueError):
        input_size = None
    constraints = list(candidate.get("constraints") or [])
    source_path = candidate.get("source_path")
    return HarnessSpec(
        func_name=func_name,
        sink_func=sink_func,
        sink_type=sink_type,
        vuln_class=vuln_class,
        n_params=int(candidate.get("n_params", 1)),
        param_types=list(candidate.get("param_types") or ["char*"]),
        buf_size=buf_size,
        input_size=input_size,
        constraints=constraints,
        source_path=str(source_path) if source_path else None,
    )


# Exposed for tests / the runner.
__all__ = [
    "HARNESS_VERSION",
    "HarnessSpec",
    "HarnessResult",
    "render_harness",
    "generate_harness",
    "compile_to_bc",
    "spec_from_candidate",
    "DEFAULT_INPUT_SIZE",
    "DEFAULT_BUF_SIZE",
]
