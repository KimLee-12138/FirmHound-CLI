"""Unit tests for the KLEE harness generator (X1, G-KLEE.md §4.2 / §7.1).

Covers HarnessSpec -> C generation for command-injection / overflow, buffer-size
handling, missing-data defaults, and candidate extraction. The *real KLEE* run
(the ``@pytest.mark.slow`` compile test) is skipped unless clang and KLEE headers are present
(G-KLEE.md §7.2 CI constraint).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tools.external.klee.harness_gen import (
    DEFAULT_BUF_SIZE,
    HARNESS_VERSION,
    HarnessSpec,
    compile_to_bc,
    generate_harness,
    render_harness,
    spec_from_candidate,
)


def test_cmdi_harness_contains_markers():
    spec = HarnessSpec(
        func_name="formexeCommand", sink_func="system", vuln_class="command_injection"
    )
    src = render_harness(spec)
    assert "klee_make_symbolic" in src
    assert "klee_assume" in src
    # printable-range constraint present
    assert "0x20" in src and "0x7e" in src
    assert "__fsa_sink" in src
    assert "system(buf)" in src
    assert HARNESS_VERSION == "v1"


def test_overflow_harness_uses_buf_size_and_stub():
    spec = HarnessSpec(
        func_name="dangerous_func", sink_func="strcpy", vuln_class="overflow", buf_size=32
    )
    src = render_harness(spec)
    assert "char buf[32]" in src
    assert "__fsa_strcpy" in src
    assert "strcpy(buf, cmd)" in src


def test_missing_buf_size_falls_back_to_default():
    spec = HarnessSpec(func_name="f", sink_func="strcpy", vuln_class="overflow")
    src = render_harness(spec)
    assert f"char buf[{DEFAULT_BUF_SIZE}]" in src


def test_format_string_harness_renders():
    spec = HarnessSpec(func_name="fmt_func", sink_func="sprintf", vuln_class="format_string")
    src = render_harness(spec)
    assert "sprintf(buf, cmd)" in src
    assert "__fsa_sink" in src


def test_spec_from_candidate_recovers_sink():
    candidate = {
        "binary_id": "sbin/httpd",
        "vuln_class": "command_injection",
        "sink": {"function": "system", "addr": "0x40a100", "type": "command_execution"},
        "buf_size": 128,
    }
    spec = spec_from_candidate(candidate)
    assert spec.sink_func == "system"
    assert spec.vuln_class == "command_injection"
    assert spec.buf_size == 128


def test_generate_harness_writes_c(tmp_path):
    spec = HarnessSpec(
        func_name="formexeCommand", sink_func="system", vuln_class="command_injection"
    )
    res = generate_harness(spec, tmp_path)
    assert res.c_path is not None and res.c_path.exists()
    text = res.c_path.read_text(encoding="utf-8")
    assert "klee_make_symbolic" in text
    # compile may or may not succeed on the host; we only assert the .c landed.
    assert res.version == HARNESS_VERSION


@pytest.mark.slow
def test_compile_to_bc_with_real_clang(tmp_path):
    clang = shutil.which("clang-16") or shutil.which("clang")
    if clang is None:
        pytest.skip("clang not installed; KLEE bitcode compile requires LLVM")
    header_probe = subprocess.run(
        [clang, "-E", "-x", "c", "-"],
        input="#include <klee/klee.h>\n",
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if header_probe.returncode != 0:
        pytest.skip("KLEE headers not installed; bitcode compile requires klee/klee.h")
    spec = HarnessSpec(
        func_name="formexeCommand", sink_func="system", vuln_class="command_injection"
    )
    res = generate_harness(spec, tmp_path)
    assert res.c_path is not None
    bc = tmp_path / "out.bc"
    ok, detail = compile_to_bc(res.c_path, bc, backend="local", llvm="16")
    assert ok, detail
    assert bc.exists()
