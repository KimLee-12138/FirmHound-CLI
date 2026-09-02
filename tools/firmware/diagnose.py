"""Firmware unpackability diagnosis for competition demos and triage."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from fsa.utils.hashing import sha256_file
from tools.firmware.collect_info import _binwalk_signatures
from tools.firmware.unpack import (
    CARVE_TARGETS,
    OPENSSL_SALTED_MAGIC,
    _check_extractors,
    _detect_strategy,
    _encrypted_signatures,
    _iter_magic_offsets,
)


def _sample_magic_hits(path: Path) -> list[dict[str, Any]]:
    """Return bounded magic hits used by the unpack fallback."""
    data = path.read_bytes()
    hits: list[dict[str, Any]] = []
    for target in CARVE_TARGETS:
        offsets = _iter_magic_offsets(data, target["magic"], max_hits=target["max_hits"])
        for offset in offsets:
            hits.append(
                {
                    "kind": target["kind"],
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "magic": target["magic"].hex(),
                }
            )
    salted = data.find(OPENSSL_SALTED_MAGIC)
    if salted >= 0 and not any(hit["offset"] == salted for hit in hits):
        hits.append(
            {
                "kind": "openssl-salted",
                "offset": salted,
                "offset_hex": hex(salted),
                "magic": OPENSSL_SALTED_MAGIC.hex(),
            }
        )
    hits.sort(key=lambda item: int(item["offset"]))
    return hits


def _recommendations(
    *,
    strategy: dict[str, Any] | None,
    encrypted: list[dict[str, Any]],
    extractors: dict[str, bool],
    magic_hits: list[dict[str, Any]],
) -> list[str]:
    """Generate plain-language next steps without pretending to decrypt firmware."""
    recs: list[str] = []
    if encrypted or any(hit["kind"] == "openssl-salted" for hit in magic_hits):
        recs.append(
            "检测到 OpenSSL Salted/加密载荷：需要厂商密码、密钥、"
            "升级工具解密逻辑或已解密中间固件。"
        )
        recs.append(
            "建议保存加密切片后逆向升级工具；不要把加密阻断样本写成"
            "无漏洞或解包成功。"
        )
    if strategy:
        missing = [
            tool[0]
            for tool in strategy.get("tools", [])
            if tool[0] not in {"dd", "gzip"} and not extractors.get(tool[0], False)
        ]
        if missing:
            missing_tools = ", ".join(sorted(set(missing)))
            recs.append(f"匹配到 {strategy['name']} 策略，但缺少提取器：{missing_tools}。")
        else:
            recs.append(
                f"匹配到 {strategy['name']} 策略，当前环境具备对应提取器，"
                "可尝试正式 unpack。"
            )
    elif magic_hits:
        kinds = ", ".join(sorted({str(hit["kind"]) for hit in magic_hits}))
        recs.append(f"未从 binwalk 直接匹配策略，但发现可 carving 魔数：{kinds}。")
    else:
        recs.append("未发现明确文件系统魔数，建议检查厂商头、压缩层或是否为差分/签名升级包。")
    if any(hit["kind"] == "squashfs" for hit in magic_hits) and not extractors.get("sasquatch"):
        recs.append(
            "发现 SquashFS 迹象但缺少 sasquatch；Tenda 等非标准 SquashFS 固件"
            "建议安装 sasquatch。"
        )
    return recs


def diagnose_firmware(path: str | Path) -> dict[str, Any]:
    """Diagnose how likely a firmware image can be unpacked in this environment."""
    firmware = Path(path).resolve()
    if not firmware.is_file():
        raise FileNotFoundError(f"Firmware not found: {firmware}")

    signatures = _binwalk_signatures(firmware)
    strategy = _detect_strategy(signatures)
    encrypted = _encrypted_signatures(signatures)
    extractors = _check_extractors()
    magic_hits = _sample_magic_hits(firmware)
    strategy_tools = strategy.get("tools", []) if strategy else []
    tool_ready = [
        tool[0] in {"dd", "gzip"} or shutil.which(tool[0]) is not None for tool in strategy_tools
    ]
    if encrypted or any(hit["kind"] == "openssl-salted" for hit in magic_hits):
        status = "blocked_needs_decryption"
        confidence = 0.2
    elif strategy and any(tool_ready):
        status = "likely_unpackable"
        confidence = 0.85
    elif any(hit["kind"] in {"squashfs", "ubi"} for hit in magic_hits):
        status = "carving_possible"
        confidence = 0.65
    else:
        status = "unknown"
        confidence = 0.3

    return {
        "status": status,
        "firmware": str(firmware),
        "size_bytes": firmware.stat().st_size,
        "sha256": sha256_file(firmware),
        "binwalk_available": bool(shutil.which("binwalk")),
        "signature_count": len(signatures),
        "signatures": signatures[:50],
        "selected_strategy": strategy["name"] if strategy else None,
        "extractors": extractors,
        "magic_hits": magic_hits[:80],
        "encrypted_indicators": encrypted,
        "confidence": confidence,
        "recommendations": _recommendations(
            strategy=strategy,
            encrypted=encrypted,
            extractors=extractors,
            magic_hits=magic_hits,
        ),
    }
