"""Generate benchmark fixtures from the team's historical CVE reproductions."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUT_DIR = ROOT / "benchmarks" / "CVEs"

CVE_ENTRIES = [
    {
        "cve_id": "CVE-2017-17215",
        "reporter": "向禹",
        "vuln_class": "command_injection",
        "device": "Huawei HG532e",
        "route": "UPnP SOAP Upgrade",
        "binary": "upnpd",
        "handler": "Upgrade",
        "source_type": "soap_arg",
        "source_name": "NewStatusURL",
        "sink_function": "system",
        "auth_hint": "preauth",
        "references": [
            "https://xz.aliyun.com/news/90989",
            "https://xidp0.github.io/2025/07/12/CVE-2017-17215%20%E5%8D%8E%E4%B8%BAHG532%E8%B7%AF%E7%94%B1%E5%99%A8RCE%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0/",
        ],
    },
    {
        "cve_id": "CVE-2019-17621",
        "reporter": "李尚凯",
        "vuln_class": "command_injection",
        "device": "D-Link DIR-859",
        "route": "/soap.cgi",
        "binary": "soap.cgi",
        "handler": "soap_main",
        "source_type": "soap_arg",
        "source_name": "SOAPAction",
        "sink_function": "system",
        "auth_hint": "preauth",
        "references": [
            "https://www.cnblogs.com/m00nflower/p/15933470.html",
            "https://cn-sec.com/archives/1610453.html",
            "https://nightrainy.github.io/2020/02/25/DIR-859-RCE%E5%88%86%E6%9E%90-CVE-2019%E2%80%9317621%E5%A4%8D%E7%8E%B0/",
        ],
    },
    {
        "cve_id": "CVE-2019-16920",
        "reporter": "阮怡萍",
        "vuln_class": "command_injection",
        "device": "D-Link DIR-8xx",
        "route": "/cgi-bin/login.cgi",
        "binary": "login.cgi",
        "handler": "login_handler",
        "source_type": "http_param",
        "source_name": "captcha",
        "sink_function": "system",
        "auth_hint": "preauth",
        "references": [
            "https://www.iotsec-zone.com/article/355",
            "https://www.freesion.com/article/5502634955/",
            "https://blog.csdn.net/nullname0396/article/details/105679377",
        ],
    },
    {
        "cve_id": "CVE-2020-9373",
        "reporter": "李铭希",
        "vuln_class": "command_injection",
        "device": "TP-Link Archer",
        "route": "/cgi-bin/xxx.cgi",
        "binary": "httpd",
        "handler": "xxx_handler",
        "source_type": "http_param",
        "source_name": "ip",
        "sink_function": "system",
        "auth_hint": "auth",
        "references": [
            "https://cloud.tencent.com/developer/article/1599692",
            "https://www.023niu.com/show-62-565-1.html",
        ],
    },
    {
        "cve_id": "CVE-2018-5767",
        "reporter": "李子凌",
        "vuln_class": "command_injection",
        "device": "D-Link DIR-8xx",
        "route": "/HNAP1/",
        "binary": "hnapd",
        "handler": "SetRouterSettings",
        "source_type": "soap_arg",
        "source_name": "RemotePort",
        "sink_function": "system",
        "auth_hint": "auth",
        "references": [
            "https://blog.csdn.net/song_lee/article/details/113800058",
            "https://xz.aliyun.com/news/19106",
        ],
    },
    {
        "cve_id": "CVE-2020-10987",
        "reporter": "朱子琪",
        "vuln_class": "command_injection",
        "device": "D-Link DIR-8xx",
        "route": "/goform/formReboot",
        "binary": "httpd",
        "handler": "formReboot",
        "source_type": "http_param",
        "source_name": "submit_url",
        "sink_function": "system",
        "auth_hint": "preauth",
        "references": [
            "https://www.iotsec-zone.com/article/119",
            "https://nosec.org/home/detail/4634.html",
            "https://blog.csdn.net/song_lee/article/details/113800058",
        ],
    },
    {
        "cve_id": "CVE-2023-27021",
        "reporter": "吴静雯",
        "vuln_class": "command_injection",
        "device": "Tenda",
        "route": "/goform/SetOnlineDevName",
        "binary": "httpd",
        "handler": "formSetOnlineDevName",
        "source_type": "http_param",
        "source_name": "devicename",
        "sink_function": "system",
        "auth_hint": "preauth",
        "references": [
            "https://yhuanhuan01.github.io/2024/05/10/CVE-2023-27021/",
            "https://xz.aliyun.com/news/12949",
            "https://avd.aliyun.com/detail?id=AVD-2023-27021",
        ],
    },
    {
        "cve_id": "CVE-2021-31802",
        "reporter": "刘睿哲",
        "vuln_class": "overflow",
        "device": "NETGEAR R7000",
        "route": "/",
        "binary": "httpd",
        "handler": "http_request_handler",
        "source_type": "header",
        "source_name": "User-Agent",
        "sink_function": "strcpy",
        "auth_hint": "preauth",
        "references": [
            "https://www.anquanke.com/post/id/272402",
            "https://github.com/flamelu/Vulnerability-1/blob/main/NETGEAR%20R7000%20%E7%BC%93%E5%86%B2%E5%8C%BA%E6%BA%A2%E5%87%BA%E6%BC%8F%E6%B4%9E%EF%BC%88CVE-2021-31802%EF%BC%89.md",
            "https://cn-sec.com/archives/3872497.html",
        ],
    },
    {
        "cve_id": "CVE-2023-32154",
        "reporter": "甄茂阳",
        "vuln_class": "other",
        "device": "MikroTik RouterOS",
        "route": "L2TP/IPv6",
        "binary": "routeros",
        "handler": "ipv6_neighbor_discovery",
        "source_type": "socket_buf",
        "source_name": "nd_packet",
        "sink_function": "memcpy",
        "auth_hint": "preauth",
        "references": [
            "https://wood1314.github.io/year/08/29/clv60a9oi0000ap3fw38uc2mg/",
            "https://devco.re/blog/2024/05/24/pwn2own-toronto-2022-a-9-year-old-bug-in-mikrotik-routeros-en/",
            "https://research.qianxin.com/archives/1985",
            "https://www.zerodayinitiative.com/advisories/ZDI-23-710/",
        ],
        "needs_dynamic": True,
    },
]


def _attack_surface(entry: dict, run_id: str) -> dict:
    return {
        "run_id": run_id,
        "firmware_path": f"fixtures/{entry['cve_id'].lower().replace('-', '_')}.bin",
        "surfaces": [
            {
                "surface_id": f"surf-{entry['cve_id']}",
                "category": (
                    "upnp"
                    if entry["source_type"] == "soap_arg"
                    else ("web" if entry["route"].startswith("/goform") else "cgi")
                ),
                "protocol": "HTTP/UPnP" if entry["source_type"] == "soap_arg" else "HTTP",
                "binary": entry["binary"],
                "route": entry["route"],
                "handler": entry["handler"],
                "input_sources": [entry["source_type"]],
                "auth_hint": entry["auth_hint"],
                "startup_evidence": [f"etc/init.d/{entry['binary']}: start command found"],
                "reachability_hint": "LAN/WAN depending on daemon bind address",
                "confidence": 0.9,
                "evidence_ids": [f"ev-{entry['cve_id']}-surface"],
            }
        ],
    }


def _candidate(entry: dict) -> dict:
    cat = (
        "command_injection"
        if entry["vuln_class"] == "command_injection"
        else ("overflow" if entry["vuln_class"] == "overflow" else "other")
    )
    score = 28 if entry["auth_hint"] == "preauth" else 22
    level = "CRITICAL" if score >= 26 else "HIGH"
    return {
        "candidate_id": f"cand-{entry['cve_id']}",
        "surface_id": f"surf-{entry['cve_id']}",
        "binary_id": f"bin-{entry['cve_id']}",
        "entry": {"function": entry["handler"], "addr": "0x00405000"},
        "source": {"type": entry["source_type"], "name": entry["source_name"]},
        "transform": [{"type": "concat", "detail": "user input passed to shell template"}],
        "validation": [],
        "authorization": {"required": entry["auth_hint"] != "preauth", "evidence": []},
        "sink": {
            "function": entry["sink_function"],
            "type": "command_execution" if cat == "command_injection" else "memory_copy",
            "detail": (
                f"{entry['source_name']} reaches {entry['sink_function']}"
                " without length/filter check"
            ),
        },
        "call_chain": [entry["handler"], entry["sink_function"]],
        "user_control": "full",
        "vuln_class_hypothesis": cat,
        "risk_score": score,
        "risk_level": level,
        "evidence": [f"ev-{entry['cve_id']}-source", f"ev-{entry['cve_id']}-sink"],
        "counterevidence": [],
        "conclusion_category": (
            "confirmed-issue" if not entry.get("needs_dynamic") else "high-confidence-candidate"
        ),
        "decisive_missing_fact": (
            None
            if not entry.get("needs_dynamic")
            else "Requires dynamic validation in QEMU to confirm reachable crash"
        ),
        "status": "confirmed" if not entry.get("needs_dynamic") else "strong",
        "metadata": {
            "cve_id": entry["cve_id"],
            "reporter": entry["reporter"],
            "device": entry["device"],
            "references": entry["references"],
        },
    }


def _verdict(entry: dict, run_id: str) -> dict:
    action = "NEED_DYNAMIC" if entry.get("needs_dynamic") else "ACCEPT"
    return {
        "run_id": run_id,
        "verdicts": [
            {
                "candidate_id": f"cand-{entry['cve_id']}",
                "action": action,
                "original_score": 28 if entry["auth_hint"] == "preauth" else 22,
                "revised_score": 28 if entry["auth_hint"] == "preauth" else 22,
                "reasons": [
                    f"{entry['source_name']} is an external input reaching "
                    f"{entry['sink_function']}.",
                    "No effective filter or length check found.",
                    "Call chain from handler to sink is supported by static evidence.",
                ],
                "supporting_evidence": [
                    f"ev-{entry['cve_id']}-source",
                    f"ev-{entry['cve_id']}-sink",
                ],
                "counterevidence": [],
                "reviewer": "rule",
            }
        ],
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for entry in CVE_ENTRIES:
        run_id = f"run-{entry['cve_id'].lower()}"
        cve_dir = OUT_DIR / entry["cve_id"]
        cve_dir.mkdir(parents=True, exist_ok=True)
        (cve_dir / "attack_surface.json").write_text(
            json.dumps(_attack_surface(entry, run_id), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (cve_dir / "candidate.json").write_text(
            json.dumps(_candidate(entry), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (cve_dir / "verdict.json").write_text(
            json.dumps(_verdict(entry, run_id), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    print(f"Generated fixtures under {OUT_DIR}")


if __name__ == "__main__":
    main()
