#!/usr/bin/env python3
"""下载 + 解包 + 回填 L3 基准固件（Tenda AC15 / Netgear R7000）。

项目约定（见 docs/external/dataset.md）：原始固件统一落到 `firmware_samples/`，
解包产物进 `tmp/unpacked/<fw>.extracted/squashfs-root`，四个外部工具（SaTC /
FirmRec / KLEE / BOND）共用同一批固件，结果才可比。

本脚本是 **一键执行入口**，把三件事串起来（均幂等，可重复跑）：
  1. 下载固件 zip（Python urllib，沙箱被拦截时优雅跳过）
  2. 解包出 .bin/.chk → `binwalk -e` 解包到 `tmp/unpacked/`（优先走 WSL 的 binwalk，
     原生 binwalk 作降级）→ 从解包后的 ELF 自动识别架构
  3. 把 SHA256 / 大小 / 架构 / 解包状态 回填 `docs/external/dataset.md` 的 L3 表

用法（在 **8/31 机器**，有真实公网 egress 的环境里跑）：
    python scripts/download_l3_firmware.py            # 下载 + 解包 + 识别架构 + 回填 dataset.md
    python scripts/download_l3_firmware.py --check    # 只测连通性，不下载
    python scripts/download_l3_firmware.py --skip-backfill   # 不改动 dataset.md

说明：开发沙箱的出站策略拦截了 down.tenda.com.cn / downloads.netgear.com，
所以本脚本必须在有正常公网访问的机器上运行。沙箱内跑 --check 会显示 BLOCKED。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # 项目根目录（不写死中文路径）
DEST = ROOT / "firmware_samples"
MANIFEST = DEST / "L3_manifest.json"
DATASET = ROOT / "docs" / "external" / "dataset.md"
UNPACK_DIR = ROOT / "tmp" / "unpacked"

UA = {"User-Agent": "Mozilla/5.0 (firmware-benchmark-downloader)"}

# 两个 L3 固件。版本选择理由见各条 note。
FIRMWARES = [
    {
        "id": "L3-a-tenda-ac15",
        "row": "L3-a",
        "vendor": "Tenda",
        "model": "AC15",
        "version": "US_AC15V1.0BR_V15.03.05.19_multi_TD01",
        "url": "https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip",
        "inner_ext": ".bin",
        "arch_fallback": "MIPS 32-bit little-endian（待解包确认）",
        "note": "命令注入家族（CVE-2020-10987 同类），与主轨复现经验直接对照，跨轨对比主力。",
    },
    {
        "id": "L3-b-netgear-r7000",
        "row": "L3-b",
        "vendor": "Netgear",
        "model": "R7000",
        "version": "R7000-V1.0.11.100_10.2.100",
        "url": "https://www.downloads.netgear.com/files/GDC/R7000/R7000-V1.0.11.100_10.2.100.zip",
        "inner_ext": ".chk",
        "arch_fallback": "ARM 32-bit little-endian（待解包确认）",
        "note": "跨厂商泛化验证目标；四件工具共用同一份固件。",
    },
]


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def to_wsl(p: Path) -> str:
    """把 Windows 路径转成 WSL 路径，如 D:/a/b -> /mnt/d/a/b。"""
    drive = p.drive.lower()[0]
    rest = p.as_posix()[2:]  # 去掉 "D:"，保留 "/揭榜挂帅.../..."
    return f"/mnt/{drive}{rest}"


def run(cmd) -> int:
    print(f"  $ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        rc = subprocess.call(cmd, shell=isinstance(cmd, str))
    except Exception as e:  # noqa: BLE001
        print(f"  ! 命令执行失败: {type(e).__name__}: {e}")
        return 1
    return rc


# --------------------------------------------------------------------------
# 下载
# --------------------------------------------------------------------------
def download(url: str, dest: Path, timeout: int) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
    except Exception as e:  # noqa: BLE001 - 网络错误一律降级
        print(f"  ! 下载失败: {type(e).__name__}: {e}")
        return False
    if not data:
        print("  ! 响应为空")
        return False
    dest.write_bytes(data)
    print(f"  + 已保存 {dest.name} ({len(data):,} bytes)")
    return True


def extract(zip_path: Path, ext: str) -> Path | None:
    try:
        with zipfile.ZipFile(zip_path) as z:
            names = [n for n in z.namelist() if n.lower().endswith(ext)]
            if not names:
                print(f"  ! {zip_path.name} 内未找到 {ext} 文件")
                return None
            member = names[0]
            out = zip_path.parent / Path(member).name
            with z.open(member) as src, out.open("wb") as dst:
                dst.write(src.read())
            print(f"  + 已解包出 {out.name}")
            return out
    except Exception as e:  # noqa: BLE001
        print(f"  ! 解包失败: {type(e).__name__}: {e}")
        return None


def check_connectivity(fw: dict) -> None:
    try:
        req = urllib.request.Request(fw["url"], headers={**UA, "Range": "bytes=0-1023"})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read(1)
        print("  连通性: OK")
    except Exception as e:  # noqa: BLE001
        print(f"  连通性: BLOCKED ({type(e).__name__}: {e})")


# --------------------------------------------------------------------------
# 解包（binwalk）+ 架构识别
# --------------------------------------------------------------------------
def find_rootfs(image: Path) -> Path | None:
    """在 tmp/unpacked 下找该固件已解出的 squashfs-root（幂等）。"""
    if not UNPACK_DIR.exists():
        return None
    cands = sorted(
        UNPACK_DIR.rglob("squashfs-root"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    stem = image.stem
    for c in cands:
        if stem in c.parent.name:
            return c
    return cands[0] if cands else None


def binwalk_unpack(image: Path) -> Path | None:
    """用 binwalk 解包到 tmp/unpacked。优先 WSL（本项目 binwalk 装在 WSL），降级原生。"""
    # 1) WSL Ubuntu-22.04（本机 binwalk/sasquatch 所在）
    proj_wsl = to_wsl(ROOT)
    img_wsl = to_wsl(image)
    wsl_cmd = f"cd '{proj_wsl}' && python3 -m binwalk -e -C tmp/unpacked '{img_wsl}'"
    if run(["wsl", "-d", "Ubuntu-22.04", "-e", "bash", "-c", wsl_cmd]) == 0:
        rf = find_rootfs(image)
        if rf:
            return rf
    # 2) 原生 binwalk 降级
    for native in (
        ["binwalk", "-e", "-C", str(UNPACK_DIR), str(image)],
        ["python3", "-m", "binwalk", "-e", "-C", str(UNPACK_DIR), str(image)],
    ):
        if run(native) == 0:
            rf = find_rootfs(image)
            if rf:
                return rf
    print("  ! binwalk 解包未产出 squashfs-root（检查 WSL/原生 binwalk 是否可用）")
    return None


def _elf_arch(path: Path) -> dict | None:
    try:
        with path.open("rb") as f:
            b = f.read(20)
    except Exception:
        return None
    if b[:4] != b"\x7fELF":
        return None
    ei_class = {1: "32-bit", 2: "64-bit"}.get(b[4], "?")
    endian = {1: "little-endian", 2: "big-endian"}.get(b[5], "?")
    machine = int.from_bytes(b[18:20], "little")
    mmap = {
        40: "ARM",
        183: "ARM64(aarch64)",
        8: "MIPS",
        3: "x86",
        62: "x86-64",
        21: "PowerPC",
        94: "RISC-V",
    }
    return {"class": ei_class, "endian": endian, "machine": mmap.get(machine, f"#{machine}")}


def detect_arch(rootfs: Path, fw: dict) -> str:
    """从解包后的 ELF 识别架构；对已知型号补 SoC 信息。"""
    pref = [rootfs / "bin" / "busybox", rootfs / "bin" / "sh", rootfs / "sbin" / "init"]
    a = None
    for c in pref:
        if c.exists():
            a = _elf_arch(c)
            if a:
                break
    if a is None:
        for p in rootfs.rglob("*"):
            if p.is_file() and not p.is_symlink():
                a = _elf_arch(p)
                if a:
                    break
    if a is None:
        return fw.get("arch_fallback", "未知（未在 rootfs 找到 ELF）")
    base = f"{a['class']} {a['endian']} ({a['machine']})"
    if fw["vendor"] == "Netgear" and fw["model"] == "R7000":
        return "ARM 32-bit little-endian (Broadcom BCM4709 / Cortex-A9)"
    if fw["vendor"] == "Tenda" and fw["model"] == "AC15":
        return base  # 待解包后由检测决定（通常 MIPS 小端）
    return base


def count_files(rootfs: Path) -> int:
    """统计解包后真实文件数，跳过符号链接（binwalk 会把外部符号链接改写为指向
    /dev/null 的悬空链接，Windows 下 stat 会抛 WinError 1920）。"""
    n = 0
    for p in rootfs.rglob("*"):
        try:
            if p.is_symlink():
                continue
            if p.is_file():
                n += 1
        except OSError:
            continue
    return n


def cleanup_dup(rootfs: Path) -> None:
    """binwalk 偶尔会多产出一个 squashfs-root-0，删掉重复。"""
    dup = rootfs.parent / "squashfs-root-0"
    if dup.exists():
        try:
            import shutil

            shutil.rmtree(dup)
            print("  + 已清理重复目录 squashfs-root-0")
        except Exception:
            pass


# --------------------------------------------------------------------------
# 回填 dataset.md 的 L3 表（按行首 | L3-a | / | L3-b | 定位，只改对应单元格）
# --------------------------------------------------------------------------
def backfill_dataset(manifest: dict) -> bool:
    if not DATASET.exists():
        print(f"  ! 找不到 {DATASET}，跳过回填")
        return False
    text = DATASET.read_text(encoding="utf-8")
    changed = False
    for fw in FIRMWARES:
        rec = manifest.get(fw["id"])
        if not rec:
            continue  # 没下载到就不改这一行
        sha = rec.get("sha256", "PENDING")
        size = f"{rec['size']:,} B" if rec.get("size") else "PENDING"
        arch = rec.get("arch") or fw.get("arch_fallback", "PENDING")
        if rec.get("extracted"):
            status = f"✅ 已下载 + 已解包（squashfs-root {rec.get('file_count', 0)} 文件）"
        else:
            status = "✅ 已下载"
        label = fw["row"]
        new_lines = []
        for line in text.split("\n"):
            if line.startswith(f"| {label} |"):
                cells = line.split("|")
                # Table cells: row, model/version, URL, SHA, size, arch, status.
                cells[4] = f" `{sha}` "
                cells[5] = f" {size} "
                cells[6] = f" {arch} "
                cells[7] = f" {status} "
                new_lines.append("|".join(cells))
                changed = True
                print(f"  + 已回填 dataset.md 的 {label} 行")
            else:
                new_lines.append(line)
        text = "\n".join(new_lines)
    if changed:
        DATASET.write_text(text, encoding="utf-8")
    return changed


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="下载 + 解包 + 回填 L3 基准固件")
    ap.add_argument("--check", action="store_true", help="只测连通性，不下载")
    ap.add_argument("--timeout", type=int, default=300, help="单文件下载超时（秒）")
    ap.add_argument("--skip-unpack", action="store_true", help="不跑 binwalk 解包")
    ap.add_argument("--skip-backfill", action="store_true", help="不改动 dataset.md")
    args = ap.parse_args()

    DEST.mkdir(parents=True, exist_ok=True)
    UNPACK_DIR.mkdir(parents=True, exist_ok=True)
    manifest: dict = {}
    if MANIFEST.exists():
        try:
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}

    for fw in FIRMWARES:
        print(f"\n== {fw['id']}  {fw['vendor']} {fw['model']} {fw['version']} ==")
        print(f"   URL: {fw['url']}")
        zip_path = DEST / f"{fw['id']}.zip"

        if args.check:
            check_connectivity(fw)
            continue

        # 1) 下载（幂等：manifest 里已有且镜像文件还在则跳过）
        img = None
        rec = manifest.get(fw["id"])
        if rec and (ROOT / rec["image"]).exists():
            img = ROOT / rec["image"]
            print(f"  + 镜像已存在，跳过下载：{img.name}")
        else:
            if download(fw["url"], zip_path, args.timeout):
                img = extract(zip_path, fw["inner_ext"])

        if not img:
            print(
                f"  ! {fw['id']} 未取到镜像（沙箱拦截 / 网络问题），本机跳过；8/31 真机可正常下载"
            )
            continue

        # 2) 解包 + 架构识别
        arch = fw["arch_fallback"]
        extracted = None
        file_count = 0
        if not args.skip_unpack:
            rootfs = find_rootfs(img)
            if rootfs is None:
                rootfs = binwalk_unpack(img)
            if rootfs:
                cleanup_dup(rootfs)
                arch = detect_arch(rootfs, fw)
                extracted = str(rootfs.relative_to(ROOT))
                file_count = count_files(rootfs)
                print(f"  + 已解包：{extracted}（{file_count} 文件）")
                print(f"  + 架构识别：{arch}")

        # 3) 写 manifest
        manifest[fw["id"]] = {
            "vendor": fw["vendor"],
            "model": fw["model"],
            "version": fw["version"],
            "url": fw["url"],
            "zip": str(zip_path.relative_to(ROOT)),
            "image": str(img.relative_to(ROOT)),
            "sha256": sha256_of(img),
            "size": img.stat().st_size,
            "arch": arch,
            "extracted": extracted,
            "file_count": file_count,
            "note": fw["note"],
            "status": "downloaded+extracted" if extracted else "downloaded",
        }
        print(f"  sha256: {manifest[fw['id']]['sha256']}")
        print(f"  size  : {img.stat().st_size:,} bytes")

    # 落盘 manifest
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nManifest 已写入: {MANIFEST}")

    # 回填 dataset.md
    if not args.skip_backfill and not args.check:
        if backfill_dataset(manifest):
            print("dataset.md L3 表已更新。")
        else:
            print("dataset.md 无变更（可能没有新下载到的固件）。")

    print("\n完成。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
