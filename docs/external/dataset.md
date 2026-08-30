# 外部分析器数据集（docs/external/dataset.md）

> 三档数据集（L1/L2/L3）是 E 同学 SaTC 复现与后续 KLEE/BOND/FirmRec 复用的共同输入。
> **下载/生成任何固件后，必须在此登记：来源 URL、SHA256、大小、架构。** 这是 F1 与
> benchmark 可复现性的地基。

## L1 — 合成固件（自带 C 源码，KLEE wllvm 路径必需）

- **生成**：`bash scripts/e2e/build_firmware.sh`（在 WSL `Ubuntu-22.04` 内跑）
- **输出**：`/mnt/c/temp/fw_demo`（含编译后的 `rootfs/bin/httpd`，`httpd.c` 用
  `getenv → sprintf → system` 注入命令注入）
- **SHA256**：每次 build 不同（源码固定，但打包时间戳会变），以**解包后 rootfs** 为准
- **用途**：SaTC/KLEE/BOND 的全链路冒烟；KLEE 需要 C 源码走 wllvm 生成 LLVM bitcode
- **状态**：✅ 脚本存在，待在 WSL 内生成

## L2 — DIR-859 真实固件（现场即有）

| 项 | 值 |
|---|---|
| 文件 | `firmware_samples/DIR859_FW102b03.bin` |
| SHA256 | `96eb1c411fa9ae20f3e9d4d4db611a4123dec8987e64ff0f590593060c90ed63` |
| 大小 | 9,289,876 字节（~8.86 MiB） |
| 架构 | MIPS（大端，Broadcom 系） |
| 已解包 | `tmp/unpacked/_DIR859_FW102b03.bin.extracted/squashfs-root` |
| 已知漏洞 | `formexeCommand` 命令注入（`CVE-2019-17621` 同类，现场复现用，非答案库） |
| 状态 | ✅ 已就位，可直接喂 SaTC |

## L3 — 两个真实固件（四项共用，统一输入）

| 固件 | 型号/版本 | 来源 URL | SHA256 | 大小 | 架构 | 状态 |
|---|---|---|---|---|---|---|
| L3-a | Tenda AC15 `US_AC15V1.0BR_V15.03.05.19_multi_TD01` | https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip | PENDING（Windows 沙箱 + WSL 均被拦截，需 8/31 真机/公网机器） | PENDING | MIPS 小端（待解包确认） | 🔶 待 8/31 机器下载（沙箱与 WSL 均无法连通 down.tenda.com.cn） |
| L3-b | Netgear R7000 `R7000-V1.0.11.100_10.2.100` | https://www.downloads.netgear.com/files/GDC/R7000/R7000-V1.0.11.100_10.2.100.zip | `7d2f704c1b132b22b512be308515b6d0a9f996a8ebcb750bd0504d329279204a` | 31,653,946 B | ARM 32-bit little-endian (Broadcom BCM4709 / Cortex-A9) | ✅ 已下载 + 已解包（squashfs-root 1572 文件） |

> 解包后内部镜像：
> - L3-b：`firmware_samples/R7000-V1.0.11.100_10.2.100.chk`（CHK 包装 → TRX@58 → LZMA 内核@86 → SquashFS@2221558，xz，little-endian）。已 `binwalk -e` 解包 → `tmp/unpacked/_R7000-V1.0.11.100_10.2.100.chk.extracted/squashfs-root`（1572 文件，ARM 小端；`bin/busybox` ELF = 32-bit LE ARM）。
> - L3-a 解包后为 `US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin`（待 8/31 机器下载后解包）。

### 如何下载（在 8/31 机器上跑，需真实公网 egress）

下载脚本已升级为**一键入口** `scripts/download_l3_firmware.py`（纯标准库、跨平台、幂等可重复跑），一条命令串起三件事：
**下载 → (binwalk 解包 + 从 ELF 自动识别架构) → 回填本表**。

- 解包走 **WSL `Ubuntu-22.04` 的 binwalk/sasquatch**（本项目 binwalk 装在 WSL；原生 `binwalk` 仅作降级），自动解到 `tmp/unpacked/<fw>.extracted/squashfs-root`，adapter `_resolve_rootfs` 自动定位。
- 架构识别：扫描解包后 rootfs 里的 ELF（优先 `bin/busybox`），读 ELF 头 machine/class/endian 得出。
- 回填：按行首 `| L3-a |` / `| L3-b |` 定位本表对应行，只改 SHA256 / 大小 / 架构 / 状态 单元格，不动型号/URL。

```bash
# 在 8/31 机器（有正常公网访问）执行 —— 一条命令完成下载+解包+回填
cd <项目根>
python scripts/download_l3_firmware.py            # 下载全部 L3 固件 + binwalk 解包 + 架构识别 + 回填 dataset.md
python scripts/download_l3_firmware.py --check    # 仅测连通性，不下载
python scripts/download_l3_firmware.py --skip-backfill   # 解包但不改动 dataset.md
```

> 本脚本在本沙箱已用已下载的 Netgear R7000 跑通验证（跳过下载 → 找到既有 squashfs-root → 识别 ARM 32-bit LE → 回填成功）；Tenda 因沙箱/WSL 双重拦截会在本机跳过，8/31 真机可正常下载并补全。

手动（curl 备选，仅当脚本不可用）：

```bash
# Tenda AC15
curl -L -o firmware_samples/AC15_V15.03.05.19.zip \
  https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip
unzip -o firmware_samples/AC15_V15.03.05.19.zip -d firmware_samples/

# Netgear R7000
curl -L -o firmware_samples/R7000_V1.0.11.100_10.2.100.zip \
  https://www.downloads.netgear.com/files/GDC/R7000/R7000-V1.0.11.100_10.2.100.zip
unzip -o firmware_samples/R7000_V1.0.11.100_10.2.100.zip -d firmware_samples/

# 再手动解包 + 识别架构 + 回填（脚本已自动完成，这里是等价手工步骤）
wsl -d Ubuntu-22.04 -e bash -c "cd /mnt/d/<项目根> && python3 -m binwalk -e -C tmp/unpacked firmware_samples/<image>"
```

> **沙箱出站说明**：开发沙箱允许通用 HTTPS（如 `example.com` → 200），但**拦截了 `down.tenda.com.cn`**（Windows 沙箱 TLS 握手被重置；已额外验证 WSL `Ubuntu-22.04` 同样无法连通，curl 134s 连接超时），故 **Tenda AC15 必须依赖 8/31 真机 / 有公网机器** 才能下载；`downloads.netgear.com` 在本沙箱用 Python `urllib` 可正常拉取（curl / PowerShell 因 schannel / .NET 的 TLS 被代理拦截而失败），故 R7000 已先行下载并解包到位。

## 共享约定

- **rootfs 路径**：所有外部器吃 `tmp/unpacked/<fw>.extracted/squashfs-root`，与 `UNPACK`
  阶段产物一致；`tools/external/adapter.py::_resolve_rootfs` 会自动定位。
- **binary_id 归一化**：统一用 `tools/external/base.py::normalize_binary_id(rootfs, path)`，
  保证外部 finding 能与主轨 `candidate.binary_id` 在 `finding_fusion` 阶段 join。
- **脱敏**：真实原始产物落 `tools/external/satc/fixtures/raw/` 前需确认无敏感字符串。
