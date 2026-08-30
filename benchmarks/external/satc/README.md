# SaTC 复现基准（benchmarks/external/satc）

> E 同学（外部分析组组长）的复现记录。本目录沉淀 **版本 / commit / 镜像 tag / 耗时基线**，
> 供后续 KLEE(B)、BOND(H)、FirmRec(F) 复用时对照。

## 工具版本（固定，复现必须锁定）

| 项 | 值 |
|---|---|
| 论文 | USENIX Security 2021, *Sharing More and Checking Less* (NSSL-SJTU/SaTC) |
| 镜像 | `smile0304/satc` |
| 镜像 digest | `sha256:74fe4d43afc2eb8f702d0d4309619f4f1ad9aa0d490637226912cb4fbd497fe4`（本机 `docker image inspect` 已确认，2026-08-30） |
| 上游 commit | `PENDING`（如自 build，记录 `git rev-parse HEAD`） |
| 依赖 | Docker + Ghidra(JDK11+) + angr（均内置于镜像） |
| 单固件单脚本量级 | 30–90 min；带 `--taint_check` 显著变慢 |
| Ghidra 内存峰值 | 建议 ≥16G，最好 32G |

## 运行配置（4 种 Ghidra 脚本 × 2 档 taint）

- 脚本：`ref2sink_cmdi` / `ref2sink_bof` / `ref2share`(+`share2sink`) / `all`
- taint：`--taint_check` 开 / 关
- 边界二进制：攻击面 Top-N（`-b`）或 `-l 3`

## 数据集（见 `docs/external/dataset.md`）

- L1：合成固件（`scripts/e2e/build_firmware.sh`，含 `getenv→sprintf→system`）
- L2：`firmware_samples/DIR859_FW102b03.bin`（已解包 `tmp/unpacked/_DIR859_FW102b03.bin.extracted/squashfs-root`）
- L3：两个真实固件（Tenda AC15 / Netgear R7000 类），**待下载后补 SHA256**

## 耗时 / 内存 / 产物基线（F9）

| 固件 | 配置 | 耗时(s) | 内存峰值 | 产物体积 | 可并发数 | 备注 |
|---|---|---|---|---|---|---|
| L1 | cmdi+taint | PENDING | PENDING | PENDING | PENDING | 真实运行后填 |
| L1 | bof | PENDING | PENDING | PENDING | PENDING | |
| L2 DIR-859 | cmdi+taint | PENDING | PENDING | PENDING | PENDING | |
| L2 DIR-859 | 全 4 脚本 | PENDING | PENDING | PENDING | PENDING | |
| L3-a | cmdi | PENDING | PENDING | PENDING | PENDING | 待固件 |
| L3-b | cmdi | PENDING | PENDING | PENDING | PENDING | 待固件 |

> **填写方式**：真实跑完一次后，把 `docker stats` / `time` 数字回填此表，并用
> `scripts/run_external.py --tool satc --run-dir <run>` 导出 `satc.json` 落盘到
> `benchmarks/external/satc/raw/<固件>-<配置>/`。

## 已知限制（写进 limitation，不算失败）

- 无 Web 前端的固件：`Clustering_result_v2.result` 很空，跨进程链路无数据。
- 官方镜像较老：遇 angr 冲突优先用 `smile0304/satc`，不行再自 build（时间盒 1h）。
- 现场策略（比赛时间紧）：只跑 `ref2sink_cmdi` + Top-1 二进制、关 `--taint_check`。
