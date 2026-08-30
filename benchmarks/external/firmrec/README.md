# FirmRec 复现基准（benchmarks/external/firmrec）

> F 同学（外部分析组）的复现记录。本目录沉淀 **版本 / 镜像 tag / 耗时基线 / 复发专项结论**，
> 供后续 KLEE(B)、BOND(H) 复用时对照。

## 工具版本（固定，复现必须锁定）

| 项 | 值 |
|---|---|
| 论文 | CCS 2024, *Accurate and Efficient Recurring Vulnerability Detection for IoT Firmware* (seclab-fudan/FirmRec) |
| 仓库 | `github.com/seclab-fudan/FirmRec`（镜像 `XYlearn/FirmRec`） |
| 基础镜像 | `xylearn/firmrec-base` |
| 镜像 digest | `PENDING`（首次 `docker pull` 后填入 `docker image inspect --format '{{.Id}}'`） |
| 依赖 | Docker + Ghidra + JDK + Gradle（base 内）+ **PostgreSQL** + Miniconda + binwalk |
| 可选依赖 | **LLM**（`config.yaml` 的 `llm_key/llm_url/llm_model`，用于输入入口搜索；用国内备案端点） |
| 单固件量级 | 视 PG 预热 + pipeline；base 镜像大，首次 pull 30–60 min |
| 硬件建议 | ≥8G RAM（16G 推荐），≥20G 磁盘 |

## 运行配置（两种 vuln_info 模式 × L1/L2/L3）

- vuln_info 来源：`vuln_info_source: our`（我们的 9-CVE 知识库） / `official`（官方样例）
- 固件：L1 合成（x86，FirmRec 主打 MIPS/ARM，支持待验）/ L2 DIR-859 / L3 两个真实固件
- 边界二进制：由 `inout/experiment.json` 任务表指定

## 数据集（见 `docs/external/dataset.md` 与 `vuln_info_mapping.md`）

- L1：合成固件（`scripts/e2e/build_firmware.sh`，含 `getenv→sprintf→system`）
- L2：`firmware_samples/DIR859_FW102b03.bin`（已解包 `tmp/unpacked/_DIR859_FW102b03.bin.extracted/squashfs-root`）
- L3：两个真实固件（Tenda AC15 / Netgear R7000 类），**待下载后补 SHA256**
- `vuln_info`：我们的 9-CVE 知识库已整理为 `tools/external/firmrec/vuln_info_dataset.json`

## 耗时 / 内存 / 产物基线（F9）

| 固件 | vuln_info 源 | 耗时(s) | PG 库体积 | 产物体积 | 备注 |
|---|---|---|---|---|---|
| L1 | our | PENDING | PENDING | PENDING | 合成 x86，支持待验 |
| L2 DIR-859 | our | PENDING | PENDING | PENDING | |
| L2 DIR-859 | official | PENDING | PENDING | PENDING | 对照基线 |
| L3-a | our | PENDING | PENDING | PENDING | 待固件 |
| L3-b | our | PENDING | PENDING | PENDING | 待固件 |

> **填写方式**：真实跑完一次后，把 `docker stats` / `time` 数字回填此表，并把
> `VULNS.md` + `pg_*.csv` + `poc_info/` 落盘到 `tools/external/firmrec/fixtures/raw/`，
> 用 `scripts/run_external.py --tool firmrec --run-dir <run>` 导出 `firmrec.json`。

## 隔离状态（X1，强制）

- ✅ 默认关闭；✅ 盲跑代码强制禁用（`FORCED_DISABLE`）；✅ 产物分流
  `recurrence_findings.json`，主链 `fused.json` 不含 FirmRec 条目；✅ 报告单列标注。
- 单测：`tests/unit/test_recurrence_isolation.py`（3 条 + 1 条 adapter 端到端）。

## 已知限制（写进 limitation，不算失败）

- 需要已知漏洞签名：与零 CVE 先验冲突，故**绝不参与 Blind Benchmark**。
- 合成固件是 x86，FirmRec 主打 MIPS/ARM，L1 支持情况待验。
- PostgreSQL 须在 `make start` 后就绪，否则 pipeline 阶段记 limitation（非伪成功）。
- 官方 `vuln_info` 真实 schema 以官方样例为准；本仓库 `vuln_info_dataset.json` 是我们
  9-CVE 的最佳努力映射，推定字段已标 `presumed=true`（见 `vuln_info_mapping.md`）。
