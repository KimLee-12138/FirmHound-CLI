---
id: 08-external-analyzers-satc
title: 外部分析器 · SaTC 共享关键字污点分析
tags: [external, satc, taint, ghidra, angr, m-external]
---

# Skill 08 · 外部分析器：SaTC

> 角色：作为 E（外部分析组组长）的实战手册。把 SaTC（USENIX Security 2021,
> NSSL-SJTU/SaTC）接入 FirmHound 流水线，产出标准化的 `external_finding`。
> 本 Skill 是「方法论 + 排错表」，不是 CVE 答案库——靠通用解析，不靠硬编码。

## 1. 目标

用 SaTC 从固件 *Web 前端关键字* 定位 *后端二进制入口*，再用 Ghidra 找 sink、
angr 做污点传播，产出真正的 `source → ... → sink` 跨函数路径。它补的是主轨
（同文件 `imports ∩ {system,sprintf}` 共现判断）完全没有的**跨函数 / 跨进程数据流**。

**关键增量**：`ref2share` + `share2sink` 链路覆盖「数据先写进 nvram/env，再被另一
进程读出送进 sink」的**跨进程污点**——这是主轨零覆盖的能力，全量复现必须跑。

## 2. 适用场景 / 输入

- **输入**：已解包的固件 rootfs（正好吃 `UNPACK` 阶段产物 `tmp/unpacked/*/squashfs-root`）。
- **触发**：`EXTERNAL_ANALYSIS` 阶段，且 `config/dev.yaml` 中 `external.satc.enabled=true`。
- **不适用**：无 Web 前端 / 无共享关键字的固件（SaTC 关键字提取会很空，记 `limitation`，非失败）。

## 3. 输出

- `runs/<id>/artifacts/external_findings/satc.json`：归一化 findings（schema `external_finding`）。
- `runs/<id>/artifacts/external_findings/all.json`：本阶段全部外部器合并结果。
- `runs/<id>/artifacts/external_findings/fused.json`：`FUSION` 阶段去重 + 交叉验证后的结果。

每个 finding 必含：`finding_id`、`tool=satc`、`binary_id`、`vuln_class`、`source`、
`sink`(function+addr)、`call_trace`、`confidence`、`status`。

## 4. 执行流程

1. **probe()**：检查 Docker daemon + `smile0304/satc` 镜像。**永不抛异常**；缺失返回
   `available=False + missing=[...]` → 整条链路 `skipped`。
2. **prepare()**：在 `tmp/external/satc/<run_id>/` 建 `out/`、`logs/`，从攻击面挑
   Top-N 边界二进制（`-b`）或退回 `-l N`。
3. **run()**：对每种 Ghidra 脚本起一次容器（`--memory=16g` + 硬超时）：
   - `ref2sink_cmdi` → 命令注入 sink 路径
   - `ref2sink_bof` → 缓冲区溢出 sink 路径
   - `ref2share` → 共享数据**写入**参数（nvram_set/setenv）
   - `share2sink` → **必须等 `ref2share` 产物**，用 `--ref2share_result` 指过去
4. **parse()**：`tools/external/satc/parser.py` 容错解析 11+1 类输出 → `external_finding`。
   `compute_confidence` 公式：`0.3 + 0.25(有Alert Address) + 0.20(--taint_check) +
   0.15(call_trace≥2) + 0.10(关键字聚到该二进制)`；无 Alert Address 时上限 0.6。
5. **normalize()**：逐条过 schema 校验，非法 finding 丢弃并计数（`dropped`）。
6. **execute()**：以上任一步异常都被兜住，返回 `status=skipped/failed`，**绝不 abort 主链**。

## 5. 命令与配置

```bash
# 调试：单工具独立跑（不经编排器）
python scripts/run_external.py --tool satc --run-dir runs/<id>

# 全量：整条外部链
python scripts/run_external.py --tool all --run-dir runs/<id>
```

`config/dev.yaml` 关键开关（默认全关）：

```yaml
external:
  enabled: false
  workdir: ./tmp/external
  satc:
    enabled: false
    image: smile0304/satc
    taint_check: true          # angr 污点引擎，显著变慢
    scripts: [ref2sink_cmdi, ref2sink_bof, ref2share]
    enable_share2sink: true
    max_bins: 3
    memory: 16g
```

**现场策略**（比赛时间紧）：只跑 `ref2sink_cmdi` + Top-1 二进制、关 `--taint_check`，
压到 20–30 分钟。全量 4 配置（带/不带 taint × 4 脚本 × 多二进制）是离线 benchmark 才跑。

## 6. 验收与降级（F7 八档不 abort）

- SaTC 缺失 → `probe()` 返回 `available=False` → `skipped` + 记 limitation，主链照常出报告。
- 8 种开关组合（全关 / satc±taint / ±share2sink / 叠加 firmrec·klee·bond 等）
  全部返回 `status ∈ {ok, skipped}`，**不抛异常、不中断**。
- `pytest tests/unit/test_external_integration.py` 固化这 8 档。

## 7. 与其他阶段协作

- **下游 G（KLEE）** 拿本产出 `call_trace` 做路径剪枝。
- **下游 H（BOND）** 拿 `source/sink/call_trace` 当 fuzz 输入。
- **FUSION** 阶段把本产出与主轨候选按 `(binary_id, sink.addr, vuln_class)` 去重，
  主轨未命中的标 `external_only`（这是 benchmark 最关键的指标）。
- **FirmRec 隔离**：带 `matched_cve` 的 finding 标 `blind_isolated`，不计入 `external_only` 增量。

---

## 踩坑表（不写等于白踩）

| 坑 | 症状 | 处理 |
|---|---|---|
| 官方镜像老 | Python/angr 版本冲突，`satc.py` 起不来 | 优先 `smile0304/satc`；不行 `docker build . -t satc`（时间盒 1h，超了用不带 `--taint_check` 模式） |
| Ghidra OOM | 容器被 kill，`ghidra_extract_result` 空 | `--memory=16g` 且降并发；仍失败只跑 Top-1（`-b`）而非 `-l 3` |
| 跑太慢 | 单固件 90min，4 配置×3 固件 = 18h | 分级全量：4 脚本**全跑不带 taint**，再对 Top-1 二进制跑带 taint 慢模式，时间砍 60% |
| 无 Web 前端 | `Clustering_result_v2.result` 很空 | 工具固有局限，记 `limitation`，不是你的锅 |
| share2sink 依赖 ref2share | 直接跑报错 | **先跑 `ref2share`**，再用 `--ref2share_result` 指过去 |
| Windows 挂载失败 | `docker: invalid mount config` | 走 `to_wsl_path()` 翻 `/mnt/c/...`；Docker Desktop 开该盘 file sharing |
| 解包的符号链接 | rootfs 复制失败 | 复用 `fsa/utils/traverse.py` 符号链接容错，别自己 `cp -r` |

---

## 反哺主轨（加分项，A1/A2）

- **A1**：把 `Clustering_result_v2.result` 的「前端关键字 ↔ 后端二进制」映射写回
  `tools/web/handler_extract.py`，补上「哪个参数由哪个 handler 处理」这环。
- **A2**：SaTC 自带 Ghidra 管线与 `skills/03-binary-decompile` 降级路径合并，
  避免同一固件跑两次 Ghidra（省 30–60 min/固件）。
