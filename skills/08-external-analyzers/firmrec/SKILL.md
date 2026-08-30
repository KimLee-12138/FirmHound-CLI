---
id: 08-external-analyzers-firmrec
title: 外部分析器 · FirmRec 复发漏洞检测
tags: [external, firmrec, recurrence, ccs24, m-external]
---

# Skill 08 · 外部分析器：FirmRec

> 角色：作为 F（外部分析组）的实战手册。把 FirmRec（CCS'24, seclab-fudan/FirmRec）
> 接入 FirmHound 流水线，产出标准化的 `external_finding`。
> 本 Skill 是「方法论 + 排错表」，不是 CVE 答案库——靠通用解析，不靠硬编码。

## 1. 目标

用 FirmRec 从**已知漏洞的利用过程语义签名**出发，在固件里找它的**复发变体**
（同厂商跨型号 / 跨版本，经代码复用或定制演变出的同类漏洞）。它补的是主轨
完全没有的能力：**利用「这个洞在别处出现过」这条信息去扫变体**。

**关键定位（特殊性）**：FirmRec **不进主链**。它要求已知漏洞签名，与系统「零 CVE
先验、不泄露 Ground Truth」的核心卖点直接冲突。因此它是全组**唯一需要防污染**
的工具——隔离机制（§隔离）是它的第一交付物，比跑通更重要。比赛现场最可能的
快速成果一招：**给了 CVE 之后，扫同厂商跨型号变体**。

## 2. 适用场景 / 输入

- **输入**：固件镜像（FirmRec 吃 `inout/firmware/images/`，我们 `UNPACK` 产物是解包
  rootfs，prepare 阶段把 rootfs 当 firmware 输入兜底）+ `inout/vuln_info/`（已知漏洞
  签名）+ `inout/experiment.json`（任务表）。
- **触发**：`EXTERNAL_ANALYSIS` 阶段，且 `config/dev.yaml` 中
  `external.firmrec.enabled=true`。**盲跑（blind=true）时由代码强制禁用**（见 §隔离）。
- **不适用**：纯盲评 benchmark（会被强制关）；合成固件（x86，FirmRec 主打 MIPS/ARM）。

## 3. 输出

- `runs/<id>/artifacts/external_findings/firmrec.json`：归一化 findings
  （schema `external_finding`，每条带 `matched_cve` = 命中的已知 CVE）。
- `runs/<id>/artifacts/external_findings/recurrence_findings.json`：**FirmRec 专属分流
  文件**，与主链 `fused.json` 完全分开。
- 每条 finding 必含：`finding_id`、`tool=firmrec`、`binary_id`、`vuln_class`、
  `sink`(function+addr)、`matched_cve`、`confidence`、`status`。

## 4. 执行流程

1. **probe()**：检查 Docker daemon + `xylearn/firmrec-base` 镜像。**永不抛异常**；
   缺失返回 `available=False + missing=[...]` → 整条链路 `skipped`。
2. **prepare()**：在 `tmp/external/firmrec/<run_id>/` 建 `out/`、`logs/`、`inout/`
   （firmware / vuln_info / experiment.json）。`vuln_info` 默认来自我们的 9-CVE 知识库
   （`vuln_info_source: our`），官方样例走 `official`（占位，跑通官方样例后填真实 schema）。
3. **run()**：容器内跑 `python -m firmrec.pipeline all`。PostgreSQL 须先经 `make start`
   起来（FirmRec 的依赖），否则记 `limitation` 说明 PG 未就绪——不伪造成功。
4. **parse()**：`tools/external/firmrec/parser.py` 容错解析三类产物：
   - `VULNS.md` → 检出 CVE + 固件 + 二进制 + 函数 + 地址 + 相似度
   - PostgreSQL `pg_*.csv`（容器内 `COPY ... TO STDOUT` 导出）→ 详细匹配行
   - `poc_info/` → **必须经 `sanitize_poc` 脱敏**，危险 payload 直接丢弃
5. **normalize()**：逐条过 schema 校验，非法 finding 丢弃并计数（`dropped`）。
6. **execute()**：以上任一步异常都被兜住，返回 `status=skipped/failed`，**绝不 abort 主链**。

## 5. 命令与配置

```bash
# 调试：单工具独立跑（不经编排器）
python scripts/run_external.py --tool firmrec --run-dir runs/<id>

# 全量：整条外部链
python scripts/run_external.py --tool all --run-dir runs/<id>
```

`config/dev.yaml` 关键开关（默认全关）：

```yaml
external:
  enabled: false
  firmrec:
    enabled: false
    image: xylearn/firmrec-base
    signature_db: ./benchmarks/CVEs     # 我们的 9-CVE 知识库
    vuln_info_source: our               # our | official
    mode: signature_only                # 盲跑禁止
    sanitize_poc: true                  # 硬门：PoC 必须过脱敏才许落盘
    timeout_s: 7200
```

**现场策略**：不要在 Blind Benchmark 开 FirmRec。只在「比赛现场给了 CVE，扫同厂商
变体」的明确场景开启，且其结论单列、不计入零先验指标。

## 6. 验收与降级（F7 八档不 abort）

- FirmRec 缺失 / 未启用 → `probe()` / `_resolve_external_config` → `skipped` + 记
  limitation，主链照常出报告。
- 8 种开关组合（全关 / firmrec±/ 叠加 satc·klee·bond 等）全部返回
  `status ∈ {ok, skipped}`，**不抛异常、不中断**。
- `pytest tests/unit/test_external_integration.py` 固化这 8 档；
  `pytest tests/unit/test_recurrence_isolation.py` 固化隔离三保证。

## 7. 与其他阶段协作

- **融合层**：FirmRec findings 全部带 `matched_cve`，`finding_fusion` 把它们标
  `blind_isolated=True`、**不计入 `external_only` 增量**、并单独落 `recurrence_findings.json`，
  主链 `fused.json` 永不混入 FirmRec 条目（守零 CVE 先验红线）。
- **报告层**：复发结论单列一章，开头明写「本节依赖已知漏洞签名，不属于零先验能力，
  不计入 Blind Benchmark 指标」。
- **下游**：FirmRec 检出的变体可反向喂给主轨做「已知变体特征」规则沉淀（限非盲场景）。

---

## 隔离说明（X1，F 的独有交付，学术诚信闸门）

四道隔离**全部实现**，缺一不可（F-FirmRec.md §4.2）：

1. **默认关闭**：`config/dev.yaml` 的 `firmrec.enabled: false`。
2. **盲跑强制禁用（代码断言）**：`tools/external/adapter._resolve_external_config`
   在 `run_ctx.blind=True` 时强制 `firmrec.enabled=False`，结果 limitation 带
   `FORCED_DISABLE`，并有单测 `test_adapter_forces_disable_on_blind_run` 固化。
3. **产物不进主链**：`finding_fusion` 把 FirmRec 分流到 `recurrence_findings.json`，
   主链 `fused.json` 不含任何 `tool=firmrec`（`test_unified_candidates_contain_no_firmrec_findings`）。
4. **报告单列标注**：报告章节开头声明其结论依赖已知签名、不计入盲评指标。

---

## 踩坑表（不写等于白踩）

| 坑 | 症状 | 处理 |
|---|---|---|
| base 镜像巨大 | pull 30–60 分钟，磁盘 20G+ | 第一优先级拉；磁盘不够先清 `tmp/` |
| PostgreSQL 起不来 | `make start` 后 `psql` 连不上 | 进容器手动 `service postgresql start`；查 `dataflow.conf` 与连接串 |
| `make build` 后改动不生效 | 改了源码/config 容器里还是旧的 | 必须重跑 `make build` 把源码拷进新镜像 |
| 没有 LLM key 跑不完整 | pipeline 走到入口搜索就停 | 配 `config.yaml` 的 `llm_key/url/model`（用国内备案端点）；不配也要跑，记录退化 |
| `vuln_info` 格式不对 | pipeline 报找不到字段 | 先跑通官方样例，再照抄格式填我们的 9 CVE |
| benchmark fixture 是抽象的 | `binary_id = bin-CVE-xxxx` 非真实路径 | 做映射表，明写推定字段（`vuln_info_mapping.md`） |
| 容器内 curl 被拉黑 | 调模型失败 | 宿主机侧 Python 预取后写进 `inout/`，避开容器内网络调用 |
| 合成固件是 x86 | FirmRec 主打 MIPS/ARM | 记录是否支持；不支持则 L1 不作为验收必需项（comparison 注明） |
| Windows 挂载失败 | `docker: invalid mount config` | 走 `to_wsl_path()` 翻 `/mnt/c/...`；Docker Desktop 开该盘 file sharing |
| PoC 含危险 payload | 落盘即违规 | `poc_info` 全经 `sanitize_poc`，拒绝的直接丢弃（`dropped_unsafe` 计数） |

---

## 反哺主轨（加分项）

- **A**：把 FirmRec 检出的「已知变体特征」（函数名 + 调用模式）沉淀进
  `source_sink_rules` 的厂商封装函数字典，作为非 CVE 先验的通用模式（不写死 CVE）。
- **B**：复发专项实验（§comparison.md）若在某固件检出 0 变体，本身是个结论——说明
  这批固件属不同代码谱系，可在报告里正面呈现。
