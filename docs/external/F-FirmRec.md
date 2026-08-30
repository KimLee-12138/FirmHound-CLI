# F 同学 · FirmRec 全量复现与集成计划

> **你的任务**：把 FirmRec（CCS'24）从"容器起得来"做到"能对我们自己的固件跑出复发漏洞结论"，
> 并**负责设计并实现 `recurrence_mode` 隔离机制**——这是全组唯一的"学术诚信闸门"。
>
> **基调：不是跑通 demo，是全量完成。** 你的验收标准见 §2 全量档 9 条。
>
> **你的特殊性**：你的工具**不进主链**。这听起来像被边缘化，恰恰相反——
> 你手上握着这个系统里**唯一需要防污染的能力**，以及比赛现场最可能快速出成果的一招：
> **给了 CVE 之后，扫同厂商跨型号变体**。

---

## 1. 三句话讲清 FirmRec

- **它解决什么**：**复发漏洞检测**（recurring vulnerability detection）。D-Link 某摄像头固件的洞，经过厂商间代码复用/定制，会以变体形式出现在 TP-Link 路由器上。FirmRec 用"基于利用过程的语义签名"去找这类变体。
- **它补我们什么**：我们现在每个固件都是独立盲跑，完全不利用"这个洞在别处出现过"这条信息。
- **它在链条哪**：**旁路**。不进 `unified_candidates`，单独落 `recurrence_findings.json`，报告单列一章。

### 1.1 它的三个技术点（答辩会问）

1. **基于利用的漏洞签名**：不比语法，比"漏洞被利用过程中的语义特征"，对二进制代码改动更鲁棒。
2. **Concolic execution 抽取签名**：从漏洞报告 + 有漏洞的二进制，符号执行生成签名。
3. **两阶段检测**：轻量搜索 → 重量级验证（精度和效率都要）。

论文数据：320 固件检出 642 个漏洞、53 个 CVE；对比 SaTC / jTrans / Greenhouse，
精确率高 28.8%、召回率高 74.1%、比 SaTC 快 4.2 倍。

---

## 2. 交付标准（三档）

### 全量档（Full）—— 你的目标

| # | 项 | 具体判定 |
|---|---|---|
| **F1** 数据集全量 | L1 合成 + L2 DIR-859 + L3 两个真实固件 **全部跑完** `python -m firmrec.pipeline all` | 3 份 `recurrence_findings.json` |
| **F2** 模式全量 | **两种模式都跑**：① 用 FirmRec 官方自带 `vuln_info` 跑一遍；② 用**我们自己整理的 9 个 CVE 漏洞集**跑一遍 | 2 组对照结果 |
| **F3** Parser 全量 | 覆盖 **3 类产出**：`VULNS.md`、PostgreSQL 库表、`poc_info/` | 三类都有 fixture |
| **F4** 单测全量 | VULNS.md 解析 + PG dump 解析 + 空结果 + 畸形行 + 版本差异，覆盖率 ≥80% | `pytest --cov` |
| **F5** 接入全量 | registry 注册 + `scripts/run_external.py --tool firmrec` 可跑 + **旁路产物 `recurrence_findings.json` 正确落盘且不与主链混合** | 三条都通 |
| **F6** Benchmark 全量 | **复发专项实验**：「用 A 组漏洞签名 → 检测 B 固件」的完整结果 | `benchmarks/external/firmrec/comparison.md` |
| **F7** 隔离完备 | **盲跑强制禁用断言**有单测覆盖；`unified_candidates.json` 中不含任何 FirmRec 来源条目（有单测断言） | 单测通过 |
| **F8** 文档全量 | SKILL.md 含 7 节 + 踩坑表 + **隔离说明** | 文档齐 |
| **F9** 性能基线 | 每固件耗时、PG 库体积、产物大小、是否需要 LLM key | 基线表 |

### 你的两项独有交付（别人没有，你必须有）

| # | 项 | 说明 |
|---|---|---|
| **X1** | **`recurrence_mode` 隔离机制** | 代码层硬断言 + 单测。这是全组的学术诚信闸门，见 §4 |
| **X2** | **我们自己的 `vuln_info` 数据集** | 从 `benchmarks/CVEs/` 的 9 个 CVE 整理成 FirmRec 要求的格式 |

### 部分档 / 兜底档

- **部分**：只跑官方自带 vuln_info，没跑自己的；或 PG 库表没解析出来；或隔离机制只有配置没有代码断言。
- **兜底**：复现报告 + Skill 文档 + adapter 空壳 + fixture 单测。
- ⚠️ **若全队只有 4 人**（见 `README.md` §1.1），你的优先级降到最低，
  只做"环境跑通 + Skill 文档 + 接口预留"，其余时间支援主线兜底。

---

## 3. 工具档案（已查证）

| 项 | 内容 |
|---|---|
| 全称 | FIRMware Recurring vulnerability detector |
| 论文 | CCS 2024，《Accurate and Efficient Recurring Vulnerability Detection for IoT Firmware》（复旦 seclab / 白泽战队） |
| 仓库 | `github.com/seclab-fudan/FirmRec`（镜像 `XYlearn/FirmRec`） |
| 基础镜像 | `docker pull xylearn/firmrec-base:latest && docker tag ... firmrec-base` |
| 依赖 | Docker、Ghidra + JDK + Gradle（在 base 镜像内）、**PostgreSQL**、Miniconda、binwalk |
| 可选依赖 | **LLM**（`config.yaml` 里配 `llm_key` / `llm_url` / `llm_model`，用于输入入口搜索） |
| 输入 | `inout/firmware/images/`（固件）+ `inout/vuln_info/`（**已知漏洞**）+ `inout/experiment.json`（任务表） |
| 输出 | `VULNS.md`、PostgreSQL 库表、`poc_info/` |
| 硬件建议 | ≥8G RAM（16G 推荐），≥20G 磁盘 |

### 命令全貌

```bash
# 构建
docker pull xylearn/firmrec-base:latest && docker tag xylearn/firmrec-base:latest firmrec-base
make build          # 拷贝源码进新镜像；改了源码或 config.yaml 后要重跑

# 准备输入
inout/
├── firmware/images/     # 固件镜像
├── vuln_info/           # 已知漏洞信息
└── experiment.json      # 任务表

# 运行
make start                          # 起容器（含 PostgreSQL 初始化）
# 容器内：
python -m firmrec.pipeline all
```

> ⚠️ **`make start` 会初始化 PostgreSQL**。这一步最容易卡住，见 §9 踩坑表。

---

## 4. ⚠ 核心任务：`recurrence_mode` 隔离机制（X1）

### 4.1 为什么必须有

FirmRec 的设计前提就是**吃已知漏洞签名**。而我们的核心卖点是**零 CVE 先验**，
且 `第一队_系统研发与自动化流水线_详细计划.md` 第二十六条明令：
**「不要把 CVE 名、PoC 或 Ground Truth 暗示给 Agent」**。

如果 FirmRec 参与 Blind Benchmark，等于把 Ground Truth 喂给了系统，
**整个 Benchmark 直接作废**。这是本项目最严重的一条红线，不是"注意一下"级别。

### 4.2 四道隔离（必须全部实现，缺一不可）

| # | 隔离层 | 实现方式 | 交付位置 |
|---|---|---|---|
| **1** | **默认关闭** | `config/dev.yaml` 的 `firmrec.enabled: false` | 配置 |
| **2** | **盲跑强制禁用（代码断言）** | 在 `scripts/run_pipeline.py` 与 `fsa/orchestrator/engine.py` 里加断言：若当前 run 标记 `blind=true`，则**强制** `firmrec.enabled=False`，并在 decision 日志里记一条 `FORCED_DISABLE` | 代码 + 决策日志 |
| **3** | **产物不进主链** | FirmRec 的 finding **不写进 `unified_candidates.json`**，单独落 `recurrence_findings.json` | `finding_fusion.py` 加过滤 |
| **4** | **报告单列标注** | 报告新增章节，开头明写：「本节结论依赖已知漏洞签名，**不属于零先验能力，不计入 Blind Benchmark 指标**」 | `skills/07-report/SKILL.md` 第 22 节 |

### 4.3 代码骨架

```python
# scripts/run_pipeline.py 或 fsa/orchestrator/engine.py 中
def _resolve_external_config(cfg: dict, run_ctx: dict) -> dict:
    external = dict(cfg.get("external", {}))
    if run_ctx.get("blind", False):
        firmrec = dict(external.get("firmrec", {}))
        if firmrec.get("enabled"):
            log_decision(
                stage="EXTERNAL_ANALYSIS",
                options=["enable", "force_disable"],
                selected="force_disable",
                reason="Blind run detected: FirmRec requires known-vuln signatures "
                       "and would leak ground truth into the benchmark.",
                confidence=1.0,
                actor="rule",
            )
        firmrec["enabled"] = False
        external["firmrec"] = firmrec
    return external
```

```python
# tools/analysis/finding_fusion.py 中
def fuse(candidates, external_findings):
    main_track = [f for f in external_findings if f["tool"] != "firmrec"]
    recurrence = [f for f in external_findings if f["tool"] == "firmrec"]
    save_json(run_dir / "recurrence_findings.json", recurrence)   # 单独落盘
    return _merge(candidates, main_track)                          # 主链只吃非 firmrec
```

### 4.4 单测（F7 的判定依据，必须写）

```python
def test_blind_run_force_disables_firmrec():
    cfg = {"external": {"firmrec": {"enabled": True}}}
    out = _resolve_external_config(cfg, run_ctx={"blind": True})
    assert out["firmrec"]["enabled"] is False

def test_unified_candidates_contain_no_firmrec_findings():
    result = fuse(candidates, [satc_finding, firmrec_finding])
    assert all("firmrec" not in e for e in result["provenance"]["tools"])

def test_recurrence_findings_saved_separately():
    ...
```

---

## 5. 验证固件与漏洞数据集

### 5.1 固件（与全组统一）

L1 合成 + L2 `DIR859_FW102b03.bin` + L3 两个（E 统一下载后分发给你）。

### 5.2 你独有的：`inout/vuln_info/` 数据集（X2）

**这是你的重点工程任务之一。** 两份都准备：

| 数据集 | 来源 | 用途 |
|---|---|---|
| **官方自带** | FirmRec 仓库 `inout/` 样例（README 提供下载） | 验证跑通，对照基线 |
| **我们自己整理的** | 从 `benchmarks/CVEs/` 的 9 个 CVE（`attack_surface.json` / `candidate.json` / `verdict.json`）整理 | **这才是真家伙**——用我们自己的漏洞知识库做复发检测 |

整理时先看 `inout/vuln_info/` 的现有格式（先跑通官方样例，再照格式填我们的 9 个 CVE）。
**9 个 CVE 的已知信息**（可从 fixture 直接提取）：

| CVE | 漏洞类 | sink |
|---|---|---|
| CVE-2017-17215 | command_injection | system |
| CVE-2018-5767 | command_injection | system |
| CVE-2019-16920 | command_injection | system |
| CVE-2019-17621 | — | 需读 fixture |
| CVE-2020-10987 | command_injection | system |
| CVE-2020-9373 | — | 需读 fixture |
| CVE-2021-31802 | **overflow** | strcpy |
| CVE-2023-27021 | — | 需读 fixture |
| CVE-2023-32154 | — | 需读 fixture |

> ⚠️ 注意：benchmark fixture 里的 `binary_id` 是抽象的 `bin-CVE-xxxx`，
> **不是真实 rootfs 路径**。填 `vuln_info` 时需要你做一次"抽象 → 真实"的映射，
> 映射表写进 `benchmarks/external/firmrec/vuln_info_mapping.md`，**说清楚哪些是推定的**。
> 不要把推定当事实——这同样是诚信问题。

### 5.3 LLM 配置（可选但建议配）

`config.yaml` 的 `llm_key` / `llm_url` / `llm_model`。
**用我们自己的 `config/models.yaml` 里那套国内备案模型端点**（不要另开账号）。

> ⚠️ **禁止用 `curl` / `wget`** 调模型（`config/safety.yaml` 已拉黑）。
> 容器内配置走文件即可；如果 FirmRec 内部用 curl，记进踩坑表并考虑用 Python 侧预取结果。

---

## 6. 逐日排期（8/30 13:00 起）

### 8/30（半天 + 晚上）—— 环境起步

| 时间 | 任务 | 产出 |
|---|---|---|
| 13:00–14:00 | 读 `docs/external/README.md` §3 共享契约；确认理解 `ExternalAnalyzer` 接口 | — |
| 14:00–16:00 | `docker pull xylearn/firmrec-base:latest`（**很大，早开始**）+ `git clone` FirmRec 源码 | 镜像 + 源码 |
| 16:00–18:00 | `make build`；`make start` 进容器；**确认 PostgreSQL 起来了**（`pg_isready`） | 容器可用 |
| 18:00–20:00 | 下载并解压官方 `inout/` 样例；准备 `inout/firmware/images/` | 样例就位 |
| 20:00–24:00 | **用官方样例跑第一遍 `python -m firmrec.pipeline all`**；记录耗时与产物 | 第一批产物 |
| 21:00 | 四人同步会 | — |

**今日硬产出**：容器能起、PG 能连、官方样例跑通（哪怕只跑完一半 pipeline，也要知道卡在哪一步）。

> ⚠️ base 镜像很大（Ghidra + JDK + Gradle + Miniconda），pull 可能要 30–60 分钟。
> **这是你今天最优先的事**，早一秒开始早一秒有数据。

### 8/31 —— 全量复现日

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | 官方样例跑完；导出 PG 库表结构（`pg_dump -s`）；搞清楚库里哪张表存什么 |
| 11:00–13:00 | **整理我们自己的 `vuln_info`**（9 个 CVE），写映射表 |
| 13:00–18:00 | L2 DIR-859 + L3 两个固件，各跑两遍（官方 vuln_info / 我们自己的 vuln_info） |
| 18:00–20:00 | L1 合成固件跑一遍（合成固件是 x86，FirmRec 主要针对 MIPS/ARM，注意记录是否支持） |
| 20:00–22:00 | 全部原始产物落盘 `tools/external/firmrec/fixtures/raw/`（含 **`pg_dump` 全量导出**）；写 `benchmarks/external/firmrec/README.md` |

**今日硬产出**：3+ 固件 × 2 种 vuln_info 的产物；PG 库表 dump；映射表。

### 9/1 —— Parser + 单测日

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | 写 `runner.py`：docker 后端 + **容器内 PostgreSQL 交互**（`docker exec` 执行 `psql -c "COPY ... TO STDOUT"` 导出） |
| 11:00–15:00 | 写 `parser.py`：解析 `VULNS.md` + PG dump + `poc_info/` |
| 15:00–17:00 | **写隔离机制（X1）**：`_resolve_external_config` + `finding_fusion` 过滤 + 3 个单测 |
| 17:00–20:00 | 写 `tests/unit/test_external_firmrec.py`：六类分支 |
| 20:00–21:00 | `pytest --cov` ≥80% |

### 9/2 —— 接入 + 联调日（⚠ 18:00 熔断）

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | registry 声明（`tools/registry/external.yaml` 的 firmrec 那几行）；`run_external.py --tool firmrec` 跑通 |
| 11:00–13:00 | **验证旁路隔离**：跑一次带 firmrec 的 full pipeline，确认 `unified_candidates.json` 里没有 firmrec 条目，`recurrence_findings.json` 正确落盘 |
| 13:00–15:00 | **验证盲跑强制禁用**：跑 blind run，确认决策日志里有 `FORCED_DISABLE` 记录 |
| 15:00–17:00 | 支援 E 做全链路联调（你的工具不进主链，时间上有余量） |
| 17:00–18:00 | 8 种开关组合降级测试 |
| **18:00** | **熔断评审**：按 §2 三档给自己定档 |

### 9/3 —— 量化 + 文档日

| 时间 | 任务 |
|---|---|
| 09:00–13:00 | **复发专项实验**：「用 A 固件/A 组漏洞的签名 → 检测 B 固件」 |
| 13:00–16:00 | 写 `benchmarks/external/firmrec/comparison.md` |
| 16:00–19:00 | 写 `skills/08-external-analyzers/firmrec/SKILL.md`（7 节 + 踩坑表 + **隔离说明**） |
| 19:00–21:00 | 写报告第 22 节「复发漏洞扫描（依赖已知漏洞签名）」的渲染模板 |

### 9/4 —— 冻结 + 演示日

- 代码冻结
- 演示素材：**"用 DIR-859 的已知洞，在另一个固件上找到变体"**（如果实验成功，这是全场最炸的 3 分钟）
- 答辩 Q&A 预案（见 §10）

---

## 7. 代码骨架

### 7.1 文件清单（你负责）

```
tools/external/firmrec/__init__.py
tools/external/firmrec/runner.py          # FirmrecAnalyzer(ExternalAnalyzer)
tools/external/firmrec/parser.py          # VULNS.md + PG dump + poc_info → external_finding
tools/external/firmrec/vuln_info.py       # 把我们 9 个 CVE 转成 FirmRec 的 vuln_info 格式
tools/external/firmrec/fixtures/raw/      # 真实产物（含 pg_dump）
tools/registry/external.yaml              # firmrec 那几行
tests/unit/test_external_firmrec.py
tests/unit/test_recurrence_isolation.py   # ★ 隔离机制单测（你的独有交付）
skills/08-external-analyzers/firmrec/SKILL.md
benchmarks/external/firmrec/{README.md,comparison.md,vuln_info_mapping.md,raw/}
docs/external/F-FirmRec.md
```

### 7.2 runner.py 要点

```python
class FirmrecAnalyzer(ExternalAnalyzer):
    name = "firmrec"

    def probe(self) -> ProbeResult:
        # docker image inspect firmrec / firmrec-base
        # docker exec 里跑 pg_isready
        # 检查 config.yaml 的 llm_* 是否配置（未配 → missing 里标注 "llm_unconfigured (optional)"）
        # 绝不抛异常

    def prepare(self, ctx) -> Path:
        workdir = ctx.workdir                       # tmp/external/firmrec/<run_id>
        # 1) 生成 inout/ 目录树
        #    inout/firmware/images/<fw>
        #    inout/vuln_info/            ← 来自 ctx.config["vuln_info_source"]
        #    inout/experiment.json       ← 任务表
        # 2) 挂载进容器

    def run(self, ctx) -> RunOutcome:
        # docker exec firmrec-container python -m firmrec.pipeline all
        # 硬超时；超时返回 status="timeout"

    def parse(self, ctx, outcome) -> list[dict]:
        # 1) VULNS.md           → 检出 CVE 列表
        # 2) PG dump            → 详细条目（binary / addr / signature 相似度 / 匹配到哪个已知洞）
        # 3) poc_info/          → PoC（必须过 sanitize，poc_sanitized=true 才留）
```

**PG 导出方式**（容器内不能直接写宿主机白名单外的路径）：

```bash
docker exec <container> psql -U <user> -d firmrec -c \
  "COPY (SELECT * FROM <table>) TO STDOUT WITH CSV HEADER" > tmp/external/firmrec/<run_id>/pg_<table>.csv
```

> 输出重定向到 `tmp/external/...`（在白名单内），**不要**让容器写 `/var/lib/postgresql`。

### 7.3 Parser 映射表

| FirmRec 产出 | 内容 | 映射到 `external_finding` |
|---|---|---|
| `VULNS.md` | 检出的 CVE 编号 + 固件 + 二进制 | `finding_id`、`notes`、`evidence` |
| PG 表（主结果表） | 匹配到的已知漏洞、目标二进制、函数地址、签名相似度 | `sink.addr`、`binary_id`、`confidence`（← 相似度）、`notes`（← 匹配到哪个已知 CVE） |
| PG 表（入口表） | 输入入口函数 | `entry_point`、`source` |
| `poc_info/` | PoC 信息 | `validation.poc_sanitized`（**必须过 H 的 sanitize 或复用其规则**） |

**confidence**：直接取 FirmRec 的签名相似度分数（如果有）；没有则按
`0.5 + 0.3×相似度 + 0.2×(是否有入口证据)` 计算，并**在 notes 里写清公式**。

**vuln_class**：从匹配到的已知 CVE 类型继承；未知则 `other`。

### 7.4 与 H 的接口

你的 `poc_info` 解析**必须走 H 的脱敏器**：

```python
from tools.external.bond.sanitize import sanitize_poc
```

如果 H 还没写完，先用一个本地最小实现占位，并在 PR 里标注 `TODO(de=H)`。
**不许不过脱敏就直接落盘。**

---

## 8. 单测清单

| 分支 | fixture | 断言 |
|---|---|---|
| VULNS.md 正常 | 真实产出 | 解析出 ≥1 条 finding，含 CVE 编号 |
| VULNS.md 空 | 手工造 | 返回 `[]`，`status="ok"` |
| PG dump 正常 | 真实 `pg_dump` CSV | 解析出 binary/addr/相似度 |
| PG dump 畸形 | 截断的 CSV | 跳过坏行 + 记 limitation |
| poc_info 含危险 payload | 手工造含 `bash -i` 的条目 | **被脱敏拒绝**，不留盘 |
| 版本差异 / 无结果 | 某固件无检出 | `findings=[]` 且 `status="ok"` |

**隔离单测（独有，必写）**：见 §4.4 三条。

**CI 约束**：只解析 fixture，绝不调用真实 FirmRec。

---

## 9. 踩坑预案

| 坑 | 症状 | 处理 |
|---|---|---|
| **base 镜像巨大** | pull 30–60 分钟，磁盘 20G+ | 今天第一件事就拉；磁盘不够先清理 `tmp/` |
| **PostgreSQL 起不来** | `make start` 后 `psql` 连不上 | `make start` 里有 PG 初始化步骤；进容器手动 `service postgresql start`；查 `dataflow.conf` 与连接串 |
| **`make build` 后改动不生效** | 改了源码/config 但容器里还是旧的 | **必须重跑 `make build`**，它会把源码重新拷进新镜像 |
| **没有 LLM key 跑不完整** | pipeline 走到输入入口搜索就停 | 配 `config.yaml` 的 `llm_key/llm_url/llm_model`（用我们的国内备案模型端点）；不配也要跑，记录退化为哪种模式 |
| **`vuln_info` 格式不对** | pipeline 报找不到字段 | **先跑通官方样例，再照抄格式**填我们的；不要凭空猜格式 |
| **benchmark fixture 是抽象的** | `binary_id = bin-CVE-xxxx`，不是真实路径 | 做映射表，**明写哪些是推定的**（§5.2） |
| LLM 调用被 curl 黑名单拦 | 容器内 curl 失败 | 记进踩坑表；考虑宿主机侧 Python 预取后写进 `inout/`，避开容器内网络调用 |
| 合成固件是 x86 | FirmRec 主要针对 MIPS/ARM 固件 | 记录是否支持；不支持则 L1 不作为你的验收必需项（在 comparison 里注明） |

---

## 10. 答辩 Q&A 预案（**你是被问概率最高的一个**）

**Q：FirmRec 要用已知漏洞，那你们「零 CVE 先验」的卖点还在吗？**
A：还在，而且我们做了**四道隔离**：① 默认关闭；② 盲跑时由代码**强制断言**置为禁用，并在决策日志里留一条 `FORCED_DISABLE` 记录；③ 产出不进 `unified_candidates`，单独落 `recurrence_findings.json`；④ 报告单列一章，开头明写「本节结论依赖已知漏洞签名，不属于零先验能力，不计入 Blind Benchmark 指标」。FirmRec 解决的是**另一个问题**——比赛现场给了 CVE 之后，扫同厂商跨型号/跨版本的变体，这是最可能快速出成果的一招。

**Q：那它到底有没有用？给个数字。**
A：看复发专项实验（§6 Day 9/3）：用 A 固件/A 组漏洞的签名，在 B 固件上检出多少变体。这个数字即使为 0 也有价值——说明我们这批固件属于不同代码谱系，这本身是个结论。

**Q：你们自己的 vuln_info 是怎么来的？会不会又泄露 Ground Truth？**
A：来自我们已有的 9 个历史 CVE 知识库（用于方法论沉淀与回归验证，不是答案库）。整理时我做了映射表，**明确标注哪些字段是从抽象 fixture 推定的**，推定不等于事实。且这批数据**只在 recurrence 专项里用**，Blind Run 完全不加载。

---

## 11. 每日 checklist

- [ ] 今天的产物落盘了？（含 `pg_dump`！）
- [ ] 耗时记进 `benchmarks/external/firmrec/README.md` 了？
- [ ] 踩过的坑写进 Skill 文档了？
- [ ] **`enabled: false` 时主链还能跑？**（每天验一次）
- [ ] **盲跑断言还生效？**（每天跑一次隔离单测）
- [ ] 有没有卡超过 4 小时没说？

---

*你手上握着这个系统里唯一需要"防污染"的能力。把闸门做硬，比把工具跑通更重要。*
