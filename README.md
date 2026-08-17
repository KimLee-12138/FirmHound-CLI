# FirmHound 固件猎犬 · Firmware Security Agent (FSA)

> 第一队 · 挑战杯「揭榜挂帅」专项赛 — 具备自主决策能力的通用网络安全智能体
> IoT 固件漏洞挖掘自动化系统：解包 → 攻击面 → 二进制分析 → 静态审计 → 风险评分 → 反证验证 → 动态验证 → 证据报告

---

## 目录

1. [项目简介](#1-项目简介)
2. [核心特性](#2-核心特性)
3. [快速开始（60 秒验收）](#3-快速开始60-秒验收)
4. [系统架构](#4-系统架构)
5. [目录结构](#5-目录结构)
6. [在哪里使用](#6-在哪里使用)
7. [安装与配置](#7-安装与配置)
8. [使用方法](#8-使用方法)
9. [流水线阶段详解](#9-流水线阶段详解)
10. [Skill 体系](#10-skill-体系)
11. [风险评分与结论模型](#11-风险评分与结论模型)
12. [安全与合规](#12-安全与合规)
13. [测试体系](#13-测试体系)
14. [常见问题（FAQ）](#14-常见问题faq)
15. [比赛现场使用指南](#15-比赛现场使用指南)

---

## 1. 项目简介

**FirmHound（固件猎犬）** 是一套面向 IoT 固件漏洞挖掘的自动化流水线系统。它把「固件解包 → 攻击面排查 → 二进制反编译 → 静态数据流审计 → 十维风险评分 → 反证验证 → 本地动态验证 → 证据报告」这一完整流程封装为**可编排的 Skill + 确定性工具链**，支持 mock（纯规则离线）与 OpenAI-Compatible（国内备案模型）两种运行时，并以 9 个历史 CVE 金标准 Benchmark 持续回归验证。

**设计目标**：比赛现场给出的 CVE 是**现场新给、未知的**，因此系统不依赖任何 CVE 特征硬编码，而是靠**通用规则 + 可复用 Skill** 发现未知漏洞——零先验知识即可从陌生固件中定位高危候选。

命名含义：**Firm**（Firmware 固件）+ **Hound**（猎犬），寓意像猎犬一样凭借敏锐嗅觉，追踪、挖掘固件中隐藏的漏洞。

## 2. 核心特性

| 特性 | 说明 |
|---|---|
| 全流程自动化 | M0–M14 十五模块，阶段机驱动（`fsa/orchestrator/engine.py`），可断点续跑（resume） |
| 零 CVE 先验 | 通用规则 + Skill 知识驱动，不硬编码 CVE 特征，适配比赛现场新固件 |
| 纯 Python 静态分析 | pyelftools + capstone 解析 ELF，Windows 可直跑，不强制依赖 Ghidra/objdump |
| 双运行时 | `mock`（离线规则兜底）/ `openai_compatible`（DeepSeek 等国内备案模型，`config/models.yaml` 切换） |
| 反证优先验证 | 10 问清单 + 12 条硬规则，五分类结论模型（confirmed / candidate / FP / unknown / observation） |
| 十维风险评分 | P-I-U-D-C-S-W-K-V-T 十维、满分 30，阈值分级 CRITICAL/HIGH/MEDIUM/LOW |
| 动态验证安全门 | 四项硬门（AUTHORIZED / LOCAL_LAB / PRIVATE_NETWORK / BASELINE_READY），非武器化探针白名单 |
| 证据链可审计 | EvidenceStore / DecisionStore 全量落盘，报告 20 节固定骨架 + 7 项合规扫描 + 脱敏渲染 |
| 金标准回归 | `benchmarks/CVEs/` 9 个历史 CVE fixture，188 个单元测试持续守护 |

## 3. 快速开始（60 秒验收）

```bash
# ① 环境自检（Windows / Linux / WSL 均可）
python scripts/dev.py test      # 预期：188 passed
python scripts/dev.py lint      # 预期：All checks passed

# ② 金标准回归（9 个历史 CVE → 评分 → 反证 → 报告）
python scripts/run_pipeline.py --out-dir runs/pipeline --top-k 5
# 产物：runs/pipeline/{ranking.json, verdicts.json, report.md}

# ③ 未知固件演练（模拟比赛：构造仿真固件 → 自动解包 → 审计 → 报告）
python scripts/run_e2e.py
# 产物：runs/e2e/{analysis.json, report.md} — 零 CVE 先验检出 4 个植入漏洞
```

## 4. 系统架构

```
                    ┌──────────────────────────────────────────┐
                    │            WorkBuddy / 智能体             │
                    │   Orchestrator（阶段机 + 决策记录）        │
                    │   Planner / StateManager / HumanGate      │
                    └───────────────┬──────────────────────────┘
                                    │ 统一 Runtime Adapter
                    ┌───────────────▼──────────────────────────┐
                    │   fsa/runtime   mock │ openai_compatible │
                    │   SkillLoader / ToolRegistry / Budget     │
                    └───────────────┬──────────────────────────┘
        ┌───────────┬───────────────┼────────────────┬──────────┐
        ▼           ▼               ▼                ▼          ▼
   skills/       tools/          fsa/safety       fsa/schemas  fsa/reporting
   (01-07 流程   (确定性工具：     (安全红线         (9 个 JSON    (EvidenceStore
   知识沉淀)     解包/攻击面/      PolicyEngine)    Schema 校验)   DecisionStore)
                二进制/审计/
                仿真验证)
        └───────────┴───────────────┴────────────────┴──────────┘
                                    ▼
                          runs/<run_id>/ 产物目录
              state/ evidence/ decisions/ artifacts/ + report.md
```

**阶段机流转**（`fsa/orchestrator/engine.py`）：

```
INIT → BASELINE → UNPACK → SURFACE → BINARY_TRIAGE → DECOMPILE
     → STATIC_ANALYSIS → RANK → VERIFY_TOP_K → {LOCAL_VALIDATION | REPORT} → DONE
```

- `UNPACK` 部分失败 → fallback 到 `BINARY_TRIAGE`（无 rootfs 也能做 ELF 分析）
- `VERIFY_TOP_K` 之后：full 深度且有 `NEED_DYNAMIC` 候选 → 走 `LOCAL_VALIDATION`，否则直通 `REPORT`
- 任一 required 阶段失败 → `ABORTED`，保留已完成产物，可用 `resume()` 续跑

## 5. 目录结构

```
.
├── fsa/                      # 核心包（编排/运行时/安全/Schema/报告）
│   ├── orchestrator/         #   引擎、计划、状态机、人工门、Verifier
│   ├── runtime/              #   Runtime Adapter、Skill Loader、工具注册表
│   ├── safety/               #   安全策略引擎（路径/命令/IP 白名单）
│   ├── schemas/              #   JSON Schema 加载器
│   ├── reporting/            #   证据/决策存储
│   ├── prompts/              #   Prompt 模板管理
│   └── utils/                #   hashing / netcheck / jsonio / proc
├── tools/                    # 确定性工具（每个都是可独立调用的函数）
│   ├── firmware/             #   解包、信息收集、rootfs 评分、架构识别
│   ├── filesystem/           #   目录清单、启动脚本解析
│   ├── web/                  #   Webroot 枚举、handler 提取、UPnP、认证矩阵、攻击面
│   ├── binary/               #   ELF 读取、安全特性、危险函数扫描、triage
│   ├── analysis/             #   source-sink 规则、数据流、误报过滤、风险评分
│   ├── emulation/            #   安全门、探针、QEMU user/system、FirmAE 封装
│   ├── registry/             #   工具注册表（YAML 声明）
│   └── wsl_wrappers/         #   Windows→WSL 工具桥接（binwalk/unsquashfs 等）
├── skills/                   # Skill 知识库（SKILL.md，供智能体加载）
│   ├── 00-orchestrator/      #   总控编排方法论
│   ├── 01-unpack/            #   固件解包
│   ├── 02-attack-surface/    #   攻击面枚举
│   ├── 03-binary-decompile/  #   二进制反编译
│   ├── 04-static-analysis/   #   静态审计
│   ├── 04-audit/             #   command-injection / buffer-overflow 专项
│   ├── 05-candidate-verifier/#   反证审查与五分类
│   ├── 06-dynamic-validation/#   本地动态验证（含 qemu-service-bootstrap）
│   └── 07-report/            #   报告生成
├── schemas/                  # 9 个 JSON Schema + examples
├── config/                   # 三件套配置（见第 7 节）
├── benchmarks/CVEs/          # 9 个历史 CVE 金标准 fixture
├── scripts/                  # CLI 入口（见第 8 节）
├── tests/                    # 单元 / 集成 / fixture 测试
├── docs/                     # 设计文档、WSL 开发指南
├── legacy/                   # 原始手工 skill 归档
└── runs/                     # 运行产物（report.md / *.json）
```

## 6. 在哪里使用

| 运行环境 | 用途 | 说明 |
|---|---|---|
| **Windows（推荐开发）** | 单元测试、静态分析流水线、金标准回归 | 纯 Python 实现，pyelftools/capstone 直接可用，无需 Linux 工具链 |
| **WSL2 Ubuntu 22.04** | 完整解包、真实固件演练 | 需要 binwalk / sasquatch / unsquashfs / mksquashfs，参考 `docs/wsl_dev_guide.md` 与 `scripts/setup_wsl.sh` |
| **Docker** | 一键容器化运行 | `python scripts/dev.py docker-build / docker-run`（需 Docker daemon） |
| **决赛现场** | 比赛环境 | 使用 `openai_compatible` 运行时接国内备案模型（DeepSeek 等），mock 作为离线兜底 |

> Windows 下即使不装 WSL，也能跑通全部**单元测试**与**静态分析流水线**；只有「真实固件解包」和「QEMU 动态验证」需要 Linux 工具链。

## 7. 安装与配置

### 7.1 环境要求

- Python **≥ 3.11**（开发验证于 3.13）
- pip + venv（推荐隔离环境）
- （可选）Docker、WSL2 Ubuntu 22.04

### 7.2 安装依赖

```bash
# 方式一：跨平台任务运行器（Windows 推荐）
python scripts/dev.py dev        # 安装生产依赖 + 可编辑安装

# 方式二：Makefile（Linux/macOS/WSL）
make dev

# 方式三：手动
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 7.3 配置三件套（`config/`）

| 文件 | 作用 | 需要改吗 |
|---|---|---|
| `config/dev.yaml` | 主配置：默认 runtime、预算、路径、日志 | 默认即可 |
| `config/models.yaml` | 模型运行时：`mock`（离线）与 `openai_compatible`（在线）的定义、token 预算 | 决赛前配好 API |
| `config/safety.yaml` | 安全红线：路径白名单、命令黑名单、网络目标白名单 | **一般不要改** |

**切换模型运行时**（`config/models.yaml`）：

```yaml
runtimes:
  mock:                    # 离线规则兜底（默认，无外部调用）
    provider: mock
  openai_compatible:       # 决赛环境：国内备案模型
    provider: openai
    base_url: https://api.deepseek.com/v1
    model: deepseek-chat
    timeout: 60
    max_retries: 3
    api_key_env: OPENAI_API_KEY   # 从环境变量读取
```

启用在线模型时设置环境变量（或在 `.env` 中声明，参考 `.env.example`）：

```bash
export OPENAI_API_KEY=sk-xxx        # Windows PowerShell: $env:OPENAI_API_KEY="sk-xxx"
```

**预算控制**（`models.yaml` → `budgets`）：`default` 档（10 万 token / 阶段 2 万 / 单阶段 50 次调用）与 `quick` 档，超限自动停止，防止模型失控调用。

### 7.4 （可选）WSL 工具链

真实固件解包需要 Linux 工具：`binwalk`、`sasquatch`、`unsquashfs`、`mksquashfs`。

```bash
wsl -d Ubuntu-22.04
cd /mnt/c/Users/<你的路径>/揭榜挂帅——网络安全
bash scripts/setup_wsl.sh          # 自动安装工具链
python scripts/wsl_smoke.py        # 诊断 WSL 工具是否就绪
```

Windows 侧通过 `tools/wsl_wrappers/*.bat` 自动桥接 WSL（`wsl_tool_runner.py` 负责路径转换），无需手动切 shell。

## 8. 使用方法

### 8.1 开发任务运行器 `scripts/dev.py`

```bash
python scripts/dev.py help        # 查看全部命令
python scripts/dev.py test        # 跑全部测试（pytest，Windows 自动加 WSL 桥接 PATH）
python scripts/dev.py lint        # ruff 代码检查
python scripts/dev.py format      # ruff 自动格式化
python scripts/dev.py smoke       # CLI 冒烟测试（需 tests/fixtures/sample.bin）
python scripts/dev.py clean       # 清理缓存
python scripts/dev.py docker-build / docker-run
```

### 8.2 金标准流水线 `scripts/run_pipeline.py`

对 `benchmarks/CVEs/` 的 9 个历史 CVE 跑「评分 → 排序 → Top-K 选取 → 反证验证 → 报告」：

```bash
python scripts/run_pipeline.py --out-dir runs/pipeline --top-k 5
```

产物：
- `runs/pipeline/ranking.json` — 全量排序（rank / risk_score / risk_level / CVE 元数据）
- `runs/pipeline/verdicts.json` — Verifier 10 问反证裁决
- `runs/pipeline/report.md` — 人类可读报告

### 8.3 未知固件演练 `scripts/run_e2e.py`（模拟比赛现场）

对任意已解包 rootfs 执行完整静态分析（inventory → webroot → startup → ELF triage → 命令注入检测 → 评分 → 报告），**无需任何 CVE 先验**：

```bash
# 有真实 rootfs：
python scripts/run_e2e.py --rootfs <你的rootfs目录>

# 没有固件样本时，自动构建含 4 个植入漏洞的仿真固件再演练：
python scripts/run_e2e.py
```

产物：`runs/e2e/{analysis.json, report.md}`。

### 8.4 评分排序演示 `scripts/demo_rank.py`

```bash
python scripts/demo_rank.py --out-dir runs/demo
# 产物：runs/demo/ranking.{json,md}
```

### 8.5 产物目录约定

```
runs/<run_id>/
├── state/task_card.json        # 任务卡
├── state/plan.json             # 执行计划
├── state/run_state.json        # 运行状态（可 resume）
├── evidence/*.json             # 证据链
├── decisions/*.json            # 决策记录
└── artifacts/                  # 阶段产物
```

## 9. 流水线阶段详解

| 阶段 | 模块 | 关键产物 | Skill |
|---|---|---|---|
| M1 任务理解 | `orchestrator/planner.py` | task_card.json / plan.json | — |
| M2 固件解包 | `tools/firmware/*` | firmware_manifest.json / rootfs | 01-unpack |
| M3 攻击面 | `tools/web/*` | attack_surface.json | 02-attack-surface |
| M4 二进制 triage | `tools/binary/*` | binary_summary（triage_score） | 03-binary-decompile |
| M5 静态审计 | `tools/analysis/*` | candidates.json（source→sink 数据流） | 04-static-analysis / 04-audit |
| M6 风险评分 | `tools/analysis/risk_score.py` | ranking.json（十维评分） | — |
| M7 反证验证 | `orchestrator/verifier.py` | verdicts.json（五分类） | 05-candidate-verifier |
| M8 动态验证 | `tools/emulation/*` | dynamic_validation.json（L0–L3） | 06-dynamic-validation |
| M9 证据链 | `reporting/evidence_store.py` | evidence/ 索引 | — |
| M10 报告 | `fsa/report/` + Skill 07 | report.md + final_verdict.json | 07-report |

## 10. Skill 体系

9 个 Skill 包把领域知识沉淀为结构化 `SKILL.md`（含「输入/输出/执行流程/失败降级路径/验收标准」五节），供智能体加载复用：

| Skill | 领域 | 关键知识 |
|---|---|---|
| 00-orchestrator | 总控编排 | 阶段机、深度档位、决策可审计 |
| 01-unpack | 固件解包 | binwalk 无签名降级、魔数表、rootfs 评分 |
| 02-attack-surface | 攻击面 | Web/UPnP/CGI 枚举、认证矩阵三层交叉 |
| 03-binary-decompile | 二进制分析 | 架构识别、Ghidra 降级路径 |
| 04-static-analysis | 静态审计 | 命令注入五步法、协议解析六步法 |
| 04-audit | 专项审计 | command-injection / buffer-overflow 复现经验 |
| 05-candidate-verifier | 反证审查 | 10 问清单、12 条硬判定规则 |
| 06-dynamic-validation | 动态验证 | L0–L3 分层、qemu-user 三大坑、安全门 |
| 07-report | 报告生成 | 20 节骨架、7 项合规扫描、脱敏渲染 |

## 11. 风险评分与结论模型

**十维评分**（`tools/analysis/risk_score.py`，每维 0–3，满分 30）：

| 维 | 含义 | 维 | 含义 |
|---|---|---|---|
| P | 预认证可达性 | S | Shell 上下文 |
| I | 输入来源 | W | 文件写入 |
| U | 用户可控性 | K | 配置持久化 |
| D | 危险函数可达 | V | 输入验证（反向） |
| C | 字符串拼接 | T | 可测试性 |

分级阈值：**≥24 CRITICAL / 18–23 HIGH / 12–17 MEDIUM / <12 LOW**。每维必须引用证据 ID，无证据记 0 并标注。

**五分类结论**（M7 Verifier 输出）：

| 类别 | 含义 |
|---|---|
| `confirmed-issue` | 确认问题：外部输入 → 可控 → 真实 sink → 可达链，无有效过滤 |
| `high-confidence-candidate` | 高置信候选：核心链路成立，存在 minor 限制（需认证/可绕过过滤） |
| `false-positive` | 误报：非外部输入、不可控、未达 sink、仅调试功能 |
| `unknown` | 未知：关键事实缺失，无法可靠判断 |
| `observation` | 观察：仅发现危险 API / 可疑字符串，缺完整链路 |

裁决动作：**ACCEPT（采纳）/ DOWNGRADE（降级）/ REJECT（拒绝）/ NEED_DYNAMIC（需动态验证）**。

## 12. 安全与合规

本项目面向比赛与授权审计场景，内置多层安全约束：

1. **命令黑名单**（`config/safety.yaml`）：`rm -rf`、`curl/wget`（外联必须走受控通道）、`bash -i`、`python -m http.server` 一律拒绝。
2. **路径白名单**：工具只能读写 `runs/`、`tmp/`、`tests/fixtures/`、`firmware_samples/` 等白名单目录；`.env`、`secrets/`、`config/safety.yaml` 禁止读写。
3. **网络隔离**：`network.allow_public: false`，仅允许私有网段与 `127.0.0.1/localhost`；动态验证目标 IP 非私有 → `ABORT_DYNAMIC_VALIDATION`，零外发流量。
4. **动态验证四门**（`tools/emulation/safety_gate.py`）：`AUTHORIZED && LOCAL_LAB && PRIVATE_NETWORK && BASELINE_READY` 全过才放行。
5. **非武器化探针**（`tools/emulation/probes.py`）：只允许 `touch/echo/id/uname` 等无害标记；反弹 shell、持久化、下载执行一律拒绝。
6. **报告合规 7 项**（Skill 07）：无真实 IP / 无反弹 Shell 特征 / 无持久化 / 无下载执行 / 无破坏性命令 / 含安全声明 / 仅标记验证；并做脱敏渲染（`<USER_INPUT>`、`<BENIGN_MARKER>` 占位）。

## 13. 测试体系

```bash
python scripts/dev.py test      # 全部测试
python scripts/dev.py lint      # 静态检查（ruff，含 E/F/W/I/UP/B/C4/SIM 规则）
```

- **单元测试**：188 passed（Schema / 工具 / 编排 / Verifier / 评分 / 动态验证 / Skill 加载 / e2e 全链路）
- **集成测试**：`tests/integration/`（解包、攻击面，依赖 WSL/Docker 时自动 skip）
- **金标准回归**：`tests/unit/test_benchmark_fixtures.py` 校验 9 个 CVE fixture 全部符合 Schema

## 14. 常见问题（FAQ）

**Q1：Windows 上没有 binwalk / unsquashfs，能跑吗？**
能。单元测试与静态分析流水线全部纯 Python（pyelftools/capstone）；只有真实固件解包需要 WSL 工具链，Windows 会通过 `tools/wsl_wrappers/` 自动桥接，工具缺失时自动降级（记录 limitation，不崩溃）。

**Q2：怎么接入比赛要求的国产大模型？**
编辑 `config/models.yaml` 的 `openai_compatible` 段（base_url / model / api_key_env），设置 `OPENAI_API_KEY` 环境变量，并把 `config/dev.yaml` 的 `runtime.default` 改为 `openai_compatible`。模型不可用时自动回退 `mock` 规则模式。

**Q3：比赛现场给的是新固件 + 新 CVE，系统能发现吗？**
可以。系统不依赖任何 CVE 特征硬编码：`run_e2e.py` 演练证明，零 CVE 先验下通用规则能自动检出 4 个植入命令注入（httpd/upnpd=23 HIGH、2 CGI=21 HIGH）。现场流程 = 解包 → 攻击面 → ELF triage → 静态审计 → 评分 → 反证 → 报告。

**Q4：怎么查看验收结果？**
`runs/pipeline/report.md` 与 `runs/e2e/report.md` 为人类可读报告；`ranking.json` / `verdicts.json` 为机器可读结果；把 report.md 交给 WorkBuddy 可转换为可视化页面预览。

**Q5：报告里会不会出现可武器化内容？**
不会。Skill 07 强制 7 项合规扫描 + 脱敏渲染，报告中真实 IP、反弹 shell、持久化、下载执行等内容会被占位符替换；全 REJECT 时如实输出「未发现强证据」。

**Q6：WSL 服务不稳定（0x8007274c）怎么办？**
`wsl --shutdown` 后重试；Windows 侧测试建议用 `python scripts/dev.py test`（自动加桥接 PATH），如仍挂起可只在 WSL 内跑 `pytest`。详见 `docs/wsl_dev_guide.md`。

## 15. 比赛现场使用指南

**赛前准备（一次性）**
1. 按第 7 节配置好 venv 依赖与模型 API，验证 `test` / `lint` 通过。
2. 用 `run_pipeline.py` 跑一遍金标准回归，确认 9 个 CVE 评分分级正确。
3. 跑一遍 `run_e2e.py` 演练，熟悉新固件流程与产物位置。
4. 打印/熟记 10 维评分规则、五分类口径、安全门含义（答辩问答高频点）。

**现场流程（拿到新固件后）**
1. `python scripts/run_e2e.py --rootfs <rootfs>`（若现场提供已解包目录）或先解包。
2. 检查 `report.md`：候选排行 → 反证裁决 → 确认高危候选的 source→sink 证据链。
3. 对 `NEED_DYNAMIC` 候选，确认安全门四项后跑动态验证补证据。
4. 用 Skill 07 生成最终报告，脱敏后提交。

**答辩亮点（对应评分维度）**
- **决策可解释**：每个阶段有决策记录（options/selected/reason/confidence/actor），报告 20 节证据链完整。
- **工具协同**：Skill 知识库 + 确定性工具 + 双运行时，三层协同架构。
- **创新**：零 CVE 先验的通用规则挖掘（未知固件 drill 实证）、反证优先验证、十维证据驱动评分。
- **任务理解**：流水线严格对齐赛题「自主决策 + 安全合规」要求，动态验证全程安全门约束。

---

*FirmHound · 固件猎犬 — 第一队 · 挑战杯揭榜挂帅「具备自主决策能力的通用网络安全智能体」赛题作品*
*内部包名/CLI 标识沿用 `fsa`（Firmware Security Agent），README 与产品命名统一为 FirmHound。*
