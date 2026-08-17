# 第一队系统研发：WorkBuddy 自执行开发计划（v2.0）

> **本文档是 WorkBuddy（本智能体）的执行手册**。它不是"思路描述"，而是一份可直接按步骤实施的施工图纸：每个模块给出文件级清单、接口契约、内部算法、异常降级路径和可验证的验收标准（Definition of Done, DoD）。WorkBuddy 将按第七部分任务分解表逐条执行，每完成一条任务并跑通 DoD 验收后，再进入下一条。
>
> **项目背景**：挑战杯"揭榜挂帅"擂台赛 XH-202609《具备自主决策能力的通用网络安全智能体》（发榜单位：杭州安恒信息）。第一队任务：把团队过往固件挖洞经验（4 份 legacy Skill）升级为一套"固件解包 → 攻击面排查 → 二进制反编译 → 静态审查 → 动态验证 → 证据报告"的自动化流水线 Agent，并在历史已知漏洞固件上做盲测能力验证。
>
> **与旧版计划的关系**：`第一队_系统研发与自动化流水线_详细计划.md`（下称"旧计划"）是需求与排期纲领；本文档是其落地实施版，模块编号、Schema 字段、目录名与旧计划保持一致，冲突时以本文档为准。
>
> **安全红线（全局最高优先级，任何代码、任何阶段不得违反）**：
> - 仅分析本地持有、明确授权的固件文件与隔离仿真环境；
> - 动态验证只允许非武器化、最小化验证（无害标记：`touch /tmp/lab_marker`、`id`、`uname -a`）；
> - 禁止生成反弹 Shell、持久化、下载执行、攻击链、真实利用 payload；
> - 禁止向公网/真实设备/校园网设备发送任何流量，仿真目标 IP 必须在 `192.168.0.0/16`、`10.0.0.0/8`、`172.16.0.0/12`；
> - 任何输出物（日志、报告、代码注释、prompt）中不得包含可直接复现的攻击请求或触发参数。

---

# 第一部分　WorkBuddy 自执行约定（先读这一节再动手）

## 0.1 执行模式

1. **严格按第七部分的"任务分解表"顺序执行**。任务编号 `T-XX`，表中标明依赖关系；被依赖任务未通过验收前不得开始后续任务。
2. **每个任务以 DoD（Definition of Done）为准绳**。DoD 全部满足并跑通验收命令后，才算完成；完成后立即 git commit，commit message 格式：`[T-XX] <一句话>`。
3. **不得跨任务顺手实现未来功能**。遇到"顺便能做"的东西，记录到 `docs/backlog.md`，不在当前任务内做。
4. **接口冻结原则**：`schemas/` 下任何 Schema 字段变更，必须同步修改对应 `schemas/examples/` 示例和受影响模块的解析代码，并在 commit message 中注明 `SCHEMA-CHANGE`。
5. **遇到本文档未覆盖的决策点**，优先选择"更通用、更不依赖单一厂商/单一模型"的方案，并在 `docs/adr/` 下新增一条 ADR（架构决策记录），格式见 3.4 节。若涉及高风险、高成本或可能影响里程碑的决策，必须先用 `AskUserQuestion` 征求用户意见。

## 0.2 全局技术约定

| 项目 | 约定 |
|---|---|
| 语言 | Python 3.11+（编排与工具层）；Shell 仅用于胶水脚本 |
| 运行环境 | Linux（Ubuntu 22.04，WSL2 或 Docker）。分析工具链（binwalk/squashfs-tools/Ghidra/QEMU）只在 Linux 环境运行。WorkBuddy 当前在 Windows 宿主，执行 Linux-only 步骤时优先用 WSL2 或 Docker；若用户环境未准备，先提示用户确认后再继续 |
| 包管理 | `pyproject.toml` + `requirements.txt` 双写；版本必须锁定 |
| 配置 | 全部走 `config/*.yaml` + 环境变量（`.env`），禁止硬编码路径/密钥/模型名 |
| 日志 | 统一 `logging` + 结构化 JSONL 落盘（见 M9），禁止裸 `print` 作为运行日志 |
| 错误处理 | 每个模块定义明确退出码与 `status` 字段（见 5.8）；禁止"异常直接 traceback 退出" |
| 测试 | `pytest`；每个 tools 脚本至少 1 个单测；每个 Skill 至少 1 个集成测试 |
| 代码风格 | `ruff` 检查通过；函数必须有 docstring 说明输入/输出 |
| 大模型调用 | 一律通过 M12 的 Runtime 适配层，禁止在业务代码里直接写 HTTP 请求调模型 |
| 确定性优先 | 能用脚本确定性完成的工作（扫描、提取、评分、格式化）绝不交给模型自由生成；模型只做理解、判断、选择和解释 |

## 0.3 目录纪律

- 4 份 legacy Skill 归档到 `legacy/`（只读），**不再修改**：
  - `legacy/router-firmware-vuln-hunting.SKILL.md`（原 SKILL.md，Tenda AC15 / Netgear R7000 案例）
  - `legacy/router-firmware-vuln-analysis-merged.SKILL.md`（原 SKILL1.md，HG532e / CVE-2017-17215 合并版）
  - `legacy/router-firmware-vuln-hunt-v2.SKILL.md`（原 SKILL2.md，D-Link 双案例版）
  - `legacy/iot-firmware-defensive-analysis/`（zip 解压版，证据链 + 离线 fuzz 方法论）
- 新能力一律落在 `skills/`（流程知识）或 `tools/`（确定性脚本）中。
- `runs/`、`reports/`、`benchmarks/private_ground_truth/` 加入 `.gitignore`（固件与 Ground Truth 不进仓库）。

## 0.4 ADR 模板（`docs/adr/NNNN-title.md`）

```markdown
# ADR-NNNN: <标题>
- 状态: proposed | accepted | superseded
- 背景: <为什么需要决策>
- 决策: <选择了什么>
- 备选: <放弃的方案及原因>
- 影响: <对哪些模块有影响>
```

---

# 第二部分　赛题要求 → 工程特性映射（评分导向设计）

赛题初审满分 100，5 个维度各 20 分；终审 = 人机协同实战赛 60% + 答辩 40%。第一队的系统必须让每个评分维度都有**可演示、可举证**的工程对应物。以下映射表是全系统设计的总纲，也是答辩材料的事实来源。

## 2.1 五维评分 → 系统特性对照表

| 评分维度（20 分） | 拿高分的关键行为 | 对应工程特性（本系统必须实现） | 证据载体 |
|---|---|---|---|
| 任务理解与执行设计 | 深度理解开放式任务、多策略选择、动态规划 | **M1 任务理解模块**：自然语言/压缩包/接口文档 → `task_card.json`；Orchestrator 状态机含分支/降级/重规划（非线性脚本） | 演示：同一固件用三种不同任务描述输入，均生成正确执行计划 |
| 系统架构与工程实现 | 模块化/插件化、代码质量、部署便捷 | 8 个职责单一 Skill + 标准 Tool 接口 + Docker 一键部署 + CLI | `docker compose up` 一条命令起全套环境；`fsa run firmware.bin` 一条命令出报告 |
| 决策逻辑与可解释性 | 决策可追溯、可复现、抗干扰 | **decision_log + evidence chain**：每次分支选择记录 inputs/options/selected/reason/confidence；`run_state.json` 支持断点恢复与重放 | 报告第 18/19 节"决策摘要"与"人工介入点"；同一固件两次运行 Top-K 稳定 |
| 工具协同与扩展能力 | 插件化管理、跨工具链自动编排 | **Tool Registry**（声明式 YAML 注册工具）+ Skill 热插拔 + Vendor Adapter（厂商字典外挂）+ Runtime Adapter（框架可替换） | 现场演示：新增一个厂商字典 yaml（不改代码）→ 重跑后候选排名变化 |
| 创新与附加价值 | 核心能力创新、显著超越基础要求 | 三个创新点：①证据链五分类结论模型（confirmed-issue / high-confidence-candidate / false-positive / unknown / observation）与反证优先的 Verifier；②"Skill 即经验资产"的人机协同进化闭环（Improvement Card → 规则/字典 → 回归测试）；③盲测 Benchmark 自动评价体系 | Benchmark 报告：Top-K 命中率、误报率、人工介入次数的量化曲线 |

## 2.2 决赛（终审）约束 → 架构含义

决赛形式：**3 名队员 + 自研 AI Agent**，在**指定受控环境**部署运行，模型 API 必须是**国内备案大模型**，经主办方 **AI 安全网关**接入，平台自动判分（客观分 60%）。赛题量"超出纯人工处理能力范围"，场景覆盖渗透测试、应急响应、漏洞挖掘、逆向分析。

这些约束倒逼以下架构决策（已在模块设计中落实）：

| 决赛约束 | 架构含义 | 落实位置 |
|---|---|---|
| 模型 API 限定国内备案、走安全网关 | 模型层必须可插拔，支持任意 OpenAI 兼容端点（DeepSeek / Qwen / GLM / 文心等），base_url 与 key 全部走配置 | M12 Runtime 适配层 |
| 受控环境、可能无外网/受限网络 | 工具链全部本地化；系统在无模型 API 时降级为"纯工具流水线"模式（结论置信度标注降级） | M0 Orchestrator `OFFLINE_MODE` |
| 网关监控 = token 与调用次数有成本 | 模型调用预算管理：每个 stage 有 token 上限；大文本先经工具压缩为结构化摘要再喂模型 | M0 `budget.py` + M4 结构化摘要层 |
| 人机协同、3 名队员现场介入 | Agent 必须支持"人工接管点"：可在任意 stage 注入人工证据/修正，Agent 吸收后继续（对应第二队 Improvement Card 流程） | M0 `human_gate.py` |
| 平台自动判分 = 输出格式可能被机器解析 | 最终结论同时输出人类可读报告（Markdown/PDF）和机器可读结论（`final_verdict.json`） | M10 报告模块 |
| 场景不止固件（渗透/应急/逆向） | 固件流水线是第一场景，但 Orchestrator、证据模型、Runtime 层按"通用安全智能体"设计，固件 Skill 包作为第一个场景插件包 | 整体架构 + 答辩叙事 |

## 2.3 提交物清单（9 月 5 日前必须齐）

| 赛题要求 | 本项目对应物 | 责任人 |
|---|---|---|
| 程序材料：源代码 | Git 仓库导出 + commit 历史 | A |
| 程序材料：一键部署方案 | `deploy/` 下 Dockerfile + docker-compose.yml + `make deploy` | D |
| 程序材料：在线可测试访问地址 | 本地/内网演示实例（Web 只读展示页，P2）或录屏替代说明 | A |
| 文档材料：方案设计文档 | `docs/design.md`（由本文档演化） | A |
| 文档材料：开发文档 | `docs/dev/`（模块 README 汇总） | 全员 |
| 文档材料：测试文档 | `docs/testing.md` + Benchmark 报告 | D |
| 文档材料：用户手册 | `docs/user_guide.md` | B |
| 文档材料：技术报告 | 含评分对照表、Benchmark 数据、创新点论证 | A |
| 文档材料：PPT + 演示视频 | 9 月 3–4 日录制完整演示 run | 全员 |
| 声明函 | 原创性/保密性声明 | 指导老师 |

---

# 第三部分　总体架构

## 3.1 分层架构

```text
┌─────────────────────────────────────────────────────────────┐
│ L5 交互层    CLI (fsa)  │ 人工接管 human_gate │ Web 展示(P2) │
├─────────────────────────────────────────────────────────────┤
│ L4 编排层    Orchestrator: Planner → Dispatcher → Verifier   │
│              StateManager │ PolicyEngine │ Budget │ Reporter │
├─────────────────────────────────────────────────────────────┤
│ L3 技能层    skills/00~07（流程知识: 何时做/怎么做/失败怎么办）│
├─────────────────────────────────────────────────────────────┤
│ L2 工具层    tools/（确定性脚本: firmware/fs/web/binary/emu/ │
│              reporting）+ Tool Registry（YAML 声明式注册）    │
├─────────────────────────────────────────────────────────────┤
│ L1 运行时层  Runtime Adapters: claude_code / hermes /        │
│              deepseek_harness / openai_compatible（国产模型） │
├─────────────────────────────────────────────────────────────┤
│ L0 数据层    schemas/ │ runs/<run_id>/ │ evidence │ vendor/  │
│              benchmarks/ + evaluator/                        │
└─────────────────────────────────────────────────────────────┘
```

**核心原则：模型在 L4/L3 做判断与选择，L2 工具做确定性执行，L0 保证一切落盘可审计。模型说"做什么"，工具决定"做得对不对"，Schema 保证"传得下去"。**

## 3.2 一次 Run 的数据流

```text
任务输入(自然语言/固件/参数)
  → M1 任务理解 → task_card.json
  → M0 Planner 生成执行计划（stage 序列 + 每 stage 成功判据）
  → M2 解包     → firmware_manifest.json      ─┐
  → M3 攻击面   → attack_surface.json          │ 每步产出
  → M4 反编译   → binary_summary.json          │ Schema 化 JSON
  → M5 静态审计 → candidates.json              │ + evidence 条目
  → M6 评分排序 → candidate_ranking.json       │ + decision 条目
  → M7 反证审查 → verdicts.json                │
  → M8 动态验证(安全门控,可选) → validation.json ┘
  → M10 报告    → report.md + final_verdict.json
  （全程）M9 证据/日志/状态落盘 runs/<run_id>/
```

## 3.3 关键设计决策（已定为 ADR，WorkBuddy 直接遵循）

- **ADR-0001 编排与框架解耦**：业务逻辑不依赖 Claude Code / Hermes / DeepSeek-Harness 任一框架的私有特性；通过 L1 Runtime Adapter 接入。理由：决赛环境模型/框架受限，必须可替换。
- **ADR-0002 工具确定性优先**：凡可脚本化的（解包、扫描、评分、报告骨架）均为 Python/Shell 工具；模型只消费工具的结构化输出。理由：可复现性（评分维度 3）与 token 成本。WorkBuddy 自身也要遵守：能用 Read/Write/Bash 工具做的工作不要依赖模型生成。
- **ADR-0003 一切结论走证据模型**：候选结论只允许五分类（`confirmed-issue` / `high-confidence-candidate` / `false-positive` / `unknown` / `observation`），沿用 legacy zip skill 的 evidence-model 并固化为 Schema。理由：可解释性与答辩叙事的核心资产。
- **ADR-0004 Schema 先行的并行开发**：第 1 天冻结 Schema v0.1 后，各模块并行开发，靠 Schema + mock 数据解耦。
- **ADR-0005 盲测隔离**：Agent 运行时可读路径白名单不包含 `benchmarks/private_ground_truth/`；Evaluator 独立进程读取。理由：能力验证的可信度。

## 3.4 仓库结构（文件级）

```text
firmware-security-agent/
├── README.md                      # 项目介绍 + 快速开始（5 分钟跑通）
├── AGENTS.md                      # 给 AI 编程智能体的开发约定（0.1–0.4 节固化版）
├── pyproject.toml
├── requirements.txt               # 锁定版本
├── Makefile                       # install/test/run/benchmark/deploy 入口
├── .env.example                   # 模型 API、路径开关的样例（无真实密钥）
├── Dockerfile
├── docker-compose.yml             # 一键部署：agent + 工具链
│
├── config/
│   ├── default.yaml               # 全局默认：TOP_N、超时、深度档位
│   ├── safety.yaml                # 安全红线 R1–R9 的机器可执行版（正则/网段/白名单）
│   ├── models.yaml                # 模型端点、预算、降级策略
│   └── benchmark.yaml             # 盲测用例清单引用、评分权重
│
├── fsa/                           # 主 Python 包（对外 CLI: fsa）
│   ├── __init__.py
│   ├── cli.py                     # 全部用户入口: run/resume/benchmark/report
│   ├── orchestrator/
│   │   ├── planner.py             # 任务理解 → 执行计划
│   │   ├── dispatcher.py          # 状态机推进、调用 Skill/Tool
│   │   ├── verifier.py            # 候选反证审查（M7 的编排侧）
│   │   ├── state_manager.py       # run_state.json 读写、断点恢复
│   │   ├── policy_engine.py       # 安全门、路径白名单、合规检查
│   │   ├── budget.py              # token/时间/调用次数预算
│   │   ├── human_gate.py          # 人工接管点（注入人工证据继续跑）
│   │   └── reporter.py            # 汇总各阶段产物 → 报告输入
│   ├── runtime/
│   │   ├── base.py                # AgentRuntime 抽象基类（接口定义）
│   │   ├── openai_compatible.py   # 国产备案模型通用适配（DeepSeek/Qwen/GLM…）
│   │   ├── claude_code.py         # 备选适配
│   │   ├── hermes.py              # 备选适配
│   │   └── mock.py                # 无模型离线模式（规则代替模型判断）
│   ├── schemas/                   # Python 侧 Schema 加载与校验
│   │   ├── loader.py
│   │   └── validators.py
│   └── utils/
│       ├── hashing.py             # sha256 等
│       ├── netcheck.py            # 私有 IP 判定（安全门用）
│       ├── jsonio.py              # 原子写 JSON（防中断写坏）
│       └── proc.py                # 子进程封装：超时/退出码/stdout 落盘
│
├── skills/                        # 技能层（SKILL.md = 流程知识，供模型加载）
│   ├── 00-orchestrator/SKILL.md
│   ├── 01-firmware-unpack/SKILL.md
│   ├── 02-attack-surface/SKILL.md
│   ├── 03-binary-decompile/SKILL.md
│   ├── 04-static-analysis/SKILL.md
│   ├── 05-candidate-verifier/SKILL.md
│   ├── 06-local-validation/SKILL.md
│   └── 07-evidence-report/SKILL.md
│
├── tools/                         # 确定性工具（每个都是可独立执行的 CLI）
│   ├── registry/                  # 工具注册表（YAML 声明：名称/入参/出参/超时）
│   │   ├── binwalk.yaml
│   │   ├── unpack.yaml
│   │   └── ... （每个工具一个 yaml）
│   ├── firmware/
│   │   ├── collect_info.py        # 哈希/file/魔数/binwalk 扫描 → 基线
│   │   ├── unpack.py              # 解包调度（squashfs/cpio/ubi/jffs2/dd 切片）
│   │   ├── rootfs_score.py        # rootfs 候选评分
│   │   └── arch_detect.py         # 架构/位数/大小端/libc 交叉确认
│   ├── filesystem/
│   │   ├── inventory.py           # rootfs 清单（ELF/脚本/配置/启动项统计）
│   │   └── startup_parse.py       # init.d/rc/inetd/procd 启动项解析
│   ├── web/
│   │   ├── webroot_enum.py        # webroot/CGI/脚本枚举
│   │   ├── handler_extract.py     # 二进制内嵌端点反推（formXxx/websFormDefine…）
│   │   ├── upnp_parse.py          # UPnP/SOAP XML → Action + direction=in 参数
│   │   └── auth_matrix.py         # 三层认证边界交叉验证
│   ├── binary/
│   │   ├── elf_triage.py          # ELF 初筛打分 → Top-N
│   │   ├── secfeatures.py         # NX/Canary/PIE/RELRO/Stripped
│   │   ├── danger_scan.py         # 危险函数 D/E/F/B/M/W 分级扫描
│   │   ├── ghidra_headless.py     # Ghidra 批处理导出（函数/调用/字符串/xref）
│   │   ├── decompile_fallback.py  # 无 Ghidra 时的 objdump/radare2 降级
│   │   ├── callgraph.py           # 调用图构建 + BFS(MAX_DEPTH=4)
│   │   └── summarize.py           # 反编译结果 → 结构化摘要（压 token）
│   ├── emulation/
│   │   ├── safety_gate.py         # 动态验证安全门（AUTHORIZED/LOCAL/PRIVATE/BASELINE）
│   │   ├── qemu_user.py           # L1 二进制可加载验证（-strace）
│   │   ├── qemu_system.py         # L2/L3 系统仿真编排（tap 隔离网）
│   │   ├── firmae_wrap.py         # FirmAE 封装（可选，环境有才启用）
│   │   └── probes.py              # 无害探针与基线连通性（curl/标记文件）
│   ├── analysis/
│   │   ├── source_sink_rules.py   # Source/Sink/Validation/Auth 规则库加载
│   │   ├── dataflow.py            # 入口→sink 链组装（七层模板 + socket 变体）
│   │   ├── risk_score.py          # 10 维 P-I-U-D-C-S-W-K-V-T 评分
│   │   └── fp_filter.py           # 误报排除引擎（CLI 工具/硬编码命令/IPC…）
│   └── reporting/
│       ├── evidence_store.py      # 证据条目读写、索引
│       ├── report_gen.py          # report.md 生成（Jinja2 模板）
│       ├── verdict_json.py        # final_verdict.json（机器可读结论）
│       └── compliance_scan.py     # 交付物安全合规扫描（7 项）
│
├── schemas/                       # JSON Schema（单一事实来源）
│   ├── task_card.schema.json
│   ├── firmware_manifest.schema.json
│   ├── attack_surface.schema.json
│   ├── binary_summary.schema.json
│   ├── candidate.schema.json
│   ├── verdict.schema.json
│   ├── evidence.schema.json
│   ├── decision.schema.json
│   ├── run_state.schema.json
│   └── examples/                  # 每个 schema 一个合法示例（测试要校验）
│
├── vendor/                        # 厂商适配字典（外挂、可热加）
│   ├── common.yaml                # 通用危险函数/认证函数/参数获取 API
│   ├── tenda.yaml                 # formXxx 端点、doSystemCmd 等
│   ├── dlink.yaml                 # lxmldbc_system/alpha_system2/AUTHORIZED_GROUP…
│   ├── huawei.yaml                # HG532e: upnp/upg 模板、cwmp…
│   ├── netgear.yaml
│   └── tplink.yaml
│
├── benchmarks/
│   ├── public/                    # case01/…{firmware.bin, manifest.yaml}（Agent 可见）
│   ├── private_ground_truth/      # case01.yaml（Agent 禁止读取，gitignore）
│   └── manifests/                 # 用例索引
│
├── evaluator/
│   ├── evaluate_run.py            # 单次盲测评分
│   ├── metrics.py                 # 10 项指标实现
│   ├── compare_runs.py            # 版本间回归对比
│   └── matching.py                # 候选 ↔ Ground Truth 匹配规则
│
├── tests/
│   ├── unit/                      # 每个 tools 脚本 ≥1
│   ├── integration/               # 固件→rootfs→surface→rank 链路
│   ├── regression/                # 历史案例防回退
│   └── fixtures/                  # 迷你 rootfs、畸形 ELF 等测试夹具
│
├── legacy/                        # 4 份旧 Skill（只读归档）
├── runs/                          # 运行产物（gitignore）
├── reports/                       # 最终报告（gitignore）
├── deploy/
│   ├── docker/                    # 工具链镜像分层（base/analysis/emulation）
│   └── scripts/install_ubuntu.sh  # 裸机一键安装（备选部署路径）
└── docs/
    ├── design.md                  # 方案设计文档（赛题提交物）
    ├── user_guide.md              # 用户手册（赛题提交物）
    ├── testing.md                 # 测试文档（赛题提交物）
    ├── adr/                       # 架构决策记录
    ├── backlog.md
    ├── progress.md                # 每日进度（旧计划节奏）
    └── legacy_skill_capability_matrix.md   # 第一阶段产出
```

---

# 第四部分　统一数据 Schema（契约层，最先冻结）

> 所有 Schema 用 JSON Schema Draft 2020-12 描述，存放于 `schemas/`；Python 侧经 `fsa/schemas/loader.py` 加载并在每次产出后强制校验。**下游模块只允许消费上游的 Schema JSON，禁止解析上游的日志文本。** 下列字段为必备字段（required），各模块可扩展 `extra` 字段但不得改必备字段语义。

## 4.1 task_card.json（M1 任务理解产出）

| 字段 | 类型 | 说明 |
|---|---|---|
| task_id | string | 唯一 ID |
| raw_input_refs | array | 原始输入引用（文本/文件路径/压缩包内成员） |
| objective | enum | `firmware_vuln_hunt` / `firmware_baseline` / `re_analysis` / `unknown` |
| firmware_path | string | 目标固件绝对路径（本地） |
| vendor/model/version | string | 可空；不得由模型臆造，只能来自输入或固件证据 |
| authorization | object | `{holder, scope, allow_emulation: bool, network_isolation}` |
| depth | enum | `quick` / `standard` / `full`（默认 standard） |
| constraints | array | 用户额外约束（如"只做静态"） |
| success_criteria | array | 由任务描述解析出的可验证成功判据 |

**硬规则**：`authorization.allow_emulation == false` 时，M8 任何阶段不得启动；objective 无法判定时 `unknown` 并请求人工澄清（human_gate），不得猜。

## 4.2 firmware_manifest.json（M2 产出）

必备字段：`run_id, firmware_path, sha256, md5, file_size, vendor, model, version, source, file_type, magic_bytes(hex 前 32 字节), filesystem[](每项: {type, offset, size, extract_method}), rootfs_path, rootfs_candidates[]({path, score, markers}), architecture, bits, endian, libc, kernel_hint, web_servers[], elf_count, extraction_confidence(0-1), status(success|partial|binary_only|failed), tool_versions{}`。

**硬规则**：`status=failed` 时 Orchestrator 不得崩溃退出，转 `BINARY_ONLY_MODE` 或终止并给出 `remaining_limitations`。

## 4.3 attack_surface.json（M3 产出）

`surfaces[]` 每项必备：`surface_id, category(web|cgi|upnp|soap|hnap|socket|daemon|script), protocol, binary, route, handler, input_sources[](http_param|header|cookie|body|soap_arg|socket_buf|env|file_upload|config), auth_hint(preauth|auth|local_only|ipc|unknown), startup_evidence[](文件:行 引用), reachability_hint, confidence(0-1), evidence_ids[]`。

## 4.4 binary_summary.json（M4 产出，每个 ELF 一份）

必备：`binary_id, path, sha256, architecture, security_features{nx,canary,pie,relro,stripped}, imports[], strings_summary(去重+分类后，非全量), functions[]({name|addr, callers[], callees[], strings[], is_source, is_sink, is_auth, is_validation}), network_functions[], sources[], sinks[], auth_functions[], validation_functions[], triage_score, decompile_status(full|fallback|failed)`。

## 4.5 candidate.json（M5 产出）

必备：`candidate_id, surface_id, binary_id, entry{}, source{}, transform[], validation[], authorization{}, sink{}, call_chain[], user_control(none|partial|full), vuln_class_hypothesis(command_injection|overflow|path_traversal|auth_bypass|config_injection|format_string|other), risk_score(0-30), risk_level(CRITICAL|HIGH|MEDIUM|LOW), evidence[], counterevidence[], conclusion_category(observation|unknown|high-confidence-candidate|confirmed-issue|false-positive), decisive_missing_fact, status(new|analyzing|rejected|strong|confirmed)`。

**硬规则**：`conclusion_category` 必须取五分类之一（ADR-0003）；只有危险 API/字符串而无数据流假设的条目强制为 `observation`；`false-positive` 必须填写击败性反证。

## 4.6 verdict.json（M7 产出）

每个 Top-K 候选一条：`candidate_id, action(ACCEPT|DOWNGRADE|REJECT|NEED_DYNAMIC), original_score, revised_score, reasons[], supporting_evidence[], counterevidence[], reviewer(mock|model|human)`。

## 4.7 evidence.json / decision.json / run_state.json

- evidence：`evidence_id, run_id, stage, type(command_output|file_observation|decompile|emulation|human_input), source_file, command, tool, tool_version, timestamp, artifact_path, observation, fact_status(confirmed|inferred|unknown|external-reference), supports[], contradicts[]`。
- decision：`decision_id, stage, inputs[], observation, options[], selected, reason, confidence, next_stage, actor(model|rule|human)`。
- run_state：`run_id, task_card_ref, current_stage, completed_stages[], failed_stages[], retry_count{}, artifacts{}, decisions[], token_usage{}, status(running|paused|done|aborted), resume_token`。

## 4.8 阶段状态码（全系统统一）

| status | 含义 | Orchestrator 行为 |
|---|---|---|
| `success` | 产出完整且通过 Schema 校验 | 推进下一 stage |
| `partial` | 有产出但置信度低/部分失败 | 记录 decision，走降级分支 |
| `skipped` | 被策略/预算跳过（如动态验证未授权） | 记录原因，继续 |
| `failed` | 无有效产出 | 按失败恢复表处理；重试 ≤2 次后降级 |
| `aborted` | 触碰安全红线 | 全 run 终止，写合规报告 |

---

# 第五部分　模块详细设计（M0–M14）

> 每个模块按统一格式描述：**目标 / 文件清单 / 输入 / 输出 / 内部逻辑（含伪代码）/ 异常与降级 / 验收（DoD）**。WorkBuddy 自执行时，每个 DoD 验收项都要通过实际命令或测试验证，不得跳过；验证失败后必须修复，不得进入后续任务。

## M0　Orchestrator 总控（负责人 A）

**目标**：把"顺序跑脚本"升级为具备条件分支、重试降级、候选聚焦、动态门控、中断恢复、决策留痕的状态机。这是评分维度 1/3 的核心载体。

### 文件清单

- `fsa/orchestrator/planner.py` — 读 task_card + config，产出 `plan.json`（stage 序列、每 stage 的 Skill/Tool 绑定、成功判据、预算配额）。
- `fsa/orchestrator/dispatcher.py` — 状态机主体。每步：调用 Tool（经 Tool Registry）→ 校验产出 Schema → 写 evidence → 按结果查转移表 → 写 decision。
- `fsa/orchestrator/state_manager.py` — `run_state.json` 的原子读写；`resume(run_id)` 从最近成功 stage 继续。
- `fsa/orchestrator/policy_engine.py` — 安全门执行者：路径白名单（禁止 Agent 读 `private_ground_truth/`）、安全红线检查（调用 `utils/netcheck.py` 与 `config/safety.yaml`）、`aborted` 判定。
- `fsa/orchestrator/budget.py` — 每 run 的 token 上限、每 stage 模型调用上限、总时长上限；超限自动降级到 `mock` runtime（规则判断）。
- `fsa/orchestrator/human_gate.py` — 人工接管：CLI 提供 `fsa inject <run_id> --evidence file.md` / `--override-verdict`，将人工证据写入 evidence（`type=human_input`）后从当前 stage 重评估。
- `fsa/orchestrator/verifier.py` — M7 的编排侧（见 M7）。
- `fsa/orchestrator/reporter.py` — 汇集各 stage 产物交给 M10。

### 状态机（转移表驱动，代码里用显式 TABLE，不写散落的 if-else）

```text
INIT → BASELINE → UNPACK
UNPACK ─success→ SURFACE
UNPACK ─partial→ FALLBACK_UNPACK ─→ (success→SURFACE / fail→BINARY_ONLY_MODE)
SURFACE → BINARY_TRIAGE → DECOMPILE → STATIC_ANALYSIS → RANK
RANK → VERIFY_TOP_K
VERIFY_TOP_K ─证据充分→ REPORT
VERIFY_TOP_K ─NEED_DYNAMIC 且安全门通过→ LOCAL_VALIDATION → REPORT
VERIFY_TOP_K ─NEED_DYNAMIC 但安全门不过→ REPORT(标注 dynamic_skipped)
VERIFY_TOP_K ─全部 REJECT→ REPORT(结论: 未发现强证据)
REPORT → DONE
任意 stage ─aborted→ ABORTED（合规报告）
```

### 决策记录硬规则

每次分支选择必须写一条 decision.json 条目（options/selected/reason/confidence/actor）。**报告中展示的是"可审计决策摘要"，绝不输出模型隐式思维链原文**；模型返回的 reasoning 只允许提炼为一句 `reason`（≤200 字）。

### 验收（DoD）

- [ ] `tests/integration/test_orchestrator_smoke.py`：用 fixture 迷你固件跑通 INIT→DONE，且 `runs/<id>/state/run_state.json`、`decisions/`、`evidence/` 全部生成并通过 Schema 校验。
- [ ] 在 DECOMPILE 阶段人为删除 Ghidra 路径，run 不崩溃，走 fallback 分支且决策日志含该分支。
- [ ] `kill` 掉运行中进程后 `fsa resume <run_id>` 能从最近成功 stage 继续，不重复已完成 stage。
- [ ] 设置 `budget.max_tokens=1` 时自动降级 mock runtime 且 run 完成。

---

## M1　任务理解模块（负责人 A）

**目标**：对接评分维度 1——接受自然语言描述 / 结构化参数 / 压缩包任务包（含接口文档、附件），产出 `task_card.json` 与执行计划。

### 文件清单

- `fsa/orchestrator/planner.py` 内的 `parse_task()`：三种输入形态统一入口。
- `skills/00-orchestrator/SKILL.md`：任务理解流程知识（如何拆目标、何时追问、禁止臆造授权信息）。

### 内部逻辑

1. 输入归一化：压缩包 → 解压到 `runs/<id>/input/`，枚举成员（说明书/固件/文档）；自然语言 → 提取固件路径、厂商型号、深度、授权声明。
2. 槽位填充：Schema 4.1 的字段逐项填充；**缺失的关键槽位（firmware_path、authorization）不猜，触发 human_gate 追问**。
3. 计划生成：默认计划模板 = 状态机全链路；按 `depth` 裁剪（quick 砍 DECOMPILE 深度与动态验证；full 强制 L3）。
4. 输出 `plan.json` + decision 条目（为何选此计划）。

### 验收（DoD）

- [ ] 三个测试用例：①纯 CLI 参数；②一段中文自然语言任务描述；③zip 任务包（内含说明 txt + 固件）。三者均产出通过校验的 task_card.json。
- [ ] 缺少授权声明时必须进入 human_gate 而不是默认放行。

---

## M2　固件解包 Skill + 工具（负责人 B）

**目标**：任意 Linux 固件输入 → 可信 rootfs + `firmware_manifest.json`。融合 legacy 四份 Skill 的解包经验（魔数表、SquashFS-LZMA、DLOB/TRX/uImage、UBI/JFFS2、rootfs 评分、架构交叉确认）。

### 文件清单

- `tools/firmware/collect_info.py` — sha256/md5/size、`file`、前 256 字节 hex、binwalk 签名扫描（只扫描不解包）、字符串提取厂商/型号/内核线索。全部命令经 `utils/proc.py` 执行并落盘。
- `tools/firmware/unpack.py` — 解包调度器。策略表（按检测结果路由）：

| 检测特征 | 策略 |
|---|---|
| SquashFS 标准 | `unsquashfs` |
| SquashFS-LZMA 非标准 | `sasquatch`；仍失败试 `7z x` |
| UBI (`UBI#`) | `ubireader_extract_images` |
| JFFS2 | `jefferson` |
| CPIO | `cpio -idmv` |
| gzip/bzip2/xz 包裹 | 先解压再递归检测 |
| TRX/uImage/DLOB 头部 | `dd` 按偏移切片后递归 |
| binwalk 无签名 | fallback：全镜像魔数扫描（`hsqs`/`sqsh`/`UBI#` 等）→ 记录偏移 → `dd` 切片 → 重试文件系统工具 |
| 仍失败 | `status=failed`，保留全部尝试日志 |

- `tools/firmware/rootfs_score.py` — 候选目录评分：`bin/sbin/etc/lib/usr` 各 +1；`www|htdocs|web` +1；`etc/init.d` 非空 +1；`bin/busybox` +1；`usr/sbin/httpd|web|goahead` +2。输出全部候选及分数，**禁止无脑选第一个**；最高分 < 5 时 `extraction_confidence` 降级。
- `tools/firmware/arch_detect.py` — 从 ≥3 个 ELF 的 `readelf -h` 交叉确认架构/位数/大小端（样本不一致时取多数并记 warning）；libc 识别（uClibc/musl/glibc）；内核线索（`*.ko` vermagic、`Linux version` 字符串）；输出推荐 QEMU binary 名。
- `skills/01-firmware-unpack/SKILL.md` — 流程知识：策略选择理由、失败降级路径、何时转 BINARY_ONLY_MODE。

### 验收（DoD）

- [ ] 单测：rootfs 评分对 fixture（完整 rootfs / 残缺 rootfs / 双 rootfs）评分正确。
- [ ] 集成：3 类真实固件样本（标准 SquashFS、带厂商头部需切片、binwalk 失败但 fallback 成功）均产出通过校验的 manifest。
- [ ] 加密/不可解固件样本：`status=failed` + 全部尝试日志 + Orchestrator 不崩溃。

---

## M3　攻击面枚举 Skill + 工具（负责人 B）

**目标**：双攻击面（Web/CGI/UPnP/SOAP/HNAP + 网络 socket/daemon）全枚举，输出 `attack_surface.json`。核心经验来自 legacy：**端点不止在 webroot，必须"文件系统枚举 + 二进制内嵌端点反推 + 启动脚本 + 监听线索"四路并进**。

### 文件清单

- `tools/filesystem/inventory.py` — rootfs 全量清单：ELF 计数与路径、脚本（lua/php/py/sh/cgi）计数与路径、配置文件、webroot 定位。
- `tools/filesystem/startup_parse.py` — 解析 `etc/init.d/`、`rcS`、`inetd.conf`、procd 脚本，提取"启动了哪些服务、参数是什么"，产出启动证据（文件:行）。
- `tools/web/webroot_enum.py` — webroot 下 goform/cgi-bin/api/lua/php 枚举 + 按功能分类（认证/配置/命令/升级/状态/调试，关键词表走 `vendor/common.yaml`）。
- `tools/web/handler_extract.py` — **二进制内嵌端点反推**（本模块灵魂）：
  - GoAhead 系：`strings` 提取 `formXxx`/`fromXxx` 命名约定函数名 + `websFormDefine` 注册痕迹 → 端点清单（Tenda `formexeCommand` 模式）；
  - 通用：`.cgi` 字符串、URL 路由字符串（`^/` 且排除 `/lib//dev/`）、`_main$` CGI handler 符号（D-Link cgibin 模式）、`HTTP_` 环境变量字符串；
  - 输出端点 → 二进制 → handler 的三元组及字符串证据。
- `tools/web/upnp_parse.py` — UPnP XML 解析：Action 列表 + `direction=in` 外部输入参数 + 高影响操作标记（Upgrade/Reboot/FactoryReset/SetPersistent）。
- `tools/web/auth_matrix.py` — 三层认证交叉验证（L1 路由层豁免标记 `noauth|skip_auth|whitelist…`；L2 handler 层认证函数调用 `sess_validate|check_auth|…`（厂商名走字典）；L3 脚本层 `AUTHORIZED_GROUP`/session 检查），按置信度矩阵给 `auth_hint` + 置信度。
- `tools/analysis/` 复用：socket 服务枚举（`objdump -d` 查 `socket/bind/listen/accept/recvfrom`，结合端口字符串与启动脚本，区分外部服务与内部 IPC）。
- `skills/02-attack-surface/SKILL.md`。

### 验收（DoD）

- [ ] 对 Tenda AC15 固件：必须枚举出 `formexeCommand` 端点（该端点不在 webroot，只能反推得到）——这是本模块的回归金标准。
- [ ] 对 HG532e 固件：UPnP `DevUpg.xml` 的 `Upgrade` Action 与 `NewDownloadURL/NewStatusURL` 输入参数必须被提取并标记高影响。
- [ ] 人工抽 1 份历史固件对照：真正网络可达入口不漏报；内部工具不误标为外部攻击面（用启动证据判定）。

---

## M4　二进制筛选与反编译 Skill + 工具（负责人 C）

**目标**：rootfs 中数百个 ELF → Top-N 深度反编译 → 结构化摘要。关键约束：**绝不把几万行反编译文本直接喂模型**；也绝不反编译全部 ELF。

### 文件清单

- `tools/binary/elf_triage.py` — 初筛打分（0 起）：被启动脚本调用 +3；网络相关导入（socket/recv…）+2；Web handler 线索 +3；危险函数导入（按 D/E/F/B/M/W 加权）+1~3；含 CGI/route/UPnP 字符串 +2；在 M3 攻击面中被引用 +4。取 Top-N（默认 10，config 可调）。
- `tools/binary/secfeatures.py` — NX/Canary/PIE/RELRO/Stripped（`readelf -l/-s` + `checksec` 逻辑自实现，不依赖外部 checksec）。
- `tools/binary/danger_scan.py` — D/E/F/B/M/W 六级危险函数扫描（分类表沿用 legacy SKILL1 模块四），输出每 ELF 的命中明细；交叉信号 `system+sprintf/snprintf` 同存时标记 `critical`。
- `tools/binary/ghidra_headless.py` — `analyzeHeadless` 批处理：导入 → 分析 → 用内置 GhidraScript 导出函数表/调用边/字符串引用/imports/xrefs/反编译伪 C（每函数单独文件）。结果落 `runs/<id>/artifacts/decompile/<binary>/`。
- `tools/binary/decompile_fallback.py` — Ghidra 不可用/导入失败时：objdump 反汇编 + strings + reloc 的降级摘要，`decompile_status=fallback`，绝不使整个 run 失败。
- `tools/binary/callgraph.py` — 由导出调用边建图，支持 BFS/DFS（默认 `MAX_DEPTH=4`，config 可调），查询接口：`paths(entry_func, sink_func)`、`callers_of(f)`、`callees_of(f)`。
- `tools/binary/summarize.py` — 每函数生成结构化摘要（4.4 Schema 的 `functions[]`）：name/addr、callers/callees、引用字符串（分类后）、是否 source/sink/auth/validation（规则库 `tools/analysis/source_sink_rules.py` + vendor 字典判定）。**喂给模型的只有这个摘要 JSON，单个二进制摘要超预算时按函数 triage 截断。**
- `skills/03-binary-decompile/SKILL.md`。

### 验收（DoD）

- [ ] HG532e `bin/upnp`：摘要中必须体现 `snprintf→system` 链与 `upg -g -U %s ... -r %s` 命令模板字符串。
- [ ] stripped ELF fixture：无函数名时仍能基于字符串/xref/调用关系保留候选（`decompile_status` 正确、不报错退出）。
- [ ] 摘要体积控制：单二进制摘要 ≤ 64KB（超则截断并记录）。

---

## M5　静态审计 Skill（负责人 C）

**目标**：对 Top-N 二进制与攻击面交叉，按统一分析模型产出 `candidates.json`。

### 分析模型（沿用 legacy 并固化为模板）

```text
Entry → Source → Transform → Validation → Authorization → Sink
      → Reachability → Counterevidence → Conclusion
```

### 文件清单

- `tools/analysis/source_sink_rules.py` — 规则库加载与匹配：
  - **Sources**：HTTP 参数/header/cookie/query/POST body/SOAP 参数/socket buffer/配置导入/文件上传/环境变量（`getenv("QUERY_STRING")`、`websGetVar`、`$_GET`、Lua `arg[`/`ngx.var`、UPnP `direction=in` 参数…，厂商 API 走字典）。
  - **Sinks 四类**：命令执行（`system/popen/exec*` + 厂商封装 `doSystemCmd/lxmldbc_system/alpha_system2`）、内存安全（`strcpy/strcat/sprintf/gets/memcpy` 含长度可控判定）、文件系统（可控路径写入/配置覆盖/脚本生成 `fwrite(*.sh)`）、格式串与解析（可控格式串、TLV length 派生循环）。
  - **Validation**：长度检查/白名单/黑名单/转义/路径规范化/类型限制——**黑名单=可能可绕过，白名单=通常安全，无过滤=高危**（规则沿用 legacy 命令注入五步法 Step 3）。
  - **Authorization**：结合 M3 auth_matrix，区分路由层/handler 层/业务层认证及初始化例外。
- `tools/analysis/dataflow.py` — 链组装：HTTP 入口走七层模板（Request→Route→C Handler→IPC/xmldb→PHP Receive→PHP Sink→Shell Execute），socket 入口走变体模板（报文→recvfrom→拷贝/格式化→sink）；每层记录过滤器存在性 + file:line 证据。**变量使用验证为强制步骤**（变量定义点与使用点必须同时存在，否则标记反证）。
- `tools/analysis/fp_filter.py` — 误报排除引擎五规则：CLI 工具（iptables/busybox/sh…）排除；命令模板无 `%s` 降级；纯内部 IPC 降级；无可达外部入口标记待确认；dead code/未启动服务降级。每条排除记录反证。
- `skills/04-static-analysis/SKILL.md` — 含命令注入五步法、协议解析六步法（TLV length→count→写→定长 buffer→无上限检查，6/6=极高危）的判定知识。

### 验收（DoD）

- [ ] 对 HG532e：自动产出 P0 候选（upnp / snprintf→system / NewDownloadURL、NewStatusURL），字段与 legacy 附录 A.6 的 CVE-2017-17215 对照表全部吻合。
- [ ] 对 Tenda AC15：自动产出 formexeCommand/`cmdinput`→`doSystemCmd`→`system()` 候选。
- [ ] 每个候选含 ≥2 条独立证据；`observation` 级条目不进入评分。

---

## M6　风险评分与候选排序（负责人 C，A 审核）

**目标**：10 维评分 P-I-U-D-C-S-W-K-V-T（每维 0–3，满分 30），产出 `candidate_ranking.json`。**看到 system/strcpy ≠ 漏洞**——评分必须基于 M5 的链证据而非函数命中。

### 文件清单

- `tools/analysis/risk_score.py` — 评分实现。维度定义沿用 legacy SKILL2 第 10 节表（P 预认证可达 / I 输入来源 / U 可控性 / D sink 可达 / C 拼接危险 / S shell 上下文 / W 文件写入 / K 配置持久化 / V 校验强弱(反向) / T 可测试性），阈值：≥24 CRITICAL、18–23 HIGH、12–17 MEDIUM、<12 LOW 仅归档。每维评分必须引用证据 ID，无证据维度记 0 并标注。
- 排序策略（Orchestrator 决策）：候选 ≤5 全进 Verifier；6–20 取 Top-5；>20 取 Top-3 + **类别多样性保留**（防排名前列全是同类重复告警）。

### 验收（DoD）

- [ ] 单测：构造已知答案的候选 fixture，评分与等级正确。
- [ ] 回归：HG532e 排序结果 P0=upnp > web > cms（与 legacy 附录 A.4 一致）。

---

## M7　Verifier 反证审查（负责人 A + C）

**目标**：独立于初始分析链路，对 Top-K 候选逐条"主动证伪"。这是结论可信度（评分维度 3）与答辩创新点 ① 的核心。

### 文件清单

- `fsa/orchestrator/verifier.py` — 编排：对每个候选执行 10 问清单（Source 是否真外部输入 / 是否用户可控 / 是否真到 Sink / 中间是否有编码或白名单 / 调用链是否可达 / handler 是否启动 / 是否需认证 / 是否仅调试功能 / 是否有构建或平台条件 / 是否存在矛盾证据），必要时回查工具（callgraph 可达性、auth_matrix 复核、变量使用验证）。
- `skills/05-candidate-verifier/SKILL.md` — 五分类结论模型与 12 条硬判定规则（沿用 legacy zip skill evidence-model：危险 API 导入 ≠ 漏洞证据；认证豁免 ≠ 未认证可达；过滤函数存在 ≠ 过滤有效；证据不足只能到 high-confidence-candidate/observation/unknown；false-positive 必须有击败性证据……完整固化进 SKILL.md）。

### 输出与降级

`verdicts.json`：`ACCEPT / DOWNGRADE / REJECT / NEED_DYNAMIC` + 原评分、修正评分、原因、支持证据、反证。**全部 REJECT 时报告如实输出"未发现强证据"，严禁强行报漏洞**；`NEED_DYNAMIC` 且安全门通过 → M8；否则报告标注 `dynamic_skipped` 及原因。

### 验收（DoD）

- [ ] 构造 3 个 fixture：真候选（ACCEPT）、白名单拦截（DOWNGRADE/REJECT）、内部 IPC（REJECT），判定正确且反证字段非空。
- [ ] `REJECT` 必须引用具体反证 evidence_id，否则 Schema 校验失败。

---

## M8　本地动态验证（负责人 D）

**目标**：在严格安全门下做 L0–L3 分层非武器化验证，只回答"可达/不可达、是否稳定异常"，绝不构造利用链。

### 分层定义

| 层 | 内容 | 产出 |
|---|---|---|
| L0 | 纯静态证据（不启动任何目标） | 默认 |
| L1 | qemu-user 可加载：架构/loader/动态库/基本启动（`-strace`，`/dev/mem` 退出属正常） | `load_ok` 证据 |
| L2 | 系统仿真服务可达：QEMU system/FirmAE，NAT+Host-only 隔离网，确认 IP/端口/基线请求正常响应 | 连通性证据 |
| L3 | 非武器化验证：单变量变化 → 观察路径是否执行/参数是否到达/是否稳定 crash 或无害标记（`touch /tmp/lab_marker`、`id` 输出） | 可达性/异常证据 |

### 文件清单

- `tools/emulation/safety_gate.py` — 四项硬门全部通过才放行：`AUTHORIZED==true && LOCAL_LAB==true && PRIVATE_NETWORK==true && BASELINE_READY==true`；任一不满足 → `ABORT_DYNAMIC_VALIDATION` 并记录。私有网段判定复用 `utils/netcheck.py`。
- `tools/emulation/qemu_user.py` — L1 实现（含 busybox 基准自检 `qemu-<arch>-static -L rootfs busybox echo QEMU_OK`）。
- `tools/emulation/qemu_system.py` — L2/L3：tap/bridge 编排、快照、串口日志采集；网络配置只接受私有段。
- `tools/emulation/firmae_wrap.py` — FirmAE 探测到才启用，否则跳过并记录 limitation。
- `tools/emulation/probes.py` — 基线连通性（`curl -i --max-time 5`）、无害探针白名单执行、冷热启动可重复性检查（各至少 1 次）。
- `skills/06-local-validation/SKILL.md` — 含 qemu-user 三大坑（br0 ioctl 死循环、/dev/nvram 修补、假监听 socket）的处理知识与"连通性先于触发"原则。

### 验收（DoD）

- [ ] 安全门单测：公网 IP / 未授权 / 无基线三种情形均被 ABORT。
- [ ] L1：对 HG532e `upnp`（MIPS 大端）可加载验证通过并留 strace 证据。
- [ ] 触碰红线（如目标 IP 非私有）时整个动态阶段不产生任何外发流量（用 fixture 断言）。

---

## M9　证据与日志系统（负责人 D）

**目标**：一切"动作 → 证据 → 判断"留痕，支撑可解释性评分与报告自动生成。

### 文件清单

- `tools/reporting/evidence_store.py` — evidence.jsonl 追加写、按 ID 索引、支持/反驳关系查询。
- `fsa/utils/jsonio.py` — 原子写（tmp+rename）。
- Run 目录规范（dispatcher 强制创建）：

```text
runs/<run_id>/
├── input/        # 原始任务输入（压缩包展开等）
├── logs/         # 每工具 stdout/stderr + 结构化 jsonl
├── artifacts/    # 反编译导出、切片、抓包等原始件
├── state/        # run_state.json
├── evidence/     # evidence.jsonl + 证据卡
├── decisions/    # decision.jsonl
├── candidates/   # candidates/ranking/verdicts
└── report/       # report.md / final_verdict.json
```

- 每条工具调用记录：时间、run_id、工作目录、工具+版本、命令、输入文件 SHA256、退出码、stdout/stderr 路径、结构化摘要、模型判断、置信度。

### 验收（DoD）

- [ ] 任意 run 结束后，`evidence/` 中每条记录通过 Schema 校验；报告中的每个结论可回溯到 ≥1 条 evidence。

---

## M10　报告生成（负责人 D）

**目标**：双产物——人类可读 `report.md`（答辩/提交用）+ 机器可读 `final_verdict.json`（平台判分/自动化用）。

### 文件清单

- `tools/reporting/report_gen.py` — Jinja2 模板渲染，章节固定 20 节（任务范围与授权边界 / 固件信息与哈希 / 解包结果 / 架构组件 / 攻击面 / 二进制分析 / 候选排行 / 主候选数据流 / 认证边界 / 输入校验 / 支持证据 / 反证 / 本地验证结果 / 结论置信度 / 限制 remaining_limitations / 修复建议 / 运行指标 / 人工介入点 / 决策摘要 / 完整证据索引）。数据全部来自 Schema JSON，**模板里禁止出现可复现攻击参数**（脱敏渲染：`<USER_INPUT>`、`<BENIGN_MARKER>`）。
- `tools/reporting/verdict_json.py` — `{run_id, firmware_sha256, findings:[{candidate_id, conclusion_category, vuln_class, location_summary, confidence}], stats:{…}}`。
- `tools/reporting/compliance_scan.py` — 交付物 7 项合规扫描：无真实 IP / 无反弹 Shell 特征 / 无持久化 / 无下载执行 / 无破坏性命令 / 含安全声明 / 仅标记验证。扫描不过 → 报告生成失败。

### 验收（DoD）

- [ ] 对任一集成测试 run 生成报告：20 节齐全、合规扫描通过、`final_verdict.json` 通过校验。
- [ ] 全部候选被 REJECT 的 run：报告结论为"未发现强证据"且不编造发现。

---

## M11　Benchmark 与 Evaluator（负责人 D，A 协助）

**目标**：老师要求的"在过往挖出过漏洞的固件上盲测能力验证"，做成真盲测 + 自动评分。

### 设计

- **数据区**：`benchmarks/public/caseNN/{firmware.bin, manifest.yaml}`（Agent 可见，manifest 只含厂商/型号/版本/授权声明，**绝不含 CVE 线索**）；`benchmarks/private_ground_truth/caseNN.yaml`（真正二进制/入口/关键函数链/漏洞类型/认证状态/根因/匹配规则；policy_engine 路径白名单禁止 Agent 读取；gitignore）。
- **首批用例（与 legacy 对齐，建库即金标准）**：①Tenda AC15（CVE-2020-10987，formexeCommand 命令注入）；②Huawei HG532e（CVE-2017-17215，UPnP upg 命令注入）；③D-Link DIR-859（Web/UPnP 路线）；④D-Link `.chk` 网络 daemon 溢出路线；⑤Netgear R7000 系列分析案例。后续按团队历史固件扩充。
- **Blind Run 流程**：固件 → Agent → 冻结 Top-K 输出 → Evaluator 独立读 Ground Truth → 自动评分。
- **10 项指标**（`evaluator/metrics.py`）：Unpack 成功率 / 攻击面召回 / 漏洞二进制排名 / Candidate Top-1/3/5/10 命中 / 根因匹配（Source→Sink 链匹配度） / 认证判断准确率 / 高风险误报数 / Time-to-first-finding / 人工介入次数 / 可复现性（同固件双跑 Top-K 稳定性）。
- `evaluator/matching.py` — 候选↔GT 匹配规则：二进制名 + 入口 + sink 类型 + 参数名多字段加权，阈值可配；匹配规则本身存 GT 中。
- `evaluator/compare_runs.py` — 版本间回归对比表（Agent v0.x vs v1.0 提升曲线，答辩素材）。

### 验收（DoD）

- [ ] 5 个金标准用例盲跑：自动评分表产出；HG532e/Tenda AC15 真实根因进入 Top-3。
- [ ] 验证隔离：模拟 Agent 进程尝试读 `private_ground_truth/` 被 policy_engine 拒绝并留 decision 记录。

---

## M12　Agent Runtime 适配层（负责人 A）

**目标**：业务逻辑与具体框架/模型完全解耦（ADR-0001），直接对接决赛"国内备案模型 + 安全网关"约束。

### 文件清单

- `fsa/runtime/base.py` — 抽象基类：

```python
class AgentRuntime(ABC):
    def run_skill(self, skill_name: str, context: dict) -> SkillResult: ...
    def call_tool(self, tool_name: str, args: dict) -> ToolResult: ...
    def ask_model(self, messages: list, budget: Budget) -> ModelReply: ...
    def save_state(self, state: dict) -> None: ...
```

- `fsa/runtime/openai_compatible.py` — **主适配**（优先实现）：任何 OpenAI 兼容端点（DeepSeek/Qwen/GLM/Moonshot…），`base_url`/`api_key`/`model` 全走 `config/models.yaml` + 环境变量；内置重试、超时、token 计数上报 budget。
- `fsa/runtime/claude_code.py` / `hermes.py` / `deepseek_harness.py` — 备选适配，骨架先行，主适配跑通后按可用环境填实现。
- `fsa/runtime/mock.py` — 无模型离线模式：规则引擎替代模型判断（评分排序照跑、Verifier 用纯规则版），产出标注 `reviewer=mock`、置信度降级。这是决赛环境失联时的保底。

### 验收（DoD）

- [ ] 同一 fixture run 分别在 openai_compatible（任一可用端点）与 mock 下完成，业务代码零改动。
- [ ] `models.yaml` 切换 base_url 即可换模型，代码无硬编码模型名。

---

## M13　CLI 与一键部署（负责人 D）

**目标**：赛题硬性提交物"一键部署方案"。

### CLI（`fsa` 命令）

```text
fsa run <firmware> [--vendor X] [--depth quick|standard|full] [--allow-emulation]
fsa resume <run_id>
fsa inject <run_id> --evidence <file> | --override-verdict <candidate_id> <action>
fsa benchmark run [--cases 01,03] [--blind]
fsa benchmark report
fsa report <run_id> [--format md|json]
fsa compliance-scan <run_id>
```

### 部署

- `Dockerfile`：分层——base（python+系统工具）→ analysis（binwalk/squashfs-tools/sasquatch/jefferson/ubireader/binutils）→ emulation（qemu-user-static/qemu-system，按需）。Ghidra 以 zip 形式在构建期下载或挂卷（license 合规，镜像不内置分发）。
- `docker-compose.yml`：一条命令起分析环境；固件目录、runs 目录挂卷。
- `deploy/scripts/install_ubuntu.sh`：裸机备选路径（apt 依赖 + pip + 自检）。
- `Makefile`：`make install / test / run FW=xx.bin / benchmark / report / deploy`。

### 验收（DoD）

- [ ] 干净 Ubuntu 22.04 虚拟机：`make deploy && fsa run <fixture>` 一次成功出报告。
- [ ] `docker compose up` 后容器内跑通集成 smoke。

---

## M14　安全合规模块（贯穿，负责人 A）

- `config/safety.yaml` 把红线 R1–R9 机器化：私有网段列表、禁止命令正则（反弹 shell/持久化/下载执行特征）、无害探针白名单、授权字段强制校验。
- `policy_engine` 在每个工具调用前过检：目标路径白名单（禁读 GT）、命令黑名单正则、网络目标 IP 校验。
- `compliance_scan`（M10）作为报告生成的前置门。
- 全部 Skill 文档开头含安全声明；报告固定含"安全边界说明"节。

### 验收（DoD）

- [ ] 单测覆盖：9 条红线各有正/反用例。
- [ ] 故意构造越界输入（公网 IP 的 emulation 请求）→ run 进入 `aborted` 且产出合规报告。

---

# 第六部分　legacy Skill → 新系统迁移映射

> 四份 legacy Skill 的经验归属表（KEEP=直接采纳 / MERGE=多份合并 / REWRITE=案例化改通用）。WorkBuddy 实现各模块时，按此表回 `legacy/` 抄规则与知识，但**禁止整段复制案例叙述进新 SKILL.md**——新 Skill 只写通用流程。

| legacy 能力 | 来源 | 处理 | 落点 |
|---|---|---|---|
| 授权门 + 全局拒绝清单 | SKILL.md §0 / SKILL2 R1–R9 | MERGE | M14 safety.yaml + 各 SKILL 声明 |
| 实验卡片（动作→证据→判断） | SKILL.md §1 | KEEP | M9 证据模型、task_card |
| 解包降级路径（魔数/偏移/切片） | SKILL.md §2 / SKILL1 模块一 / SKILL2 Step02 | MERGE | M2 unpack.py 策略表 |
| rootfs 评分标记 | SKILL1 §1.3 | REWRITE（改多候选评分制） | M2 rootfs_score.py |
| 架构/QEMU 选型表 | SKILL1 §1.4 | KEEP | M2 arch_detect.py |
| GoAhead formXxx 端点反推 | SKILL.md §5 | KEEP | M3 handler_extract.py |
| UPnP direction=in 参数提取 | SKILL1 §2.4 | KEEP | M3 upnp_parse.py |
| 双攻击面（socket+Web）枚举 | SKILL2 模块 2 | KEEP | M3 |
| 三层认证交叉验证 + 置信度矩阵 | SKILL2 模块 3 | KEEP | M3 auth_matrix.py |
| 认证豁免标记扫描 | SKILL1 §3.2 | MERGE | M3 auth_matrix.py |
| 危险函数 D/E/F/B/M/W 分级 | SKILL1 §4.1 | KEEP | M4 danger_scan.py |
| 厂商封装函数字典 | SKILL2 vendor dict | KEEP | vendor/*.yaml |
| BFS 传递调用（MAX_DEPTH=4） | SKILL.md §6.2 | KEEP | M4 callgraph.py |
| 命令注入五步法 / 协议解析六步法 | SKILL1 §4.10/4.11 | KEEP | skills/04 SKILL.md + M5 规则 |
| 七层数据流模板 + socket 变体 | SKILL2 模块 4 | KEEP | M5 dataflow.py |
| 变量使用验证 | SKILL2 §9 | KEEP | M5（强制步骤） |
| 10 维 P-I-U-D-C-S-W-K-V-T 评分 | SKILL2 §10 | KEEP | M6 risk_score.py |
| 误报排除五规则 / 修正记录模板 | SKILL1 §4.8 / SKILL2 §11 | MERGE | M5 fp_filter.py |
| 五分类结论模型 + 12 硬判定规则 + 证据卡 | zip skill evidence-model | KEEP | M5 candidate Schema + M7 Verifier |
| 反证优先 / remaining limitations 纪律 | zip skill SKILL.md §4–6 | KEEP | M7 + 报告第 15 节 |
| 离线 fuzz（isolated harness）方法 | zip skill offline-fuzzing | REWRITE（降为 P2，仅本地 parser harness） | skills/06 附录（本期不实现执行器） |
| qemu-user 三坑 + 系统仿真优先 | SKILL.md §8 / SKILL1 模块五 | MERGE | M8 |
| 认证边界动态判定（redirect 才算需认证） | SKILL.md §9.1 | KEEP | M8 probes.py（L3 用） |
| 无害探针白名单 | SKILL2 R7 / SKILL.md §9.2 | KEEP | M8 probes.py + safety.yaml |
| 10 节/20 节报告模板 | SKILL1 模块六 / SKILL2 §13 / zip templates | MERGE | M10 模板 |
| 工作流检查点恢复 | SKILL2 workflow_state | KEEP | M0 state_manager |
| 交付物 7 项合规扫描 | SKILL2 §14 | KEEP | M10 compliance_scan |

---

# 第七部分　WorkBuddy 任务分解表（执行顺序与依赖）

> 每行是一个可独立提交的任务。`依赖` 列为前置任务；`DoD` 为验收底线（详见第五部分对应模块）。建议一个任务一个 commit（或一个 PR）。

## 阶段 0：地基（第 1 天）

| 任务 | 内容 | 依赖 | 主要产出 |
|---|---|---|---|
| T-01 | 仓库骨架 + pyproject/requirements/Makefile/ruff/pytest 配置 + legacy 归档 | — | 目录结构、`legacy/` |
| T-02 | 9 个 JSON Schema + examples + loader/validators | T-01 | `schemas/`、`fsa/schemas/` |
| T-03 | utils（hashing/netcheck/jsonio/proc）+ 单测 | T-01 | `fsa/utils/` |
| T-04 | safety.yaml + policy_engine（路径白名单/命令黑名单/IP 校验）+ 红线单测 | T-02, T-03 | M14 核心 |
| T-05 | run_state + evidence_store + decision 落盘 + Run 目录规范 | T-02, T-03 | M9 核心 |

## 阶段 1：确定性工具链（第 1–4 天，B/C/D 并行）

| 任务 | 内容 | 依赖 | 主要产出 |
|---|---|---|---|
| T-10 | collect_info + unpack + rootfs_score + arch_detect | T-03 | M2 工具 |
| T-11 | M2 单测 + 3 类固件集成测试 + skills/01 SKILL.md | T-10 | M2 完整 |
| T-12 | inventory + startup_parse + webroot_enum | T-03 | M3 前半 |
| T-13 | handler_extract（GoAhead 反推 + 通用字符串路由）+ upnp_parse + auth_matrix | T-12 | M3 后半 |
| T-14 | M3 集成测试（AC15 formexeCommand / HG532e UPnP 金标准）+ skills/02 | T-13 | M3 完整 |
| T-15 | elf_triage + secfeatures + danger_scan | T-03 | M4 前半 |
| T-16 | ghidra_headless + decompile_fallback + callgraph + summarize | T-15 | M4 后半 |
| T-17 | M4 集成测试（HG532e upnp 摘要金标准、stripped fixture）+ skills/03 | T-16 | M4 完整 |
| T-18 | source_sink_rules + dataflow + fp_filter + vendor/common+tenda+dlink+huawei 字典 | T-13, T-16 | M5 工具 |
| T-19 | risk_score + 排序策略 + M5/M6 集成（HG532e P0 金标准）+ skills/04 | T-18 | M5/M6 完整 |

## 阶段 2：编排与运行时（第 3–6 天，A 为主）

| 任务 | 内容 | 依赖 | 主要产出 |
|---|---|---|---|
| T-20 | Tool Registry（YAML 声明 + 加载器） | T-03 | tools/registry/ |
| T-21 | runtime/base + mock runtime（规则版） | T-02 | M12 保底 |
| T-22 | runtime/openai_compatible + budget | T-21 | M12 主适配 |
| T-23 | dispatcher 状态机（转移表驱动）+ planner + task_card 解析 | T-05, T-20, T-21 | M0/M1 |
| T-24 | resume + human_gate + decision 记录贯通 | T-23 | M0 完整 |
| T-25 | verifier（10 问清单 + 五分类）+ skills/05 | T-19, T-23 | M7 |

## 阶段 3：验证、报告与 Benchmark（第 5–8 天）

| 任务 | 内容 | 依赖 | 主要产出 |
|---|---|---|---|
| T-30 | emulation 安全门 + qemu_user(L1) + probes 基线 | T-04 | M8 前半 |
| T-31 | qemu_system(L2/L3) + firmae_wrap 探测 + skills/06 | T-30 | M8 完整 |
| T-32 | report_gen 20 节模板 + verdict_json + compliance_scan + skills/07 | T-05 | M10 |
| T-33 | Benchmark 数据区 + GT 隔离验证 + 5 金标准用例入库 | T-04 | M11 数据 |
| T-34 | evaluate_run + metrics + matching + compare_runs | T-33 | M11 评分 |
| T-35 | 全链路集成 smoke（fixture 固件 INIT→DONE） | T-23, T-19, T-32 | 端到端 |

## 阶段 4：加固、部署与交付（第 8–14 天）

| 任务 | 内容 | 依赖 | 主要产出 |
|---|---|---|---|
| T-40 | 失败恢复全表覆盖测试（旧计划第十九节 10 种异常） | T-35 | 鲁棒性 |
| T-41 | CLI fsa 全命令 + Makefile | T-35 | M13 CLI |
| T-42 | Dockerfile 分层 + compose + install_ubuntu.sh | T-41 | M13 部署 |
| T-43 | 全量金标准盲跑 + 指标表 + 复现性双跑 | T-34, T-35 | Benchmark 报告 |
| T-44 | docs：design/user_guide/testing/README/AGENTS.md | T-35 | 文档材料 |
| T-45 | 回归测试套件接入 Improvement Card 流程（与第二队联调） | T-34 | 进化闭环 |
| T-46 | （P2）Web 只读展示页 / 演示 run 录制脚本 | T-43 | 加分项 |

---

# 第八部分　测试体系

- **单元**：T-03 起每个工具脚本 ≥1 用例；重点覆盖：rootfs 评分、ELF 架构、危险函数分级、私有 IP 判定、风险评分、Schema 校验、命令黑名单正则。
- **集成**：`firmware→unpack→surface→binary→rank` 链路（fixture 固件）；Orchestrator smoke（T-35）。
- **金标准回归**：5 个历史案例固定断言（AC15 formexeCommand 进 Top-3、HG532e upnp P0、DIR-859 Web 路线、`.chk` daemon 路线、R7000 流程完整）；每次改 Skill/规则必跑，防"修好一个品牌弄坏另一个"。
- **合规测试**：M14 红线正反用例 + 报告合规扫描。
- **复现性**：同固件双跑，Top-K 与核心证据一致性断言。

---

# 第九部分　排期（8 月 17 日起，对齐提交节点）

| 日期 | 目标 | 门禁 |
|---|---|---|
| 8/17 | T-01~T-05 地基；能力矩阵文档 | 骨架 + Schema v0.1 |
| 8/18–19 | T-10~T-14（M2/M3） | 一个固件跑到 attack_surface.json |
| 8/20–21 | T-15~T-19（M4/M5/M6） | 金标准固件出 Top-3 候选 |
| 8/22 | T-20~T-25 主体（M0/M1/M7/M12） | mock runtime 全链路 |
| 8/23 | T-33/T-34 + 第一轮 Blind Run | ≥2 历史案例自动评分 |
| 8/24–25 | 修 Blind Run 暴露问题；vendor 字典扩充；T-30/T-31 | 异常恢复生效 |
| 8/26 | T-32 报告 + 合规扫描 | 20 节报告产出 |
| 8/27 | 第二队反馈接入（T-45 启动） | Improvement Card 闭环 |
| 8/28–29 | T-40 鲁棒性加固；编排调优；去硬编码 | 10 种异常全覆盖 |
| 8/30 | Agent v0.9；全量金标准盲跑 | 指标表 v1 |
| 8/31 | 架构冻结，只修 bug | — |
| 9/1–2 | v1.0；全量 Benchmark；演示 run 固化 | 最终性能表 |
| 9/3–4 | T-42 部署、T-44 文档、PPT、演示视频 | 提交物齐套 |
| **9/5** | **作品提交截止** | 对照 2.3 清单逐项核对 |
| 9/20 初审后 | 按晋级结果备战终审；申请 120 小时仿真测试平台 | — |

## 决赛备战专项（11 月终审前）

1. **120 小时测试平台使用计划**：前 20h 环境适配（网关接入、模型备案信息报备、部署验证）；中 60h 按"渗透/应急/漏洞挖掘/逆向"四类场景做人机协同训练（3 名队员分工：1 人监控决策日志、1 人人工复核候选、1 人用 human_gate 注入证据）；后 40h 全流程模拟赛 + 复盘。
2. **人机协同模式固化**：把第二队的"Blind Run → 人工复核 → Improvement Card → 重跑"流程压进决赛节奏，human_gate 是唯一人工入口，保证可审计。
3. **模型预案**：主备两个国内备案模型的 models.yaml 预案；网关失联自动降级 mock runtime 的演示视频备份。

---

# 第十部分　风险登记册

| 风险 | 等级 | 缓解 |
|---|---|---|
| Ghidra Headless 在部分固件上导入失败/耗时过长 | 高 | decompile_fallback 保底；triager 限制 Top-N；超时熔断 |
| 金标准案例不足 5 个（历史固件不全） | 中 | 8/17 当天盘点历史固件库存，缺则优先补 Tenda/D-Link 系公开固件 |
| 模型 API 成本/速率限制 | 中 | budget.py 配额 + 结构化摘要压 token + mock 降级 |
| 动态验证环境（QEMU system/FirmAE）搭建超期 | 中 | L1 先行，L2/L3 可标记 dynamic_skipped 不阻塞主链路 |
| 队员被第二队支援挤占 | 中 | 接口冻结 + Improvement Card 异步流转 |
| 评分维度"创新"体现不足 | 低 | 证据链五分类 + 进化闭环 + Benchmark 量化三个创新点必须在答辩 PPT 单列一页 |

---

# 附：给 WorkBuddy 的首次启动指令建议

```text
请阅读本文件（第一队_WorkBuddy全栈实施开发计划.md），严格按第七部分任务分解表执行。
从 T-01 开始；每完成一个任务运行其 DoD 验收命令，通过后提交 commit（格式 [T-XX] ...）。
Schema 冻结前（T-02 完成前）不要写任何业务代码。
任何安全相关实现以 config/safety.yaml 与 M14 为准，不得弱化。
```

---

> **一句话标准**：本系统成功的唯一判据是——任意一份受支持的 Linux 路由器固件输入后，能自动走完"基线→解包→攻击面→二进制→候选→Top-K→反证→（可选）安全验证→证据报告"全链路，中间出错可降级可恢复，每个结论有证据，没漏洞时敢说"未发现强证据"，历史已知漏洞盲测中根因稳定进入 Top-K。



