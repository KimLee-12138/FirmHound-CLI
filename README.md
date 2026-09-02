<div align="center">

# FirmHound 固件猎犬

**IoT 固件漏洞挖掘自动化流水线** · 解包 → 攻击面 → 二进制分析 → 静态审计 → 十维评分 → 反证验证 → 动态验证 → 证据报告

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20WSL2%20%7C%20Linux-2F6FAD)](docs/wsl_dev_guide.md)
[![Tests](https://img.shields.io/badge/tests-189%20passed-1D9E75)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![CVE Benchmark](https://img.shields.io/badge/benchmark-9%20CVEs-534AB7)](benchmarks/CVEs)
[![Skills](https://img.shields.io/badge/skills-9%20packs-0F6E56)](skills)

*第一队 · 挑战杯「揭榜挂帅」· 具备自主决策能力的通用网络安全智能体*

</div>

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [快速开始（60 秒）](#快速开始60-秒)
- [系统架构](#系统架构)
- [环境配置：两条路任选](#环境配置两条路任选)
  - [路线 A：Windows + WSL2](#路线-a-windows--wsl2推荐)
  - [路线 B：纯 Linux](#路线-b-纯-linux)
- [拿到固件后怎么做（完整流程）](#拿到固件后怎么做完整流程)
  - [第 1 步 · 放置固件](#第-1-步--放置固件)
  - [第 2 步 · 解包固件](#第-2-步--解包固件)
  - [第 3 步 · 静态分析](#第-3-步--静态分析)
  - [第 4 步 · 解读报告](#第-4-步--解读报告)
  - [第 5 步 · 人工审计（10 问）](#第-5-步--人工审计10-问)
  - [第 6 步 · 动态验证（可选）](#第-6-步--动态验证可选)
- [CLI 命令参考](#cli-命令参考)
- [配置说明](#配置说明)
- [项目结构](#项目结构)
- [Skill 体系](#skill-体系)
- [评分与结论模型](#评分与结论模型)
- [安全与合规](#安全与合规)
- [测试](#测试)
- [常见问题（FAQ）](#常见问题faq)
- [许可证](#许可证)

---

## 项目简介

**FirmHound（固件猎犬）** 是一套面向 IoT 固件漏洞挖掘的自动化流水线系统：把「固件解包 → 攻击面排查 → 二进制分析 → 静态数据流审计 → 十维风险评分 → 反证验证 → 本地动态验证 → 证据报告」这一完整流程，封装为**可编排的 Skill 知识库 + 确定性 Python 工具链**。

**设计目标**：比赛现场给出的 CVE 是**现场新给、未知的**。因此系统不依赖任何 CVE 特征硬编码，而是靠**通用规则 + 可复用 Skill** 发现未知漏洞——零先验知识即可从陌生固件中定位高危候选。

命名含义：**Firm**（Firmware 固件）+ **Hound**（猎犬），寓意像猎犬一样凭借敏锐嗅觉，追踪、挖掘固件中隐藏的漏洞。

## 核心特性

| 特性 | 说明 |
|---|---|
| 🐾 全流程自动化 | M0–M14 模块化，阶段机驱动（`fsa/orchestrator/engine.py`），支持断点续跑 |
| 🎯 零 CVE 先验 | 通用规则 + Skill 知识驱动，不硬编码 CVE 特征，适配现场新固件 |
| 🐍 纯 Python 分析 | pyelftools + capstone 解析 ELF，Windows 可直跑，不强制依赖 Ghidra/objdump |
| 🔌 双运行时 | `offline`（确定性离线规则，不生成模型结论） / `openai_compatible`（国内备案模型） |
| 🛡️ 反证优先验证 | 10 问清单 + 12 条硬规则，五分类结论模型 |
| 📊 十维风险评分 | P-I-U-D-C-S-W-K-V-T 十维、满分 30，阈值分级 CRITICAL/HIGH/MEDIUM/LOW |
| 🔒 动态验证安全门 | 四项硬门（AUTHORIZED / LOCAL_LAB / PRIVATE_NETWORK / BASELINE_READY），仅无害探针 |
| 📜 证据链可审计 | EvidenceStore / DecisionStore 全量落盘，报告 21 节骨架，静态结论保留反证与限制 |
| ✅ 金标准回归 | `benchmarks/CVEs/` 9 个历史 CVE fixture，300+ 项测试持续守护 |

## 快速开始（60 秒）

```bash
# ① 安装 CLI 并自检
python -m pip install -e .
python scripts/dev.py test

# ② 分析已解包 rootfs（授权主体为必填项）
fsa analyze tmp/unpacked/squashfs-root --input-type rootfs \
  --authorization-holder "设备所有者" --depth standard --run-id hunt1

# ③ 或直接提交固件镜像（需要已配置可用的解包工具）
fsa analyze firmware_samples/router.bin --input-type firmware \
  --authorization-holder "设备所有者" --depth full
```

> ⚠️ CLI 只接受 `config/safety.yaml` 白名单内的输入路径。Windows/Linux 都可分析 rootfs；直接解包真实固件仍建议准备 WSL/Linux 解包工具链。

## 系统架构

```
                    ┌──────────────────────────────────────────┐
                    │           WorkBuddy / 智能体              │
                    │  Orchestrator（阶段机 + 决策记录）         │
                    │  Planner / StateManager / HumanGate       │
                    └───────────────┬──────────────────────────┘
                                    │ 统一 Runtime Adapter
                    ┌───────────────▼──────────────────────────┐
                    │ fsa/runtime offline │ openai_compatible  │
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

**阶段机流转**：`INIT → BASELINE → UNPACK → SURFACE → BINARY_TRIAGE → DECOMPILE → STATIC_ANALYSIS → RANK → VERIFY_TOP_K → {LOCAL_VALIDATION | REPORT} → DONE`

- `UNPACK` 部分失败 → fallback 到 `BINARY_TRIAGE`（无 rootfs 也能做 ELF 级分析）
- 任一 required 阶段失败 → `ABORTED`，保留产物，可 `resume()` 续跑

---

## 环境配置：两条路任选

> **核心原则**：静态分析层是**纯 Python**（pyelftools/capstone），Windows 直接跑；**解包与动态验证**依赖 Linux 工具链（binwalk / sasquatch / qemu）。所以有两条路：

| 路线 | 适用人群 | 解包 | 静态分析 | 动态验证 |
|---|---|---|---|---|
| **A. Windows + WSL2** | 主力机是 Windows 的同学 | ✅ WSL2 内 | ✅ 任意一侧 | ✅ WSL2 内 |
| **B. 纯 Linux** | 有 Linux 机器/服务器/云主机 | ✅ 原生 | ✅ 原生 | ✅ 原生 |

---

### 路线 A：Windows + WSL2（推荐）

日常在 Windows 上操作，解包时通过 WSL2 调用 Linux 工具，全程无需切换系统。

#### A1. 安装 WSL2

```powershell
# 以管理员身份打开 PowerShell，执行：
wsl --install -d Ubuntu-22.04
```

> **注意**：安装后**必须重启电脑**。重启后 WSL 会自动完成 Ubuntu 初始化，并让你设置 Linux 用户名/密码（记好密码，后面 `sudo` 要用）。

验证：

```powershell
wsl -l -v
# 应看到 Ubuntu-22.04，VERSION 列为 2（表示 WSL2，不是 WSL1）
```

> **如果 VERSION 是 1**：执行 `wsl --set-version Ubuntu-22.04 2` 升级到 WSL2。

#### A2. 安装 Linux 工具链（一键脚本）

```powershell
# 在 PowerShell 中执行（脚本会自动完成 apt 安装 + binwalk/sasquatch 编译）
wsl -d Ubuntu-22.04 -- bash /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全/scripts/setup_wsl.sh
```

> 脚本会安装：`binwalk`、`squashfs-tools`（unsquashfs/mksquashfs）、`sasquatch`（非标准 SquashFS）、`cpio`、`p7zip`、`qemu-user-static`、`strings/readelf/objdump` 等。

#### A3. 安装 Python 与项目依赖（Windows 侧）

```powershell
# 1) 安装 Python 3.11+（https://www.python.org/downloads/，勾选 "Add to PATH"）

# 2) 进入项目目录，创建虚拟环境
cd C:\Users\22067\Desktop\揭榜挂帅——网络安全
python -m venv .venv
.venv\Scripts\activate

# 3) 安装依赖
pip install -r requirements.txt
pip install -e .
```

#### A4. 验证两条路都通

```powershell
# Windows 侧：单元测试
python scripts/dev.py test

# WSL 侧：工具链自检
wsl -d Ubuntu-22.04 -- bash -lc "which binwalk unsquashfs sasquatch strings readelf"
```

#### A5. 常见问题（Windows + WSL2）

| 问题 | 原因 | 解决 |
|---|---|---|
| `wsl --install` 后重启仍报错 | WSL 内核/虚拟化未启用 | BIOS 开启虚拟化（VT-x/AMD-V）；PowerShell 执行 `bcdedit /set hypervisorlaunchtype auto` 后重启 |
| `wsl -l -v` 显示 VERSION=1 | 默认 WSL1 | `wsl --set-version Ubuntu-22.04 2` |
| WSL 报 `Wsl/Service/0x8007274c` | WSL 服务偶发抽风（已知问题） | `wsl --shutdown` 后重新进 |
| WSL 里 `localhost` 访问不了 Windows 服务 | NAT 模式代理未镜像 | 属正常现象，不影响本工具（我们只用 WSL 跑命令行工具） |
| `binwalk: command not found` | PATH 未含 `~/.local/bin` | WSL 内执行 `export PATH="$HOME/.local/bin:$PATH"`，或重跑 setup_wsl.sh |
| Windows 侧 `python` 不是内部命令 | 未加入 PATH | 重装 Python 并勾选 "Add to PATH"，或使用完整路径 |
| 解包目录在 Windows 侧打不开 | 解包产物含 Linux 符号链接 | 属正常，Windows 资源管理器无法显示符号链接；用 CLI 分析即可（已做符号链接容错） |

---

### 路线 B：纯 Linux

适合有 Linux 笔记本 / 服务器 / 云主机的同学，**一切原生，无需 WSL**。

#### B1. 安装系统依赖

```bash
# Debian / Ubuntu 系
sudo apt update && sudo apt install -y \
    binwalk squashfs-tools cpio p7zip-full p7zip-rar file \
    build-essential binutils qemu-user-static qemu-system-arm \
    python3 python3-pip python3-venv python3-dev git

# Fedora / RHEL 系
sudo dnf install -y binwalk squashfs-tools cpio p7zip p7zip-plugins file \
    gcc make binutils qemu-user-static qemu-system-arm python3 python3-pip git
```

#### B2. 安装 sasquatch（非标准 SquashFS，强烈建议）

```bash
cd /tmp
git clone --depth 1 https://github.com/onekey-sec/sasquatch.git
cd sasquatch
make && sudo make install
```

> 很多路由固件用非标准 SquashFS（`squashfs:little endian` 变体），`unsquashfs` 解不了，必须用 sasquatch。

#### B3. 安装 Python 与项目依赖

```bash
cd <项目路径>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

#### B4. 验证

```bash
python scripts/dev.py test
which binwalk unsquashfs sasquatch strings readelf
```

#### B5. 常见问题（纯 Linux）

| 问题 | 原因 | 解决 |
|---|---|---|
| `binwalk -e` 解不出内容 | 固件加密 / 自定义头 | 换 `sasquatch` 手动解；或 `binwalk --extract --signature` 逐段看签名 |
| `ModuleNotFoundError: No module named 'capstone'` | 依赖没装 | `pip install -r requirements.txt` 重装 |
| `Permission denied` 运行脚本 | 可执行位缺失 | `chmod +x scripts/*.sh` |
| QEMU 缺架构 | 不同架构固件需不同 qemu | `sudo apt install qemu-user-static`（已含常见架构） |
| `pip` 报 externally-managed-environment | 新版 Debian/Ubuntu 限制 | 用 venv（本项目推荐），或 `pip install --break-system-packages` |

---

## 拿到固件后怎么做（完整流程）

> 这是最核心的一节。假设你刚从官网下载了一个固件（如 `DIR859_FW102b03.bin`），按下面 6 步走。

### 第 1 步 · 放置固件

把固件文件放到项目目录下的 **`firmware_samples/`** 文件夹：

```
<项目根目录>/
├── firmware_samples/
│   └── DIR859_FW102b03.bin     ← 你的固件放这里
├── tmp/                        ← 解包产物（自动创建）
└── runs/                       ← 分析报告（自动创建）
```

> **为什么必须放这里？** 安全策略（`config/safety.yaml`）只允许工具读写白名单目录：`runs/`、`tmp/`、`tests/fixtures/`、`firmware_samples/`。放别处会被 `Policy rejected` 拦截。

### 第 2 步 · 解包固件

固件是"打包文件"，先解出里面的文件系统（rootfs）。

**Windows + WSL2 路线**（PowerShell 执行）：

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/c/Users/<你的用户名>/Desktop/揭榜挂帅——网络安全 && binwalk -e -M firmware_samples/DIR859_FW102b03.bin -C /mnt/c/Users/<你的用户名>/Desktop/揭榜挂帅——网络安全/tmp/unpacked"
```

**纯 Linux 路线**：

```bash
cd <项目路径>
binwalk -e -M firmware_samples/DIR859_FW102b03.bin -C tmp/unpacked
```

参数说明：
- `-e` 提取；`-M` 递归提取（固件里可能有嵌套压缩层）
- `-C` 指定输出目录

**找到 rootfs**：解包后通常出现 `tmp/unpacked/_DIR859_FW102b03.bin-0.extracted/squashfs-root`，里面应有 `bin/`、`etc/`、`usr/`、`www/`（或 `htdocs/`）等目录——**这就是分析目标 rootfs**。

```bash
# 找不到 squashfs-root 时，列出解包结果
ls tmp/unpacked/_DIR859_FW102b03.bin-0.extracted/

# 备用：sasquatch 手动解
sasquatch -d tmp/squashfs-root firmware_samples/DIR859_FW102b03.bin
```

### 第 3 步 · 静态分析

**Windows 或 Linux 均可**（纯 Python，无需 WSL）：

```bash
fsa analyze <rootfs路径> --input-type rootfs --authorization-holder "设备所有者" --run-id <本次任务名>
```

**Windows 示例**：

```powershell
fsa analyze "C:\Users\22067\Desktop\揭榜挂帅——网络安全\tmp\unpacked\_DIR859_FW102b03.bin-0.extracted\squashfs-root" --input-type rootfs --authorization-holder "设备所有者" --run-id dir859_run1
```

**Linux 示例**：

```bash
fsa analyze "tmp/unpacked/_DIR859_FW102b03.bin-0.extracted/squashfs-root" --input-type rootfs --authorization-holder "设备所有者" --run-id dir859_run1
```

运行结束会打印报告，并保存到 `runs/dir859_run1/report.md`。

### 第 4 步 · 解读报告

打开 `runs/dir859_run1/report.md`，重点看三块：

```markdown
# 固件端到端静态分析报告
- ELF 二进制: 113        ← 固件里有多少可执行程序
- 检出候选: 29           ← 疑似漏洞数量

## 检出候选（命令注入）
| 候选 | 二进制 | Sink | 分数 | 等级 |
| e2e-elf-fileaccess.cgi | htdocs\fileaccess.cgi | system | 23 | HIGH |
| e2e-elf-httpd          | sbin\httpd           | system | 23 | HIGH |
```

**判读口诀**：
- **分数**：≥24 CRITICAL / 18–23 HIGH / 12–17 MEDIUM / <12 LOW
- **Sink**：`system` / `popen` / `eval` 是命令执行信号；`strcpy` / `sprintf` 是溢出信号
- **优先审 HIGH 以上**：通常 29 个候选里只有少数是真漏洞，其余是系统程序自带的正常 `system` 调用（误报），需要人工过滤

### 第 5 步 · 人工审计（10 问）

CLI 负责"找可疑点"，**人工审计负责"确认真漏洞"**。对每个 HIGH 以上候选逐条回答：

| # | 问题 | 验证手段 |
|---|---|---|
| 1 | 输入真的来自外部？ | HTTP 参数 / Header / Cookie / SOAP？还是常量？ |
| 2 | 攻击者能控制吗？ | 请求里能否任意设置该值？ |
| 3 | 真的到危险函数了？ | 反汇编：`objdump -d fileaccess.cgi | grep -A5 "jal.*system"` |
| 4 | 中间有过滤吗？ | 白名单 / 黑名单 / 长度检查？ |
| 5 | 调用链可达吗？ | 该 handler 被 httpd 路由注册了吗？ |
| 6 | 程序启动了吗？ | `etc/init.d/` 或 `rcS` 里有它吗？ |
| 7 | 需要认证吗？ | 登录后才可达？有认证绕过？ |
| 8 | 是调试功能吗？ | 函数名含 debug/test/diag？ |
| 9 | 有平台限制吗？ | 编译开关 / 特定硬件才走此路径？ |
| 10 | 有矛盾证据吗？ | 证据库里有没有反证？ |

**辅助命令**（WSL 或 Linux 内）：

```bash
strings <binary> | grep -E "system|popen|%s|reboot"   # 找命令模板
objdump -d <binary> | grep -A5 "jal.*system"           # 找调用点（MIPS）
readelf -s <binary> | grep system                       # 确认导入
```

**判定规则**：
- 10 问全过 → `confirmed-issue`（确认漏洞）
- 有认证/过滤但可绕过 → `high-confidence-candidate`
- 任一项不满足 → 降级或 `false-positive`，**别硬报**

### 第 6 步 · 动态验证（可选）

想在 QEMU 里证明漏洞真的能触发：

```bash
# WSL 或 Linux 内，qemu 用户态模式（适合单程序）
qemu-mipsel-static -L tmp/squashfs-root tmp/squashfs-root/htdocs/fileaccess.cgi
```

**红线（必须遵守）**：
- 只打自己下载的固件，目标 IP 必须私有网段（`192.168.x.x` / `10.x.x.x`）
- 只发无害 payload（`id`、`touch /tmp/lab_marker`）
- **禁止**反弹 shell、持久化、下载执行、真实攻击流量

---

## CLI 命令参考

| 命令 | 用途 | 产物 |
|---|---|---|
| `fsa analyze <固件或rootfs> --authorization-holder <授权主体>` | **正式分析入口**；自动识别文件/目录 | `runs/<run-id>/` 全量证据、状态、报告 |
| `fsa status <run-id>` | 查看持久化阶段状态 | 当前阶段 / 成功与失败阶段 |
| `fsa resume <run-id>` | 从第一个未完成阶段恢复 | 更新原运行目录 |
| `python scripts/dev.py test` | 跑全部单元测试 | — |
| `python scripts/dev.py test-all` | 单元测试 + 主机相关集成测试 | — |
| `python scripts/dev.py ext-smoke` | 探测 SaTC/FirmRec/KLEE/BOND，可缺失降级 | JSONL 状态 |
| `python scripts/dev.py lint` | ruff 代码检查 | — |
| `python scripts/dev.py format` | 自动格式化 | — |
| `python scripts/run_pipeline.py --benchmark-fixtures ...` | 金标准回归脚本（必须显式确认 fixture 模式） | fixture 回归产物 |
| `python scripts/run_e2e.py --fixture-mode ...` | 合成样本回归（必须显式确认 fixture 模式） | 演练产物 |
| `python scripts/demo_rank.py ...` | 独立评分示例（测试用途） | 示例排序产物 |
| `bash scripts/setup_wsl.sh`（WSL 内） | 一键装 Linux 工具链 | — |

## 配置说明

| 文件 | 作用 | 默认即用？ |
|---|---|---|
| `config/dev.yaml` | 主配置：runtime / 路径 / 日志 | ✅ |
| `config/models.yaml` | 模型运行时（offline / openai_compatible）与预算 | ✅（offline 默认） |
| `config/safety.yaml` | 安全红线（路径白名单 / 命令黑名单 / 网络白名单） | ✅（**不要改**） |
| `.env` | 模型 API Key 等环境变量（参考 `.env.example`） | 可选 |

**启用 LLM 运行时**（决赛场景）：

```yaml
# config/models.yaml
runtimes:
  openai_compatible:
    provider: openai
    base_url: https://api.deepseek.com/v1   # 或你的国内备案模型端点
    model: deepseek-chat
    api_key_env: OPENAI_API_KEY
```

```bash
export OPENAI_API_KEY=sk-xxx    # Windows PowerShell: $env:OPENAI_API_KEY="sk-xxx"
```

## 项目结构

```
.
├── fsa/                    # 核心包：orchestrator / runtime / safety / schemas / reporting / prompts / utils
├── tools/                  # 确定性工具：firmware(解包) / filesystem / web(攻击面) / binary / analysis / emulation
├── skills/                 # Skill 知识库（00-08，含四个外部分析器子 Skill）
├── schemas/                # JSON Schema + examples（含 external_finding）
├── config/                 # dev.yaml / models.yaml / safety.yaml
├── benchmarks/CVEs/        # 9 个历史 CVE 金标准 fixture
├── scripts/                # 开发、回归与环境辅助脚本（正式 CLI 位于 fsa/cli.py）
├── firmware_samples/       # ← 固件放置目录
├── tmp/                    # 解包产物
├── runs/                   # 分析报告与 JSON 产物
├── tests/                  # 单元 / 集成测试（CI 不依赖外部重型工具）
└── docs/                   # 设计文档、WSL 指南、挖洞教程
```

## Skill 体系

| Skill | 领域 | 关键知识 |
|---|---|---|
| 00-orchestrator | 总控编排 | 阶段机、深度档位、决策可审计 |
| 01-unpack | 固件解包 | binwalk 降级、魔数表、rootfs 评分 |
| 02-attack-surface | 攻击面 | Web/UPnP/CGI 枚举、认证矩阵三层交叉 |
| 03-binary-decompile | 二进制分析 | 架构识别、Ghidra 降级路径 |
| 04-static-analysis | 静态审计 | 命令注入五步法、协议解析六步法 |
| 04-audit | 专项审计 | command-injection / buffer-overflow 复现经验 |
| 05-candidate-verifier | 反证审查 | 10 问清单、12 条硬判定 |
| 06-dynamic-validation | 动态验证 | L0–L3 分层、qemu-user 三大坑、安全门 |
| 07-report | 报告生成 | 21 节骨架、8 项合规扫描、脱敏 |
| 08-external-analyzers | 双轨外部分析 | SaTC/FirmRec/KLEE/BOND、汇聚、降级与先验隔离 |

## 外部分析器双轨链

`--depth full` 使用固定顺序：SaTC/FirmRec 上游分析 → FUSION → KLEE 保守剪枝 →
RANK/Verifier → mini-BOND 约束验证。FirmRec 是已知漏洞复发扫描旁路，Blind Run
会被代码强制关闭，结果独立保存且不计入零先验指标。

四器全部是可选增强：总开关和单工具开关默认关闭；缺镜像、缺 KLEE、超时或解析失败
都必须返回结构化 `status + limitation`，不能阻断主报告。安装、能力边界和复现状态见
`docs/external_analyzers.md`。

## 评分与结论模型

**十维评分**（每维 0–3，满分 30）：`P` 预认证可达性 · `I` 输入来源 · `U` 用户可控性 · `D` 危险函数可达 · `C` 字符串拼接 · `S` Shell 上下文 · `W` 文件写入 · `K` 配置持久化 · `V` 输入验证(反向) · `T` 可测试性。

阈值：**≥24 CRITICAL / 18–23 HIGH / 12–17 MEDIUM / <12 LOW**。

**五分类结论**：`confirmed-issue`（确认） / `high-confidence-candidate`（高置信） / `false-positive`（误报） / `unknown`（未知） / `observation`（观察）。

**裁决动作**：`ACCEPT`（采纳） / `DOWNGRADE`（降级） / `REJECT`（拒绝） / `NEED_DYNAMIC`（需动态验证）。

## 安全与合规

1. **命令黑名单**：`rm -rf`、`curl/wget`、`bash -i` 一律拒绝
2. **路径白名单**：仅 `runs/`、`tmp/`、`tests/fixtures/`、`firmware_samples/`；`.env`/`secrets/` 禁止读写
3. **网络隔离**：仅私有网段与 `127.0.0.1`；动态验证目标非私有 → `ABORT_DYNAMIC_VALIDATION`
4. **动态验证四门**：`AUTHORIZED && LOCAL_LAB && PRIVATE_NETWORK && BASELINE_READY`
5. **非武器化探针**：只允许 `touch/echo/id/uname`；反弹 shell / 持久化 / 下载执行一律拒绝
6. **报告合规 8 项**：原 7 项 + 外部 PoC 必须 `poc_sanitized=true`

## 测试

```bash
python scripts/dev.py test    # 确定性单元测试（CI 主门）
python scripts/dev.py test-all # 含可选 WSL/Linux 工具集成测试
python scripts/dev.py lint    # ruff 全绿
```

- 单元测试覆盖：Schema / 工具 / 编排 / Verifier / 评分 / 动态验证 / Skill 加载 / e2e
- 金标准回归：9 个 CVE fixture 全部通过 Schema 校验
- 集成测试：`tests/integration/`（解包/攻击面，依赖 WSL/Docker 时自动 skip）

## 常见问题（FAQ）

**Q1：Windows 上没有 binwalk，能跑吗？**
能。单元测试与静态分析是纯 Python；只有真实固件解包需要 Linux 工具，用 WSL2 一条命令解包后，Windows 侧分析。

**Q2：解包时符号链接报错 / 目录打不开？**
真实固件 rootfs 含 Linux 符号链接（如 `tmp -> /dev/null`），Windows 无法 stat。CLI 已做符号链接容错（`fsa/utils/traverse.py`），直接分析即可，无需手动清理。

**Q3：怎么接入国产大模型？**
编辑 `config/models.yaml` 的 `openai_compatible` 段，设置 `OPENAI_API_KEY` 环境变量，`config/dev.yaml` 的 `runtime.default` 改为 `openai_compatible`。模型不可用时只返回明确的 degraded 状态，不生成替代模型结论。

**Q4：比赛现场给新固件，系统能发现漏洞吗？**
能。系统不依赖 CVE 特征硬编码：`run_e2e.py` 演练证明零 CVE 先验可检出植入命令注入。现场流程 = 放置固件 → 解包 → 分析 → 人工审计 → 报告。

**Q5：报告里会不会出现可武器化内容？**
不会。Skill 07 强制 8 项合规扫描 + 脱敏渲染，真实 IP / 反弹 shell 等以占位符替代；未标记 `poc_sanitized=true` 的外部验证证据会被拒绝。

**Q6：WSL 服务不稳定（0x8007274c）？**
`wsl --shutdown` 后重试；或直接改用纯 Linux 路线（路线 B）。

**Q7：怎么查看报告？**
`runs/<任务名>/report.md` 是 Markdown；`analysis.json` 是结构化结果。也可以把 report.md 交给 WorkBuddy 渲染成网页。

## 许可证

MIT © 第一队 · 挑战杯「揭榜挂帅」专项赛

---

*FirmHound · 固件猎犬 — 用确定性工具发现漏洞，用证据链赢得信任。*
