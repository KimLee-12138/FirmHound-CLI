---
name: router-firmware-vuln-hunt
description: 通用 Linux 路由器 / IoT 固件漏洞挖掘与验证工作流。当需要对一个本地固件文件（.bin/.img/.chk/.trx 等）在授权实验环境中完成"解包 → 攻击面枚举 → 危险函数扫描 → 认证边界分析 → 风险评分 → 数据流追踪 → 误报排查 → 报告生成 →（可选）本地仿真验证"时使用。覆盖双攻击面：网络 socket 服务 与 Web/CGI/UPnP 入口。仅限本地分析，不访问真实设备或公网。
version: 2.0.0
---

# 路由器固件漏洞挖掘与验证 Agent Skill

> 一条通用的、与具体 CVE/厂商解耦的固件漏洞分析流水线。
> 由两个案例型 Skill（D-Link `.chk` 网络守护进程路线、D-Link DIR-859 Web/UPnP 路线）合并提炼而来。
> **所有分析仅限本地/仿真环境，绝不针对真实设备、公网 IP 或校园网设备。**

---

## 0. 安全声明

本 Skill 及所有脚本、参考文件只做**本地、授权、教学型**静态分析与本地仿真验证：

- 不向真实设备、公网 IP、非授权网络发送任何流量。
- 仿真验证仅限 QEMU / FirmAE 虚拟环境，目标 IP 必须在私有网段内。
- 命令执行验证仅使用无害标记文件（`touch /tmp/lab_marker` 等）。
- 不含反弹 Shell、持久化、下载执行、破坏性 payload。

任何一步违反上述边界 → 立即中止。

---

## 1. Skill 目标与适用范围

### 目标

从固件二进制文件出发，自动产出一份结构化漏洞分析报告，覆盖两类攻击面：

| 攻击面 | 入口形态 | 典型 sink |
|--------|----------|-----------|
| **入口 A — 网络 socket 服务** | C 守护进程监听 TCP/UDP，`recvfrom/socket/bind` | `strcpy/strcat/sprintf/system` 等 |
| **入口 B — Web/CGI/UPnP** | HTTP 路由 → CGI/PHP 处理器 | PHP `system/exec`、Shell 脚本写入、命令拼接 |

### 适用范围

- 任意 Linux 路由器 / IoT 固件（`.bin` `.img` `.chk` `.trx` `.bin` 等）。
- 任意 CPU 架构（MIPS / ARM / x86 / PPC，含大小端）。
- 任意厂商（厂商封装函数通过 `examples/vendor_function_dictionaries.md` 扩展，不写死在主流程）。

### 不适用

- 非 Linux 固件（RTOS 裸机、无文件系统）——需另行适配。
- 需要真实硬件才能触发的漏洞（本 Skill 只到仿真验证为止）。

---

## 2. 使用前提

### 环境要求

| 工具 | 用途 | 必需 |
|------|------|------|
| `file` `strings` `readelf` `objdump` | 固件识别与二进制分析 | 是 |
| `binwalk` | 固件扫描与辅助解包 | 是 |
| `unsquashfs` / `sasquatch` | SquashFS 解包（sasquatch 用于非标准 LZMA） | 是 |
| `dd` | 从固件镜像中剥离文件系统偏移 | 是 |
| `python3` | 评分、报告生成、合规扫描 | 是 |
| FirmAE / QEMU | 本地仿真验证 | 否（仅 Step 10） |
| Ghidra / IDA | C 层深度逆向 | 否 |

### 前置条件

- 固件文件已下载到本地，且你拥有对其分析的合法授权（自有设备 / 授权实验 / 教学）。
- 所有分析在本地完成，不访问公网或真实设备。

---

## 3. 强制安全规则

以下规则优先级最高。所有脚本、所有分析步骤、所有输出均须遵守。违反任一条 → 立即中止。

| # | 规则 |
|---|------|
| **R1** | 仅分析本地固件文件，脚本入口拒绝网络挂载路径 |
| **R2** | 仅针对本地仿真环境，所有目标 IP 必须在 `192.168.0.0/16`、`10.0.0.0/8`、`172.16.0.0/12` 内 |
| **R3** | 禁止对真实设备、公网 IP、校园网设备分析或验证；检测到非私有 IP → ABORT |
| **R4** | 禁止生成反弹 Shell（`nc -e`、`bash -i` 等） |
| **R5** | 禁止生成持久化代码（`crontab` 写入、`/etc/rc`、`init.d` 变更） |
| **R6** | 禁止生成下载执行外部程序的命令（`wget ... | sh`、`curl ... | sh`、`tftp -g`） |
| **R7** | 验证命令仅限无害标记：`touch /tmp/lab_marker`、`echo LAB >/tmp/lab_marker.txt`、`id >/tmp/lab_id.txt` |
| **R8** | 危险 payload 默认禁止（`ENABLE_DANGEROUS=false`），需用户显式开启 |
| **R9** | 无法确认本地仿真环境（IP 范围 + 可达性 + 网络隔离）则停止 |

完整强制代码与检测正则：见 `references/safety_rules.md`。

---

## 4. 输入输出格式

### 输入

| 参数 | 必需 | 说明 | 默认值 |
|------|------|------|--------|
| `FIRMWARE_PATH` | 是 | 固件二进制文件绝对路径 | — |
| `OUTPUT_DIR` | 是 | 所有产出物输出目录 | — |
| `LOG_DIR` | 否 | 运行日志目录 | `{OUTPUT_DIR}/../logs` |
| `ROOTFS_PATH` | 否 | 已解包根文件系统路径（跳过解包） | — |
| `TARGET_VENDOR` | 否 | 厂商名，用于封装函数字典与 FirmAE 模式选择 | `auto` |
| `DEPTH` | 否 | 分析深度：`quick` / `standard` / `full` | `standard` |
| `ENABLE_EMULATION` | 否 | 启用仿真验证（需显式授权） | `false` |
| `EMU_IP` | 否 | 仿真设备 IP（必须私有） | `192.168.0.1` |
| `TOP_N` | 否 | 深度分析候选数量 | `5` |
| `RESUME` | 否 | 从检查点恢复 | `true` |

完整配置示例：`examples/example_config.yaml`。

### 输出

```
{OUTPUT_DIR}/
├── logs/                              # 逐步运行日志
│   ├── 01_firmware_info.log
│   ├── 02_unpack.log
│   ├── 03_attack_surface.log
│   ├── 04_scan_dangerous.log
│   ├── 05_rank_candidates.log
│   └── 09_generate_report.log
├── output/                            # 分析产出
│   ├── firmware_info_*.txt
│   ├── attack_surface_*.txt
│   ├── dangerous_scan_*.txt
│   ├── candidate_ranking_*.json
│   └── vulnerability_report_*.md     # 最终报告
├── screenshots/                       # 仿真截图清单
└── state/
    └── workflow_state.json            # 检查点 / 恢复
```

---

## 5. 总体工作流

```
Step 01 [脚本]  → 固件信息采集        scripts/collect_firmware_info.sh
Step 02 [脚本]  → 固件解包 + 架构识别   scripts/unpack_firmware.sh
Step 03 [脚本]  → 攻击面枚举（双入口）  scripts/scan_attack_surface.sh
Step 04 [脚本]  → 认证边界 + 危险函数   scripts/scan_dangerous_patterns.sh
Step 05 [脚本]  → 风险评分与排序       scripts/rank_candidates.py
Step 06 [Agent] → 数据流追踪          （参考 references/dangerous_function_dataflow.md）
Step 07 [Agent] → 误报排查与评分修正   （参考 references/risk_scoring.md §6）
Step 08 [Agent] → 主漏洞深度分析       （参考对应 case_studies/）
Step 09 [脚本]  → 报告骨架生成        scripts/generate_report_skeleton.py
Step 10 [Agent] → 本地仿真验证（可选） （参考 references/local_emulation_validation.md）
```

每个 Step 完成后写入 `state/workflow_state.json`，支持中断恢复。

---

## 6. 模块 1：固件信息采集 + 解包 + 架构识别

**负责步骤**：Step 01 + Step 02

### Step 01 — 固件信息采集（`scripts/collect_firmware_info.sh`）

- `file` + `hexdump`（前 256 字节）+ `binwalk` 扫描（不解包）
- 计算 MD5 / SHA1 / SHA256
- 提取嵌入式字符串：厂商、型号、版本、内核、Web 服务器、架构
- 输出：`output/firmware_info_*.txt`、`logs/01_firmware_info.log`

### Step 02 — 固件解包 + 架构识别（`scripts/unpack_firmware.sh`）

- 识别封装格式：DLOB / uImage / TRX / SquashFS / CPIO / LZMA（通用判断表见 `references/firmware_unpacking.md`）
- 按格式选择解包策略（DLOB → `dd` + `sasquatch`；SquashFS → `unsquashfs`/`sasquatch`）
- CPU 架构检测：定位 libc → `readelf -h` → 确定 MIPS/ARM/x86/PPC + 大小端
- 输出：提取后的 rootfs、`logs/02_unpack.log`

---

## 7. 模块 2：攻击面枚举（双入口）

**负责步骤**：Step 03（`scripts/scan_attack_surface.sh`）

这是本 Skill 相对单一案例的核心增强：同时枚举两类入口。

### 入口 A — 网络 socket 服务（来自案例 A）

| 方法 | 命令 |
|------|------|
| 列出服务二进制 | 扫描 rootfs 中所有 ELF 可执行文件 |
| socket 入口识别 | `objdump -d <bin> \| grep -E 'recvfrom|recv|socket|bind'` |
| 监听端口推断 | `strings <bin> \| grep -E ':[0-9]{2,5}|port'`、rc 脚本中的启动参数 |

目标：找出**直接消费网络报文**的守护进程（非 HTTP），这是 Web 入口扫描会漏掉的攻击面。

### 入口 B — Web / CGI / UPnP（来自案例 B）

| 类别 | 方法 |
|------|------|
| CGI 处理器 | `strings cgibin \| grep '_main$'` |
| httpd 路由 | 搜索 `httpd.conf` / rc 脚本中的 alias/location |
| URL 路由 | `grep -rn 'ln -s.*cgibin' etc/` |
| PHP 清单 | `find htdocs -name '*.php'` |
| UPnP 组件 | 搜索 gena/soap/ssdp/hnap 相关文件 |
| 环境变量注入点 | `strings httpd \| grep HTTP_` |
| 二进制安全特性 | `readelf -l \| grep GNU_STACK/RELRO`（NX/Canary/PIE/RELRO） |

输出：`output/attack_surface_*.txt`、`logs/03_attack_surface.log`。

详细搜索优先级、处理器分类、UPnP 发现流程：见 `references/attack_surface_enumeration.md`。

---

## 8. 模块 3：认证边界识别

**负责步骤**：Step 04（Part A，`scripts/scan_dangerous_patterns.sh`）

用于判断一个入口是否**预认证可达**（无需登录即可触发），这是漏洞严重度排序的关键前置。

### 三层交叉验证模型

| 层 | 检查点 | 方法 | 证据强度 |
|----|--------|------|---------|
| L1 — httpd 路由 | `.cgi` 是否绕过认证检查 | `strings httpd \| grep -iE 'auth|session|check'` | 中 |
| L2 — C 处理器 | 是否调用 `sess_validate` / `check_auth` 等 | `strings cgibin \| grep -iE 'sess_validate\|check_auth'` | 强 |
| L3 — PHP 层 | 是否检查 `AUTHORIZED_GROUP` / session | `grep -rn 'AUTHORIZED_GROUP' htdocs/` | 最强 |

> 认证函数/变量名因厂商而异，需按 `examples/vendor_function_dictionaries.md` 替换，不要写死为单一厂商字符串。

### 置信度矩阵

| 情况 | 判定 | 得分 P |
|------|------|--------|
| 3 层均无认证 | 确认预认证 | 3 |
| 2/3 层无认证 | 很可能预认证 | 2 |
| 1/3 层无认证 | 可能预认证 | 1 |
| 0/3 层无认证 | 需认证 | 0 |

**关键认知**：UPnP 协议处理器（gena/soap/ssdp/hnap）通常为预认证——这是协议设计特性而非漏洞，但使 UPnP 处理器成为最高优先级分析目标。

详细方法、认证字符串字典、误报预防：见 `references/auth_boundary_analysis.md`。

---

## 9. 模块 4：危险函数扫描与数据流追踪

**负责步骤**：Step 04（Part B）+ Step 06

### 危险函数扫描（统一函数分类表）

| 类别 | C 函数 | PHP 函数 | 检测方法 |
|------|--------|---------|---------|
| 命令执行 | `system` `popen` `execl/execv` | `system()` `exec()` `passthru()` `shell_exec()` | `readelf -s` / `grep` |
| 厂商封装函数 | 见 `examples/vendor_function_dictionaries.md`（如 D-Link `lxmldbc_system`/`alpha_system2`/`do_system`） | — | `strings \| grep` |
| Shell 脚本写入 | `fwrite(.sh)` | `fwrite(*.sh)` `file_put_contents(*.sh)` | `grep -rn` |
| 内存破坏 | `sprintf` `strcpy` `strcat` `gets` | — | `readelf -s` |
| 代码执行 | — | `eval()` `assert()` `preg_replace /e` | `grep -rn` |

同时检测二进制安全特性（NX/Canary/PIE/RELRO/Stripped）。

### 数据流追踪（Step 06 — Agent 驱动）

对每个 Top N 候选，沿输入到 sink 逐层追踪。**入口不同则模板不同**：

- 入口 B（HTTP）→ 7 层模板（见下）。
- 入口 A（socket）→ 变体模板：`网络报文 → recvfrom 接收 → 拷贝/格式化（strcpy/sprintf）→ sink`。

```
Layer 1 [HTTP Request]  → Method + URL + Attacker-controlled Headers
Layer 2 [httpd Route]   → URL 匹配 → 处理器分发 → 环境变量设置
Layer 3 [C Handler]     → getenv() → 本地变量 → 认证检查? → 输入验证?
Layer 4 [IPC/xmldb]     → 命令拼接（如 "cmd -V KEY=" + var）→ 变量嵌入
Layer 5 [PHP Receive]   → 变量绑定 → PHP $variable → escapeshellarg?
Layer 6 [PHP Sink]      → fwrite(fp, "..." . $variable) → Shell 脚本注入点
Layer 7 [Shell Execute] → sh script.sh (root) → 元字符展开 → 命令执行
```

每层记录：过滤器存在性 + 证据（file:line）+ 引用类型。

**变量使用验证**（最重要的误报检查）：
```bash
grep -n '$var\s*=' file.php    # 变量定义
grep -n '$var' file.php         # 变量使用（验证是否真正到达 sink）
```

详细函数分类、注入上下文分析、过滤器清单：见 `references/dangerous_function_dataflow.md`。

---

## 10. 模块 5：风险评分与排序

**负责步骤**：Step 05（`scripts/rank_candidates.py`）

### 快速预筛（来自案例 A 的启发式）

在完整评分前，先做一遍粗筛：命中 **「网络输入 ×（内存破坏 / 命令执行）」** 组合的候选优先进入评分池，其余仅归档。

### 10 维评分体系（P-I-U-D-C-S-W-K-V-T，每维 0–3，满分 30）

| # | 维度 | 0 分 | 1 分 | 2 分 | 3 分 |
|---|------|------|------|------|------|
| **P** | 预认证可达性 | 需认证 | 可能需认证 | 很可能预认证 | 确认预认证（3 层交叉验证） |
| **I** | 输入来源 | 无外部输入 | 间接/内部 | 文件系统/配置 | 直接 HTTP/网络输入 |
| **U** | 用户可控性 | 不可控 | 有限控制 | 部分可控 | 完全可控 |
| **D** | 危险函数可达 | 无可达危险函数 | 推测可能 | 字符串证据 | 源码确认 |
| **C** | 字符串拼接 | 无拼接 | 固定格式 | 格式化含输入 | 原始拼接 |
| **S** | Shell 上下文 | 无 Shell | 可能 Shell | 很可能 Shell | 确认 Shell（sh -c / system） |
| **W** | 文件写入 | 无写入 | 日志写入 | 配置文件写入 | 任意/Shell 脚本写入 |
| **K** | 配置持久化 | 无配置写入 | 间接路径 | 可控配置键 | 直接配置注入+持久化 |
| **V** | 输入验证（反向分） | 强验证 | 白/黑名单 | 弱/最小验证 | 无任何验证 |
| **T** | 可测试性 | 极难（需硬件） | 需 Ghidra+QEMU | 中等难度 | 简单 HTTP/网络请求 |

### 风险等级阈值

| 等级 | 分数 | 动作 |
|------|------|------|
| CRITICAL | ≥ 24 | 立即深度数据流分析 |
| HIGH | 18–23 | Critical 之后分析 |
| MEDIUM | 12–17 | 记录，时间允许时分析 |
| LOW | < 12 | 仅归档 |

### 系统排除列表（模板）

默认排除无 LAN 可达网络暴露的组件（如 `pppd` `dnsmasq` `hostapd` `iptables` `servd` `openssl`）。此名单需按固件实际启动脚本调整，不可当作硬编码绝对规则。

完整评分指南、证据分级 L1–L5：见 `references/risk_scoring.md`。

---

## 11. 模块 6：误报排查与评分修正

**负责步骤**：Step 07（Agent 驱动）

### 5 种误报排查方法

| # | 方法 | 操作 | 典型修正幅度 |
|---|------|------|-------------|
| 1 | 变量使用验证 | 确认用户可控变量是否实际被危险 sink 消费 | −5 ~ −7 |
| 2 | 输入来源复核 | 确认输入来自用户（HTTP/网络）还是内核/内部服务 | −5 ~ −7 |
| 3 | 认证边界复核 | 重新检查 3 层认证，确认是否功能端点（login/captcha） | −3 ~ −5 |
| 4 | 白名单评估 | 验证输入是否被白名单限制为安全值集合 | −2 ~ −3 |
| 5 | 过度标记区分 | 区分功能端点（Login/CAPTCHA）与漏洞候选 | −2 ~ −4 |

### 评分修正记录模板

```
候选 #N: {name}
  初始分数: XX/30 → 最终分数: YY/30
  修正幅度: −ZZ
  修正原因: {具体发现 + file:line}
  影响: {风险等级变化}
```

详细修正模式：见 `references/risk_scoring.md` §6。

---

## 12. 模块 7：本地仿真验证（可选）

**负责步骤**：Step 10（默认跳过）

**前置条件**：`ENABLE_EMULATION=true`（显式授权）**且**通过预检安全检查。

### 三阶段验证

| 阶段 | 操作 | 条件 |
|------|------|------|
| A — 可达性 | 发送基线请求确认目标接口响应 | 始终允许 |
| B — Shell 脚本生成 | 确认正常请求产生 Shell 脚本 | 始终允许 |
| C — 无害标记注入 | `touch /tmp/lab_marker` 验证命令执行 | **仅** `ENABLE_DANGEROUS=true` |

**允许的标记命令白名单**：`touch /tmp/lab_marker`、`echo LAB >/tmp/lab_marker.txt`、`id >/tmp/lab_id.txt`、`wget http://{HOST_IP}:{PORT}/path -O /dev/null`（仅 HOST 私有 IP）。

**EMU_IP 必须为私有 IP**，非私有 IP → FATAL ABORT。

详细 FirmAE 搭建、快照管理、故障排查：见 `references/local_emulation_validation.md`。

---

## 13. 模块 8：自动报告生成

**负责步骤**：Step 09（`scripts/generate_report_skeleton.py`）

报告模板 10 节，`[AUTO]` 由脚本填充，`[AGENT]` 由 Agent 在 Step 06/07/08 完成后写入。

| 节号 | 内容 | 标记 |
|------|------|------|
| 1 | 固件信息（品牌/型号/哈希/架构） | [AUTO] |
| 2 | 攻击面摘要（服务/处理器/PHP/socket 入口） | [AUTO] |
| 3 | 认证边界分析（3 层交叉验证表） | [AUTO] 表格 + [AGENT] 关键发现 |
| 4 | 危险函数扫描 | [AUTO] |
| 5 | 候选排序（10 维评分表） | [AUTO] 表格 + [AGENT] 选择理由 |
| 6 | 深度数据流分析 | [AGENT] |
| 7 | 误报排查与评分修正 | [AGENT] |
| 8 | 修复建议（P0/P1/P2） | [AGENT] |
| 9 | 交付物索引 | [AUTO] |
| 10 | 安全声明 | [AUTO]，必须完整保留 |

完整模板：见 `references/report_template.md`。

---

## 14. 完成标准与合规扫描

### 最低完成标准（`DEPTH=quick`）
- Step 01–05 无错误执行，`candidate_ranking_*.json` 已生成，日志齐全。

### 标准完成标准（`DEPTH=standard`）
- Step 01–09 无错误；Agent 数据流分析覆盖 Top 3；误报排查完成 Top 5；报告完整（含 [AUTO] 与 [AGENT]）；安全声明节完整保留。

### 完整完成标准（`DEPTH=full`）
- 上述全部 + Step 10 仿真验证完成 + ≥10 张截图 + ≥1 个 `CONFIRMED`/`PARTIAL` 结果。

### 安全合规检查
- 所有输出通过 7 项安全扫描（无真实 IP / 无反弹 Shell / 无持久化 / 无下载器 / 无破坏性命令 / 有安全声明 / 仅标记验证）。
- 完整清单：见 `references/deliverables_checklist.md`。

---

## 15. 脚本索引

| 脚本 | 用途 | Step |
|------|------|------|
| `scripts/collect_firmware_info.sh` | 固件识别、哈希、字符串分析 | 01 |
| `scripts/unpack_firmware.sh` | 格式识别、解包、架构检测 | 02 |
| `scripts/scan_attack_surface.sh` | 双入口枚举（socket + Web/CGI/UPnP） | 03 |
| `scripts/scan_dangerous_patterns.sh` | 认证边界（Part A）+ 危险函数（Part B） | 04 |
| `scripts/rank_candidates.py` | 10 维评分 + 快速预筛 + Top N | 05 |
| `scripts/generate_report_skeleton.py` | 10 节报告 [AUTO] 填充 | 09 |
| `scripts/audit_compliance.sh` | 交付物安全合规扫描 | 收尾 |

## 16. 参考文件索引

| 文件 | 内容 |
|------|------|
| `references/safety_rules.md` | 安全规则 + 检测正则（改写后，不含可执行危险命令串） |
| `references/firmware_unpacking.md` | 通用格式识别表、解包方法、架构检测 |
| `references/attack_surface_enumeration.md` | 双入口枚举、处理器分类、UPnP 发现 |
| `references/auth_boundary_analysis.md` | 三层认证模型、置信度矩阵、字符串字典 |
| `references/dangerous_function_dataflow.md` | 统一函数分类、7 层模板 + socket 变体、变量使用验证 |
| `references/risk_scoring.md` | 10 维定义、排除规则、证据分级、误报修正 |
| `references/local_emulation_validation.md` | FirmAE 搭建、3 阶段验证、截图清单 |
| `references/report_template.md` | 10 节报告模板 [AUTO]/[AGENT] 标记 |
| `references/deliverables_checklist.md` | 交付物自检 + 合规扫描 |
| `references/case_studies/` | 两个来源案例的完整分析路线（附录） |

---

## 17. 案例附录导航

主流程刻意与具体 CVE/厂商解耦。需要参照实战细节时，查阅：

- `references/case_studies/dir859_web_upnp_command_injection.md` —— Web/CGI/UPnP 预认证命令注入路线（来自案例 B，D-Link DIR-859）。
- `references/case_studies/dlink_chk_network_daemon_overflow.md` —— `.chk` 网络守护进程 socket 入口 + 内存破坏路线（来自案例 A）。

---

> **SAFETY DECLARATION**: This Skill and all associated scripts perform LOCAL-ONLY analysis. No network traffic is ever sent to real devices, public IPs, or campus network devices. All emulation validation is confined to QEMU/FirmAE virtual environments with private IP ranges. Command execution verification uses only harmless marker files (`touch /tmp/lab_marker`). This Skill does not contain reverse shells, persistence mechanisms, downloaders, or destructive payloads.
