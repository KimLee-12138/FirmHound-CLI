# G 同学 · KLEE 全量复现与集成计划

> **你的任务**：把 KLEE（v3.2）从"能跑 hello world"做到"能对真实固件候选做路径可行性剪枝"，
> 并自主实现 **harness 生成器**——这是四人里**自研工程量最大**的一块。
>
> **基调：不是跑通 demo，是全量完成。** 你的验收标准见 §2 全量档 9 条。
>
> **你为什么关键**：BOND 的定向 fuzz 很贵（十几分钟到几十分钟一次）。
> 你先用符号执行证明"这条路根本走不通"，把这类候选剪掉，**只把剩下的送进 BOND**。
> 你省下的每一分钟，都是 H 的预算。

---

## 1. 三句话讲清 KLEE

- **它解决什么**：动态符号执行。把输入符号化，沿路径收集约束，交给 SMT 求解器（STP/Z3）判定"这条路径能不能走通"，能走通就给出**具体输入**。
- **它补我们什么**：我们现在答不出"这条 source→sink 路径在约束上真的能执行到吗"。误报全靠 5 条经验规则和人工 10 问扛。KLEE 给的是**数学判定**。
- **它在链条哪**：`SYMEX_PRUNE` 阶段，吃汇聚后的候选，产出 `symex.reachable` + `witness_input`。

### 1.1 一个关键优势（答辩要讲）

**KLEE 跑的是 LLVM bitcode 语义，天然跨架构。** 固件是 MIPS/ARM，但一旦拿到 bitcode，
KLEE 不需要 qemu、不需要真机、不需要关心字节序。这比 BOND 的黑盒 fuzz 干净得多，
也是它适合放在 fuzz 之前当"过滤器"的原因。

---

## 2. 交付标准（三档）

### 全量档（Full）—— 你的目标

| # | 项 | 具体判定 |
|---|---|---|
| **F1** 数据集全量 | L1 合成 + L2 DIR-859 + L3 两个真实固件，**三个都做过符号执行** | 3 份剪枝报告 |
| **F2** 模式全量 | **三种 bitcode 策略全试过**：S1 源码 wllvm / S2 harness / S3 二进制提升。S1、S2 必须成功，S3 允许失败但必须**给出失败的诚实归因** | 三份策略报告 |
| **F3** Parser 全量 | 覆盖 `klee-out-N/` 的**全部产物类型**：6 类 `.err`、`.ktest`、`info`、`run.stats`、`warnings.txt`、`.path` | 单测对每类有 fixture |
| **F4** 单测全量 | **harness 生成器单测** + parser 六类分支（正常/空/畸形/超时/路径爆炸/版本差异），覆盖率 ≥80% | `pytest --cov` |
| **F5** 接入全量 | registry 注册 + `run_external.py --tool klee` 可跑 + `--depth full` 下 `SYMEX_PRUNE` 阶段跑通 | 三条都通 |
| **F6** Benchmark 全量 | 3 固件 × Top-10 候选的剪枝实验：**剪枝率 + 人工抽检 5 条确认无误杀** | `benchmarks/external/klee/comparison.md` |
| **F7** 降级完备 | KLEE 缺失时主链行为不变；超时/路径爆炸**不改分**只记 limitation；8 种开关组合不 abort | 8/8 通过 |
| **F8** 文档全量 | SKILL.md 含 7 节 + 踩坑表 + **harness 生成规则说明** | 文档齐 |
| **F9** 性能基线 | 每候选的符号执行耗时、内存峰值、路径数、状态数 | 基线表 |

### 你的独有交付（别人没有）

| # | 项 | 说明 |
|---|---|---|
| **X1** | **`tools/external/klee/harness_gen.py`** | 从 candidate 的 sink 签名自动生成 C 桩 → 编成 bitcode。**这是纯自研，是 KLEE 能否用于真实固件的唯一钥匙** |
| **X2** | **误杀防护机制** | `reachable=false` 必须注明"在 harness 模型下"，只写反证不删候选；剪枝率 >70% 触发抽检 |

### 部分档 / 兜底档

- **部分**：只跑通 S1（合成固件源码路径），真实固件没跑通；或 parser 只覆盖 `.err` 不覆盖 `.ktest`。
- **兜底**：复现报告 + Skill 文档 + adapter 空壳 + fixture 单测。

---

## 3. 工具档案（已查证）

| 项 | 内容 |
|---|---|
| 全称 | KLEE Symbolic Execution Engine |
| 版本 | **KLEE 3.2（2025-12-23 发布）**，官方提供 Docker |
| LLVM | **推荐 LLVM 16**（3.2 已部分支持 17–19；不再支持 <11） |
| 求解器 | STP（历史最稳）或 **Z3（≥4.4，推荐，我们选用）**，也支持 metaSMT |
| 输入 | **LLVM bitcode `.bc`** ← 这是最大约束 |
| 输出 | `klee-out-N/`：`*.err`（内存错误）、`test*.ktest`（具体输入）、`info`、`run.stats`、`warnings.txt` |
| 辅助 | `ktest-tool` 读 `.ktest`；`klee-stats` 看统计；`wllvm` 编全程序 bitcode（推荐装） |

### 常用命令

```bash
# 编译到 bitcode
clang-16 -emit-llvm -g -O0 -c harness.c -o harness.bc
# 或全程序（源码可得时）
wllvm -O0 -g -o prog prog.c && extract-bc prog

# 符号执行
klee --max-time=300s \
     --max-depth=200 \
     --max-forks=64 \
     --solver-backend=z3 \
     --search=dfs \
     --output-dir=klee-out-0 \
     harness.bc

# 读具体输入
ktest-tool --write-ints klee-out-0/test000001.ktest
```

### `.err` 文件类型（Parser 必须全认）

| 文件 | 含义 |
|---|---|
| `ptr.err` | 指针越界（**溢出类候选的关键证据**） |
| `free.err` | 重复释放 / 非法释放 |
| `div.err` | 除零 |
| `overflow.err` | 整数溢出 |
| `assert.err` | `klee_assert` 失败 |
| `model.err` | 内存模型限制（不是漏洞，是 limitation） |
| `exec.err` | 外部调用/不支持的指令（limitation） |

> ⚠️ **`model.err` 和 `exec.err` 不是漏洞证据**，必须归到 `limitation`，
> 否则你的误报会比没接 KLEE 时还多。

---

## 4. 核心难题与三条 bitcode 路径

**问题**：KLEE 只吃 LLVM bitcode，而固件是编译好的 MIPS/ARM 二进制。

### 4.1 三条路径（优先级从高到低）

| 路径 | 适用 | 做法 | 时间盒 |
|---|---|---|---|
| **S1 · 源码 wllvm** | **L1 合成固件**（自带 `httpd.c` / `upnpd.c` 源码！） | `wllvm -O0 -g` 编译 → `extract-bc` 拿到 `.bc` | 必成，Day0 就做 |
| **S2 · harness 桩（主推）** | **L2/L3 真实固件**（无源码） | 从 candidate 的 sink 签名生成 C 桩 + 符号输入 → `clang -emit-llvm` | **你的主战场** |
| **S3 · 二进制提升** | 理论上通用 | mcsema / retDec / llvm-mctoll 把 ELF 抬成 LLVM IR | **4 小时硬上限，失败即放弃并记录** |

> ✅ **好消息**：`scripts/e2e/build_firmware.sh` 生成的合成固件**自带 C 源码**
> （`httpd.c` 的 `getenv("QUERY_STRING")` → `sprintf(buf,"%s; reboot",cmd)` → `system(buf)`）。
> **S1 路径对 L1 是必成的**，你 Day0 晚上就能拿到第一批真实符号执行结果。

> ⚠️ **S3 不要恋战**。二进制提升对 MIPS/ARM 支持很差，成功率和产物质量都不可靠。
> 4 小时拿不到可用 bitcode 就**立刻放弃**，把时间还给 S2。这是明智的止损，不是失败。

### 4.2 S2 harness 生成器设计（X1，你的核心工程）

**输入**（来自 candidate + 二进制信息）：

```python
@dataclass
class HarnessSpec:
    func_name: str            # e.g. "formexeCommand", "dangerous_func"
    sink_func: str            # "system" / "strcpy" / "sprintf"
    sink_type: str            # command_execution / memory_copy / format_output
    n_params: int             # 参数个数
    param_types: list[str]    # ["char*", "int", ...]
    buf_size: int | None      # 目标 buffer 大小（从反汇编的栈帧推断，可缺省）
    constraints: list[dict]   # 已知路径约束（来自 SaTC/BOND），可选
    vuln_class: str           # command_injection / overflow
```

**生成的 C 桩**（命令注入型示例）：

```c
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>

/* sink stub：不真的执行 shell，只标记"参数到达了 sink" */
static int g_reached_sink = 0;
static char g_sink_arg[512];

void __fsa_sink(const char *cmd) {
    g_reached_sink = 1;
    strncpy(g_sink_arg, cmd, sizeof(g_sink_arg) - 1);
    klee_assert(strlen(cmd) < sizeof(g_sink_arg));   /* 触发 ptr.err 的机会 */
}
#define system(x) __fsa_sink(x)      /* 把真实 sink 换成桩 */

/* 被审函数的桩实现（签名从二进制信息推断） */
void formexeCommand(char *cmd) {
    char buf[256];
    sprintf(buf, "%s; reboot", cmd);
    system(buf);
}

int main(void) {
    char input[64];
    klee_make_symbolic(input, sizeof(input), "input");
    /* 约束：模拟 HTTP 参数的可打印字符范围 */
    for (int i = 0; i < sizeof(input) - 1; i++)
        klee_assume(input[i] >= 0x20 && input[i] <= 0x7e);
    input[sizeof(input) - 1] = '\0';

    formexeCommand(input);

    /* 到达 sink 且参数中含符号字节 → 路径可达且可控 */
    klee_assert(!g_reached_sink || 1);
    return 0;
}
```

**溢出型**区别：把 buffer 大小设成从反汇编推断的值，让 `sprintf`/`strcpy` 真的越界 → 触发 `ptr.err`。

**判定逻辑**（写进 `prune.py`）：

| KLEE 结果 | `symex.reachable` | `symex.reason` | 动作 |
|---|---|---|---|
| 有路径走到 sink 桩且参数含符号字节 | `true` | `ok` | 写 evidence；`witness_input` = ktest 解压出的具体输入 |
| 触发 `ptr.err`（越界） | `true` | `ok` | **强证据**：可达 + 内存错误，升级候选 |
| 所有路径 UNSAT / 走不到 sink | `false` | `infeasible` | 写 counterevidence，Verifier 判 `false-positive` |
| 超时 | `null` | `timeout` | **不改分**，只记 limitation |
| 路径爆炸（fork 上限） | `null` | `path_explosion` | **不改分**，记 limitation |
| 架构/指令不支持 | `null` | `unsupported_arch` | 记 limitation |

### 4.3 ⚠ 误杀防护（X2，必须实现）

**KLEE 判 `infeasible` 只说明"在我的 harness 模型下不可达"，不等于"真实固件里不可达"**
（我的桩可能简化掉了真实的库函数调用、真实的全局变量状态）。

因此三条硬约束：

1. **只写 counterevidence，绝不删候选**。是否判 `false-positive` 交给 `Verifier`（10 问 + 12 硬规则）决定。
2. **`reason` 字段必须带上 harness 版本号**，报告里写明「该结论基于 harness v1 的建模假设」。
3. **剪枝率 > 70% 触发人工抽检 5 条**。抽检结果写进 `benchmarks/external/klee/comparison.md`。

```python
# prune.py
def prune(candidate, symex_result) -> dict:
    if symex_result["reachable"] is False and symex_result["reason"] == "infeasible":
        candidate["counterevidence"].append(
            f"klee:infeasible:harness_v{HARNESS_VERSION}:{symex_result['finding_id']}"
        )
        # 不直接改 conclusion_category，交给 Verifier
    if symex_result["reason"] in ("timeout", "path_explosion"):
        candidate["limitations"].append(f"klee:{symex_result['reason']}")
    return candidate
```

---

## 5. 逐日排期（8/30 13:00 起）

### 8/30（半天 + 晚上）—— 环境 + S1 打通

| 时间 | 任务 | 产出 |
|---|---|---|
| 13:00–14:00 | 读 `README.md` §3 共享契约 | — |
| 14:00–17:00 | 装环境：KLEE 3.2 Docker（或 LLVM 16 + clang + Z3 + wllvm + lit） | `klee --version` 能跑 |
| 17:00–19:00 | **S1 打通**：用 `scripts/e2e/build_firmware.sh` 的 `httpd.c` / `upnpd.c`，wllvm 编出 `.bc`，跑 `klee` | **第一批真实符号执行结果** |
| 19:00–21:00 | 跑通 `ktest-tool`；确认能拿到具体输入；确认 `system(buf)` 路径可达 | witness input 样例 |
| 21:00–24:00 | 试 S3（二进制提升），**计时 4 小时上限**；同时开始设计 `harness_gen.py` | S3 结论 + harness 设计 |
| 21:00 | 四人同步会 | — |

**今日硬产出**：`klee --version` 能跑；L1 合成固件的 `.bc` 跑出结果；`ktest-tool` 拿到具体输入。

> ⚠️ S3 试到 24:00 还没戏就放弃，**明天不要再碰**。

### 8/31 —— S2 harness + 全量复现

| 时间 | 任务 |
|---|---|
| 09:00–12:00 | 写 `harness_gen.py` v1：从 HarnessSpec 生成 C + 编译成 `.bc` |
| 12:00–14:00 | **用 L1 合成固件验证 harness 路径**（有 ground truth：已知 `system(buf)` 可达） |
| 14:00–19:00 | 对 **L2 DIR-859** 的 Top-10 候选全部生成 harness 并跑 KLEE |
| 19:00–22:00 | 对 **L3 两个固件**同样处理；记录耗时/路径数/状态数 |
| 22:00–23:00 | 原始 `klee-out-N/` 产物落盘 `fixtures/raw/` |

**今日硬产出**：`harness_gen.py` v1 可用；3 固件 × Top-10 候选的符号执行结果。

### 9/1 —— Parser + 单测日

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | 写 `runner.py`：wsl/local 后端，拼 klee 命令，硬超时（`--max-time`） |
| 11:00–15:00 | 写 `parser.py`：**7 类 `.err` + `.ktest` + `info` + `run.stats` + `warnings.txt`** |
| 15:00–18:00 | 写 `prune.py`（含误杀防护三条约束） |
| 18:00–20:00 | 单测：harness 生成器 + parser 六类分支 |
| 20:00–21:00 | `pytest --cov` ≥80% |

### 9/2 —— 接入 + 联调日（⚠ 18:00 熔断）

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | registry 声明；`run_external.py --tool klee` 跑通 |
| 11:00–13:00 | 与 E 对接 `finding_fusion`（你要的候选输入格式、你回写的 `symex` 字段） |
| 13:00–15:00 | `SYMEX_PRUNE` 阶段接入；`--depth full` 全链路跑通 |
| 15:00–17:00 | 8 种开关组合降级测试；**验证超时/路径爆炸不改分** |
| 17:00–18:00 | 把你的 `source/sink/call_trace` 输出格式交给 H（BOND 要用） |
| **18:00** | **熔断评审**：按 §2 三档给自己定档 |

### 9/3 —— 量化 + 文档日

| 时间 | 任务 |
|---|---|
| 09:00–13:00 | 剪枝实验：3 固件 × Top-10 候选，统计**剪枝率** |
| 13:00–15:00 | **人工抽检 5 条被剪候选**，确认无误杀（这是 F6 的硬要求） |
| 15:00–18:00 | 写 `benchmarks/external/klee/comparison.md` |
| 18:00–20:00 | 写 `skills/08-external-analyzers/klee/SKILL.md`（7 节 + 踩坑表 + harness 规则） |
| 20:00–21:00 | 更新 `docs/external_analyzers.md` 的 KLEE 部分 |

### 9/4 —— 冻结 + 演示日

- 代码冻结
- 演示素材：**"KLEE 证明了这 4 个候选根本走不通，给 BOND 省下 40 分钟"**
- 答辩 Q&A 预案（见 §9）

---

## 6. 代码骨架

### 6.1 文件清单（你负责）

```
tools/external/klee/__init__.py
tools/external/klee/runner.py          # KleeAnalyzer(ExternalAnalyzer)
tools/external/klee/parser.py          # klee-out-N/* → external_finding
tools/external/klee/harness_gen.py     # ★ X1：HarnessSpec → C → .bc
tools/external/klee/prune.py           # ★ X2：剪枝 + 误杀防护
tools/external/klee/templates/         # C 桩模板（cmdi / bof / fmt）
tools/external/klee/fixtures/raw/      # klee-out-N 产物
tools/registry/external.yaml           # klee 那几行
config/dev.yaml                        # external.klee 段
tests/unit/test_external_klee.py
tests/unit/test_harness_gen.py         # ★ harness 生成器单测
skills/08-external-analyzers/klee/SKILL.md
benchmarks/external/klee/{README.md,comparison.md,raw/}
docs/external/G-KLEE.md
```

### 6.2 parser.py 映射表

| KLEE 产出 | 内容 | 映射到 |
|---|---|---|
| `test*.ktest` | 具体输入（+ 到达的路径） | `symex.witness_input`；若走到 sink → `reachable=true` |
| `ptr.err` | 指针越界 | `vuln_class=overflow` 的**强证据**；`reachable=true` |
| `overflow.err` | 整数溢出 | 证据（记 `notes`） |
| `div.err` | 除零 | 证据（低优先级，记 `notes`） |
| `assert.err` | `klee_assert` 失败 | 取决于断言含义，记 `notes` |
| **`model.err`** | 内存模型限制 | ⚠️ **归 `limitation`，不是漏洞** |
| **`exec.err`** | 外部调用/不支持指令 | ⚠️ **归 `limitation`，不是漏洞** |
| `info` | 版本、参数、路径数 | `tool_version`、`notes` |
| `run.stats` | 指令数、状态数、内存峰值 | `duration_s`、`notes`（性能基线） |
| `warnings.txt` | 警告 | `limitation` |
| `klee-out-N/assembly.ll` | 具体出错位置 | `sink.addr` 辅助定位（需与 ELF 地址对齐，难，可留 TODO） |

### 6.3 `external_finding` 的 `symex` 字段（你专有）

```json
"symex": {
  "reachable": true,
  "reason": "ok",
  "witness_input": {"input": "AAAA...", "encoding": "printable-ascii"},
  "harness_version": "v1",
  "stats": {"instructions": 12345, "states": 42, "paths": 7}
}
```

**`harness_version` 必须写**——这是误杀防护可追溯的前提。

### 6.4 与 H 的接口（你在 9/2 17:00 前要给 H）

H 的 BOND 需要 `source / sink / call_trace` 三元组。你的输出**已经是这个格式**，
H 会优先消费**你判定 `reachable=true` 且带 `witness_input` 的候选**。
请把以下字段保证齐全：`source.type`、`source.name`、`sink.function`、`sink.addr`、`call_trace[]`、`constraints[]`（若有）。

---

## 7. 单测清单

### 7.1 harness 生成器（`test_harness_gen.py`）

| 用例 | 断言 |
|---|---|
| 命令注入型 HarnessSpec → C | 生成的代码含 `klee_make_symbolic`、`klee_assume` 可打印范围、sink 桩 |
| 溢出型 HarnessSpec → C | buffer 大小正确，能触发 `ptr.err` |
| 参数个数/类型不同 | 生成代码编译通过（`clang -emit-llvm` 无错） |
| 缺少 `buf_size` | 用默认大小，不崩 |
| 生成的 bitcode 真的能跑 | `klee --max-time=10s` 有输出（这个用例依赖 KLEE，**标记 `@pytest.mark.slow`，CI 里 skip**） |

### 7.2 parser（`test_external_klee.py`）

| 分支 | fixture | 断言 |
|---|---|---|
| 正常（走到 sink） | 真实 `klee-out-N/` | `reachable=true` + witness |
| 有 `ptr.err` | 真实产物 | `reachable=true` + `vuln_class=overflow` 证据 |
| **`model.err` / `exec.err`** | 手工造 | **归 `limitation`，不产生漏洞证据**（这是防误报的关键用例，必须写） |
| 空目录 | 手工造 | `findings=[]`，`status="ok"` |
| 畸形/截断文件 | 手工造 | 跳过 + 记 limitation |
| 超时（无完整结果） | 手工造 | `reason=timeout`，`reachable=null` |
| 路径爆炸 | 造 `run.stats` 显示 fork 上限 | `reason=path_explosion` |

**CI 约束**：除 `slow` 标记的用例外，**单测不调用真实 KLEE**。

---

## 8. Benchmark 方案

### 8.1 剪枝实验（3 固件 × Top-10 候选）

```
输入：finding_fusion 产出的 unified_candidates 的 Top-10
过程：每个候选生成 harness → klee --max-time=300s
统计：
  - 剪枝率 = 判 infeasible 的候选 / 送检候选
  - 平均单候选耗时
  - 路径爆炸 / 超时占比
  - 触发 ptr.err 的数量（意外收获：KLEE 直接证明内存错误）
```

### 8.2 人工抽检（F6 硬要求）

**剪枝率 > 70% 时**，从被剪候选中**随机抽 5 条**人工复核：
- 确认 harness 建模是否合理（有没有简化掉关键调用）
- 确认这条路径在真实固件里确实走不通
- 结果写进 `comparison.md`；若发现误杀，**立刻把该 harness 模板标为不可靠并调低其权重**

### 8.3 表格骨架

| 固件 | 送检候选 | infeasible | 可达+witness | 超时 | 路径爆炸 | 触发 ptr.err | 剪枝率 | 抽检结果 | 平均耗时 |
|---|---|---|---|---|---|---|---|---|---|
| L1 合成 | 10 | | | | | | | | |
| L2 DIR-859 | 10 | | | | | | | | |
| L3-a | 10 | | | | | | | | |
| L3-b | 10 | | | | | | | | |

---

## 9. 踩坑预案

| 坑 | 症状 | 处理 |
|---|---|---|
| **拿不到 bitcode** | MIPS/ARM 二进制无法提升 | S2 harness 是主方案；S3 超 4 小时放弃 |
| **uClibc 只完备支持 x86** | MIPS/ARM 的 libc 调用跑不了 | 用 harness 桩绕开 libc（sink 用自定义桩，不真调） |
| **路径爆炸** | 状态数飙升，几分钟出不来 | `--max-forks=64` + `--max-depth=200` + `--search=dfs`；超时即降级为 `path_explosion` |
| **外部函数无法符号化** | `exec.err` 满屏 | 全部写桩；`exec.err` 归 limitation 不算漏洞 |
| **KLEE 版本/LLVM 不匹配** | 装不上 | 优先用**官方 Docker 镜像**（已配好 LLVM 16 + Z3），别自己编译 LLVM |
| **`model.err` 被误当成漏洞** | 误报反而变多 | parser 里显式把 `model.err`/`exec.err` 路由到 `limitation`（单测覆盖） |
| harness 建模过度简化导致误杀 | 剪枝率异常高 | 抽检 + `harness_version` 可追溯 + 只写反证不删候选 |
| Windows 侧跑不了 | KLEE 无 Windows 支持 | 走 `wsl` 后端；或用 Docker Desktop |

---

## 10. 答辩 Q&A 预案

**Q：KLEE 要 LLVM bitcode，固件是二进制，你们怎么办？**
A：三条路，我们主推 **harness**。① 有源码的组件（合成固件的 httpd/upnpd、开源组件 Boa/goahead）走 `wllvm`，最干净；② 真实固件无源码，就把可疑函数抠出来写 C 桩编成 bitcode——这是我们的自研 `harness_gen.py`；③ 二进制提升（mcsema/retDec）对 MIPS/ARM 支持差，我们给了 4 小时验证，行不通就止损。**而且 KLEE 跑的是 bitcode 语义，天然跨架构，不需要 qemu 和真机。**

**Q：KLEE 判"不可达"，会不会把真漏洞误杀掉？**
A：这是我最担心的，所以做了三重防护：① 结论只写 `counterevidence`，**不直接删候选**，是否判误报交给 Verifier 的 10 问 + 12 硬规则；② `reachable=false` 必须带 `harness_version`，报告里写明「基于 harness 建模假设」；③ **剪枝率 >70% 触发人工抽检 5 条**。宁可少剪，不可错杀。

**Q：超时的候选怎么处理？**
A：**不改分**。超时和路径爆炸都只记 `limitation`，既不升也不降。只有明确的 `infeasible` 才写反证。

---

## 11. 每日 checklist

- [ ] 今天的 `klee-out-N/` 产物落盘了？
- [ ] 每个候选的耗时/路径数/状态数记了？（F9 性能基线）
- [ ] `model.err` / `exec.err` 有没有被误当成漏洞？（每天查一次）
- [ ] harness 版本号更新了吗？
- [ ] `enabled: false` 时主链还能跑？
- [ ] 有没有卡超过 4 小时没说？

---

*你是全组的省钱器。你每剪掉一个假候选，H 就多出十几分钟去打真目标。*
