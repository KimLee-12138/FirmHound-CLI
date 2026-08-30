# KLEE 外部分析器技能卡（G 同学 · 符号执行路径可行性剪枝）

> 位置：`tools/external/klee/`
> 角色：`SYMEX_PRUNE` 阶段。吃汇聚后的候选，回答"这条 source→sink 路径在约束上真的走不通吗"，
> 把判定为 `infeasible` 的候选剪掉，**只把剩下的送进 BOND**（H 的定向 fuzz 很贵）。
> 你是全组的省钱器：每剪一个假候选，H 就多十几分钟打真目标。

---

## 1. 一句话定位

KLEE 是动态符号执行引擎（v3.2，LLVM 16 + Z3）。它把输入符号化、沿路径收集约束、
交给 SMT 求解器判定路径可达性，可达时给出**具体输入（witness）**。它跑的是 LLVM
bitcode 语义，**天然跨架构**——不需要 qemu、不需要真机、不关心字节序。

## 2. 关键约束（必读）

- **只吃 LLVM bitcode（`.bc`）**，固件是 MIPS/ARM 二进制 → 必须拿到 bitcode。
- `model.err` / `exec.err` **不是漏洞**，必须归到 `limitation`（否则误报比没接还多）。
- `infeasible` 只说明"在我的 harness 模型下不可达"，**不等于真实固件不可达**。
- 超时 / 路径爆炸**不改分**，只记 `limitation`。

## 3. 三条 bitcode 策略（优先级从高到低）

| 路径 | 适用 | 做法 | 时间盒 |
|---|---|---|---|
| **S1 源码 wllvm** | 有源码的组件（合成固件 `httpd.c`/`upnpd.c`、开源 Boa/goahead） | `wllvm -O0 -g` → `extract-bc` | 必成 |
| **S2 harness 桩**（主推） | 真实固件无源码 | 从候选 sink 签名生成 C 桩 → `clang -emit-llvm` | 主战场 |
| **S3 二进制提升** | 理论上通用 | mcsema / retDec 抬成 LLVM IR | **4h 硬上限，失败即放弃并诚实归因** |

选择逻辑（`_select_strategy`）：`auto` 下候选带 `source_path` 走 S1，否则 S2；`mode=source`
无源码则降级 S2；`mode=binary` 走 S3（失败记 limitation，不编造 `.bc`）。

## 4. harness 生成规则（X1 · `harness_gen.py`）

`HarnessSpec`（来自候选 sink 签名）→ 渲染 C 桩 → 编成 `.bc`：

- **符号化输入**：`klee_make_symbolic(input, ...)` + `klee_assume` 约束为可打印范围（`0x20..0x7e`）。
- **sink 必须桩化**：`#define system(x) __fsa_sink(x)`，桩只记录"参数到达了 sink"，**绝不真调 shell**。
- **溢出型**：buffer 大小用反汇编推断的 `buf_size`（缺省 `DEFAULT_BUF_SIZE=256`），让 `strcpy` 真的越界 → 触发 `ptr.err`。
- **版本号**：`HARNESS_VERSION="v1"` 必须盖在每个 harness / finding 上，误杀防护可追溯的前提。
- 命令注入 / 溢出 / 格式串 三种模板见 `templates/{command_injection,overflow,format_string}.harness.c`。

## 5. 判定逻辑与 `symex` 字段（X2 · `prune.py`）

| KLEE 结果 | `symex.reachable` | `symex.reason` | 动作 |
|---|---|---|---|
| 走到 sink + witness | `true` | `ok` | 写 evidence；`witness_input` 给 BOND |
| `ptr.err` | `true` | `ok` | **强证据**：可达 + 内存错误，升级 `vuln_class=overflow` |
| 所有路径 UNSAT | `false` | `infeasible` | 写 **counterevidence**，交 Verifier 判 |
| 超时 | `null` | `timeout` | **不改分**，记 `limitation` |
| 路径爆炸 | `null` | `path_explosion` | **不改分**，记 `limitation` |
| `model.err`/`exec.err` | `null` | `unsupported_arch` | 记 `limitation`，非漏洞 |

**误杀防护三条硬约束**：
1. 只写 counterevidence，**绝不删候选**；是否判 `false-positive` 交给 Verifier。
2. `reason` 必须带 `harness_version`，报告写明"基于 harness v1 建模假设"。
3. **剪枝率 > 70% 触发人工抽检 5 条**（`needs_manual_audit` / `sample_for_audit`）。

## 6. 跑通命令

```bash
# 单工具
python -m tools.external.adapter run_klee <run_dir> --config-path config/dev.yaml

# 全链路（--depth full 下 SYMEX_PRUNE 自动路由到本工具）
python scripts/dev.py test        # 仅跑单测（不要加 WSL 解包集成测试）
pytest tests/unit/test_external_klee.py tests/unit/test_harness_gen.py tests/unit/test_external_klee_runner.py
```

产物：`<run_dir>/artifacts/external_findings/klee.json`（每个候选一条 `symex` 结论）。

## 7. 踩坑表

| 坑 | 症状 | 处理 |
|---|---|---|
| 拿不到 bitcode | MIPS/ARM 二进制无法提升 | S2 harness 主方案；S3 超 4h 放弃 |
| uClibc 只完备支持 x86 | MIPS/ARM 的 libc 调用跑不了 | sink 用自定义桩绕开 libc |
| 路径爆炸 | 状态数飙升 | `--max-forks=64 --max-depth=200 --search=dfs`；超时降级为 `path_explosion` |
| 外部函数无法符号化 | `exec.err` 满屏 | 全部写桩；`exec.err` 归 limitation |
| `model.err` 被误当漏洞 | 误报变多 | parser 显式把 `model.err`/`exec.err` 路由 limitation（单测覆盖） |
| harness 过度简化误杀 | 剪枝率异常高 | 抽检 + `harness_version` 可追溯 + 只写反证不删候选 |
| Windows 跑不了 | KLEE 无 Win 支持 | `backend=wsl` 或 Docker（`kleever/klee:llvm-16`） |
| 真实运行被环境挡 | Docker 文件共享坏 / 无 KLEE | 代码全落地 + 单测全绿；真实符号执行在 8/31 机器任务补 |

## 8. 交付档位（F1–F9 + X1/X2）

- **F1** 数据集全量：L1 合成 + L2 DIR-859 + L3 两固件都做过符号执行（真实运行待 8/31）。
- **F2** 模式全量：S1/S2 必须成功，S3 允许失败并诚实归因（代码已就绪）。
- **F3** Parser 全量：覆盖 `klee-out-N/` 全部产物（6 类 `.err` + `.ktest` + `info` + `run.stats` + `warnings.txt` + `.path`），单测每类有 fixture。
- **F4** 单测全量：harness 生成器单测 + parser 六类分支，覆盖率 ≥80%（当前 23 用例绿）。
- **F5** 接入全量：registry 已声明 + `run_external.py --tool klee` 可跑 + `SYMEX_PRUNE` 路由已通。
- **F6** Benchmark 全量：`benchmarks/external/klee/comparison.md`（剪枝率 + 5 条抽检，待真实运行填）。
- **F7** 降级完备：缺失主链不变；超时/路径爆炸不改分；8 开关组合不 abort（单测覆盖）。
- **F8** 文档全量：本 SKILL.md（7 节 + 踩坑 + harness 规则）。
- **F9** 性能基线：`run.stats` → `symex.stats`（instructions/states/paths/time），待真实运行填表。
- **X1** `harness_gen.py`：纯自研，HarnessSpec→C→`.bc`。
- **X2** `prune.py`：误杀防护（counterevidence 不删 + 70% 抽检）。
