# 外部 工具组 · 四人协同总纲与共享契约

> 本目录是**四人并行作战的共享底座**。个人计划见 `E-SaTC.md` / `F-FirmRec.md` / `G-KLEE.md` / `H-BOND.md`。  
> 上层设计总纲见仓库根目录 `第一队_外部分析工具集成_下一步开发计划.md`。
>
> **基调：目标不是"跑通 demo"，是全量完成。** 每人的验收标准分三档，全量档是必须冲的目标，  
> 「部分」是如实标注的中间态，「兜底」是熔断底线。9/2 18:00 熔断评审时，  
> 我们要能明确回答"这四个工具各自做到了哪一档"，而不是"都跑通了 demo"。

---

## 1. 四人分工

| 编号    | 工具          | 论文            | 在链条中的位置             | 优先级    | 是否进主链       |
| ----- | ----------- | ------------- | ------------------- | ------ | ----------- |
| **E** | **SaTC**    | USENIX Sec'21 | 污点报告源头，**阻塞 G 和 H** | **P0** | 是           |
| **F** | **FirmRec** | CCS'24        | 旁路：复发变体检测           | P1     | **否**（独立旁路） |
| **G** | **KLEE**    | OSDI'08（v3.2） | 路径可行性剪枝，BOND 的省钱器   | **P0** | 是           |
| **H** | **BOND**    | USENIX Sec'26 | 定向验证，把候选变成证据        | P1     | 是（受限）       |

**E 兼任外部工具组组长**：负责 §3 共享契约的落地、四人联调、与原第一队的接口。

### 1.1 前提说明：主线谁做？

本配置假定**外部工具组 4 人（E/F/G/H）+ 原第一队 4 人（A/B/C/D）**&#x5171; 8 人，主线由 A/B/C/D 继续推进。

**如果全队总共只有 4 人**（即 E/F/G/H 就是全部人力），主线必须压缩并由四人分摊兜底。  
按下表认领，**每人在工具任务之外额外背一块主线**：

| 主线兜底项                            | 认领人 | 说明                  |
| -------------------------------- | --- | ------------------- |
| v1.0 冻结 + `pytest tests/unit` 全绿 | G   | 与 KLEE 单测同一天做，顺路    |
| 全量 Benchmark 跑批 + 性能表            | E   | E 本来就要跑对照实验，合并      |
| 报告渲染（第 21 节外部交叉验证）               | F   | F 的旁路本来就要写报告章节，顺手合流 |
| 文档 + 部署 + 演示素材                   | H   | H 的 PoC 演示本来就是素材    |

> 此情况下 **FirmRec 优先级降到最低**：只做"环境跑通 + Skill 文档 + 接口预留"，  
> F 把主要精力放在主线兜底上。

---

## 2. 验证固件：三层数据集（四人统一，结果才可比）

> 已确认仓库现状：`firmware_samples/DIR859_FW102b03.bin`（真实 D-Link DIR-859，9.3MB）已存在，  
> 且已解包至 `tmp/unpacked/_DIR859_FW102b03.bin.extracted/squashfs-root`。  
> `scripts/e2e/build_firmware.sh` 可生成**带 C 源码**的合成固件（含植入的命令注入漏洞）。

| 层               | 固件                                                                                        | 用途                                             | 负责人                                                       |
| --------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------- | --------------------------------------------------------- |
| **L1 合成固件**     | `scripts/e2e/build_firmware.sh` 生成（输出到 `/mnt/c/temp/fw_demo`，**自带 httpd.c / upnpd.c 源码**） | **Parser 正确性验证 + 回归测试 + KLEE 源码路径**；可控、快、有确定答案 | 四人共用，**G 尤其依赖**（有源码 = 能 wllvm 编 bitcode，绕开最难的 bitcode 提升） |
| **L2 真实固件 A**   | `firmware_samples/DIR859_FW102b03.bin`（已解包）                                               | 真实验证主力，**今天就能开跑，不用等下载**                        | 四人共用                                                      |
| **L3 真实固件 B/C** | 需下载 2 个（建议 Tenda AC15、Netgear R7000 或 TP-Link 同类型）                                        | 跨厂商泛化验证                                        | **E 在 8/30 下午统一负责下载并分发**，G/H 不要各自下                        |

**硬性要求**：四人对**同一批固件**跑，所有耗时/命中率数据才可比。L3 由 E 统一下载后放 `firmware_samples/`，并在 `docs/external/dataset.md` 记录来源 URL、SHA256、大小、架构。

**L1 合成固件的确定答案**（`scripts/e2e/build_firmware.sh` 内已写明，G/H 可直接用作 ground truth）：

- `bin/httpd`：`getenv("QUERY_STRING")` → `sprintf(buf, "%s; reboot", cmd)` → `system(buf)` → **命令注入**
- `bin/upnpd`：`snprintf(cmd, "upg -g -U %s -r %s", url, url)` → `system` → **命令注入（HG532e 型）**

---

## 3. 共享契约（8/30 下午必须冻结，此后任何人不得单方面修改）

### 3.1 统一输出格式：`schemas/external_finding.schema.json`

权威定义在根目录计划的 §4.1。**E 在 8/30 下午落地此文件**，四人的 `parser.py` 全部以它为准。

最小必填字段：

```json
{
  "finding_id":    "{tool}-{binary}-{addr}",
  "tool":          "satc | firmrec | klee | bond",
  "tool_version":  "string",
  "run_id":        "string",
  "binary_id":     "相对 rootfs 路径，必须与 candidate.binary_id 对齐",
  "vuln_class":    "command_injection | overflow | path_traversal | auth_bypass | config_injection | format_string | other",
  "source":        {"type": "...", "name": "...", "evidence": "..."},
  "sink":          {"function": "...", "addr": "0x...", "type": "..."},
  "call_trace":    [{"addr": "0x...", "func": "...", "note": "..."}],
  "confidence":    0.0,
  "status":        "ok | skipped | failed | timeout | unsafe",
  "run_id":        "..."
}
```

工具专有字段：`constraints[]`（H）、`symex{}`（G）、`validation{}`（H）。

> `binary_id` 必须与 `candidate.binary_id` 用**同一套相对路径规则**，否则汇聚层 join 不上。  
> 这是四人最容易各自跑偏的地方，E 在 Day0 必须写一个共享工具函数  
> `tools/external/base.py::normalize_binary_id(rootfs: Path, path: Path) -> str` 供四人调用。

### 3.2 Adapter 抽象：`tools/external/base.py`

```python
class ExternalAnalyzer(ABC):
    name: str
    def probe(self) -> ProbeResult: ...      # 不许抛异常
    def prepare(self, ctx: AnalysisContext) -> Path: ...
    def run(self, ctx: AnalysisContext) -> RunOutcome: ...
    def parse(self, ctx, outcome) -> list[dict]: ...
    def normalize(self, findings) -> list[dict]: ...
    def execute(self, ctx) -> dict: ...      # 流水线唯一入口，内部兜住所有异常
```

完整代码骨架见根目录计划 §4.2。**E 在 8/30 下午落地 `base.py` + `backends.py`**，四人各自只写子类。

执行后端三选一：`local`（纯 Linux）/ `wsl`（复用 `tools/wsl_wrappers/to_wsl_path()`）/ `docker`（SaTC、FirmRec）。

### 3.3 三人必须遵守的四条铁律

1. **不许在主链里 import 外部工具**。只通过 `ToolRegistry.call()` 与 `execute()` 调用。
2. **`probe()` 绝不许抛异常**。抛异常 = 拖死整条流水线。所有异常在 `execute()` 里兜住。
3. **每个 parser 必须配 fixture 单测**，fixture 来自真实输出（脱敏后存 `tools/external/<tool>/fixtures/`）。**CI 永远不许依赖真实工具**。
4. **工作目录锁死 `./tmp/external/<tool>/<run_id>/`**（`./tmp` 已在 `config/safety.yaml` 白名单内）。

---

## 4. 全量交付标准（分三档）

> **全量是目标。没做到全量要如实标注做到哪一档，不许含糊其辞说"跑通了"。**

### 全量档（Full）——四人的共同目标

| #  | 项            | 判定                                                                                                 |
| -- | ------------ | -------------------------------------------------------------------------------------------------- |
| F1 | 数据集全量        | L1 + L2 + L3 三层固件**全部跑完**，不是只跑官方样例                                                                 |
| F2 | 工具配置全量       | 工具提供的**所有主要分析模式**都跑过（如 SaTC 的 4 种 Ghidra 脚本、KLEE 的 3 种 bitcode 路径、BOND 的 Plan A + Plan B）          |
| F3 | Parser 全量    | 覆盖工具**全部输出文件类型**（含中间产物），不是只解析最终告警                                                                  |
| F4 | 单测全量         | 覆盖正常/空/畸形/超时/版本差异五类分支，覆盖率 ≥80%                                                                     |
| F5 | 接入全量         | `tools/registry/external.yaml` 注册 + `scripts/run_external.py --tool X` 可独立跑 + `--depth full` 全链路跑通 |
| F6 | Benchmark 全量 | 3 固件 × (开/关该工具) 的完整对比数据                                                                            |
| F7 | 降级完备         | 该工具缺失时主链行为与缺失前**完全一致**，8 种开关组合不 abort                                                              |
| F8 | 文档全量         | Skill 文档含：目标/输入/输出/执行流程/失败降级路径/验收标准/踩坑表                                                            |
| F9 | 性能基线         | 单固件耗时、内存峰值、产物体积、并发能力，全部记录                                                                          |

### 部分档（Partial）——可以接受，但必须写明缺什么

- 只跑通 L1+L2，L3 没跑；或只跑了部分分析模式；或 parser 只覆盖最终告警不含中间产物；或单测只覆盖正常路径。

### 兜底档（Fallback）——熔断底线

- 只有：复现报告（版本/commit/镜像 tag/踩坑/耗时）+ Skill 文档 + adapter 空壳（有 `probe()` 返回 `available=False`）+ fixture 单测。
- **兜底档不是失败**，它证明了"接口已经预留，装上就能用"。但四人都不许把兜底当目标。

---

## 5. 逐日节奏（8/30 13:00 起 → 9/4）

| 日               | 主题          | 四人的硬产出（当天必须交）                                                                                      | 里程碑              |
| --------------- | ----------- | -------------------------------------------------------------------------------------------------- | ---------------- |
| **8/30**（半天+晚上） | 契约 + 环境     | E：契约三件套（`schema` + `base.py` + `backends.py`）+ 下载 L3 固件  
F/G/H：环境就绪 + **各自工具在 L1 合成固件上跑出第一批真实产物** | **契约冻结**         |
| **8/31**        | 全量复现        | 四人在 **L1 + L2 + L3 全部跑完**全部分析模式，原始产物落盘 `fixtures/raw/`                                             | **数据集全量跑完**      |
| **9/1**         | Parser + 单测 | 四人 parser 覆盖全部输出类型 + 单测覆盖五类分支 + `normalize()` 过 Schema                                             | **单测全绿**         |
| **9/2**         | 接入 + 联调     | 四人 runner 接入 registry + `--depth full` 全链路跑通 + 8 种开关组合不 abort                                      | **⚠ 18:00 熔断评审** |
| **9/3**         | 量化 + 文档     | 四人各自 Benchmark 对比表 + Skill 文档 + 性能基线表                                                              | **数据出齐**         |
| **9/4**         | 冻结 + 演示     | 代码冻结；演示素材（**"外部工具找出主轨没找到的东西"**）；答辩 Q\&A 预案                                                         | **交付**           |

### 每日同步（强制）

**每天 21:00**，四人各报三件事：今天跑完了什么 / 卡在哪 / 明天要什么资源。  
**单人卡超过 4 小时必须立刻在群里说**，不许自己硬扛到熔断评审。

---

## 6. 熔断机制（9/2 18:00）

评审标准：**按 §4 的三档给每人定档，不是"过/不过"。**

若某人处于"兜底档"，则：

- 该工具的 `enabled` 保持 `false`，不进流水线
- 该人**转去支援 P0 的同学**（优先支援 E，其次 G），或做主线兜底（见 §1.1）
- 交付物仍然是：复现报告 + Skill 文档 + adapter 空壳 + fixture 单测

**熔断不是失败。** 老师在意的不是我们四天半能不能把四篇顶会全部复现出来，  
而是这套系统有没有能力把外部工具以统一方式接进来。接口做扎实、降级做干净，本身就是核心交付。

---

## 7. 文件改动边界（避免 git 冲突）

| 文件/目录                                                             | 归属                     | 其他人需要改时  |
| ----------------------------------------------------------------- | ---------------------- | -------- |
| `schemas/external_finding.schema.json`、`schemas/examples/`        | **E**                  | 提 PR 给 E |
| `tools/external/base.py`、`backends.py`、`run_all.py`、`__init__.py` | **E**                  | 提 PR 给 E |
| `tools/external/satc/`                                            | E                      | —        |
| `tools/external/firmrec/`                                         | F                      | —        |
| `tools/external/klee/`                                            | G                      | —        |
| `tools/external/bond/`                                            | H                      | —        |
| `tools/analysis/finding_fusion.py`                                | **E 写骨架，G/H 提需求**      | 提 PR 给 E |
| `tools/registry/external.yaml`                                    | **各自写自己那几行**（文件级冲突风险低） | 冲突找 E    |
| `fsa/orchestrator/engine.py`、`planner.py`                         | **E**（统一改，避免四人改崩状态机）   | 提 PR 给 E |
| `config/dev.yaml` 的 `external:` 段                                 | **各自写自己那段**            | 冲突找 E    |
| `skills/08-external-analyzers/`                                   | 各自写自己的子目录              | —        |
| `benchmarks/external/<tool>/`                                     | 各自写自己的目录               | —        |
| `tests/unit/test_external_<tool>.py`                              | 各自写自己的文件               | —        |
| `docs/external/`                                                  | 各自写自己的文件               | —        |

---

## 8. 四人公共 checklist（每天自检）

- [ ] 今天的产物落盘了吗？（原始产物 → `fixtures/raw/`，解析结果 → `runs/`）
- [ ] 耗时记录了吗？（`docs/external/dataset.md` 或各自的 `benchmarks/external/<tool>/README.md`）
- [ ] 踩过的坑写进 Skill 文档了吗？（**不写等于白踩**）
- [ ] 我的工具在缺失时主链还能跑吗？（每天至少验一次 `enabled: false`）
- [ ] 我有没有卡超过 4 小时没说？

---

## 9. 安全红线（四人共同遵守，违反即打回）

1. **禁止真实设备 / 公网 / 未授权目标**。BOND 的 `target` 只允许 `emulation`，IP 必须私有网段，代码层硬断言。
2. **禁止用 `curl` / `wget` 调模型**（`config/safety.yaml` 已拉黑）。统一走 `fsa/runtime/openai_compatible.py`。
3. **FirmRec 在 Blind Run 中强制禁用**（代码断言，不靠人记），产出不进 `unified_candidates`。
4. **PoC 必须过脱敏且 `poc_sanitized == true` 才许落盘/进报告**。
5. 外部工具工作目录锁在 `./tmp/external/<tool>/<run_id>/`。

---

*四人并行，契约先行，全量交付，降级干净。*
