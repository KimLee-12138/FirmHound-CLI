# E 同学 · SaTC 全量复现与集成计划

> **你的任务**：把 SaTC（USENIX Sec'21）从"能跑"做到"全量接入流水线的污点分析引擎"，
> 并作为外部工具组组长，冻结并维护四人共享契约。
>
> **基调：不是跑通 demo，是全量完成。** 你的验收标准见 §2 全量档 9 条，
> 逐条对照打勾，没做到的如实标注。
>
> **你为什么最关键**：SaTC 是整条链的**源头**。G（KLEE）要拿你的 `call_trace` 做路径剪枝，
> H（BOND）要拿你的 `source/sink/call_trace` 当 fuzz 输入。**你晚一天，G 和 H 就晚一天。**

---

## 1. 三句话讲清 SaTC

- **它解决什么**：固件 Web 前端（html/js/cgi 里的参数名）和后端二进制（httpd 里引用的字符串）用的是**同一批"共享关键字"**。SaTC 用这批关键字定位后端入口，再用 Ghidra 找 sink、用 angr 做污点分析。
- **它补我们什么**：我们现在判断命令注入靠 `imports ∩ {system,sprintf}` 的**同文件共现**，根本没有跨函数数据流。SaTC 给的是真正的 `source → ... → sink` 路径。
- **它在链条哪**：`EXTERNAL_ANALYSIS` 阶段，与 FirmRec 并行跑，产出进 `finding_fusion` 汇聚层。

---

## 2. 交付标准（三档）

### 全量档（Full）—— 你的目标，逐条打勾

| # | 项 | 具体判定 |
|---|---|---|
| **F1** 数据集全量 | L1 合成固件 + L2 `DIR859_FW102b03.bin` + L3 两个真实固件，**三个都跑完** | 3 份 `external_findings.json`，每个非空 |
| **F2** 分析模式全量 | SaTC 的 **4 种 Ghidra 脚本配置全跑**：`ref2sink_cmdi` / `ref2sink_bof` / `ref2share`+`share2sink` / `all`。且**每种都跑过带 `--taint_check` 与不带两遍** | 每固件 ≥4 组产物 |
| **F3** Parser 全量 | 覆盖 **11 类输出文件**（见 §5.3 全清单），不是只解析 `result-*.txt` | 单测对每类都有 fixture |
| **F4** 单测全量 | 覆盖正常 / 空文件 / 畸形行 / 无告警 / 超时截断 / 版本差异 六类分支，覆盖率 ≥80% | `pytest --cov` 报告 |
| **F5** 接入全量 | `tools/registry/external.yaml` 注册 + `scripts/run_external.py --tool satc` 可独立跑 + `--depth full` 全链路跑通 | 三条命令都通 |
| **F6** Benchmark 全量 | 3 固件 × (开/关 SaTC) 的 Top-1/3/5、误报数、耗时完整对比 | `benchmarks/external/satc/comparison.md` |
| **F7** 降级完备 | SaTC 缺失时主链行为与缺失前完全一致；8 种开关组合不 abort | 8/8 通过 |
| **F8** 文档全量 | `skills/08-external-analyzers/satc/SKILL.md` 含 7 节 + 踩坑表 | 文档齐 |
| **F9** 性能基线 | 每固件的耗时、内存峰值、产物体积、可并发数 | 基线表 |

### 额外加分项（做完上面 9 条再做）

- **A1 反哺攻击面**：把 `Clustering_result_v2.result` 的"前端关键字 ↔ 后端二进制"映射，
  写回 `tools/web/handler_extract.py`，补上我们现在最缺的一环（哪个参数由哪个 handler 处理）。
- **A2 复用 Ghidra**：SaTC 自带 Ghidra 管线，与 `skills/03-binary-decompile` 的降级路径合并，避免同一固件跑两次 Ghidra（省 30–60 分钟/固件）。

### 部分档 / 兜底档

- **部分**：只跑通 L1+L2；或只跑 `ref2sink_cmdi` 一种脚本；或 parser 只覆盖 `result-*.txt`。**必须写明缺什么**。
- **兜底**：只有复现报告 + Skill 文档 + adapter 空壳（`probe()` 返回 `available=False`）+ fixture 单测。

---

## 3. 工具档案（已查证，不用再查）

| 项 | 内容 |
|---|---|
| 全称 | Shared-keywords aware Taint Checking |
| 论文 | USENIX Security 2021，《Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems》 |
| 仓库 | `github.com/NSSL-SJTU/SaTC` |
| 镜像 | `docker pull smile0304/satc`（或 `cd SaTC && docker build . -t satc`） |
| 依赖 | Docker、Ghidra（需 JDK 11+）、angr |
| 输入 | **已解包的固件根目录**（正好吃我们 `UNPACK` 阶段的产物） |
| 时间量级 | 单固件单脚本 30–90 分钟；带 `--taint_check` 显著变慢；Ghidra 内存峰值大（建议 ≥16G，最好 32G） |

### 命令全貌

```bash
python satc.py \
  -d /root/path/_ac18.extracted \
  -o /root/output \
  --ghidra_script {ref2sink_cmdi | ref2sink_bof | share2sink | ref2share | all} \
  --ref2share_result /root/path/ref2share_result   # 仅 share2sink 需要
  --save_ghidra_project                            # 可选，会很大
  --taint_check                                    # 启用 angr 污点引擎
  -b /var/ac18/bin/httpd | -b httpd                # 指定边界二进制
  -l 3                                             # 不指定 -b 时，取 Top-N 边界二进制
```

**四种 Ghidra 脚本的区别（全量必须都跑）**：

| 脚本 | 作用 | 产出 |
|---|---|---|
| `ref2sink_cmdi` | 从共享关键字的引用出发，找**命令注入**类 sink 的路径 | `<bin>_ref2sink_cmdi.result` + `.result-alter2` |
| `ref2sink_bof` | 同上，找**缓冲区溢出**类 sink | `<bin>_ref2sink_bof.result` |
| `ref2share` | 找共享数据**写入**函数的参数（如 `nvram_set`、`setenv`） | 供 `share2sink` 用 |
| `share2sink` | 找共享数据**读取**函数（如 `nvram_get`、`getenv`）→ sink | 需 `--ref2share_result` |
| `all` | 同时跑 cmdi + bof + ref2share | 三份产出 |

> **关键**：`ref2share` + `share2sink` 这条链路是我们主轨**完全没有**的能力——
> 它覆盖"数据先写进 nvram/env，再被另一个进程读出并送进 sink"的**跨进程污点**。
> 这是 SaTC 相对我们规则库最大的增量，**全量必须跑**。

---

## 4. 验证固件

见 `docs/external/README.md` §2。你额外负责：

- [ ] **8/30 下午统一下载 L3 的两个真实固件**，放 `firmware_samples/`
  - 建议：Tenda AC15（命令注入，与主轨 `04-audit/command-injection` 的复现经验直接对照）、Netgear R7000 或 TP-Link 同类
  - 下载后记录：来源 URL、SHA256、大小、架构 → `docs/external/dataset.md`
- [ ] L1 合成固件：`bash scripts/e2e/build_firmware.sh`（WSL 内跑，输出到 `/mnt/c/temp/fw_demo`）

---

## 5. 逐日排期（8/30 13:00 起）

### 8/30（今天，半天 + 晚上）—— 契约日 + 环境起步

| 时间 | 任务 | 产出 |
|---|---|---|
| 13:00–14:00 | **冻结 §5.1 三个契约文件**（这是四人并行的地基，最高优先级） | `schemas/external_finding.schema.json`、`schemas/examples/external_finding.example.json` |
| 14:00–16:00 | 落地 `tools/external/base.py`（`ExternalAnalyzer` ABC + `AnalysisContext` + `ProbeResult` + `RunOutcome`）+ `backends.py`（local/wsl/docker）+ `__init__.py` | 可 import，四人可继承 |
| 14:00–16:00 **并行** | `docker pull smile0304/satc`（后台跑） | 镜像就位 |
| 16:00–17:00 | 建 `tools/registry/external.yaml` 骨架 + `config/dev.yaml` 的 `external:` 段（全关） | 配置就位 |
| 17:00–18:00 | **下载 L3 真实固件** + 建 `docs/external/dataset.md` | 数据集就位 |
| 18:00–19:00 | 建 `tools/external/base.py::normalize_binary_id(rootfs, path)` 共享函数（四人共用，防 binary_id 跑偏） | 工具函数 |
| 19:00–21:00 | **L1 合成固件跑第一遍**：`--ghidra_script ref2sink_cmdi --taint_check -b httpd` | 第一批真实产物 |
| 21:00–24:00 | L1 跑 `ref2sink_bof`、`ref2share`；**后台并发**开跑 L2（DIR-859） | 产物积累 |
| 21:00 | **四人同步会**（你主持） | 契约确认 |

**今日硬产出**：契约三件套合入 + L1 至少两种脚本的产物 + L3 固件下载完成。

> ⚠️ **今晚不要睡太早**。L2/L3 单次运行 30–90 分钟，靠晚上批量挂后台跑，
> 明天早上才有全量数据。跑之前确认机器内存 ≥16G，否则 Ghidra 会 OOM。

### 8/31 —— 全量复现日（目标：三层固件 × 四种配置全部跑完）

> 这一天的核心是**压满机器并行度**。别串行跑，那要 10+ 小时。

| 时间 | 任务 |
|---|---|
| 09:00–09:30 | 收昨晚后台任务；检查 L2 是否 OOM；记录耗时 |
| 09:30–12:00 | **并发开 3–4 个 Docker 容器**跑 L2（DIR-859）的 4 种配置。注意：`-b` 不同二进制要分开跑 |
| 12:00–13:00 | 检查产物完整性；失败的立刻重跑（换 `--taint_check` 关掉试试） |
| 13:00–18:00 | L3 两个真实固件，同样 4 种配置并发跑 |
| 18:00–20:00 | **补齐缺口**：哪个固件哪种配置没跑成就补；跑不动的**记录 limitation 而不是硬扛** |
| 20:00–22:00 | 所有原始产物脱敏后落盘 `tools/external/satc/fixtures/raw/`；建 `benchmarks/external/satc/README.md` 记版本/commit/镜像 tag/耗时 |
| 21:00 | 同步会 |

**今日硬产出**：`fixtures/raw/` 下有 **3 固件 × 4 配置** 的完整产物树；耗时基线表。

**并发注意事项**：
- 每个 SaTC 容器建议限制 `--memory=16g`，避免 Ghidra OOM 拖垮宿主机
- 容器间用不同 `-o` 输出目录，避免写冲突
- 记下"几并发时开始变慢"，这是 F9 性能基线的一部分

### 9/1 —— Parser + 单测日

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | 写 `runner.py`：docker 后端，mount `tmp/external/satc/<run_id>`，拼命令，硬超时 |
| 11:00–15:00 | 写 `parser.py`，**覆盖 §5.3 全部 11 类文件** |
| 15:00–18:00 | 写 `tests/unit/test_external_satc.py`，六类分支全覆盖 |
| 18:00–20:00 | `normalize()` 过 Schema 校验；写 `fixtures/` 的样例文件 |
| 20:00–21:00 | 跑 `pytest tests/unit --cov=tools.external.satc` ≥80% |

### 9/2 —— 接入 + 联调日（⚠ 18:00 熔断）

| 时间 | 任务 |
|---|---|
| 09:00–11:00 | 写 `tools/external/satc/` 的 registry 声明；`scripts/run_external.py --tool satc` 跑通 |
| 11:00–13:00 | 改 `fsa/orchestrator/engine.py`（Stage 枚举 + TRANSITIONS）与 `planner.py`（4 个新阶段，`required=False`） |
| 13:00–15:00 | **写 `tools/analysis/finding_fusion.py` 骨架**（去重 + 交叉验证矩阵 + 证据合并），收 G/H 的需求 |
| 15:00–17:00 | fixture 回归链 `python scripts/run_pipeline.py --benchmark-fixtures --depth full --out-dir runs/ext_full` 跑通；真实输入使用 `fsa analyze` |
| 17:00–18:00 | **8 种开关组合降级测试**（全关/逐个开/全开），确认不 abort |
| **18:00** | **熔断评审**：按 §2 三档给自己定档 |

### 9/3 —— 量化 + 文档日

| 时间 | 任务 |
|---|---|
| 09:00–14:00 | 3 固件 × (开/关 SaTC) 对照实验，出 `benchmarks/external/satc/comparison.md` |
| 14:00–17:00 | 写 `skills/08-external-analyzers/satc/SKILL.md`（7 节 + 踩坑表） |
| 17:00–19:00 | 写 `docs/external_analyzers.md` 中 SaTC 部分；更新 README |
| 19:00–21:00 | **做加分项 A1（反哺 `handler_extract.py`）** —— 只有前面的全做完了才做 |

### 9/4 —— 冻结 + 演示日

- 代码冻结；此后只修 bug
- 出演示素材：**"SaTC 找到了主轨没找到的东西"** 的完整 run（这是最有说服力的 3 分钟）
- 答辩 Q&A 预案（见 §9）

---

## 6. 代码骨架

### 6.1 文件清单（你负责）

```
tools/external/base.py                  # ExternalAnalyzer ABC（你写，四人继承）
tools/external/backends.py              # local / wsl / docker 后端（你写）
tools/external/run_all.py               # EXTERNAL_ANALYSIS 阶段并行调度（你写）
tools/external/satc/__init__.py
tools/external/satc/runner.py           # SatcAnalyzer(ExternalAnalyzer)
tools/external/satc/parser.py           # 11 类输出 → external_finding
tools/external/satc/fixtures/raw/       # 真实原始产物（脱敏）
tools/external/satc/fixtures/*.json     # 单测 fixture
tools/registry/external.yaml            # satc 那几行
tests/unit/test_external_satc.py
tests/unit/test_external_base.py        # base.py 本身的单测
skills/08-external-analyzers/satc/SKILL.md
benchmarks/external/satc/{README.md,comparison.md,raw/}
docs/external/E-SaTC.md                 # 本文件
```

### 6.2 runner.py 要点

```python
class SatcAnalyzer(ExternalAnalyzer):
    name = "satc"

    def probe(self) -> ProbeResult:
        # docker image inspect smile0304/satc
        # 检查 ghidra 是否在镜像内、JDK 版本、angr 版本
        # 任何失败 → available=False + missing 列表。绝不抛异常。

    def prepare(self, ctx: AnalysisContext) -> Path:
        workdir = ctx.workdir                      # tmp/external/satc/<run_id>
        # 1) 把 rootfs 软链/复制到 workdir/rootfs（不要移动原文件）
        # 2) 从 ctx.attack_surface 挑 Top-N 边界二进制 → 决定 -b 还是 -l
        # 3) 生成 experiment 清单，供 run() 循环

    def run(self, ctx) -> RunOutcome:
        # 对每种 ghidra_script 配置起一次容器
        # docker run --rm --memory=16g \
        #   -v <to_wsl_path(workdir)>:/work \
        #   smile0304/satc python satc.py -d /work/rootfs -o /work/out/... \
        #   --ghidra_script X --taint_check -b <bin>
        # 硬超时 ctx.timeout_s；超时返回 status="timeout"

    def parse(self, ctx, outcome) -> list[dict]:
        # 见 §5.3 映射表
```

> **安全约束**：`docker run` 的 `-v` 挂载路径必须落在 `./tmp/external/satc/<run_id>/` 内
> （`./tmp` 在 `config/safety.yaml` 白名单）。Windows 路径走 `to_wsl_path()` 翻译。

### 6.3 Parser 映射表（11 类输出文件 → external_finding）

| # | SaTC 输出文件 | 解析出什么 | 映射到 |
|---|---|---|---|
| 1 | `keyword_extract_result/simple/API_simple.result` | 前端 API 名列表 | `entry_point.params[]` |
| 2 | `keyword_extract_result/simple/Prar_simple.result` | 前端参数名列表 | `source.name` 候选 |
| 3 | `keyword_extract_result/detail/API_detail.result` | API 名 + 出现文件/行 | `entry_point` 细化 + `evidence` |
| 4 | `keyword_extract_result/detail/Prar_detail.result` | 参数名 + 出现文件/行 | `source.evidence` |
| 5 | `keyword_extract_result/detail/api_split.result` | 复合关键字拆分 | 参数名清洗 |
| 6 | **`keyword_extract_result/detail/Clustering_result_v2.result`** | **关键字 ↔ 后端二进制的匹配**（最有价值） | `entry_point.params` + `binary_id` 归属 + **A1 反哺攻击面** |
| 7 | `keyword_extract_result/detail/File_detail.result` | 前端文件清单 | `evidence` |
| 8 | `keyword_extract_result/detail/from_bin_add_para.result` | 从二进制补充的参数 | `source.name` 扩充 |
| 9 | `keyword_extract_result/detail/Not_Analysise_JS_File.result` | 未分析的 JS | 记 `limitation` |
| 10 | `ghidra_extract_result/<bin>/<bin>_ref2sink_cmdi.result`（含 `-alter2`） | 命令注入 sink + 路径 | `sink` + `call_trace`，`vuln_class=command_injection` |
| 11 | `ghidra_extract_result/<bin>/<bin>_ref2sink_bof.result` | 溢出 sink + 路径 | `sink` + `call_trace`，`vuln_class=overflow` |
| 12 | `result-<bin>-<script>-<rand>.txt` | 最终告警 + **Alert Address** | `sink.addr`（主键）、`confidence` |

**confidence 计算建议**（要能解释，别拍脑袋）：

```
confidence = 0.3                                  # 基线：关键字命中
           + 0.25 if 有 Alert Address
           + 0.20 if 跑过 --taint_check
           + 0.15 if call_trace 长度 ≥ 2
           + 0.10 if 关键字在 Clustering_result_v2 中命中该二进制
上限 1.0；没有 Alert Address 时上限 0.6
```

### 6.4 去重键与 `finding_id`

```python
finding_id = f"satc-{binary_slug}-{addr}"          # addr 无则用 sink 函数名+序号
dedup_key  = (binary_id, normalize_addr(addr), vuln_class)
```

`normalize_addr`：统一成小写十六进制、去前导零（`0x0040A1B0` → `0x40a1b0`），四人统一。

---

## 7. 单测清单（`tests/unit/test_external_satc.py`）

必须覆盖的六类分支，**每类都要有真实 fixture**：

| 分支 | fixture 来源 | 断言 |
|---|---|---|
| 正常 | L1 合成固件的 `result-httpd-ref2sink_cmdi-*.txt` | 解析出 `bin/httpd` + `command_injection` + Alert Address |
| 空文件 | 手工造 0 字节文件 | 返回 `[]`，不抛异常 |
| 畸形行 | 手工造截断/乱码行 | 跳过该行 + 记 `limitation`，不崩 |
| 无告警 | 某固件某脚本跑出空 result | `findings=[]` 且 `status="ok"`（不是 failed） |
| 超时截断 | 手工截断一半的 result | 解析出已有部分 + 标 `truncated` |
| 版本差异 | 若有两版 SaTC 产物（官方镜像 vs 自 build） | 两版都能解析 |

外加：
- `test_external_base.py`：`execute()` 在 `probe/prepare/run/parse` 任一抛异常时都能兜住并返回 `status="failed"`
- `normalize()` 不合规 finding 被丢弃且被计数

**CI 约束**：单测**只解析 fixture，绝不调用真实 SaTC**。

---

## 8. Benchmark 方案

### 8.1 对照实验（3 固件 × 2 配置）

```
A 组：--depth standard        （关全部外部器，基线）
B 组：--depth full + satc     （只开 SaTC，关 KLEE/BOND/FirmRec）
```

每组记录：Top-1/3/5 命中、误报数、端到端耗时、SaTC 自身耗时。

### 8.2 你要回答的三个问题

1. **Top-K 有没有提升？** SaTC 的污点证据是否让真漏洞排得更靠前。
2. **误报有没有变化？** 注意：SaTC 会**新增**候选（外部独有发现），误报数可能先升后降——
   要看的是**精度**（真漏洞/总候选），不是绝对误报数。
3. **External-Only Hits 是多少？** SaTC 命中而主轨未命中的**真漏洞**数。
   **这个数如果为 0，要写清楚为什么**（是 SaTC 不行，还是我们的主轨已经覆盖了）。

### 8.3 表格骨架（`benchmarks/external/satc/comparison.md`）

| 固件 | A: Top-1/3/5 | A: 候选数 | A: 精度 | B: Top-1/3/5 | B: 候选数 | B: 精度 | External-Only | SaTC 耗时 | 总耗时增量 |
|---|---|---|---|---|---|---|---|---|---|
| L1 合成 | | | | | | | | | |
| L2 DIR-859 | | | | | | | | | |
| L3-a | | | | | | | | | |
| L3-b | | | | | | | | | |

---

## 9. 踩坑预案

| 坑 | 症状 | 处理 |
|---|---|---|
| **官方镜像老** | Python/angr 版本冲突，`satc.py` 起不来 | 优先用 `smile0304/satc`；不行则 `docker build . -t satc` 自 build（**时间盒 1 小时**，超了就用不带 `--taint_check` 的模式跑） |
| **Ghidra OOM** | 容器被 kill，`ghidra_extract_result` 空 | `--memory=16g` 且降低并发数；仍失败则只跑 Top-1 二进制（`-b`）而非 `-l 3` |
| **跑太慢** | 单固件 90 分钟，4 配置 × 3 固件 = 18 小时 | **分级全量**：4 种配置**全部跑不带 `--taint_check` 的快模式**；再对 Top-1 边界二进制跑带 `--taint_check` 的慢模式。这样全量覆盖到了，时间砍掉 60% |
| **无 Web 前端的固件关键字少** | `Clustering_result_v2.result` 很空 | 这是工具固有局限，记 `limitation`，不是你的锅 |
| **`share2sink` 依赖 `ref2share` 结果** | 直接跑会报错 | 必须**先跑 `ref2share`**，再用 `--ref2share_result` 指向其输出 |
| Windows 路径挂载失败 | `docker: invalid mount config` | 走 `to_wsl_path()` 翻译成 `/mnt/c/...`；确认 Docker Desktop 已开启该盘符的 file sharing |
| 解包的 Linux 符号链接 | rootfs 复制失败 | 复用 `fsa/utils/traverse.py` 的符号链接容错，别自己 `cp -r` |

---

## 10. 答辩 Q&A 预案（你可能会被问到）

**Q：SaTC 和你们主轨的静态分析区别在哪？**
A：主轨是 `imports ∩ {system, sprintf}` 的**同文件共现判断**，答不出"这个参数到底传没传过去"。SaTC 从前端关键字定位后端入口，用 Ghidra 找 sink、angr 做污点传播，给的是 `source → ... → sink` 的**跨函数路径**。而且 `ref2share`+`share2sink` 还能覆盖"写进 nvram、另一进程读出"的**跨进程污点**，这是主轨完全没有的。

**Q：SaTC 跑一次要多久？比赛现场来得及吗？**
A：单固件单脚本 30–90 分钟。现场策略：**只跑 `ref2sink_cmdi` + Top-1 边界二进制、关掉 `--taint_check`**，压到 20–30 分钟以内。全量 4 配置是离线 benchmark 才跑的。

**Q：如果 SaTC 没跑通呢？**
A：流水线不受影响。SaTC 是 `required=False`，`probe()` 失败即 `skipped` + 记录 limitation，主链照常出报告。这是设计约束不是补救措施。

---

## 11. 每日 checklist

- [ ] 今天的产物落盘了？（原始 → `fixtures/raw/`，解析 → `runs/`）
- [ ] 耗时记进 `benchmarks/external/satc/README.md` 了？
- [ ] 踩过的坑写进 Skill 文档了？（**不写等于白踩**）
- [ ] `enabled: false` 时主链还能跑？（每天至少验一次）
- [ ] 有没有卡超过 4 小时没说？
- [ ] 作为组长：其他三人的契约有没有跑偏？

---

*你是链条源头。你稳，G 和 H 才能跑。*
