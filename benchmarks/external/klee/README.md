# KLEE 外部分析器 · Benchmark 档案

> 工具：KLEE 3.2（LLVM 16 + Z3）。阶段：`SYMEX_PRUNE`。
> 负责同学：G。计划：见 `docs/external/G-KLEE.md`。技能卡：`skills/08-external-analyzers/klee/SKILL.md`。

## 这个工具解决什么

动态符号执行，判定"汇聚后的候选里，哪些 source→sink 路径在约束上根本走不通"。
把 `infeasible` 的候选剪掉，**只把剩下的送进 BOND 做昂贵的定向 fuzz**。

## 三条 bitcode 策略

| 策略 | 输入 | 状态 |
|---|---|---|
| S1 源码 wllvm | 合成固件 `httpd.c`/`upnpd.c`、开源组件 | 必成 |
| S2 harness 桩（主推） | 从候选 sink 签名自动生成 C 桩 | 主战场（已落地 `harness_gen.py`） |
| S3 二进制提升 | mcsema / retDec 抬 ELF | 4h 硬上限，失败即放弃并诚实归因 |

## 数据集（F1）

| 固件 | 层级 | bitcode 策略 | 状态 |
|---|---|---|---|
| L1 合成固件 | L1 | S1 + S2 | 真实符号执行待 8/31 机器任务 |
| L2 DIR-859 | L2 | S2 | 同上 |
| L3-a | L3 | S2 | 同上 |
| L3-b | L3 | S2 | 同上 |

## 当前档位

- **代码 / 单测**：Full（23 用例绿，覆盖 parser 六类分支 + harness 生成 + 降级 + X2 误杀防护）。
- **真实符号执行（F1/F2/F6/F9）**：Part（本机 Docker 文件共享损坏 + 未装 KLEE，真实运行推迟到
  8/31 机器任务；代码与 harness 生成器已就绪，到机器上 `backend=wsl` 或 Docker 直接跑）。
- **诚实归因**：S3 二进制提升若 4h 内拿不到可用 bitcode，记为 limitation，不编造结果。

## 文件

- `comparison.md` — 剪枝实验（3 固件 × Top-10 候选）：剪枝率 + 5 条人工抽检。
- `raw/README.md` — 真实 `klee-out-N/` 产物落盘说明。
