# KLEE 剪枝实验 · comparison.md

> 实验设计（G-KLEE.md §8）：对 `finding_fusion` 产出的 unified candidates 的 Top-10，逐个生成
> harness → `klee --max-time=300s`，统计**剪枝率**与**人工抽检**。

## 指标

- **剪枝率** = 判 `infeasible` 的候选 / 送检候选。
- **平均单候选耗时**、**路径爆炸 / 超时占比**、**触发 `ptr.err` 数量**（意外收获：直接证明内存错误）。
- **抽检**：剪枝率 > 70% 时，从被剪候选随机抽 5 条人工复核（确认无路可走、harness 建模合理）。

## 表格骨架（待 8/31 真实符号执行填写）

| 固件 | 送检 | infeasible | 可达+witness | 超时 | 路径爆炸 | ptr.err | 剪枝率 | 抽检结果 | 平均耗时 |
|---|---|---|---|---|---|---|---|---|---|
| L1 合成 | 10 | - | - | - | - | - | - | - | - |
| L2 DIR-859 | 10 | - | - | - | - | - | - | - | - |
| L3-a | 10 | - | - | - | - | - | - | - | - |
| L3-b | 10 | - | - | - | - | - | - | - | - |

## 误杀防护校验（X2）

- 每个 `infeasible` 结论带 `harness_version`（当前 `v1`），报告写明"基于 harness v1 建模假设"。
- `infeasible` 只写 `counterevidence`，**不删候选**；是否判误报交给 Verifier 的 10 问 + 12 硬规则。
- 抽检发现误杀 → 立即把对应 harness 模板标为不可靠并调低权重（见 `skills/08-external-analyzers/klee/SKILL.md`）。

## 状态

- 代码与 harness 生成器已落地并通过单测（见 `tests/unit/test_external_klee*.py`）。
- 真实数字待 8/31 机器任务补齐（本机无 KLEE、Docker 文件共享损坏）。
