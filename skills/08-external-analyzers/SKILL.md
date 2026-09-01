---
id: 08-external-analyzers
title: 外部分析器双轨编排
tags: [external, orchestration, satc, firmrec, klee, bond, fusion]
---

# Skill 08：外部分析器双轨编排

## 目标

把 SaTC、FirmRec、KLEE 与 mini-BOND 作为可选增强接入主轨，统一输出
`external_finding`，并保证任一重型依赖缺失时主流水线仍可生成报告。

## 输入

- `artifacts/candidates.json`：主轨候选；
- 已解包 rootfs；
- `config/dev.yaml` 的 `external` 配置；
- Blind Run 标记与授权、安全门状态。

## 输出

- `artifacts/external_findings/{satc,klee,bond}.json`；
- `artifacts/external_findings/recurrence_findings.json`（FirmRec 独立旁路）；
- `artifacts/unified_candidates.json`；
- 所有入口都返回 `status` 与 `limitation`。

## 执行流程

1. `EXTERNAL_ANALYSIS` 只并行运行上游 SaTC 与 FirmRec；Blind Run 强制关闭 FirmRec。
2. `FUSION` 按 `(binary_id, sink.addr, vuln_class)` 去重，合并主轨与 SaTC 证据。
3. `SYMEX_PRUNE` 运行 KLEE；不可达仅写 counterevidence，绝不自动删除候选。
4. `RANK` 与 `VERIFY_TOP_K` 继续使用原十维 30 分制和 10 问/12 条规则。
5. `CONSTRAINED_VALIDATION` 运行 mini-BOND；只有已脱敏的 marker/crash 证据可确认。
6. `REPORT` 第 21 节展示交叉验证、限制与 FirmRec 的先验隔离声明。

## 安全约束

- 总开关 `external.enabled=false` 不可被任何单工具开关绕过。
- 工作目录必须位于 `./tmp/external/<tool>/<run_id>/`。
- BOND 只允许 `target=emulation`、私有网段、授权、本地实验室和基线就绪。
- 禁止 curl/wget 调模型；禁止真机、公网和可武器化 PoC。
- `poc_sanitized != true` 的触发证据一律拒绝。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| 工具未安装/镜像缺失 | `skipped` + missing/limitation，主链继续 |
| 超时/路径爆炸 | `timeout` 或 limitation，不改候选分数 |
| Parser 异常 | `failed` + limitation，FUSION 仍以主轨候选工作 |
| FirmRec + Blind Run | `skipped/FORCED_DISABLE`，结果不进入 unified candidates |
| KLEE infeasible | 只写 counterevidence，交给 Verifier 裁决 |
| BOND 未触发 | 记为 inconclusive/NEED_DYNAMIC，不否决候选 |

## 验收标准

- `schemas/external_finding.schema.json` 与四工具示例全部通过验证。
- `--depth full` 产出 external/fusion/unified/report 完整工件链。
- 四器全关时结果与基线一致；8 种开关组合均不 abort。
- Blind Run 中 FirmRec 无法进入 unified candidates。
- 单元测试不依赖 Docker、WSL、IDA、KLEE 或真实设备。
