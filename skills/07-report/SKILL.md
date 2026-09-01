---
id: 07-report
title: 漏洞分析报告生成
tags: [report, verdict, compliance, m10, redaction]
---

# Skill 07：漏洞分析报告生成（report.md + final_verdict.json）

## 目标

把整条流水线的产物（candidate / verdict / 证据 / 决策）汇集成**双产物**：

- `report.md` — 人类可读，答辩 / 提交用；
- `final_verdict.json` — 机器可读，平台判分 / 自动化用。

核心原则：**可解释、可审计、如实、脱敏**。看到 `system`/`strcpy` ≠ 漏洞，报告必须基于证据链而非函数命中；全部 REJECT 时如实输出「未发现强证据」，严禁强行报漏洞。

## 输入

- `ranking.json` / `candidates.json`（M6 排序结果）
- `verdicts.json`（M7 裁决）
- `evidence` 索引（M9 证据链）
- `decision.json` 条目（决策记录）
- `dynamic_validation.json`（M8，可选）
- `artifacts/external_findings/fused.json`、`recurrence_findings.json`、
  `unified_candidates.json`（外部轨，可选）

## 输出

- `report.md`：固定 21 节章节
- `final_verdict.json`：`{run_id, firmware_sha256, findings:[...], stats:{...}}`

## 报告 21 节固定骨架

1. 任务范围与授权边界
2. 固件信息与哈希
3. 解包结果
4. 架构组件
5. 攻击面
6. 二进制分析
7. 候选排行
8. 主候选数据流（source → transform → sink → call_chain）
9. 认证边界
10. 输入校验
11. 支持证据
12. 反证
13. 本地验证结果（M8，无则标注 `dynamic_skipped` 及原因）
14. 结论置信度
15. 限制 `remaining_limitations`
16. 修复建议
17. 运行指标
18. 人工介入点
19. 决策摘要
20. 完整证据索引
21. 外部工具交叉验证（SaTC/KLEE/BOND 主链；FirmRec 复发扫描独立标注）

## 执行流程

1. **结论口径对齐**
   - 五分类：confirmed-issue / high-confidence-candidate / false-positive / unknown / observation。
   - 裁决动作：ACCEPT（采纳）/ DOWNGRADE（降级）/ REJECT（拒绝）/ NEED_DYNAMIC（需动态验证）。
   - `observation` 级条目不进入评分，只入证据索引。

2. **脱敏渲染（强制）**
   - 模板中禁止出现可复现攻击参数，一律替换为占位符：`<USER_INPUT>`、`<BENIGN_MARKER>`。
   - 不出现真实目标 IP、反弹 shell、持久化、下载执行等可武器化内容。

3. **决策摘要硬规则**
   - 报告中展示的是**可审计决策摘要**（options / selected / reason / confidence / actor）。
   - **绝不输出模型隐式思维链原文**；模型 reasoning 只提炼为一句 `reason`（≤200 字）。

4. **合规扫描 8 项（全过才生成报告）**
   - 无真实 IP；无反弹 Shell 特征；无持久化；无下载执行；无破坏性命令；含安全声明；仅标记验证（`touch`/`echo`/`id`）。
   - 外部 PoC 必须 `poc_sanitized == true`；不满足时整条证据拒绝落盘和渲染。
   - 复用 `tools/emulation/probes.detect_dangerous_payload` + `utils/netcheck.is_private_ip`。

5. **如实报告**
   - 全部 REJECT → 结论写「未发现强证据」，并保留反证清单。
   - `NEED_DYNAMIC` 但安全门不过 → 标注 `dynamic_skipped` 及原因，不虚构验证结果。

6. **双产物写出**
   - `report.md` 用固定 20 节模板渲染；`final_verdict.json` 通过 `verdict.schema.json` 校验。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| 合规扫描不过 | 报告生成失败，输出违规项清单 |
| 无 candidate | 报告如实写「未发现候选」，21 节骨架仍齐全 |
| M8 未运行 | 第 13 节标 `dynamic_skipped` + 原因 |
| 证据索引缺失 | 第 20 节标「证据索引不完整」，不阻断报告 |
| 外部工具缺失/超时 | 第 21 节写 `degraded` 与 limitation；主报告继续生成 |
| FirmRec 在 Blind Run 被请求 | 强制 `skipped/FORCED_DISABLE`，只报告隔离事实，不渲染已知 CVE 结果 |

## 验收标准

- 对任一 run 生成报告：21 节齐全、8 项合规扫描通过、`final_verdict.json` 通过 Schema 校验。
- 报告中不出现任何可复现攻击参数（脱敏后）。
- 全部 REJECT 场景如实输出「未发现强证据」。
