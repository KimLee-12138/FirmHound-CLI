---
id: 00-orchestrator
title: 流水线总控编排（阶段机 / Planner / Verifier 联动）
tags: [orchestrator, pipeline, m0, state-machine, planner]
---

# Skill 00：流水线总控编排

## 目标

本 Skill 定义整条「固件漏洞挖掘自动化流水线」的**总控逻辑**：把 01–07 各领域 Skill 串成可恢复、可审计、可中断的阶段机。WorkBuddy/模型在收到比赛任务卡（task_card）时，必须先加载本 Skill 理解阶段流转、裁决口径与产物契约，再按阶段派发子 Skill 与确定性工具。

核心原则：**阶段机器驱动，而非自由发挥**。任何一次分析都必须走 `INIT → … → REPORT → DONE`，中途可断点续跑（resume）、可人工门控（HumanGate）、可失败降级（fallback），但结论必须落在统一证据模型上。

## 阶段机（Stage Machine）

| Stage | 含义 | 关键产物 | 主要工具/Skill |
|---|---|---|---|
| INIT | 解析任务、生成计划、初始化 run 目录 | task_card.json / plan.json / run_state.json | `fsa/orchestrator/planner.py` |
| BASELINE | 固件哈希与环境自检 | 基线证据 | `tools/firmware/build_manifest.py` |
| UNPACK | 固件解包 + rootfs 评分 | manifest / rootfs 目录 | Skill 01 |
| SURFACE | 攻击面枚举（Web/UPnP/CGI/启动链） | attack_surface.json | Skill 02 |
| BINARY_TRIAGE | ELF 架构 / 保护 / 危险符号 triage | triage 报告 | `tools/binary/elf_triage.py` |
| DECOMPILE | 反编译（可选，非必须） | 反编译缓存 | Skill 03 |
| STATIC_ANALYSIS | source→sink 数据流审计 | candidates.json | Skill 04 |
| RANK | 十维风险评分排序 | ranking.json | `tools/analysis/risk_score.py` |
| VERIFY_TOP_K | 反证审查（10 问） | verdicts.json | Skill 05 / `verifier.py` |
| LOCAL_VALIDATION | 本地动态验证（可选，full 深度） | dynamic_validation.json | Skill 06 |
| REPORT | 双产物报告 + 合规扫描 | report.md / final_verdict.json | Skill 07 |
| DONE / ABORTED | 终态 | — | — |

### 转换表（引擎已实现于 `fsa/orchestrator/engine.py`）

```
INIT → BASELINE → UNPACK → SURFACE → BINARY_TRIAGE → DECOMPILE → STATIC_ANALYSIS
     → RANK → VERIFY_TOP_K → {REPORT | LOCAL_VALIDATION} → DONE
```

- `VERIFY_TOP_K` 之后：有 `NEED_DYNAMIC` 候选且深度为 full → 走 `LOCAL_VALIDATION`，否则直通 `REPORT`。
- `UNPACK` 部分失败（fallback）→ 跳到 `BINARY_TRIAGE`（无 rootfs 也能做 ELF 静态分析）。
- 任意 required 阶段失败 → `ABORTED`，保留已完成阶段产物供 resume。

## 深度档位（Planner）

| depth | 阶段集 | budget_profile |
|---|---|---|
| `quick` | 跳过 DECOMPILE / LOCAL_VALIDATION | quick |
| `standard`（默认） | 含 DECOMPILE，不含 LOCAL_VALIDATION | default |
| `full` | 全部含 LOCAL_VALIDATION | default |

任务卡缺口（缺 firmware_path / 缺授权人）→ `requires_human_gate=True`，进入 HumanGate 等待补全，不自动继续。

## 执行流程

1. **解析任务卡（Planner.parse_task）**
   - 接受 CLI 参数 / 自然语言 / zip 任务包三种输入，归一化为 task_card。
   - 自然语言启发式抽取：路径（`*.bin|trx|chk|img|fw`）、厂商、型号、深度关键词（快速/深度）、授权关键词。
   - 通过 `task_card.schema.json` 校验后才允许进入 INIT。

2. **构建计划（Planner.build_plan）**
   - 按 depth 选阶段集与 stage_configs（每阶段绑定确定性工具：unpack / build_attack_surface / triage / static / rank / verify / validate / report）。
   - 设定成功标准（`min_confidence >= 0.6`、`max_false_positives <= 5`）与预算档位。

3. **初始化 run 目录（Orchestrator.create_run）**
   - `runs/<run_id>/` 下建 `state/`、`evidence/`、`decisions/`、`artifacts/` 四类子目录。
   - 初始化 StateManager / EvidenceStore / DecisionStore / HumanGate 四件套。
   - run_id 缺省用 12 位随机 hex；task_card 自带 task_id 时优先。

4. **逐阶段执行（Orchestrator._execute_stage）**
   - 每个阶段先记录决策（options=[execute,skip,abort]）。
   - 调用注册表工具（`ToolRegistry.call`），工具入参统一传 `{"run_dir": ...}`。
   - 按 result.status 分派：success→下一阶段；partial→若阶段非 required 则 fallback；error→required 则 ABORTED。
   - 工具调用前由 `PolicyEngine` 拦截危险命令 / 非白名单路径 / 公网 host（`config/safety.yaml`）。

5. **断点续跑（Orchestrator.resume）**
   - 读 run_state.json 找首个未完成阶段，从该阶段继续；`metadata.resumed=true` 落盘。
   - 每阶段完成即持久化，异常中断不丢已做工作。

6. **反证审查（CandidateVerifier，M7）**
   - 对 Top-K 候选跑 10 问清单，规则推导出裁决动作：`ACCEPT` / `DOWNGRADE` / `REJECT` / `NEED_DYNAMIC`。
   - 结论类别严格五分类：`confirmed-issue` / `high-confidence-candidate` / `false-positive` / `unknown` / `observation`。
   - 裁决必须引用证据 ID 或反证 ID，禁止无证据裁决；reviewer 标注 rule/model/human。

7. **动态验证衔接（Skill 06，full 深度）**
   - 仅 `NEED_DYNAMIC` 或 high-confidence 候选进入。
   - 四项安全门全过才放行：`AUTHORIZED && LOCAL_LAB && PRIVATE_NETWORK && BASELINE_READY`。
   - 安全门不过 → 输出 `ABORT_DYNAMIC_VALIDATION`，候选保留 NEED_DYNAMIC，报告标注 `dynamic_skipped`。

8. **报告与终态（Skill 07）**
   - 合规扫描 7 项全过才生成 report.md / final_verdict.json。
   - 全部 REJECT → 如实写「未发现强证据」；绝不虚构漏洞。
   - 终态置 DONE；产物目录结构完整可审计。

## 统一 Runtime Adapter（可选 LLM 增强）

- 编排引擎本身是纯规则的（mock runtime 即可跑通）。
- 需要 LLM 参与时配置 `config/models.yaml` 的 `openai_compatible` runtime（base_url / model / api_key_env），通过 `fsa.runtime.load_runtime("openai_compatible")` 加载。
- Budget 硬约束：max_total_tokens / max_tokens_per_stage / max_model_calls_per_stage / max_total_duration_seconds，超限即停，防止失控调用。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| task_card 缺固件或授权 | requires_human_gate=True，挂起等待人工补全 |
| UNPACK 部分失败（无 rootfs） | fallback 到 BINARY_TRIAGE，仅做 ELF 级分析 |
| required 阶段 error | run 状态置 ABORTED，保留已完成产物 |
| 模型 runtime 不可用 | 回退 mock 纯规则执行，不中断流水线 |
| 安全门 / 策略拦截 | 工具返回 status=unsafe，记录决策后跳过该调用 |
| 动态验证被禁用或门不过 | LOCAL_VALIDATION → skipped，报告标 dynamic_skipped |
| 中途断点 | resume() 从首个未完成阶段继续，不重跑已完成阶段 |

## 与子 Skill 的接口契约

- 每个子 Skill 的 SKILL.md 必须含「输入 / 输出 / 执行流程 / 失败降级路径 / 验收标准」五节（SkillLoader 依赖其解析 workflow_steps / failure_fallbacks / acceptance_criteria）。
- 阶段产物文件名固定：`task_card.json`、`plan.json`、`run_state.json`、`attack_surface.json`、`candidates.json`、`ranking.json`、`verdicts.json`、`dynamic_validation.json`、`report.md`、`final_verdict.json`。
- 证据模型统一走 `EvidenceStore`（evidence_id / type / source / stage / observation / fact_status / supports / contradicts）；决策统一走 `DecisionStore`。
- Skill id 命名规范：`NN-领域`，子 Skill 用 `NN-领域-子项`（如 `06-dynamic-validation-qemu-service-bootstrap`）；目录命名与 id 保持一致。

## 验收标准

- 端到端：给定含植入漏洞的仿真固件（无 CVE 先验），0 知识跑通 INIT→REPORT，检出候选并输出合规报告。
- resume：中断一次后恢复，不重跑已完成阶段，产物 md5 一致。
- 决策可审计：每个阶段至少一条决策记录（options/selected/reason/confidence/actor）。
- 安全：任何含公网 IP / 反弹 shell / 破坏性命令的工具调用均被策略拦截且留痕。
- 全部 REJECT 场景：报告如实输出「未发现强证据」，通过合规扫描。
