---
id: 05-candidate-verifier
title: 候选漏洞反证审查与五分类结论
tags: [verifier, m7, evidence-model]
---

# Skill 05：候选漏洞反证审查与五分类结论

## 目标

对 M6 评分排序产生的 Top-K 候选进行**独立、主动的证伪审查**，输出符合 `verdict.schema.json` 的 `verdicts.json`。本 Skill 是证据链可信度与答辩叙事创新点 ① 的核心载体。

## 核心原则

**反证优先（falsification-first）**：Verifier 的职责不是证明候选是漏洞，而是寻找能推翻候选的证据。只有经过系统性质询仍无法证伪的候选，才能进入高置信度或确认类别。

## 五分类结论模型

| 类别 | 含义 | 使用条件 |
|---|---|---|
| `confirmed-issue` | 确认问题 | 外部输入 → 用户可控 → 真实 sink → 可达调用链，无有效过滤，无重大条件限制 |
| `high-confidence-candidate` | 高置信候选 | 核心链路成立，但存在 minor 条件限制（如需认证、有过滤但可绕过可能） |
| `false-positive` | 误报 | 存在击败性反证：非外部输入、不可控、不到 sink、调试功能、链不可达等 |
| `unknown` | 未知 | 关键事实缺失，无法在当前静态证据下做出可靠判断 |
| `observation` | 观察 | 仅发现危险 API / 可疑字符串 / 弱校验痕迹，但缺少完整链路证据 |

## 12 条硬判定规则

1. **危险 API 导入 ≠ 漏洞证据**。仅在二进制中看见 `system`/`exec`/`strcpy` 等字符串只能生成 `observation`。
2. **认证豁免 ≠ 未认证可达**。路由层标记 `public` 需结合 handler 层与启动证据复核。
3. **过滤函数存在 ≠ 过滤有效**。必须审查过滤逻辑是否可被绕过（黑名单不完整、长度检查后可截断等）。
4. **源代码存在调用 ≠ 运行时可达**。必须提供从入口到 sink 的调用链或控制流证据。
5. **配置文件中硬编码 ≠ 用户可控**。常量、编译期宏、默认配置不能视为攻击者输入。
6. **调试/测试函数 ≠ 生产攻击面**。函数名或路径含 `debug`/`test`/`diag` 且无启动证据时降级为 `false-positive`。
7. **存在 `require_auth` 调用 ≠ 一定需要认证**。需确认该调用在真实路径上被实际执行，而非死代码。
8. **UPnP/SOAP Action 输入 ≠ 公网可达**。需确认 daemon 监听在 WAN 侧或可通过 LAN 侧横向利用。
9. **证据不足时只能到 `high-confidence-candidate`/`observation`/`unknown`**，禁止为了报告好看而提升为 `confirmed-issue`。
10. **`false-positive` 必须有击败性证据**。仅凭"不确定"不能判为误报，必须指出具体推翻点。
11. **同一候选存在矛盾证据时优先降级**。若支持与反对证据势均力敌，结论应为 `unknown` 并标记需动态验证。
12. **reviewer 必须标注**。规则版标注 `rule`，模型版标注 `model`，人工复核标注 `human`。

## 10 问清单

对每一个候选逐条回答以下问题：

1. **Source 是否真外部输入？** 来源是 HTTP 参数/Header/Cookie、URL 路径、SOAP/UPnP 参数、socket 输入还是常量/配置文件？
2. **是否用户可控？** 攻击者能否在请求中任意设置或显著影响该值？
3. **是否真到 Sink？** 是否存在从 Source 到 Sink 的数据流/调用链证据？
4. **中间是否有编码或白名单？** 是否存在长度检查、黑名单、白名单、URL 解码、转义等缓解？
5. **调用链是否可达？** 从入口 handler 到 sink 的完整调用链是否被 decompile/callgraph/字符串交叉证据支持？
6. **handler 是否启动？** 目标二进制/daemon 是否有启动脚本或监听证据？
7. **是否需认证？** 路由/handler/脚本三层是否都需要有效会话？是否伴随 auth bypass？
8. **是否仅调试功能？** 该入口是否只在调试/测试/诊断模式下出现？
9. **是否有构建或平台条件？** 是否存在编译开关、平台特定代码、特定版本条件导致无法通用利用？
10. **是否存在矛盾证据？** evidence store 中是否有明确 contradicts 该候选的条目？

## 执行流程

1. **加载输入**
   - 读取 `candidates.json` 或 `candidate_ranking.json`
   - 读取 `attack_surface.json` 用于校验 surface/handler/启动证据
   - 读取 evidence store 查找支持/反对证据

2. **逐候选 10 问审查**
   - 调用 `fsa/orchestrator/verifier.py` 的规则引擎生成答案
   - 每项答案必须引用证据 ID 或明确说明"证据缺失"

3. **应用 12 条硬规则推导结论**
   - 满足任一 false-positive 条件 → `REJECT`
   - 存在缓解但不构成击败 → `DOWNGRADE`
   - 核心链路完整且无反证 → `ACCEPT`
   - 关键事实缺失 → `NEED_DYNAMIC`

4. **输出 verdicts.json**
   - 校验 `verdict.schema.json`
   - 写入 `runs/<run_id>/verdicts.json`

## 失败降级路径

| 场景 | 行为 |
|---|---|
| candidates 文件缺失 | 返回空 verdicts 并记录 warning |
| attack_surface 缺失 | 仅使用 candidate 自带证据审查，handler 启动问题标记为 unknown |
| 模型不可用 | 切换 `reviewer=rule`，使用纯规则版 Verifier |
| 动态验证被禁用 | `NEED_DYNAMIC` 结论保留，写入 `validation.json` 占位但不执行 |

## 验收标准

- 对 AC15 `formexeCommand` 式命令注入候选：在无过滤证据时输出 `ACCEPT`/`confirmed-issue`。
- 对仅有危险 API 字符串但无调用链的候选：输出 `REJECT`/`false-positive` 或 `observation`。
- 对需认证但无 auth bypass 的候选：输出 `DOWNGRADE` 并保留为 `high-confidence-candidate`。
- verdicts.json 必须通过 Schema 校验。
