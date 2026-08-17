# Firmware Security Agent (FSA)

> 第一队系统研发——具备自主决策能力的通用网络安全智能体

本项目将 IoT 固件漏洞挖掘流程（解包 → 攻击面排查 → 二进制反编译 → 静态审查 → 风险评分 → 动态验证 → 证据报告）封装为可编排的 Skill 与确定性工具链，支持 mock / OpenAI-Compatible 运行时适配，并以金标准 Benchmark 进行能力验证。

## 快速开始

```bash
# 1. 安装依赖
make dev

# 2. 运行全链路基线
make run-smoke

# 3. 查看帮助
make help
```

## 目录结构

| 目录 | 说明 |
|---|---|
| `fsa/` | 编排、运行时、Schema、报告生成 |
| `tools/` | 确定性工具脚本（解包/攻击面/二进制/审计/报告） |
| `schemas/` | 阶段产物 JSON Schema 与示例 |
| `skills/` | Skill 定义（md + yaml + 示例） |
| `config/` | YAML 配置（安全策略、模型、运行时） |
| `tests/` | 单元、集成、金标准回归测试 |
| `legacy/` | 原始手工 skill 归档 |
| `docs/` | 设计文档、架构决策、Backlog |

## 开发约定

- 严格按 `第一队_WorkBuddy全栈实施开发计划.md` 第七部分任务表执行。
- 每个任务完成并通过 DoD 后提交，commit 格式：`[T-XX] 一句话`。
- 安全策略以 `config/safety.yaml` 为准，不得弱化。
