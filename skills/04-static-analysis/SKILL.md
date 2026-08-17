---
id: 04-static-analysis
title: 静态审计分析模型
tags: [static, audit, dataflow, source_sink, m5]
---

# Skill 04：静态审计分析模型

## 目标

对 Top-N 二进制与攻击面交叉，按统一分析模型产出 `candidates.json`。本 Skill 固化命令注入五步法、协议解析六步法、七层数据流模板与误报排除五规则，供 `tools/analysis/` 规则引擎驱动。

## 输入

- `binaries_summary.json`：M4 结构化摘要
- `attack_surface.json`：M3 攻击面
- `auth_matrix.json`：M3 认证矩阵

## 输出

- `candidates.json`：漏洞候选列表（`candidate.schema.json`）

## 分析模型

```text
Entry → Source → Transform → Validation → Authorization → Sink
      → Reachability → Counterevidence → Conclusion
```

## 执行流程

1. **命令注入五步法**
   - 找 entry（handler 入口）→ 找 source（外部输入）→ 追 transform（拼接）→ 找 sink（system/popen）→ 判断过滤是否可绕过。
   - 白名单=通常安全；黑名单=可能可绕过；无过滤=高危。

2. **协议解析六步法**
   - TLV length → count → 写 → 定长 buffer → 无上限检查（6/6=极高危）。
   - 用于 CVE-2021-31802（NETGEAR R7000 HTTP 头缓冲区溢出）类候选。

3. **七层数据流模板（HTTP 入口）**
   - Request → Route → C Handler → IPC/xmldb → PHP Receive → PHP Sink → Shell Execute。
   - 每层记录过滤器存在性与 file:line 证据。

4. **socket 入口变体模板**
   - 报文 → recvfrom → 拷贝/格式化 → sink。

5. **变量使用验证（强制）**
   - 变量定义点与使用点必须同时存在，否则标记反证（`verify_variable_usage`）。

6. **误报排除五规则（fp_filter）**
   - CLI 工具排除；命令模板无 `%s` 降级；纯内部 IPC 降级；无可达外部入口标记待确认；dead code/未启动服务降级。

7. **候选生成**
   - 每个候选 ≥2 条独立证据；`observation` 级不进入评分。
   - `conclusion_category` 采用五分类：confirmed-issue / high-confidence-candidate / false-positive / unknown / observation。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| 无函数级反编译 | 用 imports + strings 交叉证据生成 candidate，confidence 降级 |
| source 与 sink 无法连通 | 不生成 candidate，输出 observation |
| 变量未定义或未使用 | 标记 counterevidence，降级为 observation |
| 规则库未覆盖的 API | 落 observation 并标注 `unmatched_sink` |

## 验收标准

- 对 HG532e：自动产出 P0 候选（upnp / snprintf→system / NewDownloadURL、NewStatusURL），与 CVE-2017-17215 对照表吻合。
- 对 Tenda AC15：自动产出 formexeCommand / `cmdinput`→`doSystemCmd`→`system()` 候选。
- 每个候选含 ≥2 条独立证据。
