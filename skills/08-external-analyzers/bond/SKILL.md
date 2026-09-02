---
name: bond-external-analyzer
description: Integrate or maintain FirmHound's BOND constraint-directed validator, including real Ghidra export, bounded emulator probes, four safety gates, and PoC sanitization.
---

# BOND 外部分析器

在修改 `tools/external/bond/`、`CONSTRAINED_VALIDATION` 阶段或 BOND 配置时使用本 Skill。

## 产品契约

- 输入优先选择 `symex.reachable == true` 的候选；没有可达标记时可以尝试全部候选，但必须保留证据强度差异。
- `simulate: true` 是不可用/跳过状态，不得创建产物、finding 或 `TRIGGERED` 记录。
- `use_ghidra: true` 必须调用真实 Ghidra headless 和 `ghidra_scripts/ExportCfgCg.java`。工具缺失时明确降级，禁止合成 CFG/CG。
- 真实验证使用内置、限时、限响应大小的 HTTP 探针。只有真实响应包含配置的 `trigger_marker` 时，才能设置 `validation.triggered=true`。
- 未触发的真实探针只能证明“已尝试但未观察到标记”，不能证明目标安全。

## 安全约束

任何网络活动前都必须通过 `tools.emulation.safety_gate.evaluate_gate` 的四道门：

1. 目标类型是 `emulation`；
2. `target_ip` 属于私有网络；
3. `authorized=true`；
4. `local_lab=true` 且 `baseline_ready=true`。

任一道门失败都返回 `unsafe` 且保持零出站。禁止真实设备、公网地址、重定向和任意协议 URL。

所有持久化请求必须通过 `tools.external.bond.sanitize.sanitize_poc`。被拦截的内容只记录拒绝原因，不得写入 PoC 或报告。响应正文不落盘，只保存 HTTP 状态和 SHA-256。

## 实现位置

- `tools/external/bond/runner.py`：候选选择、安全门、真实探针与产物编排。
- `tools/external/bond/mini/ghidra_export.py`：Ghidra headless 调用与结果验证。
- `tools/external/bond/ghidra_scripts/ExportCfgCg.java`：CFG/调用图导出脚本。
- `tools/external/bond/parser.py`：标准化为 `external_finding`。
- `tools/external/bond/sanitize.py`：统一 PoC 安全过滤。

改动后至少运行 `tests/unit/test_external_bond.py`；涉及适配器或主链时同时运行外部集成测试和 CLI 集成测试。
