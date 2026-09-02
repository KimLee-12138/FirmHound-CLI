# BOND vs 上游 BOND — 能力对照与降级映射

> 用于答辩“你们和原版 BOND 差在哪”。mini-BOND 是可审计的安全子集，不宣称与论文原型能力等价。

| 维度 | 上游 BOND（原版） | 本组 mini-BOND（Plan B） | 差异说明 |
|------|------------------|--------------------------|----------|
| 入口识别 | IDA Pro 7.5 导出 CFG/CG | 可选真实 Ghidra headless（`mini/ghidra_export.py`） | 缺失时明确降级，不合成图 |
| 约束抽取 | EmTaint 污点分析 | `mini/constraint.py` 6 类语义约束启发式抽取 | 启发式弱于污点，但覆盖 mandatory/partial/none 三档 |
| 模板生成 | 手工/规则模板 | 基于候选元数据的确定性规则模板 | 可离线复现，但协议覆盖较窄 |
| 种子调度 | 修补版 BooFuzz 库 | `mini/scheduler.py` 有界优先级种子生成 | 保留约束优先思想，不宣称策略等价 |
| fuzz 执行 | 真机（路由器实体） | 内置限界 HTTP 传输到 QEMU/FirmAE 等仿真目标 | **仅仿真**，不包含完整 BooFuzz 会话能力 |
| PoC 脱敏 | 人工审查 | `tools.external.bond.sanitize.sanitize_poc`（全组统一） | 自动化、可单测 |
| 触发验证 | 真机 crash/响应 | 仿真响应 marker + `validation` 字段 | 当前不宣称具备 crash 监控；缺席时诚实降级 |

## 红线增强（本组独有）

- **目标硬约束**：`target=emulation` + 私有网段，代码层 `assert`，单测覆盖。
- **PoC 不入库**：`sanitize_poc` 阻断即丢弃 finding，不进 `fused.json`/报告。
- **不伪造触发**：模拟模式跳过；真实响应无 marker → `triggered=false`。

## 与流水线的对接

```
KLEE(symex.reachable) → fused.json
   → CONSTRAINED_VALIDATION → run_bond
       → mini M1/M2/M3 → fuzz (emulation, private) → validation{triggered,poc_sanitized}
   → 写回 candidate 的 validation；poc_sanitized==true 才许进报告
```
