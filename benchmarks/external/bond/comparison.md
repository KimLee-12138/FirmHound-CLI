# BOND vs 上游 BOND — 能力对照与降级映射

> 用于答辩"你们和原版 BOND 差在哪"。结论：**能力等价、依赖开源化、安全增强**。

| 维度 | 上游 BOND（原版） | 本组 mini-BOND（Plan B） | 差异说明 |
|------|------------------|--------------------------|----------|
| 入口识别 | IDA Pro 7.5 导出 CFG/CG | Ghidra headless（`mini/ghidra_export.py`），缺席时合成 CFG | 功能等价；开源免费 |
| 约束抽取 | EmTaint 污点分析 | `mini/constraint.py` 6 类语义约束启发式抽取 | 启发式弱于污点，但覆盖 mandatory/partial/none 三档 |
| 模板生成 | 手工/规则模板 | LLM runtime 生成 + 规则兜底（无 curl/wget） | 生成能力更强，且强制安全 |
| 种子调度 | 修补版 BooFuzz 库 | `mini/scheduler.py` 优先级种子生成 | 策略等价（按约束档位加权） |
| fuzz 执行 | 真机（路由器实体） | `qemu_user` / FirmAE 仿真 | **仅仿真**，安全红线要求 |
| PoC 脱敏 | 人工审查 | `tools.external.bond.sanitize.sanitize_poc`（全组统一） | 自动化、可单测 |
| 触发验证 | 真机 crash/响应 | 仿真器 marker/crash + `validation` 字段 | 仿真缺席时诚实降级 |

## 红线增强（本组独有）

- **目标硬约束**：`target=emulation` + 私有网段，代码层 `assert`，单测覆盖。
- **PoC 不入库**：`sanitize_poc` 阻断即丢弃 finding，不进 `fused.json`/报告。
- **不伪造触发**：仿真器缺席 → `triggered=None`，不写 marker。

## 与流水线的对接

```
KLEE(symex.reachable) → fused.json
   → CONSTRAINED_VALIDATION → run_bond
       → mini M1/M2/M3 → fuzz (emulation, private) → validation{triggered,poc_sanitized}
   → 写回 candidate 的 validation；poc_sanitized==true 才许进报告
```
