# BOND 外部分析器 — Benchmark 与接入说明

> 对应计划：`docs/external/H-BOND.md`
> 工具定位：约束导向定向验证，尝试为 KLEE 保活候选取得真实仿真响应证据（CONSTRAINED_VALIDATION 阶段）
> 安全模型：仅 `emulation` 目标 + 私有网段，PoC 必经 `sanitize_poc`

## 1. 本目录结构

```
benchmarks/external/bond/
  README.md            # 本文件
  comparison.md        # 与上游 BOND 的能力对照 + 降级映射
  plan_a_assessment.md # Plan A（上游 BOND 真机）可行性评估与为何走 Plan B
  raw/                 # 真实运行落盘区（待 8/31 机器 job）
    README.md
```

## 2. 交付状态（逐项）

| 编号 | 内容 | 状态 |
|------|------|------|
| H1 | runner/parser/adapter/registry 集成 | ✅ Full（代码+单测） |
| H2 | mini-BOND 三件套（M1/M2/M3 + scheduler） | ✅ Full（代码+单测） |
| H3 | 6 类产物解析（action_find/constraints/fuzz_log/crash/timeout/version-diff） | ✅ Full（单测 6 分支） |
| H4 | 私有网段安全闸（4 道硬闸，零出站保证） | ✅ Full（单测覆盖） |
| H5 | 全组统一 PoC 脱敏器 `sanitize_poc` | ✅ Full（红线全覆） |
| H6 | KLEE 保活候选 → BOND 验证闭环 | ✅ Full（接口连通，真实传输由本机回环服务单测） |
| H7 | SKILL + 文档 | ✅ Full |
| H8 | 真实 fuzz 运行（仿真器/真机） | ⚠️ Partial（待 8/31 机器 job） |

## 3. 仿真运行（H8，诚实降级）

本机（Windows + Docker 文件共享损坏）**无法做真实 fuzz**。代码与契约已就绪：

- 机器上置 `config/dev.yaml` 的 `bond.authorized/local_lab/baseline_ready=true`、`simulate=false`、`target_ip=192.168.x.x`（私有）。
- 准备可达的隔离仿真 HTTP 服务；需要入口图时另行安装 Ghidra headless 并设 `use_ghidra=true`。
- `scripts/run_external.py --tool bond --run-dir <dir>` 直接起，无需改代码。
- 真实 `Bond_result/`、`fuzz_log/` 落盘到 `benchmarks/external/bond/raw/`。

## 4. 红线（答辩必背）

1. **绝不打真机**：代码层硬断言 `target=emulation` + `is_private_ip`，违反即零出站。
2. **PoC 必脱敏**：`poc_sanitized==false` 的 finding 直接丢弃，不进 `fused.json`。
3. **不伪造触发**：模拟模式直接跳过；真实响应没有标记时 `triggered=false`，宁可漏报不误报。
