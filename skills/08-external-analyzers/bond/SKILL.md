---
name: bond-external-analyzer
description: Use when integrating the BOND constraint-directed fuzzing validator into the FirmHound external-analysis track (SYMEX_PRUNE -> CONSTRAINED_VALIDATION). Covers mini-BOND X2 (Ghidra->EmTaint->BooFuzz replacement), the private-network safety gate, and the canonical PoC sanitizer contract.
type: skill
---

# BOND 外部分析器接入（H 同学 / mini-BOND）

BOND 是四件外部工具里**唯一真正打（仿真）目标的**，因此它的接入以**安全红线**和**验证闭环**为第一优先级，而非复现上游论文。本 Skill 描述如何把 BOND 接入 `SYMEX_PRUNE -> RANK -> VERIFY_TOP_K -> LOCAL_VALIDATION -> CONSTRAINED_VALIDATION -> REPORT` 这一段，并说明 mini-BOND（Plan B）如何作为主线卖点。

## 1. 角色与定位

- **输入**：KLEE 符号执行后 `symex.reachable == True` 的候选（来自 `unified_candidates`，经 `finding_fusion` 汇聚后的 `fused.json`）。
- **做什么**：把"疑似"变成"可触发"。对每个候选抽取约束 → 生成 fuzz 模板 → 优先级种子调度 → 定向 fuzz（仿真设备）。
- **输出**：`external_finding`（带 `validation` 字段：`triggered / probe / poc_sanitized / poc`）。只有 `poc_sanitized==true` 的 PoC 才许进报告。
- **非复发工具**：BOND 不是 FirmRec 那种"复发检测"，其 findings **直进 `fused.json`**，不参与 Blind Run 隔离。`RECURRENCE_ONLY_TOOLS` 不含 bond。

## 2. 接入点（代码层）

| 位置 | 作用 |
|------|------|
| `tools/external/bond/runner.py` (`BondAnalyzer`) | `ExternalAnalyzer` 子类，`build()` 工厂 |
| `tools/external/bond/parser.py` (`parse_bond_output`) | 解析 `Bond_result/` + `fuzz_log/` → `external_finding` + `validation` |
| `tools/external/bond/sanitize.py` (`sanitize_poc`) | **全组统一** PoC 脱敏器（FirmRec 也复用它） |
| `tools/external/bond/mini/` | mini-BOND 三件套：M1 入口识别 / M2 约束抽取 / M3 模板+调度 |
| `tools/registry/external.yaml` (`tools.external.bond` → `run_bond`) | 声明式注册，`ToolRegistry.call()` 走 no-op 降级 |
| `tools/external/adapter.py` (`run_bond`) | 与 satc/firmrec/klee 并列的入口 |
| 阶段机 `CONSTRAINED_VALIDATION` | 路由到 `tools.external.bond` |

注册方式与其他三件完全一致：`required=False`，`probe()` 失败即 `skipped` + limitation，**主链零 import 外部工具**，开关工具不改变 benchmark 结果。

## 3. 安全红线（不可违反，单测覆盖）

`tools.emulation.safety_gate.evaluate_gate` 四道闸在**任何网络活动之前**被 `BondAnalyzer.check_safety()` 硬断言：

1. `target` 必须是 `"emulation"` —— 打真机直接 `status="unsafe"`，零出站。
2. `target_ip` 必须是私有网段（RFC1918，`is_private_ip`）—— 公网 IP 即 `unsafe`。
3. `authorized == True` —— 操作者授权。
4. `local_lab == True` 且 `baseline_ready == True` —— 实验环境 + 干净基线（用于 crash diff）。

任一不满足 → `run()` 返回 `status="unsafe"`，**不写任何出站产物**。单测 `test_public_ip_target_aborts` / `test_private_emulation_...` 验证此行为。

## 4. mini-BOND（X2，主线卖点）

上游 BOND 依赖 **IDA Pro 7.5 + EmTaint + 修补版 BooFuzz 库 + 真机**。本组用开源替代，构成可答辩的 Plan B：

- **M1 入口识别**：`mini/ghidra_export.py` 用 **Ghidra headless**（替 IDA Pro）导出 CFG/CG；Ghidra 缺席时合成最小 CFG（dispatch 节点注册 handler → 朝 sink 调用），反向遍历仍能定位入口点。
- **M2 约束抽取**：`mini/constraint.py` 从候选/二进制抽取 6 类语义约束（string_eq / numeric_range / null_check / length / format / charset），分 mandatory/partial/none 三档（替 EmTaint）。
- **M3 模板+调度**：`mini/template.py` 用 **LLM runtime 生成 fuzz 模板**（无 LLM 时规则兜底，**绝不生成 curl/wget/下载执行**）；`mini/scheduler.py` 按约束档位做优先级种子生成（替修补版 BooFuzz 库）。
- **仿真目标**：`qemu_user` / FirmAE（替真机）。

## 5. PoC 脱敏契约（全组统一）

`sanitize_poc(payload, *, strict=True) -> (text, ok)`：

- `ok == False` 的硬红线（绝不入库、绝不渲染）：反弹 shell、下载执行（`curl|sh`、`wget`）、持久化（`crontab`/`/etc/init.d`）、破坏性（`rm -rf /`）、`$(...)`/反引号命令替换、公网 IP/域名（脱敏为 `<DEVICE_IP>`/`<HOST>`）、超长溢出串（脱敏为 `A×N`）。
- 良性标记类 PoC（如 `touch /tmp/lab_marker`、`id`）保留并 `ok==True`。
- FirmRec 的 `sanitize.py` 已改为直接复用此实现（TODO(de=H) 已解）。

## 6. 降级行为（诚实）

- BooFuzz / Ghidra / 仿真器缺席 → `skipped` / 诚实 `limitation`，**不中断流水线**。
- `simulate: true`（CI/本机默认）→ 不真发 fuzz 流量，只写 `fuzz_sent_log.txt` 的结构骨架，**绝不伪造 TRIGGERED**。
- 超时/未触发 → `validation.triggered = False`（降级，非拒收），报告标 `NEED_DYNAMIC_VALIDATION`。

## 7. 踩坑与反误报

| 坑 | 处理 |
|----|------|
| 上游 BOND 真实打真机 | 代码层硬断言 `target=emulation` + 私有网段，违反即零出站 |
| PoC 含反弹 shell | `sanitize_poc` 阻断，`finding` 直接丢弃，不进报告 |
| 伪造触发以"证明"漏洞 | 仿真器缺席时 `triggered=None` 且不写 marker，宁可漏报不误报 |
| IDA Pro 7.5 授权 | 用 Ghidra headless 替，合成 CFG 兜底 |
| EmTaint / 修补 BooFuzz 库缺失 | 自研 constraint + scheduler 替，LLM 模板规则兜底 |
| FirmRec 各自一套脱敏 | 统一指向 `bond.sanitize.sanitize_poc`，单点维护红线 |
| 版本漂移（上游 BOND 产物） | 解析时比对 `VERSION` 行，记入 `notes.bond-version` |

## 8. 文件地图

```
tools/external/bond/
  __init__.py            # 导出 BondAnalyzer, build, parse_bond_output, sanitize_poc
  runner.py              # BondAnalyzer + build；四道安全闸；写 Bond_result/fuzz_log
  parser.py              # 解析 6 类产物 -> external_finding + validation
  sanitize.py           # 全组统一 PoC 脱敏器（红线）
  mini/
    __init__.py
    ghidra_export.py    # M1：Ghidra 导出 / 合成 CFG 反向定位入口
    constraint.py       # M2：6 类语义约束抽取（替 EmTaint）
    template.py         # M3：LLM 模板生成（规则兜底，无 curl/wget）
    scheduler.py        # 优先级种子调度（替修补 BooFuzz）
  fixtures/raw/cand-{0..5}/  # 6 分支：normal/marker, empty, malformed, timeout, no-trigger, version-diff
tests/unit/
  test_sanitize.py       # 全红线 + 良性保留
  test_constraint.py     # 6 类约束
  test_external_bond.py  # 6 分支解析 + 安全闸 + mini 模块
benchmarks/external/bond/   # README / comparison / plan_a_assessment / raw/
```
