---
id: 03-binary-decompile
title: 二进制筛选与反编译
tags: [binary, decompile, triage, m4, elf]
---

# Skill 03：二进制筛选与反编译

## 目标

对解包后的 rootfs 中数百个 ELF 做「初筛 → Top-N 深度反编译 → 结构化摘要」，产出符合 `binary_summary.schema.json` 的摘要。**核心约束：绝不把几万行反编译文本直接喂给模型；绝不反编译全部 ELF。**

## 输入

- `rootfs_dir`：已解包的 rootfs 目录
- `attack_surface.json`：M3 输出（用于攻击面引用加权）
- `startup_scripts`：启动脚本解析结果（用于启动调用加权）
- `max_binaries`：Top-N 阈值（默认 10，config 可调）

## 输出

- `binaries_summary.json`：Top-N 二进制的结构化摘要列表（`binary_summary.schema.json`）
- `runs/<id>/artifacts/decompile/<binary>/`：反编译产物（函数表、调用边、字符串引用、伪 C）

## 执行流程

1. **ELF 初筛打分（0 起）**
   - 被启动脚本调用 +3
   - 网络相关导入（socket/recv/send/accept…）+2
   - Web handler 线索（/cgi-bin、http、UPnP、SOAP、formexeCommand）+3
   - 危险函数导入（按 D/E/F/B/M/W 加权）+1~3
   - 在 M3 攻击面中被引用 +4
   - 取 Top-N（`elf_triage.py` 输出 `triage_score` ∈ [0,1]）

2. **安全特性检测（secfeatures）**
   - NX：`PT_GNU_STACK` 无执行位 → True；缺失时保守判 False。
   - Canary：存在 `__stack_chk_fail` / `__stack_chk_guard` 符号。
   - PIE：`e_type == ET_DYN`。
   - RELRO：`PT_GNU_RELRO` + `DT_BIND_NOW` → full；仅有 RELRO → partial；无 → none。
   - Stripped：无 `.symtab` 或符号表为空。

3. **危险函数扫描（danger_scan）**
   - D/E/F/B/M/W 六级分类；`system + sprintf/snprintf` 同存标记 `critical`。
   - 交叉信号是命令注入的高价值线索，但**危险 API 导入 ≠ 漏洞证据**。

4. **深度反编译（仅 Top-N）**
   - Ghidra `analyzeHeadless` 批处理：导入 → 分析 → 导出函数表/调用边/字符串引用/imports/xrefs/每函数伪 C。
   - 失败走 `decompile_fallback`：objdump 反汇编 + strings + reloc 降级摘要，`decompile_status=fallback`，绝不使整个 run 失败。

5. **结构化摘要（summarize）**
   - 每函数生成 name/addr、callers/callees、引用字符串（分类）、是否 source/sink/auth/validation（规则库 + vendor 字典判定）。
   - **单二进制摘要 ≤ 64KB，超则按函数 triage 截断并记录。**

## 失败降级路径

| 场景 | 行为 |
|---|---|
| Ghidra 不可用/导入失败 | objdump + strings 降级摘要，`decompile_status=fallback` |
| stripped 无函数名 | 基于字符串/xref/调用关系保留候选，不报错退出 |
| 摘要超 64KB | 按函数 triage 截断并记录 `truncated=true` |
| 非 ELF 文件 | 跳过，记 `decompile_status=failed`，不影响其他二进制 |

## 验收标准

- HG532e `bin/upnp`：摘要体现 `snprintf→system` 链与 `upg -g -U %s ... -r %s` 命令模板字符串。
- stripped ELF fixture：无函数名时仍能基于字符串/xref 保留候选，`decompile_status` 正确、不报错退出。
- 摘要体积控制：单二进制摘要 ≤ 64KB。
