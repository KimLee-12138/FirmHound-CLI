---
id: 04-audit-buffer-overflow
title: 缓冲区溢出漏洞静态审计
tags: [audit, buffer_overflow, cve, m5]
---

# Skill 04-audit-02：缓冲区溢出漏洞静态审计

## 目标

对已解包 rootfs 中处理 HTTP header / body / socket 输入的二进制进行缓冲区溢出类漏洞审计，输出符合 `candidate.schema.json` 的候选列表。

本 Skill 主要基于 CVE-2021-31802（NETGEAR R7000 HTTP header 栈溢出）的复现经验，同时兼容其他 header/body 长度 unchecked copy 场景。

## 输入

- `rootfs_dir`：已解包的 rootfs 目录
- `attack_surface.json`：M3 输出的攻击面
- `firmware_manifest.json`：架构信息
- `run_id` / `run_root`：运行标识与输出目录

## 输出

- `candidates_buffer_overflow.json`：缓冲区溢出候选列表
- 每条候选标明受影响的 buffer、长度来源、危险函数、是否可被用户控制长度

## 执行流程

1. **入口定位**
   - 关注 `input_sources` 含 `header`、`http_param`、`body`、`socket_buf` 的 surface。
   - 重点检查处理长字符串的 handler，如：
     - HTTP header：`User-Agent`、`Referer`、`Cookie`、`SOAPAction`、`Authorization`
     - URL path / query string
     - socket 接收缓冲区

2. **二进制目标选择**
   - 优先分析 `httpd`、`upnpd`、`cms`、`net-cgi`、`lighttpd` 等 daemon。
   - 使用 `arch_detect` 确认架构，为后续反编译/QEMU 做准备。

3. **危险函数定位**
   - 高风险：`strcpy`、`strcat`、`sprintf`、`gets`、`scanf`（无长度限定）。
   - 中风险：`memcpy` / `memmove` 且长度参数来自外部输入。
   - 低风险：`strncpy`、`snprintf` 但长度计算错误（如 off-by-one）。

4. **长度检查审查**
   - 检查 sink 之前是否有 `strlen`、`sizeof`、固定长度上限、或 `if (len > MAX)` 校验。
   - 若长度上限大于目标 buffer 大小，或校验在 copy 之后，视为无效缓解。

5. **用户可控长度判定**
   - `full`：攻击者可直接控制输入长度（HTTP header、socket buf）。
   - `partial`：输入经过截断、编码或长度限制。
   - `none`：长度由服务端决定或硬编码。

6. **调用链与崩溃路径**
   - 提取从入口 handler 到危险函数的调用链。
   - 若危险函数在栈上局部 buffer 操作，标记为 `stack_overflow`。
   - 若在堆上，标记为 `heap_overflow`。

7. **候选生成**
   - 风险评分：
     - 未认证 + 用户可控长度 + strcpy/sprintf：26–30（CRITICAL）
     - 需认证 + 用户可控长度 + memcpy：20–25（HIGH）
     - 有长度检查但可绕过 / off-by-one：14–20（MEDIUM）
     - 仅有 strcpy 字符串但无调用链：observation

## 失败降级路径

| 场景 | 行为 |
|---|---|
| 无反编译器（Ghidra/angr 未就绪） | 用字符串 + 导入表生成 observation |
| binary 带符号剥离 | 依赖函数名模板 + 调用图 heuristics |
| 无法确定 buffer 大小 | 标记 `decisive_missing_fact="need dynamic验证"`，输出 high-confidence-candidate |
| 输入长度不可控 | 判为 false-positive 或 observation |

## 验收标准

- 对 R7000-like 固件：必须检出来自 HTTP header 长字符串进入 `strcpy`/`memcpy` 的候选。
- 候选必须包含 `source.type=header` 与 `sink.type=memory_copy`。
- candidates.json 通过 Schema 校验。
