---
id: 04-audit-command-injection
title: 命令注入漏洞静态审计
tags: [audit, command_injection, cve, m5]
---

# Skill 04-audit-01：命令注入漏洞静态审计

## 目标

对已解包的 rootfs 与攻击面进行命令注入类漏洞的定向审计，输出符合 `candidate.schema.json` 的候选列表。

本 Skill 沉淀了 CVE-2017-17215（华为 HG532e UPnP）、CVE-2019-17621（D-Link DIR-859）、CVE-2019-16920（D-Link 多型号）、CVE-2020-9373、CVE-2018-5767、CVE-2020-10987、CVE-2023-27021 等复现经验。

## 输入

- `rootfs_dir`：已解包的 rootfs 目录
- `attack_surface.json`：M3 输出的攻击面
- `run_id` / `run_root`：运行标识与输出目录

## 输出

- `candidates_command_injection.json`：命令注入候选列表
- 每条候选包含 source → transform → sink → call_chain → authorization 完整链路

## 执行流程

1. **入口定位**
   - 从 `attack_surface.json` 筛选 `input_sources` 含 `http_param`、`header`、`body`、`soap_arg` 的 surface。
   - 优先关注 `category` 为 `upnp` / `soap` / `cgi` / `web` 的条目。
   - 参考历史 CVE 的高危入口：
     - UPnP `SOAPAction`、`NewStatusURL`、`NewDownloadURL`（HG532e、DIR-859）
     - HTTP form 字段如 `cmd`、`command`、`ip`、`ping`、`user`、`devicename`
     - HTTP header 如 `Cookie`、`User-Agent`、`X-Requested-With`

2. **Source 识别**
   - 在对应 binary 中定位读取输入的函数：
     - Web/CGI：`websGetVar`、`getenv("HTTP_*)`、`fgets(stdin)`、`sscanf`
     - UPnP：`UPnPGetArgumentValue`、`ParseHttpRequest`、`soap_get`
   - 标记输入是否直接来自外部请求，还是来自常量/配置文件。

3. **Transform 追踪**
   - 追踪输入是否经过 `sprintf`/`snprintf`、`strcat`/`strncat`、`strcpy`、`memcpy`、`websWrite` 等拼接。
   - 记录拼接模板（如 `"ping -c 4 %s"`、`"%s; %s"`）。
   - 识别是否存在 URL 解码、base64、HTML 转义等中间变换。

4. **Sink 匹配**
   - 危险执行函数：`system`、`popen`、`_popen`、`__system`、`execve`、`execv`、`eval`、`do_system`。
   - 危险文件操作：若拼接后用于 `fopen`/`open` 且路径含用户输入，考虑 `path_traversal` 降级输出。

5. **过滤绕过检测**
   - 黑名单过滤（`;`、`&`、`|`、`$`、`` ` ``）：检查是否可用 `%0a`、`%3b`、`\n`、编码、双写绕过。
   - 白名单过滤：若仅允许 IP/数字，评估是否可通过 `@`、`/`、DNS payload 绕过。
   - 长度检查：若长度限制在 sink 之后生效，可能仍可利用。

6. **认证前可达判定**
   - 复用 `auth_matrix` 结果：
     - `auth_hint=preauth` 且 L1/L2/L3 均无有效校验 → 高危。
     - `auth_hint=auth` 但存在 `whitelist`、`public` 豁免或 `cookie` 硬编码 → 降级但仍保留。

7. **候选生成**
   - 完整链路：source → transform → sink → call_chain → user_control。
   - 风险评分：
     - 未认证 + 直接拼接 system：28–30（CRITICAL）
     - 需认证 + 直接拼接：22–26（HIGH）
     - 有过滤但可绕过：18–24（HIGH/MEDIUM）
     - 仅有危险 API 字符串无链路：observation

## 失败降级路径

| 场景 | 行为 |
|---|---|
| attack_surface 缺失 | 只基于 `www/`、`cgi-bin/` 文件与二进制字符串做轻量扫描，生成低置信候选 |
| binary 不是 ELF | 用字符串扫描 + 正则生成 observation |
| 反编译失败 | 以函数名/字符串交叉证据生成 candidate，confidence 降级 |
| 无 sink 证据 | 不生成候选，只输出 observation |

## 验收标准

- 对 HG532e-like 固件：必须检出 UPnP `Upgrade` Action → `system` 的候选。
- 对 DIR-859-like 固件：必须检出 HTTP `/soap.cgi` → `system` 的候选。
- 对 AC15-like 固件：必须检出 `/goform/formexeCommand` → `system` 的候选。
- candidates.json 通过 Schema 校验。
