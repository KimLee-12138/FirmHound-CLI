---
id: 06-dynamic-validation-qemu-service-bootstrap
title: QEMU 服务启动与漏洞本地验证
tags: [dynamic, qemu, local_validation, m7, m8]
---

# Skill 06-dynamic-validation-01：QEMU 服务启动与漏洞本地验证

## 目标

对 M6/M7 产出的高置信候选在本地进行动态验证，确认漏洞可被真实触发。输出符合项目 evidence / verdict 规范的 `validation.json`。

本 Skill 服务于命令注入（如 CVE-2017-17215、CVE-2019-17621）与缓冲区溢出（如 CVE-2021-31802）两类 CVE 的复现路径。

## 输入

- `candidate.json`：待验证候选
- `rootfs_dir`：已解包的 rootfs
- `firmware_manifest.json`：架构、libc、推荐 QEMU binary
- `attack_surface.json`：端点、端口、协议信息
- `run_id` / `run_root`：运行标识与输出目录

## 输出

- `validation.json`：每条候选的验证结果
  - `result`: `pwned` / `crash` / `no_trigger` / `inconclusive`
  - `method`: `qemu_user` / `qemu_system` / `docker` / `manual`
  - `evidence`: 截图、pcap、core、日志路径
  - `notes`: 失败原因或利用条件说明

## 执行流程

1. **选择 QEMU 模式**
   - **用户态 (`qemu-<arch>`)**：适合单一 ELF + 预置 rootfs 的 CGI/handler。
   - **系统态 (`qemu-system-<arch>`)**：适合需要完整启动、多 daemon 交互的场景（如 UPnP daemon + HTTP server）。
   - 优先用户态；若依赖内核/网络命名空间，切系统态。

2. **准备运行环境**
   - 根据 `firmware_manifest.architecture.recommended_qemu_binary` 选择 qemu。
   - 挂载 rootfs 为 chroot：
     ```bash
     cp $(which qemu-<arch>-static) $rootfs_dir/usr/bin/
     chroot $rootfs_dir /bin/sh
     ```
   - 或系统态启动：准备 kernel/initrd/rootfs 镜像，配置 `-net user,hostfwd=tcp::8080-:80`。

3. **启动目标服务**
   - 从 `attack_surface.startup_evidence` 找到启动命令。
   - 对 UPnP：启动 `upnpd`、`miniupnpd` 或对应 daemon。
   - 对 Web/CGI：启动 `httpd`、`goahead`、`lighttpd`。
   - 监听端口确认服务就绪（`netstat -ln` 或轮询 HTTP 200）。

4. **构造触发请求**
   - **命令注入**：在对应 source 字段注入 payload，例如：
     - UPnP SOAP：`NewStatusURL=http://x.com/$(id> /tmp/pwn)`
     - HTTP param：`cmd=127.0.0.1;id`
     - HTTP header：`User-Agent: $(/bin/busybox id)`
   - **缓冲区溢出**：发送超长 header/body，观察崩溃或异常返回。

5. **监控与取证**
   - 检测进程是否崩溃（SIGSEGV/SIGABRT）、产生 core dump。
   - 检查 `/tmp/`、`/var/log/` 是否出现预期 side-effect 文件。
   - 捕获 QEMU 输出、strace、tcpdump。

6. **结果判定**
   - `pwned`：成功执行非预期命令或稳定控制 PC/返回 shell。
   - `crash`：服务崩溃，确认是候选 sink 触发（需排除无关崩溃）。
   - `no_trigger`：服务正常响应，无崩溃/无命令执行证据。
   - `inconclusive`：环境依赖未满足（如需要 WAN 侧、特定硬件、特定版本），保留 high-confidence-candidate。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| QEMU binary 不存在 | 记录 `inconclusive`，建议安装 `qemu-user-static` / `qemu-system-*` |
| 服务无法启动 | 检查启动脚本与依赖库，尝试 `LD_PRELOAD` stub 缺失库；仍失败则标记 `inconclusive` |
| 网络转发失败 | 系统态改用 hostfwd 或 tap；用户态改用 `socat` 转发 stdin/stdout |
| 候选触发无崩溃但疑似命令注入 | 使用 `sleep` / `dns` / `ping` 等延时/外联 payload 二次确认 |
| 动态验证被禁用 | 输出 `validation.json` 占位，`result=skipped`，候选保持 NEED_DYNAMIC |

## 安全红线

- 只连接本地或 NAT 内的 QEMU 实例，禁止向公网发送真实攻击流量。
- 命令注入 payload 优先使用 `id`、`hostname`、`sleep` 等无害 side-effect，避免实际 shell 反弹。
- 溢出验证不发送已知的完整 exploit，仅发送超长字符串触发崩溃。

## 验收标准

- 对 HG532e-like UPnP 命令注入：在 QEMU 中启动服务后，发送 SOAP `NewStatusURL` payload 能在 `/tmp/` 留下 side-effect 或产生命令执行日志。
- 对 R7000-like 栈溢出：发送超长 header 后目标进程崩溃并生成可关联到候选 sink 的 backtrace。
- validation.json 通过 Schema 校验，且所有验证行为被 evidence store 记录。
