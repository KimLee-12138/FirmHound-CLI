---
id: 06-local-validation
title: 本地动态验证（QEMU/FirmAE）
tags: [dynamic, emulation, qemu, firmae, m8]
---

# Skill 06：本地动态验证（L0–L3 分层）

## 目标

在严格安全门下做 L0–L3 分层非武器化验证，只回答「可达 / 不可达、是否稳定异常」，绝不构造利用链。

| 层 | 内容 | 产出 |
|---|---|---|
| L0 | 纯静态证据（不启动任何目标） | 默认 |
| L1 | qemu-user 可加载（架构/loader/动态库/basic boot） | `load_ok` 证据 |
| L2 | 系统仿真服务可达（QEMU system/FirmAE，NAT+Host-only 隔离） | 连通性证据 |
| L3 | 非武器化验证（单变量变化 → 观察路径/参数/稳定 crash/无害标记） | 可达性/异常证据 |

## 输入

- `candidate`（含 `NEED_DYNAMIC` 裁决的候选优先）
- `rootfs_dir`、`architecture`、`target_ip`（必须私有网段）
- `authorized` / `local_lab` / `baseline_ready` 门控标志

## 输出

- `dynamic_validation.json`：每层 `status`（success / skipped / failed）+ 证据 + limitation
- 任一安全门不满足 → `ABORT_DYNAMIC_VALIDATION`，不产生任何外发流量

## 执行流程

1. **安全门（强制，最先执行）**
   - 四项硬门全通过才放行：`AUTHORIZED && LOCAL_LAB && PRIVATE_NETWORK && BASELINE_READY`。
   - 目标 IP 必须私有网段（`192.168.0.0/16`、`10.0.0.0/8`、`172.16.0.0/12` 等）；非私有 → ABORT。
   - **连通性先于触发**：先确认基线正常响应，再谈触发。

2. **L1 qemu-user 加载**
   - `qemu-<arch>-static -L rootfs busybox echo QEMU_OK` 基准自检。
   - qemu-user 三大坑：
     - `br0` ioctl 死循环 → 用 `-strace` 观察，属正常；
     - `/dev/nvram` 缺失 → 修补或 `-L` 指向含 stub 的 rootfs；
     - 假监听 socket（进程起来但端口不监听）→ 用 `netstat`/串口日志确认真实监听。

3. **L2 服务可达**
   - QEMU system 模式或 FirmAE，NAT+Host-only 隔离网，tap/bridge 编排。
   - 基线连通性：`curl -i --max-time 5 http://<private_ip>:<port>/`。
   - 冷/热启动各至少 1 次，记录可重复性。

4. **L3 非武器化验证**
   - 单变量变化 → 观察路径是否执行 / 参数是否到达 / 是否稳定 crash。
   - 仅无害标记：`touch /tmp/lab_marker`、`echo LAB >/tmp/lab_marker.txt`、`id`。

5. **危险 payload 拒绝**
   - 反弹 shell（`nc -e`、`bash -i`、`/dev/tcp`）、持久化（`crontab`、`init.d`）、下载执行（`wget|sh`）一律拒绝。

## 失败降级路径

| 场景 | 行为 |
|---|---|
| qemu-user 二进制缺失 | L1 → skipped，记录 limitation，不崩溃 |
| qemu-system 缺失 | L2/L3 → skipped，记录 limitation |
| FirmAE 未安装 | 回退 QEMU system 模式，记录 limitation |
| 目标 IP 非私有 | ABORT_DYNAMIC_VALIDATION，零外发流量 |
| 授权/本地实验标志缺失 | ABORT_DYNAMIC_VALIDATION |

## 验收标准

- 安全门单测：公网 IP / 未授权 / 无基线三种情形均 ABORT。
- L1：HG532e `upnp`（MIPS 大端）可加载验证通过并留 strace 证据。
- 触碰红线（目标 IP 非私有）时整个动态阶段不产生任何外发流量。
