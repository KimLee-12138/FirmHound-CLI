# Skill 01：固件解包与基线提取

## 目标

将任意 Linux 路由器/IoT 固件镜像转化为可用的 rootfs 目录，并输出符合 `firmware_manifest.schema.json` 的基线信息。

## 输入

- `firmware_path`：本地固件文件路径（`.bin`、`.trx`、`.chk`、`.img` 等）
- `run_id` 与 `run_root`：本次运行的标识与输出根目录

## 输出

- `firmware_manifest.json`（写入 `runs/<run_id>/`）
- `extracted/` 目录（解包中间产物）
- `collect_info.log`（命令尝试记录）

## 执行流程

1. **基线采集** (`tools/firmware/collect_info.py`)
   - 计算 SHA-256 / MD5 / 文件大小
   - 运行 `file` 命令获取文件类型
   - 提取前 256 字节十六进制魔数
   - 运行 `binwalk --signature --term` 获取签名扫描结果
   - 用 `strings` 提取厂商、型号、版本、内核版本线索

2. **解包路由** (`tools/firmware/unpack.py`)
   - 根据 binwalk 签名选择策略：
     - SquashFS 标准 → `unsquashfs`
     - SquashFS-LZMA 非标准 → `sasquatch`；失败试 `7z x`
     - UBI → `ubireader_extract_images`
     - JFFS2 → `jefferson`
     - CPIO → `cpio -idmv`
     - gzip/bzip2/xz → 先解压再递归检测
     - TRX/uImage/DLOB 头部 → `dd` 切片后递归
   - 无签名或策略失败 → ** carving fallback**：扫描 `hsqs`/`sqsh`/`UBI#`/gzip 魔数，按偏移 `dd` 切片后重试
   - 仍失败 → `status=failed`，保留全部尝试日志，转 `BINARY_ONLY_MODE`

3. **Rootfs 评分** (`tools/firmware/rootfs_score.py`)
   - 对 `extracted/` 下所有候选目录评分：
     - `bin`/`sbin`/`etc`/`lib`/`usr` 各 +1
     - `www`/`htdocs`/`web` +1
     - `etc/init.d` 非空 +1
     - `bin/busybox` +1
     - `usr/sbin/httpd`、`bin/goahead` 等 +2
   - 返回全部候选及最高分；最高分 < 5 时 `extraction_confidence` 降级为 0.3

4. **架构检测** (`tools/firmware/arch_detect.py`)
   - 在 rootfs 中采样 ≥3 个 ELF
   - `readelf -h` 交叉确认 Machine / Class / Data
   - 识别 libc（uClibc/musl/glibc）
   - 提取内核线索（`*.ko` vermagic、`Linux version` 字符串）
   - 输出推荐 QEMU binary

5. **Manifest 生成** (`tools/firmware/build_manifest.py`)
   - 组合以上结果，校验 `firmware_manifest.schema.json`
   - 写入 `runs/<run_id>/firmware_manifest.json`

## 失败降级路径

| 场景 | 行为 |
|---|---|
| binwalk 无签名 | carving fallback |
| 标准工具失败 | 尝试备选工具（sasquatch/7z） |
| 无可用 rootfs | `status=failed`，`BINARY_ONLY_MODE` |
| ELF 样本不足 | `architecture=unknown`，继续下游静态分析 |
| 外部命令不存在（如 Windows） | 自动降级，返回 `status=partial` 并继续 carving |

## 验收标准

- 标准 SquashFS 固件：产出 `status=success` 且 `extraction_confidence >= 0.7`
- 带厂商头部固件：切片后成功解包
- 加密/不可解固件：`status=failed` + 完整尝试日志 + Orchestrator 不崩溃
