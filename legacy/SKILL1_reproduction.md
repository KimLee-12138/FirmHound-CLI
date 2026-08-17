# 路由器固件自动化漏洞分析 Skill（合并版）

> 通用路由器固件自动化漏洞分析 Agent 工作流
> 覆盖: 固件解包 → Web入口 → 认证边界 → 危险函数追踪 → 本地仿真验证 → 报告生成
> 适用范围: 任何 Linux-based 路由器固件 (Huawei HG532e, RouterOS, OpenWrt, DD-WRT, TP-Link, Ubiquiti 等)
> 合并来源: 1SKILL.md (通用框架) + 2SKILL.md (HG532e深度分析 + 方法论)

---

## 快速导航

| 模块 | 内容 | 适用场景 |
|------|------|---------|
| 模块1 | 固件解包 — 格式识别、文件系统提取、架构判断 | 任何固件分析第一步 |
| 模块2 | Web入口识别 — 全量扫描Web目录、CGI、脚本、API | 发现所有网络可达接口 |
| 模块3 | 认证边界识别 — preauth接口判断、协议层认证分析 | 判断哪些接口无需登录即可访问 |
| 模块4 | 危险函数与数据流 — system/popen/exec追踪、命令模板搜索、误报排除 | 定位可利用的漏洞点 |
| 模块5 | 本地仿真验证 — QEMU用户态、最小复现程序 | 无害验证漏洞可达性 |
| 模块6 | 自动报告生成 — 10节标准化报告 | 输出最终分析结果 |

---

## 模块一：固件解包模块

### 1.0 模块目标

输入固件文件，自动完成格式识别、文件系统提取、架构判断、Web服务组件识别，输出固件结构摘要。

### 1.1 格式识别

```bash
# === 识别固件格式 ===
FIRMWARE=<path_to_firmware>
WORKDIR="/tmp/stage3_work"
mkdir -p "$WORKDIR"/{scans,logs,reports,emulation}

file "$FIRMWARE"
head -c 64 "$FIRMWARE" | xxd | head -20

# 常见魔数速查:
#   hsqs / sqsh       → Squashfs (可直接 unsquashfs)
#   UBI# / \x06       → UBI image (ubireader)
#   \x1f\x8b          → gzip compressed
#   \x42\x5a          → bzip2 compressed
#   \xfd7zXZ          → xz compressed
#   \x37\x7a\xbc\xaf  → 7-zip
#   ELF               → 可能是内核镜像 (vmlinux)
#   \x89PNG           → 误识别 — 非固件
#   data              → 常见于自定义固件, 继续用 binwalk

# 如果 file 无法识别:
binwalk "$FIRMWARE" 2>/dev/null | head -40 | tee "$WORKDIR/scans/binwalk_scan.txt"
```

**输出：** `固件格式: <format> | file 输出: <raw>`

### 1.2 文件系统提取

根据 1.1 的格式输出选择提取方法：

```bash
# === 根据格式选择提取命令 ===
FW_FILE="$FIRMWARE"
EXTRACT_DIR="$WORKDIR/_extracted"
mkdir -p "$EXTRACT_DIR"

# Squashfs (标准):
#   unsquashfs -d "$EXTRACT_DIR/rootfs" "$FW_FILE"

# Squashfs-LZMA (华为/TP-Link常用, 标准unsquashfs失败时):
#   7z x -o"$EXTRACT_DIR/rootfs" <squashfs-file>

# 嵌入式 Squashfs (binwalk 提取后):
binwalk -Me --directory="$EXTRACT_DIR" "$FW_FILE" 2>&1 | tee -a "$WORKDIR/logs/workflow.log"

# CPIO:
#   mkdir -p "$EXTRACT_DIR/rootfs" && cd "$EXTRACT_DIR/rootfs" && cpio -idmv < "$FW_FILE"

# TAR + compress:
#   tar -xvf "$FW_FILE" -C "$EXTRACT_DIR"

# UBI:
#   ubireader_extract_images "$FW_FILE"

# JFFS2:
#   jefferson "$FW_FILE" -d "$EXTRACT_DIR/rootfs"

# 原始磁盘镜像 (.img/.vmdk):
#   fdisk -l "$FW_FILE"  # 获取 Start 扇区
#   mount -o loop,offset=$((Start*512)) "$FW_FILE" /mnt/ros
```

### 1.3 rootfs 定位与验证

```bash
# === 验证 rootfs 完整性 ===

# 查找 bin/ 目录 (rootfs 的标志)
find "$EXTRACT_DIR" -maxdepth 8 -type d -name "bin" 2>/dev/null | while read bindir; do
    parent=$(dirname "$bindir")
    score=0
    for d in bin sbin etc lib usr; do
        [ -d "$parent/$d" ] && score=$((score + 1)) && echo "  [✓] $d"
    done
    if [ $score -ge 4 ]; then
        echo "  [+] 确认为 rootfs (得分: $score/5)"
        echo "$parent" > "$WORKDIR/rootfs_path.txt"
    fi
done

ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)
[ -z "$ROOTFS" ] && { echo "[-] 未找到 rootfs, 请检查固件是否加密"; exit 1; }

echo "rootfs: $ROOTFS"

# 扩展检查 — Web 目录
for d in www htdocs web cgi-bin; do
    [ -d "$ROOTFS/$d" ] && echo "  [Web] $d"
done

# RouterOS 特有检查
for d in nova bndl; do
    [ -d "$ROOTFS/$d" ] && echo "  [ROS] $d"
done

# OpenWrt 特有检查
[ -d "$ROOTFS/etc/config" ] && echo "  [UCI] etc/config (OpenWrt)"

# 判定: ≥4 个标准目录 → 可信 rootfs
```

**输出：** `rootfs路径: <path> | 完整度: <N>/5 | Web目录: <列表>`

### 1.4 架构与平台信息

```bash
# === 识别 CPU 架构 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "--- CPU 架构 ---" | tee -a "$WORKDIR/scans/architecture.txt"

# 找一个可执行 ELF 检测架构
SAMPLE_BIN=$(find "$ROOTFS/bin" -type f 2>/dev/null | head -1)
if [ -n "$SAMPLE_BIN" ]; then
    file "$SAMPLE_BIN" | tee -a "$WORKDIR/scans/architecture.txt"
    
    # 提取架构关键字
    ARCH=""
    file "$SAMPLE_BIN" | grep -q "MSB" && ARCH="${ARCH}大端"
    file "$SAMPLE_BIN" | grep -q "LSB" && ARCH="${ARCH}小端"
    file "$SAMPLE_BIN" | grep -q "MIPS" && ARCH="MIPS $ARCH"
    file "$SAMPLE_BIN" | grep -q "ARM" && ARCH="ARM $ARCH"
    file "$SAMPLE_BIN" | grep -q "x86-64" && ARCH="x86_64"
    echo "推断架构: $ARCH" | tee -a "$WORKDIR/scans/architecture.txt"
    
    # 确认 QEMU 可用性
    case "$ARCH" in
        *MIPS*大端*) QEMU_BIN="qemu-mips-static" ;;
        *MIPS*小端*) QEMU_BIN="qemu-mipsel-static" ;;
        *ARM*)        QEMU_BIN="qemu-arm-static" ;;
        *ARM*aarch64*) QEMU_BIN="qemu-aarch64-static" ;;
        *x86_64*)     QEMU_BIN="" ;;  # 可以直接运行
        *)            QEMU_BIN="" ;;
    esac
    echo "QEMU工具: $QEMU_BIN ($(which $QEMU_BIN 2>/dev/null || echo '需安装'))"
fi

# 检测 busybox
BUSYBOX=$(find "$ROOTFS" -type f -name 'busybox' 2>/dev/null | head -1)
[ -n "$BUSYBOX" ] && echo "busybox: $BUSYBOX"

# 内核版本
echo "--- 内核版本 ---" | tee -a "$WORKDIR/scans/architecture.txt"
find "$ROOTFS" -name "*.ko" 2>/dev/null | head -1 | xargs strings 2>/dev/null | grep -E "vermagic|Linux version" | head -3
strings "$FW_FILE" 2>/dev/null | grep -E "Linux version [0-9]" | head -3 | tee -a "$WORKDIR/scans/architecture.txt"
find "$ROOTFS"/lib/modules -maxdepth 1 -type d 2>/dev/null | head -3

# libc 类型
echo "--- libc 类型 ---"
ls "$ROOTFS/lib/"libc*.so* 2>/dev/null | while read libc; do
    libc_name=$(basename "$libc")
    case "$libc_name" in
        *uClibc*) echo "  libc: uClibc ($libc_name)" ;;
        *musl*)   echo "  libc: musl ($libc_name)" ;;
        *glibc*|*libc-2*) echo "  libc: glibc ($libc_name)" ;;
        *)        echo "  libc: $libc_name" ;;
    esac
done
```

**输出：** `架构: <arch> | 位数: <32/64> | BusyBox: <有/无> | QEMU: <bin> | 内核: <version> | libc: <type>`

### 1.5 Web 服务组件识别

```bash
# === 识别 Web 服务器 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "--- Web 服务器二进制 ---" | tee "$WORKDIR/scans/web_services.txt"
for name in www httpd goahead lighttpd uhttpd boa nginx mini_httpd apache apache2 lighthttpd web; do
    found=$(find "$ROOTFS" -name "$name" -type f 2>/dev/null)
    if [ -n "$found" ]; then
        echo "[+] $name: $found" | tee -a "$WORKDIR/scans/web_services.txt"
        file "$found" | tee -a "$WORKDIR/scans/web_services.txt"
    fi
done

# Web 配置文件
echo "--- Web 相关配置文件 ---" | tee -a "$WORKDIR/scans/web_services.txt"
find "$ROOTFS"/etc -type f \( -name 'lighttpd*' -o -name 'uhttpd*' -o -name 'goahead*' \
    -o -name 'nginx*' -o -name 'httpd*' -o -name 'boa*' \) 2>/dev/null | tee -a "$WORKDIR/scans/web_services.txt"

# 脚本语言
echo "--- Web 脚本语言 ---"
find "$ROOTFS" -type f -name '*.lua' 2>/dev/null | wc -l | xargs echo "Lua 文件:"
find "$ROOTFS" -type f -name '*.php' 2>/dev/null | wc -l | xargs echo "PHP 文件:"
find "$ROOTFS" -type f -name '*.py' 2>/dev/null | wc -l | xargs echo "Python 文件:"
find "$ROOTFS" -type f -name '*.cgi' 2>/dev/null | wc -l | xargs echo "CGI 文件:"

# CGI 目录
echo "--- CGI 目录 ---"
find "$ROOTFS" -type d -name 'cgi-bin' 2>/dev/null

# 从 init.d 中搜索 Web 服务启动
echo "--- init.d 中的 Web 服务 ---"
grep -rE "httpd|web|boa|lighttpd|www|cgi|goahead|uhttpd|nginx" "$ROOTFS/etc/init.d/" 2>/dev/null | head -20
```

**输出：** `Web服务器: <列表> | 脚本语言: <Lua/PHP/Python/CGI数量>`

### 1.6 固件结构摘要输出

模块一最终输出统一摘要：

```markdown
## 固件结构摘要

| 字段 | 值 |
|---|---|
| 固件文件 | <路径> |
| 固件格式 | <format> |
| rootfs 路径 | <path> |
| CPU 架构 | <arch> |
| 位数 | <32/64> |
| BusyBox | <有/无/路径> |
| 内核版本 | <version> |
| libc 类型 | <type> |
| QEMU 工具 | <bin> |
| Web 服务器 | <组件列表> |
| 脚本语言 | Lua:<N> PHP:<N> Python:<N> CGI:<N> |
| ELF 二进制数 | <N> |
| etc 配置文件数 | <N> |
| rootfs 完整度 | <N>/5 |
```

### 1.7 常见异常处理

| 异常 | 原因 | 处理方式 |
|------|------|---------|
| `binwalk` 未安装 | 缺少工具 | `sudo apt install binwalk -y` |
| `binwalk` 只输出少量签名 | 固件加密/有自定义头部 | 用 hexdump + strings 手动分析, 标注 `[加密固件]` |
| unsquashfs 报 "Filesystem uses lzma" | SquashFS-LZMA 变体 | 改用 `7z x -orootfs` |
| 找不到 `bin/` | 非标准文件结构 | `find _extracted -type f -exec file {} \; \| grep ELF` |
| 多个 rootfs 候选 | 固件含备份分区或双系统 | 选最大的, 在报告中注明存在多个 |
| 文件名或路径包含空格 | Windows/VBox 兼容问题 | 给路径加引号, 或复制到无空格路径 |
| VirtualBox 共享文件夹限制 | vboxsf 不支持 symlink/mknod | `cp -r` 到本地 ext4 再操作 |

---

## 模块二：Web 入口识别模块

### 2.0 模块目标

从解包后的文件系统出发，系统性地枚举所有可能的 Web 入口，输出入口清单。覆盖 CGI、Lua、PHP、Python、Shell 脚本和 UPnP/SOAP 接口。

### 2.1 目标目录覆盖

```bash
# === 全量 Web 目录扫描 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

# 必须扫描的目录:
#   /www    — 最常见 (OpenWrt, RouterOS, DD-WRT)
#   /htdocs — Apache 风格
#   /web    — TP-Link, Huawei 等
#   /cgi-bin — CGI 脚本
#   /usr/sbin — 可能有 Web CGI 二进制
#   /bin     — 可能有被 CGI 调用的工具
#   /etc/init.d — 启动脚本中的 Web 配置

for dir in www htdocs web cgi-bin; do
    path="$ROOTFS/$dir"
    if [ -d "$path" ]; then
        echo "=== $path ($(find "$path" -type f 2>/dev/null | wc -l) 个文件) ==="
        find "$path" -type f -exec file {} \; 2>/dev/null | head -30
    fi
done

# 搜索非标准路径的 Web 处理器
find "$ROOTFS" -path '*/lua/*' -name '*.lua' -type f 2>/dev/null | head -20
find "$ROOTFS" -path '*/cgi/*' -type f 2>/dev/null | head -20
find "$ROOTFS" -path '*/api/*' -type f 2>/dev/null | head -20
```

### 2.2 Web 二进制 CGI 端点提取（关键步骤）

```bash
# === 从 Web 二进制中提取内嵌 CGI 端点 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

for webbin in $(find "$ROOTFS" -name "web" -o -name "httpd" -o -name "boa" -o -name "goahead" -o -name "uhttpd" 2>/dev/null); do
    [ ! -f "$webbin" ] && continue
    binname=$(basename "$webbin")
    echo "[*] $binname ($webbin):" | tee -a "$WORKDIR/scans/web_cgi.txt"
    
    # 提取 .cgi 端点
    cgi_list=$(strings "$webbin" | grep "\.cgi" | sort -u)
    cgi_count=$(echo "$cgi_list" | grep -c "\.cgi" 2>/dev/null || echo 0)
    
    if [ "$cgi_count" -gt 0 ]; then
        echo "  发现 $cgi_count 个 CGI 端点" | tee -a "$WORKDIR/scans/web_cgi.txt"
        echo "$cgi_list" | tee "$WORKDIR/scans/${binname}_cgi.txt"
        
        # 按功能分类
        echo "  --- 按功能分类 ---" | tee -a "$WORKDIR/scans/web_cgi.txt"
        echo "  认证类: $(echo "$cgi_list" | grep -iE 'login|logout|auth|password|session')" | tee -a "$WORKDIR/scans/web_cgi.txt"
        echo "  配置类: $(echo "$cgi_list" | grep -iE 'setcfg|addcfg|delcfg|config|apply')" | tee -a "$WORKDIR/scans/web_cgi.txt"
        echo "  命令类: $(echo "$cgi_list" | grep -iE 'exec|cmd|command|excute')" | tee -a "$WORKDIR/scans/web_cgi.txt"
        echo "  升级类: $(echo "$cgi_list" | grep -iE 'upg|upgrade|firmware|upload|image')" | tee -a "$WORKDIR/scans/web_cgi.txt"
        echo "  状态类: $(echo "$cgi_list" | grep -iE 'status|state|get|info|version')" | tee -a "$WORKDIR/scans/web_cgi.txt"
        echo "  调试类: $(echo "$cgi_list" | grep -iE 'debug|test|diag|nff|restore|ping|trace')" | tee -a "$WORKDIR/scans/web_cgi.txt"
    fi
    
    # 提取 URL 路由
    echo "  --- URL 路由 ---" | tee -a "$WORKDIR/scans/web_cgi.txt"
    strings "$webbin" | grep -E "^/" | grep -v "^/lib/" | grep -v "^/dev/" | sort -u | head -20 | tee -a "$WORKDIR/scans/web_cgi.txt"
done
```

### 2.3 入口文件按类型分类

```bash
# === 按文件类型分类枚举入口 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "--- CGI (ELF二进制) ---" | tee "$WORKDIR/scans/entry_types.txt"
find "$ROOTFS" \( -path '*/cgi-bin/*' -o -path '*/cgi/*' \) -type f -executable 2>/dev/null \
    | while read f; do file "$f" | grep -q 'ELF' && echo "$f"; done | tee -a "$WORKDIR/scans/entry_types.txt"

echo "--- CGI (Shell/Mixed) ---" | tee -a "$WORKDIR/scans/entry_types.txt"
find "$ROOTFS" \( -path '*/cgi-bin/*' -o -path '*/cgi/*' \) -type f \( -name '*.sh' -o -name '*.pl' \) 2>/dev/null | tee -a "$WORKDIR/scans/entry_types.txt"

echo "--- Lua Handler ---" | tee -a "$WORKDIR/scans/entry_types.txt"
find "$ROOTFS" \( -path '*/www/*' -o -path '*/lua/*' -o -path '*/htdocs/*' \) -name '*.lua' -type f 2>/dev/null \
    | while read f; do
        grep -lE 'entry\(|handle_request|function.*\(req|arg\[|FORM\[|QUERY|cgilua|ngx\.' "$f" 2>/dev/null
    done | head -20 | tee -a "$WORKDIR/scans/entry_types.txt"

echo "--- PHP Handler ---" | tee -a "$WORKDIR/scans/entry_types.txt"
find "$ROOTFS" \( -path '*/www/*' -o -path '*/htdocs/*' \) -name '*.php' -type f 2>/dev/null | head -30 | tee -a "$WORKDIR/scans/entry_types.txt"

echo "--- Python Handler ---" | tee -a "$WORKDIR/scans/entry_types.txt"
find "$ROOTFS" \( -path '*/www/*' -o -path '*/usr/lib/*' \) -name '*.py' -type f 2>/dev/null | head -10 | tee -a "$WORKDIR/scans/entry_types.txt"
```

### 2.4 UPnP/SOAP/TR-064 接口提取

```bash
# === UPnP SOAP 接口 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

UPNP_DIRS=$(find "$ROOTFS" -type d -iname "*upnp*" -o -type d -iname "*tr064*" 2>/dev/null)

if [ -n "$UPNP_DIRS" ]; then
    echo "[+] 发现 UPnP 目录: $UPNP_DIRS" | tee "$WORKDIR/scans/upnp_interfaces.txt"
    for upnpdir in $UPNP_DIRS; do
        for xml in "$upnpdir"/*.xml; do
            [ ! -f "$xml" ] && continue
            filename=$(basename "$xml")
            
            # 提取 Action 名称
            actions=$(grep "<name>" "$xml" | head -20 | sed 's/.*<name>//;s/<\/name>//' | sed 's/^/    /')
            
            # 提取 direction=in 的参数 (外部可控输入!)
            in_params=$(grep -B3 "direction>in<" "$xml" 2>/dev/null | grep "<name>" | sed 's/.*<name>//;s/<\/name>//' | sed 's/^/      /')
            
            echo "  [$filename]" | tee -a "$WORKDIR/scans/upnp_interfaces.txt"
            echo "    Action: $actions" | tee -a "$WORKDIR/scans/upnp_interfaces.txt"
            [ -n "$in_params" ] && echo "    ⚠ 外部输入参数 (direction=in): $in_params" | tee -a "$WORKDIR/scans/upnp_interfaces.txt"
            
            # 标记高影响操作
            echo "$filename" | grep -qiE "Upg|Upgrade|Reboot|Factory|Reset|Config|Security" && \
                echo "    [!] 高影响操作文件!" | tee -a "$WORKDIR/scans/upnp_interfaces.txt"
        done
    done
else
    echo "[-] 未发现 UPnP 目录" | tee "$WORKDIR/scans/upnp_interfaces.txt"
fi
```

### 2.5 其他网络服务

```bash
# === 补充网络服务 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "--- inetd 服务 ---" | tee "$WORKDIR/scans/network_services.txt"
cat "$ROOTFS/etc/inetd.conf" 2>/dev/null | grep -v "^#" | grep -v "^$" | tee -a "$WORKDIR/scans/network_services.txt"

echo "--- 常见网络服务二进制 ---" | tee -a "$WORKDIR/scans/network_services.txt"
for svc in telnetd telnet ftpd ftp sshd dropbear snmpd snmp tftpd tftp ntp sntp dnsmasq dhcpd dhcp radvd ripd zebra ospfd cwmp; do
    found=$(find "$ROOTFS" -name "$svc" -type f 2>/dev/null)
    [ -n "$found" ] && echo "[+] $found" | tee -a "$WORKDIR/scans/network_services.txt"
done

# CWMP/TR-069 (运营商远程管理)
echo "--- CWMP/TR-069 ---" | tee -a "$WORKDIR/scans/network_services.txt"
find "$ROOTFS" -name "cwmp" -o -name "tr069" -o -name "tr069c" 2>/dev/null | while read f; do
    echo "[+] $f" | tee -a "$WORKDIR/scans/network_services.txt"
    strings "$f" | grep -iE "download|upgrade|reboot|factory|config|execute" | head -10 | tee -a "$WORKDIR/scans/network_services.txt"
done
```

### 2.6 启动脚本入口分析

```bash
# === 检查 init 脚本中的 Web 服务启动 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "--- 启动脚本 Web 服务注册 ---"
grep -RInaE 'start\(|procd_set_param|service_start|daemon' "$ROOTFS"/etc/init.d 2>/dev/null \
    | grep -iE 'http|www|web|lighttpd|uhttpd|goahead|nginx|boa' | head -20
```

### 2.7 Web 入口清单输出

模块二最终输出：

```markdown
## Web 入口清单

### Web 服务二进制
| 二进制 | 路径 | 架构 |
|--------|------|------|

### CGI 端点
| # | 端点 | 功能分类 | 风险提示 |
|---:|------|---------|---------|

### UPnP/SOAP 接口
| # | 服务描述文件 | Action | 外部输入参数 | 风险 |
|---:|------------|--------|-------------|------|

### 其他网络服务
| # | 服务 | 二进制 | 协议 | 
|---:|------|--------|------|

### 脚本入口
| 类型 | 数量 | 详情 |
|------|------|------|
| Lua | <N> | |
| PHP  | <N> | |
| Python | <N> | |
| Shell CGI | <N> | |
```

---

## 模块三：认证边界识别模块

### 3.0 模块目标

从 Web 入口清单出发，识别哪些接口直接绕过或不需要认证检查 (preauth)，输出疑似 preauth 接口列表。

### 3.1 认证框架检测

```bash
# === 检测认证机制 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "=== 认证框架检测 ===" | tee "$WORKDIR/scans/auth_boundary.txt"

# 从 Web 二进制中搜索认证函数
for webbin in $(find "$ROOTFS" -name "web" -o -name "httpd" -o -name "goahead" -o -name "boa" 2>/dev/null); do
    echo "--- $(basename $webbin) ---" | tee -a "$WORKDIR/scans/auth_boundary.txt"
    strings "$webbin" | grep -iE "login|logout|auth|session|token|cookie|password|user|admin|credential|verify" | sort -u | head -30 | tee -a "$WORKDIR/scans/auth_boundary.txt"
done

# 从 UPnP 中搜索
for upnpbin in $(find "$ROOTFS" -name "upnp" -o -name "upnpd" 2>/dev/null); do
    echo "--- $(basename $upnpbin) ---" | tee -a "$WORKDIR/scans/auth_boundary.txt"
    strings "$upnpbin" | grep -iE "auth|security|tr064|login|password|cert|access" | sort -u | head -20 | tee -a "$WORKDIR/scans/auth_boundary.txt"
done
```

### 3.2 认证豁免标记搜索

```bash
# === 搜索认证豁免关键字 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

# 多种框架的认证豁免标记:
grep -RInaE 'noauth|no_auth|skip_auth|skipauth|public|whitelist|before_login|preauth|allow_guest|guest_ok|anonymous' \
    "$ROOTFS"/etc "$ROOTFS"/www "$ROOTFS"/usr 2>/dev/null | grep -vE '^Binary' | head -40 | tee -a "$WORKDIR/scans/auth_boundary.txt"

# 检查认证中间件/函数:
grep -RInaE 'check_auth|require_auth|verify_session|valid_token|is_logged|login_required|need_login' \
    "$ROOTFS"/etc "$ROOTFS"/www "$ROOTFS"/usr 2>/dev/null | grep -vE '^Binary' | head -30 | tee -a "$WORKDIR/scans/auth_boundary.txt"
```

### 3.3 逐文件认证检查 (多语言)

```bash
# === 对每个入口文件检查是否有认证逻辑 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

# --- Lua 入口 ---
for f in $(find "$ROOTFS" \( -path '*/www/*' -o -path '*/lua/*' \) -name '*.lua' -type f 2>/dev/null); do
    has_auth=$(grep -cE 'session|auth|login|token|credential|password|check_login' "$f" 2>/dev/null)
    has_input=$(grep -cE 'arg\[|FORM\[|QUERY|ngx\.var|cgilua|req\.body|io\.read' "$f" 2>/dev/null)
    if [ "$has_input" -gt 0 ] && [ "$has_auth" -eq 0 ]; then
        echo "⚠ PREAUTH? $f (有输入处理, 无认证检查)" | tee -a "$WORKDIR/scans/auth_boundary.txt"
    fi
done

# --- Shell CGI ---
for f in $(find "$ROOTFS" \( -path '*/cgi-bin/*' -o -path '*/cgi/*' \) -name '*.sh' -type f 2>/dev/null); do
    has_auth=$(grep -cE 'session|auth|login|token|credential|password|check' "$f" 2>/dev/null)
    has_input=$(grep -cE 'QUERY_STRING|POST|read|cat|echo' "$f" 2>/dev/null)
    if [ "$has_input" -gt 0 ] && [ "$has_auth" -eq 0 ]; then
        echo "⚠ PREAUTH? $f (有输入处理, 无认证检查)" | tee -a "$WORKDIR/scans/auth_boundary.txt"
    fi
done

# --- PHP 入口 ---
for f in $(find "$ROOTFS" \( -path '*/www/*' -o -path '*/htdocs/*' \) -name '*.php' -type f 2>/dev/null); do
    has_auth=$(grep -cE 'session|auth|login|token|credential|password|check_login|require_login' "$f" 2>/dev/null)
    has_input=$(grep -cE '\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|php://input' "$f" 2>/dev/null)
    if [ "$has_input" -gt 0 ] && [ "$has_auth" -eq 0 ]; then
        echo "⚠ PREAUTH? $f (有输入处理, 无认证检查)" | tee -a "$WORKDIR/scans/auth_boundary.txt"
    fi
done
```

### 3.4 UPnP/SOAP 接口认证状态

```bash
# === UPnP 接口认证状态 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

for xml in $(find "$ROOTFS" -name "*.xml" -path "*/upnp/*" 2>/dev/null); do
    filename=$(basename "$xml")
    has_input=$(grep -c "direction>in<" "$xml" 2>/dev/null)
    has_auth=$(grep -ic "auth\|security\|require\|verify\|certificate" "$xml" 2>/dev/null)
    
    if [ "$has_input" -gt 0 ]; then
        if [ "$has_auth" -eq 0 ]; then
            echo "[!] $filename: 有外部输入参数但 XML 中无认证定义 → 疑似 pre-auth" | tee -a "$WORKDIR/scans/auth_boundary.txt"
            grep -B3 "direction>in<" "$xml" | grep "<name>" | sed 's/.*<name>/    param: /;s/<\/name>//' | tee -a "$WORKDIR/scans/auth_boundary.txt"
        fi
    fi
done

# 高影响操作审核
echo "--- 高影响操作 ---" | tee -a "$WORKDIR/scans/auth_boundary.txt"
for xml in "$ROOTFS/etc/upnp/"*.xml 2>/dev/null; do
    grep -l "Reboot\|FactoryReset\|Upgrade\|SetPersistent\|Download" "$xml" 2>/dev/null | while read f; do
        echo "[!] $(basename $f): 包含高影响操作" | tee -a "$WORKDIR/scans/auth_boundary.txt"
    done
done
```

### 3.5 协议层 Preauth 判断

对于非 Web 的网络服务 (DHCP, ICMPv6, DNS 等)：

```bash
# === 按协议层判断 preauth ===
# 链路层协议 (L2): 总是 preauth
#   - ICMPv6 ND/RA/RS (radvd, odhcp6c)
#   - ARP, DHCP (L2广播阶段), PPPoE Discovery

# 网络层协议 (L3): 通常 preauth
#   - ICMPv6, IPsec IKE, OSPF, BGP

# 传输层无连接 (L4 UDP): 通常 preauth (无会话)
#   - DNS (dnsmasq), NTP, SNMP, TFTP

# 传输层有连接 (L4 TCP) + 应用层认证: 半 preauth
#   - SSH (有用户认证), HTTP/HTTPS (取决于路由配置)

# 用于判断的命令:
BIN=<network_service_binary>

# 检查网络 I/O 类型:
NET_TYPE=$(objdump -T "$BIN" 2>/dev/null | grep -oE 'recvmsg|recvfrom|recv\b' | head -1)
case "$NET_TYPE" in
    recvmsg) echo "L3: 原始套接字 → 大概率 preauth" ;;
    recvfrom) echo "L4 UDP: 无连接 → 可能 preauth" ;;
    recv) echo "L4 TCP: 有连接 → 需检查应用层认证" ;;
esac

# 检查是否依赖会话:
strings "$BIN" | grep -ciE 'session|login|auth|password|token' 2>/dev/null
# 0 → 大概率 preauth; >5 → 有认证机制
```

### 3.6 Preauth 风险分类

| 风险等级 | 条件 | 示例 |
|:---:|---|---|
| 🔴 **关键** | preauth + 直接调用 system/popen + 参数可控 | 未认证 CGI 调用 shell |
| 🔴 **高** | preauth + 调用底层协议解析 (recvmsg/recvfrom) + 变长结构 | 未认证协议处理器 |
| 🟡 **中** | preauth + 文件操作 (fopen/fwrite) + 路径部分可控 | 未认证配置写入 |
| 🟢 **低** | preauth + 仅读取数据 + 无写操作 | 未认证信息泄露 |

### 3.7 认证边界输出

```markdown
## Preauth 接口清单

### Web Preauth 接口
| # | 入口路径 | 类型 | 输入参数 | 无认证证据 | 风险等级 |
|---:|---|---|---|---|---|

### 协议层 Preauth 服务
| # | 二进制 | 协议 | I/O类型 | 无认证证据 | 风险等级 |
|---:|---|---|---|---|---|

### 已认证接口 (不在分析优先级中)
| # | 入口路径 | 认证方式 | 说明 |
|---:|---|---|---|
```

---

## 模块四：危险函数与数据流分析模块

### 4.0 模块目标

这是最核心的模块。从 preauth 接口出发，追踪用户输入参数到危险函数的完整调用链，分析过滤逻辑，输出按风险排序的危险调用链。

### 4.1 危险函数分类体系

```
等级D (Deadly — 命令执行, 权重x3):
    system, popen
    → 调用 /bin/sh -c, 直接解释 shell 元字符

等级E (Execute — 程序执行, 权重x2):
    execl, execlp, execle, execv, execvp, execve, execvpe
    → 直接执行程序, 参数可能可控

等级F (Format — 格式化字符串, 单独x1 / 与D结合x3):
    sprintf, snprintf, vsprintf, vasprintf
    → 如果结果传给 system() → 命令注入

等级B (Buffer — 缓冲区, 权重x2):
    strcpy, strcat, gets
    → 无界字符串复制, 栈缓冲区溢出

等级M (Memory — 内存, 权重x1):
    memcpy, memmove
    → 如果长度参数可控, 可导致堆溢出或任意写

等级W (Write — 文件/配置写入, 权重x2):
    fopen+fwrite, nvram_set, uci_set, config_write
    → 配置注入或任意文件写
```

### 4.2 全量危险函数扫描 (ELF 二进制)

```bash
# === 全量危险函数扫描 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "=== 全量危险函数扫描 ===" | tee "$WORKDIR/scans/dangerous_functions.txt"

for bin in "$ROOTFS"/bin/* "$ROOTFS"/sbin/* "$ROOTFS"/usr/bin/* "$ROOTFS"/usr/sbin/*; do
    [ ! -f "$bin" ] && continue
    file "$bin" | grep -q ELF || continue
    name=$(basename "$bin")
    
    # D级: 命令执行
    d_system=$(objdump -T "$bin" 2>/dev/null | grep -c " system$")
    d_popen=$(objdump -T "$bin" 2>/dev/null | grep -c " popen$")
    d_score=$((d_system * 3 + d_popen * 3))
    
    # E级: 程序执行
    e_score=$(objdump -T "$bin" 2>/dev/null | grep -cE "execl|execlp|execle|execv|execvp|execve")
    
    # F级: 格式化
    f_score=$(objdump -T "$bin" 2>/dev/null | grep -cE "snprintf|sprintf\b|vsprintf|vasprintf")
    
    # B级: 缓冲区
    b_score=$(objdump -T "$bin" 2>/dev/null | grep -cE "strcpy|strcat|gets")
    
    # M级: 内存
    m_score=$(objdump -T "$bin" 2>/dev/null | grep -cE "\bmemcpy\b|\bmemmove\b")
    
    total=$((d_score + e_score + f_score + b_score + m_score))
    
    if [ "$total" -gt 0 ]; then
        printf "[%-15s] D:%d E:%d F:%d B:%d M:%d = %d\n" \
            "$name" "$d_score" "$e_score" "$f_score" "$b_score" "$m_score" "$total" \
            | tee -a "$WORKDIR/scans/dangerous_functions.txt"
        
        # 详细记录
        objdump -T "$bin" 2>/dev/null | grep -E "system|popen|execl|execlp|execle|execv|execvp|execve|snprintf|sprintf\b|strcpy|strcat|gets|memcpy|memmove" \
            | awk -v bin="$name" '{printf "  [%s] %s @ %s\n", bin, $6, $2}' \
            >> "$WORKDIR/scans/dangerous_functions_detail.txt"
    fi
done | sort -t= -k2 -rn
```

### 4.3 system() + sprintf() 交叉筛选

命令注入的最强信号：

```bash
# === 最高风险候选 (system + sprintf 同时存在) ===
echo "=== system + sprintf/snprintf 交叉 ===" | tee "$WORKDIR/scans/highest_risk.txt"

for bin in "$ROOTFS"/bin/* "$ROOTFS"/sbin/*; do
    [ ! -f "$bin" ] && continue
    file "$bin" | grep -q ELF || continue
    name=$(basename "$bin")
    
    has_system=$(objdump -T "$bin" 2>/dev/null | grep -c " system$")
    has_snprintf=$(objdump -T "$bin" 2>/dev/null | grep -c "snprintf")
    has_sprintf=$(objdump -T "$bin" 2>/dev/null | grep -c " sprintf$")
    
    if [ "$has_system" -gt 0 ] && [ $((has_snprintf + has_sprintf)) -gt 0 ]; then
        echo "[!!!] $name — system:$has_system snprintf:$has_snprintf sprintf:$has_sprintf" \
            | tee -a "$WORKDIR/scans/highest_risk.txt"
        echo "$name" >> "$WORKDIR/scans/critical_bins.txt"
    fi
done
```

### 4.4 多语言危险函数搜索

```bash
# === Shell 脚本危险函数 ===
for f in $(find "$ROOTFS" \( -name '*.sh' -o -name '*.cgi' \) -type f 2>/dev/null); do
    hits=$(grep -cE 'system\(|popen\(|exec\(|eval\b|\`.*\`|\$\(.*\)' "$f" 2>/dev/null)
    [ "$hits" -gt 0 ] && echo "[Shell] $f: $hits 处危险调用"
done

# === Lua 危险函数 ===
for f in $(find "$ROOTFS" -name '*.lua' -type f 2>/dev/null); do
    hits=$(grep -cE 'os\.execute|io\.popen|loadstring|dofile' "$f" 2>/dev/null)
    [ "$hits" -gt 0 ] && echo "[Lua] $f: $hits 处危险调用"
done

# === PHP 危险函数 ===
for f in $(find "$ROOTFS" -name '*.php' -type f 2>/dev/null); do
    hits=$(grep -cE 'system\(|exec\(|shell_exec\(|passthru\(|popen\(|proc_open\(|eval\(|assert\(' "$f" 2>/dev/null)
    [ "$hits" -gt 0 ] && echo "[PHP] $f: $hits 处危险调用"
done
```

### 4.5 命令模板字符串搜索 (关键步骤)

```bash
# === 命令模板搜索 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

echo "=== 命令模板搜索 ===" | tee "$WORKDIR/scans/command_templates.txt"

# 只在 system() 导入的二进制中搜索
for bin in $(cat "$WORKDIR/scans/critical_bins.txt" 2>/dev/null); do
    binpath=$(find "$ROOTFS" -name "$bin" -type f 2>/dev/null | head -1)
    [ ! -f "$binpath" ] && continue
    
    # 跳过确认的 CLI 工具
    case "$bin" in iptables|ebtables|ip6tables|ip|tc|brctl|busybox|ash|sh) continue ;; esac
    
    echo "--- $bin ---" | tee -a "$WORKDIR/scans/command_templates.txt"
    
    # 核心: 包含 %s 且与 shell 命令相关的字符串
    templates=$(strings "$binpath" | grep -E "%s|%d" | grep -iE "upg|ping|trace|iptables|ifconfig|echo|cat |rm |cp |mv |wget|tftp|telnet|reboot|flash|system|/bin/|/tmp/" | head -20)
    
    if [ -n "$templates" ]; then
        echo "$templates" | tee -a "$WORKDIR/scans/command_templates.txt"
        echo "$templates" > "$WORKDIR/scans/${bin}_templates.txt"
    else
        echo "  (未发现命令模板)" | tee -a "$WORKDIR/scans/command_templates.txt"
    fi
done
```

### 4.6 输入参数来源追踪

```bash
# === 参数来源追踪 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

for bin_name in $(cat "$WORKDIR/scans/critical_bins.txt" 2>/dev/null); do
    bin=$(find "$ROOTFS" -name "$bin_name" -type f 2>/dev/null | head -1)
    [ ! -f "$bin" ] && continue
    
    echo "--- $bin_name ---" | tee -a "$WORKDIR/scans/parameter_sources.txt"
    
    # 搜索可能的参数名
    echo "  参数名:" | tee -a "$WORKDIR/scans/parameter_sources.txt"
    strings "$bin" | grep -E "New[A-Z][a-z]+|Set[A-Z][a-z]+|Get[A-Z][a-z]+" | sort -u | head -20 | tee -a "$WORKDIR/scans/parameter_sources.txt"
    
    # 搜索 URL/路径
    echo "  接口路径:" | tee -a "$WORKDIR/scans/parameter_sources.txt"
    strings "$bin" | grep -E "^/[a-z]" | sort -u | head -10 | tee -a "$WORKDIR/scans/parameter_sources.txt"
    
    # 搜索服务 URN
    echo "  服务 URN:" | tee -a "$WORKDIR/scans/parameter_sources.txt"
    strings "$bin" | grep -E "urn:" | sort -u | head -10 | tee -a "$WORKDIR/scans/parameter_sources.txt"
done
```

### 4.7 参数过滤逻辑分析

```bash
# === 检查过滤/验证/转义 ===
ENTRY=<file_path>

echo "=== 过滤检查 ==="

# 白名单模式 (安全):
grep -nE 'if.*\b(in|not in|!=|==)|\"start\"|\"stop\"|\"restart\"|\"enable\"|\"disable\"|\"on\"|\"off\"' "$ENTRY" 2>/dev/null

# 黑名单模式 (可能可绕过):
grep -nE 'gsub.*[;&|\`\$]|erase|remove|strip|escape|sanitize|filter|deny|block' "$ENTRY" 2>/dev/null

# 转义:
grep -nE 'escapeshellarg|quotemeta|addslashes|htmlspecialchars|urlencode' "$ENTRY" 2>/dev/null

# 长度限制:
grep -nE 'strlen|len\(|length\(|size\(|\.length' "$ENTRY" 2>/dev/null

# 在二进制中搜索校验函数名
strings "$ENTRY" | grep -iE "validate|filter|sanitize|check.*input|whitelist|blacklist" 2>/dev/null

# 判定:
#   白名单 = 通常安全
#   黑名单 = 可能可绕过
#   转义 = 需要检查转义完整性
#   无任何过滤 = 🔴 极高风险
```

### 4.8 误报排除引擎

```bash
# === 误报排除 ===
echo "=== 误报排除 ===" | tee "$WORKDIR/scans/false_positive_exclusion.txt"

# 排除规则:
# 规则1: 非守护进程 — CLI工具, 被其他程序调用, 本身不监听端口
# 规则2: 命令模板不含%s — system()使用硬编码命令, 无外部参数注入
# 规则3: 纯内部IPC — 通过共享内存/消息队列接收命令, 不直接暴露网络
# 规则4: 参数来自可信源 — 虽然接收外部输入但经过严格验证或来自认证用户
# 规则5: 无外部输入入口 — 二进制虽有system()但所有参数内部生成/硬编码

for bin_name in $(cat "$WORKDIR/scans/critical_bins.txt" 2>/dev/null); do
    bin=$(find "$ROOTFS" -name "$bin_name" -type f 2>/dev/null | head -1)
    [ ! -f "$bin" ] && continue
    
    is_cli=0
    case "$bin_name" in
        iptables|ebtables|ip6tables|ip|tc|brctl|busybox|ash|sh|bash|mount|umount|insmod|rmmod|lsmod) is_cli=1 ;;
    esac
    
    has_template=$(strings "$bin" | grep -cE "%s|%d")
    has_cgi=$(strings "$bin" | grep -c "\.cgi")
    has_url=$(strings "$bin" | grep -cE "^/(ctrlt|ctrlu|desc|api|cgi|evt|icon)")
    
    verdict="保留"
    reasons=""
    
    [ "$is_cli" -eq 1 ] && verdict="排除" && reasons="$reasons CLI工具;"
    [ "$has_template" -eq 0 ] && verdict="降级" && reasons="$reasons system()无%S模板;"
    [ "$has_cgi" -eq 0 ] && [ "$has_url" -eq 0 ] && verdict="待确认" && reasons="$reasons 未发现外部入口;"
    
    printf "[%s] %s — %s\n" "$verdict" "$bin_name" "$reasons" | tee -a "$WORKDIR/scans/false_positive_exclusion.txt"
done
```

### 4.9 风险评分模型

对每个候选漏洞点使用以下评分模型（满分 10 分）：

| 维度 | 权重 | 评分标准 |
|------|------|---------|
| 网络可达性 | 3分 | 3=明确监听端口 / 2=可能暴露 / 1=仅本地 / 0=非网络 |
| 认证要求 | 3分 | 3=无需认证 / 2=弱认证 / 1=需认证但可能绕过 / 0=强认证 |
| 危险函数 | 2分 | 2=system()/popen() / 1=exec家族 / 0=仅sprintf/strcpy |
| 参数可控性 | 2分 | 2=完全可控(string类型) / 1=部分可控 / 0=不可控 |

### 4.10 命令注入专项判定

```
命令注入判定五步法:

Step 1: 确认存在命令执行点
  system() / popen() / os.execute() / io.popen()

Step 2: 追溯所有参数来源
  搜索变量赋值和拼接, 向上追溯到外部输入

Step 3: 评估过滤充分性
  白名单 → 安全 (除非白名单逻辑有bug)
  黑名单 → 检查是否遗漏元字符: ; | & ` $ ( ) < > \n \r ' " \ # ! ~ * ? [ ] { }
  转义   → 检查是否正确使用 (escapeshellarg vs str_replace)
  无过滤 → 🔴 极高概率命令注入

Step 4: 确认能否传入 Shell 元字符
  如果 ; | & ` $(...) 中任何一个可传入 → 命令注入

Step 5: 区分 popen/fork+exec
  popen("command") → 经过 /bin/sh → 命令注入可能
  execve("/bin/ping", ["ping", arg]) → 不经过 shell → 无法注入
```

### 4.11 协议解析漏洞判定

```
协议解析漏洞判定六步法:

Step 1: 确认解析变长结构 (TLV / option / 变长 header)
Step 2: 确认 length/size 字段来自网络报文
Step 3: 确认 length 派生出循环控制变量 (count = length / N)
Step 4: 确认循环内存在写入操作 (mov / memcpy)
Step 5: 确认写入目标缓冲区容量固定或有限
Step 6: 确认缺少 count 或 buffer_size 上限检查

→ 6/6 = 极高概率 OOB R/W → 5/6 = 高风险 → ≤3/6 = 需进一步分析
```

### 4.12 数据流追踪模板

对每个 preauth + 危险函数的组合，按以下模板追踪：

```
[数据流追踪模板]

入口: [HTTP GET / POST / SOAP / ICMPv6 RA / DHCP Request / ...]
  ↓
参数提取点: [getenv("QUERY_STRING") / $_GET['ip'] / recvmsg → buf+offset / libxmlapi解析]
  ↓ 参数名: [NewStatusURL / ip / hostname / dns_server / ...]
  ↓ 类型: [字符串 / 二进制 / 结构体]
参数传递:
  ↓ 变量: [user_input_var]
  ↓ 赋值: [strcpy(dest, getenv("QUERY_STRING"))]
  ↓ 拼接: [snprintf(cmd, size, "upg -g -U %s ... -r %s", user_input1, user_input2)]
  ↓ 缓冲区: [stack_buf[512] / heap_malloc(n)]
过滤检查: [无 / 白名单(PASS) / 黑名单(BYPASS?) / 转义(CHECK) / 长度限制(VALUE)]
  ↓
汇聚点: [system(cmd) / memcpy(dst, src, user_len) / fopen(user_path, "w")]
  ↓ 危险函数类型: [命令执行 / 缓冲区溢出 / 任意文件写 / 配置注入]
  ↓
漏洞效果: [RCE风险 / DoS / 信息泄露 / 权限提升]
```

### 4.13 危险调用链输出

模块四最终输出：

```markdown
## 危险调用链

### 风险排序

| 优先级 | 二进制 | 漏洞类型 | 评分 | 关键证据 |
|--------|--------|---------|------|---------|

### Chain #N: [调用链名称]

| 步骤 | 位置 | 操作 | 证据等级 |
|:---:|---|---|:---:|
| 1 | <file:line> | <input extraction> | L3 |
| 2 | <file:line> | <string formatting> | L3 |
| 3 | <file:line> | <dangerous call> | L3 |

**过滤检查:** <结果>
**判定:** <🔴/🟡/🟢> <结论>
**需要人工确认:** <列表>

---
汇总:
- 🔴 关键: <N> 个调用链
- 🟡 中等: <N> 个调用链
- 🟢 低/误报: <N> 个调用链
```

---

## 模块五：本地仿真验证模块

> **约束**: 仅限本地 QEMU/隔离环境; 所有命令标记为 SUGGEST; 不自动执行

### 5.0 模块目标

对模块四识别的高风险调用链，输出本地验证方案。所有命令仅建议，由用户手动执行。

### 5.1 安全约束

```
禁止清单:
  - 禁止向公网 IP 发送请求
  - 禁止在真实设备上测试
  - 禁止执行 system() 或 popen() 的真实调用
  - 禁止启动完整的系统仿真 (除非在隔离的虚拟网络环境中)

允许清单:
  - QEMU 用户态加载二进制 (验证可加载)
  - QEMU -strace 观察系统调用 (到 /dev/mem 失败退出是正常的)
  - 编译并运行最小 C 复现程序 (仅打印命令, 不执行)
  - 在回环接口 (127.0.0.1) 上测试本地模拟服务
  - 使用 echo/id/whoami/touch /tmp/poc_ok 等无害命令
```

### 5.2 QEMU 用户态加载验证

```bash
# === QEMU 用户态验证 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)
QEMU="$QEMU_BIN"   # 来自模块1.4

echo "=== QEMU 用户态验证 ===" | tee "$WORKDIR/logs/emulation.log"

if [ -z "$QEMU" ]; then
    echo "[-] QEMU验证跳过: 不支持的架构或无QEMU工具"
elif ! which "$QEMU" >/dev/null 2>&1; then
    echo "[*] 安装 QEMU 用户态工具..."
    sudo apt install qemu-user-static -y
fi

# 基准测试: busybox
if timeout 5 "$QEMU" -L "$ROOTFS" "$ROOTFS/bin/busybox" echo "QEMU_OK" 2>/dev/null | grep -q "QEMU_OK"; then
    echo "[✓] QEMU 工作正常" | tee -a "$WORKDIR/logs/emulation.log"
fi

# 对 Top-3 候选进行加载验证
for bin_name in $(cat "$WORKDIR/scans/critical_bins.txt" 2>/dev/null | head -3); do
    bin_path=$(find "$ROOTFS" -name "$bin_name" -type f 2>/dev/null | head -1)
    [ ! -f "$bin_path" ] && continue
    
    echo "[*] 验证 $bin_name ..." | tee -a "$WORKDIR/logs/emulation.log"
    timeout 5 "$QEMU" -strace -L "$ROOTFS" "$bin_path" 2>&1 | head -50 \
        | tee "$WORKDIR/emulation/${bin_name}_strace.txt"
    
    if grep -q "open.*lib\|mmap\|read" "$WORKDIR/emulation/${bin_name}_strace.txt" 2>/dev/null; then
        echo "  [✓] $bin_name 可加载 (so库正常链接)" | tee -a "$WORKDIR/logs/emulation.log"
    fi
    if grep -q "/dev/mem\|Could not" "$WORKDIR/emulation/${bin_name}_strace.txt" 2>/dev/null; then
        echo "  [*] 正常退出: 硬件依赖 (/dev/mem等)" | tee -a "$WORKDIR/logs/emulation.log"
    fi
done
```

### 5.3 最小复现程序自动生成

```bash
# === 最小复现程序 ===
ROOTFS=$(cat "$WORKDIR/rootfs_path.txt" 2>/dev/null)

for bin_name in $(cat "$WORKDIR/scans/critical_bins.txt" 2>/dev/null | head -3); do
    bin=$(find "$ROOTFS" -name "$bin_name" -type f 2>/dev/null | head -1)
    [ ! -f "$bin" ] && continue
    
    # 从二进制中提取命令模板
    cmd_template=$(strings "$bin" | grep -E "%s.*%s" | grep -iE "upg|ping|trace|iptables|system|exec|cmd" | head -1)
    [ -z "$cmd_template" ] && continue
    
    echo "[*] 为 $bin_name 生成最小复现 (模板: $cmd_template)" | tee -a "$WORKDIR/logs/emulation.log"
    
    cat > "$WORKDIR/emulation/poc_${bin_name}.c" << POCEOF
/*
 * 最小复现程序 — 模拟固件中 $bin_name 的命令注入代码路径
 * 
 * 安全声明: 本程序仅打印命令, 不实际调用 system()
 *           严禁用于对真实设备的测试
 */
#include <stdio.h>
#include <string.h>

void vulnerable_func(const char *user_input) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "$cmd_template", user_input, user_input);
    printf("构建的命令:\\n  %s\\n", cmd);
    printf("[!] 真实固件中这里调用 system(cmd), 本演示仅打印。\\n");
}

int main() {
    printf("=== 正常输入 ===\\n");
    vulnerable_func("http://example.com/ok");
    printf("\\n=== 恶意输入 (shell元字符) ===\\n");
    vulnerable_func("; id; whoami; ");
    return 0;
}
POCEOF

    gcc -o "$WORKDIR/emulation/poc_${bin_name}" "$WORKDIR/emulation/poc_${bin_name}.c" 2>&1 && {
        echo "  [✓] 编译成功" | tee -a "$WORKDIR/logs/emulation.log"
        "$WORKDIR/emulation/poc_${bin_name}" 2>&1 | tee "$WORKDIR/emulation/poc_${bin_name}_output.txt"
    }
done
```

### 5.4 QEMU 系统仿真方案 (可选, 需用户手动执行)

```bash
# === SUGGEST: QEMU 启动 (根据架构选择) ===
# 以下命令仅作建议, 需要用户根据实际情况调整, 手动执行

# x86_64:
# qemu-system-x86_64 -m 256M -enable-kvm -hda <image> \
#   -netdev tap,id=net0,ifname=tap-dev,script=no \
#   -device e1000,netdev=net0,mac=52:54:00:12:34:56 -nographic

# ARM:
# qemu-system-arm -m 256M -kernel <zImage> -dtb <dtb> \
#   -netdev tap,id=net0,ifname=tap-dev -device virtio-net,netdev=net0 -nographic

# MIPS:
# qemu-system-mips -m 256M -kernel <vmlinux> \
#   -netdev tap,id=net0,ifname=tap-dev -device virtio-net,netdev=net0 -nographic

# 隔离网络配置:
# ip tuntap add tap-dev mode tap && ip link set tap-dev up
# ip addr add 192.168.100.1/24 dev tap-dev
```

### 5.5 验证方案生成模板

```markdown
### 验证方案 #N: [调用链名称]

**目标:** 验证参数 [param] 是否到达 [dangerous_function]

**QEMU 访问方式:**
- Web: `curl http://192.168.100.10/cgi-bin/xxx.cgi?ip=<test>`
- 协议: 使用 scapy 构造报文从 tap-dev 发送

**无害验证步骤:**
1. 正常参数 → 预期正常响应
2. 边界参数: A*256 → 预期正常拒绝或截断
3. 元字符探测: `; echo VULN_TEST` → ⚠ 仅验证过滤

**观察要点:**
- [ ] 响应中包含 "VULN_TEST" (命令执行成功)
- [ ] 响应中包含截断后的 ip (过滤生效)
- [ ] 日志中出现 crash/segfault (OOB 触发)

**安全提示:** 仅使用 tap-dev 隔离网络; 仅使用 echo/id/uname 等无害命令
```

### 5.6 验证结果记录模板

```markdown
### 验证记录 #N

**日期/时间:** <ISO8601>
**环境:** QEMU user-mode / tap-dev 隔离网络

**测试输入:**
| # | 输入 | 预期 | 实际 | 判定 |
|---:|---|---|---|---|
| 1 | 正常参数 | 正常执行 | <实际> | <判定> |
| 2 | 恶意参数 | (取决于过滤) | <实际> | <判定> |

**结论:**
- [ ] 正常链路验证通过
- [ ] 参数可达危险函数 (已确认 / 未确认)
- [ ] 过滤存在且充分 / 过滤存在但可绕过 / 无过滤
- [ ] 未观察到异常 / 观察到异常行为 (描述)
```

---

## 模块六：自动报告生成模块

### 6.0 模块目标

基于模块一到五的所有输出，自动生成结构化漏洞分析报告。

### 6.1 报告结构

```markdown
================================================================================
  [固件名称] 自动化漏洞分析报告
  生成时间: <ISO8601>
  分析引擎: Router Firmware Auto-Analysis Skill v3.0
  分析路线: 固件解包 → Web入口 → 认证边界 → 危险函数 → 本地验证 → 报告
================================================================================

## 1. 固件基本信息

| 字段 | 值 |
|---|---|
| 固件文件 | [模块1] |
| 固件格式 | [模块1] |
| 文件大小 | [模块1] |
| MD5 / SHA256 | [模块1] |
| rootfs 路径 | [模块1] |
| CPU 架构 | [模块1] |
| 内核版本 | [模块1] |
| libc 类型 | [模块1] |
| ELF 二进制数 | [模块1] |
| 配置文件数 | [模块1] |

## 2. Web 服务信息

| 字段 | 值 |
|---|---|
| Web 服务器 | [模块2] |
| CGI 入口 | [模块2: N个, 按功能分类] |
| UPnP/SOAP 接口 | [模块2: N个Action, M个外部输入参数] |
| 脚本语言 | [模块2: Lua/ PHP/ Python/ Shell CGI 数量] |
| 其他网络服务 | [模块2: telnetd, cwmp, dhcp, dns, ...] |

## 3. 攻击面总览

| 类别 | 数量 | 🔴关键 | 🟡中等 | 🟢低 |
|---|---|---|---|---|
| Preauth Web 接口 | | | | |
| Preauth 协议服务 | | | | |
| 需认证接口 | | | | |

## 4. 高风险接口

### P0: [二进制名] — [漏洞类型]

- **危险函数**: [PLT地址]
- **命令模板**: [模板字符串]
- **可控参数**: [参数名 (来自配置文件)]
- **认证状态**: [需要? / 推断依据]
- **数据流路径**:
```
  [网络请求] → [协议解析] → [参数提取] → [字符串拼接] → [危险函数] → [命令执行]
  ```
- **攻击可行性**: [评估]
- **修复建议**: [具体措施]

### P1: [二进制名] — [漏洞类型]
[同上格式]

## 5. 漏洞触发路径

  ```
攻击者 (LAN内)
    │
    ▼
[服务端口] [协议类型]
    │
    ▼
[协议解析层]
    │
    ▼
[参数提取] 来自 [配置文件]
    │
    ▼
[字符串格式化] snprintf(buf, size, "[命令模板]", [用户输入])
    │
    ▼
[命令执行] system(buf) → /bin/sh -c "[命令]"
    │
    ▼
[shell 元字符注入] ; | & $() ` 被 shell 解释 → 以 root 权限执行
```

## 6. 是否需要认证

| 接口 | 认证要求 | 判断依据 | 可信度 |
|------|---------|---------|--------|
[模块3]

## 7. 本地验证结果

### QEMU 用户态验证
| 二进制 | 加载状态 | 退出原因 |
|--------|---------|---------|
[模块5]

### 最小复现验证
- 正常输入输出: [截图/文本]
- 恶意输入输出: [截图/文本]

### 验证局限性
- [ ] 未在完整系统仿真中启动服务
- [ ] 未实际发送网络请求
- [ ] 未动态观察 system() 调用

## 8. 误报分析

| 二进制 | 原风险 | 最终判定 | 排除/降级原因 |
|--------|--------|---------|-------------|
[模块4]

## 9. 修复建议

1. **输入校验**: 对参数添加白名单, 拒绝 shell 元字符
2. **替换危险函数**: 用 execve() 替代 system()
3. **权限隔离**: 以非 root 用户运行服务
4. **固件升级**: 升级到厂商已修复版本
5. **网络隔离**: 限制管理端口仅对可信 IP 开放

## 10. 安全边界说明

### 本报告范围
- [x] 静态分析 (strings / objdump / readelf / 配置解读)
- [x] QEMU 用户态验证 (二进制可加载确认)
- [x] 最小复现程序 (仅演示代码路径, 不实际执行命令)
- [ ] 完整 QEMU 系统仿真 (未进行)
- [ ] 真实设备测试 (未进行, 不允许)

### 使用限制
本报告仅供授权安全研究和教学使用。严禁用于对未授权设备的测试。

================================================================================
```

### 6.2 Agent 自动填充规则

| 报告章节 | 数据来源 |
|---------|---------|
| §1 固件基本信息 | `scans/firmware_summary.txt`, `architecture.txt` |
| §2 Web服务信息 | `scans/web_services.txt`, `web_cgi.txt`, `upnp_interfaces.txt` |
| §3 攻击面总览 | `scans/auth_boundary.txt` + 模块4排序结果 |
| §4 高风险接口 | `scans/highest_risk.txt`, `command_templates.txt`, `parameter_sources.txt` |
| §5 漏洞触发路径 | 模块4数据流分析 |
| §6 认证状态 | `scans/auth_boundary.txt` |
| §7 本地验证 | `logs/emulation.log`, `emulation/*_output.txt` |
| §8 误报分析 | `scans/false_positive_exclusion.txt` |
| §9 修复建议 | Agent 根据漏洞类型生成 |
| §10 安全边界 | 固定模板 + 根据实际执行勾选 |

---

## 附录A：HG532e / CVE-2017-17215 实际运行示例

### A.1 模块1输出摘要

```
rootfs: ./router HG532e/_extracted/.../rootfs/
架构: MIPS 32-bit Big Endian
内核: Linux 2.6.21.5
libc: uClibc 0.9.30
ELF总数: 44
QEMU: qemu-mips-static
```

### A.2 模块2输出摘要

```
Web二进制: bin/web (48个CGI端点, 含 excutecmd.cgi, remoteupg.cgi)
UPnP: 12个XML, DevUpg.xml: Upgrade + NewDownloadURL(in) + NewStatusURL(in)
其他: telnetd, cwmp, mic
```

### A.3 模块3输出摘要

```
Web认证: login.cgi/logout.cgi + Session管理 → 认证框架存在
UPnP认证: DevUpg.xml无auth要求 → Upgrade疑似pre-auth
```

### A.4 模块4输出摘要

```
全量扫描: 44 ELF → 16个导入system() → 10个同时有system+sprintf
命令模板发现:
  upnp: "upg -g -U %s -r %s -d -b" ← 最高危
  web:  4个upg命令模板含%s
  cms:  20+个ping/traceroute模板含%s
误报排除: 8个CLI工具排除, 4个降级
最终排序: P0=upnp(10分) > P1=web(8分) > P1=cms(6分)
```

### A.5 模块5输出摘要

```
QEMU验证: qemu-mips-static加载upnp成功 (在/dev/mem退出, 正常)
最小复现: poc_upnp.c编译运行成功
  正常: upg -g -U http://example.com/fw.bin ... -r http://example.com/status -d -b
  恶意: upg -g -U ... -r ;id; -d -b → 命令注入确认
```

### A.6 P0 发现与 CVE-2017-17215 对比

| 维度 | Skill 发现 | 公开 CVE | 匹配 |
|------|-----------|---------|------|
| 二进制 | bin/upnp | bin/upnp | ✓ |
| 函数链 | snprintf→system | snprintf→system | ✓ |
| 模板 | upg -g -U %s...-r %s... | 相同 | ✓ |
| 参数 | NewDownloadURL/NewStatusURL | 相同 | ✓ |
| 服务URN | urn:www-huawei-com:service:DeviceUpgrade:1 | 相同 | ✓ |
| 认证 | 推断无需认证 | 确认无需认证 | ✓ |

**结论**: 本 Skill 的自动化流程成功独立发现了 CVE-2017-17215 的所有关键要素。

---

## 附录B：常用命令速查表

### 固件解包
```bash
binwalk -Me --directory=_extracted <firmware>
7z x -orootfs <squashfs-file>                              # SquashFS-LZMA
unsquashfs -d rootfs <squashfs-file>                       # 标准 SquashFS
```

### 架构与系统
```bash
file <sample-elf>                                           # 判断架构
readelf -h <elf> | grep -E 'Machine|Class'                  # 详细架构
find <rootfs> -name '*.ko' | head -1 | xargs strings | grep 'vermagic'  # 内核版本
```

### 危险函数扫描
```bash
objdump -T <binary> | grep -E 'system|popen|exec|sprintf|strcpy|memcpy|gets'
strings <binary> | grep -E "%s|%d" | grep -iE "upg|ping|trace|iptables|/bin/"
strings <binary> | grep "\.cgi" | sort -u                   # CGI端点
strings <binary> | grep -iE "validate|filter|sanitize"      # 校验函数
```

### QEMU 验证
```bash
qemu-mips-static -L <rootfs> <rootfs>/bin/busybox echo "test"
qemu-mips-static -strace -L <rootfs> <rootfs>/bin/<target> 2>&1 | head -50
```

---

## 附录C：模块编排与异常恢复

| 异常 | 影响 | 恢复策略 |
|------|------|---------|
| 固件解包失败 (加密) | 全部 | 标注, 建议尝试已知密钥或公开解包工具 |
| rootfs 中无 ELF (纯脚本) | 模块2/4 | 改为脚本分析模式 |
| QEMU 不支持该架构 | 模块5 | 跳过 QEMU 验证, 仅做最小复现 |
| 所有候选都是误报 | 模块6 | 报告中如实说明"未发现明确漏洞" |
| 工具缺失 (binwalk/objdump) | 各自模块 | 自动 `sudo apt install` |
| 文件名含空格 | 全部 | 给路径加引号, 或 `cp` 到无空格路径 |

