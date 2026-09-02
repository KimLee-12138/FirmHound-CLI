# FirmHound 固件猎犬 · 小白全链路挖洞教程

> 从「下载一个固件」到「拿到一份漏洞报告」，全程手把手。  
> 第二队同学实战专用 · 结合历史 CVE 复现过的品牌开展未知漏洞挖掘。

---

## 0. 先回答你最关心的问题：用 Windows 还是 Linux？

**结论：用 WSL2（Windows 自带的 Linux 子系统），平时在 Windows 上操作即可。**

| 环节       | 用哪个环境                | 原因                                                    |
| -------- | -------------------- | ----------------------------------------------------- |
| 下载固件     | Windows 浏览器          | 直接下载到电脑                                               |
| **解包固件** | **WSL2 Ubuntu**（必须）  | 需要 `binwalk` / `sasquatch` / `unsquashfs` 这些 Linux 工具 |
| 静态分析     | **Windows 或 WSL 都行** | CLI 是纯 Python，Windows 直接跑                             |
| 人工审计     | 都行                   | 看报告文件即可                                               |
| 动态验证（可选） | WSL2（必须）             | 需要 QEMU                                               |

**简单说：解包必须走 WSL，分析在 Windows 就能跑。** 我们的 CLI 会自动识别 Windows/WSL，你不需要来回切换——装好 WSL 后，两条命令搞定全流程。

> 你们队之前已经装好了 WSL 工具链（binwalk、sasquatch、unsquashfs、mksquashfs 都已验证就绪）。

---

## 1. 准备工作（只做一次）

### 1.1 确认项目在电脑上的位置

项目文件夹：`C:\Users\22067\Desktop\揭榜挂帅——网络安全\`

**以后所有命令都在这个文件夹里执行**（叫"项目根目录"）。打开方式：

- 打开文件夹 → 在地址栏输入 `cmd` 回车 → 出现黑色命令行窗口
- 或按 `Win + R` 输入 `cmd` → 输入 `cd C:\Users\22067\Desktop\揭榜挂帅——网络安全` 回车

### 1.2 确认 Python 环境（一次性）

PS C:\Users\22067\Desktop\揭榜挂帅——网络安全> C:\Users\22067.workbuddy\binaries\python\envs\default\Scripts\python.exe scripts\run_e2e.py --rootfs "C:\Users\22067\Desktop\揭榜挂帅——网络安全\tmp\unpacked_DIR859_FW102b03.bin-0.extracted\squashfs-root" --out-dir runs\dir859_run1  
Traceback (most recent call last):  
File "C:\Users\22067\Desktop\揭榜挂帅——网络安全\scripts\run_e2e.py", line 274, in <module>  
raise SystemExit(main())

```^^

File "C:\Users\22067\Desktop\揭榜挂帅——网络安全\scripts\run_e2e.py", line 261, in main
result = analyze_rootfs(args.rootfs)
File "C:\Users\22067\Desktop\揭榜挂帅——网络安全\scripts\run_e2e.py", line 174, in analyze_rootfs
inventory = inventory_rootfs(rootfs)
File "C:\Users\22067\Desktop\揭榜挂帅——网络安全\tools\filesystem\inventory.py", line 30, in inventory_rootfs
if not path.is_file():
~~~~~~~~~~~~^^
File "C:\Users\22067\.workbuddy\binaries\python\versions\3.13.12\Lib\pathlib\_abc.py", line 482, in is_file
return S_ISREG(self.stat(follow_symlinks=follow_symlinks).st_mode)
~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "C:\Users\22067\.workbuddy\binaries\python\versions\3.13.12\Lib\pathlib\_local.py", line 515, in stat
return os.stat(self, follow_symlinks=follow_symlinks)
~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
OSError: [WinError 1920] 系统无法访问此文件。: 'C:\\Users\\22067\\Desktop\\揭榜挂帅——网络安全\\tmp\\unpacked\\_DIR859_FW102b03.bin-0.extracted\\squashfs-root\\tmp'
```

应该输出 `Python 3.13.x`。**以后用到 python 的地方，都用这个完整路径**（太长？可以复制到一个记事本里备用）。

> 小技巧：把下面这行存成一个 `run.bat` 放在项目根目录，双击就能进入环境：
>
> ```bat
> C:\Users\22067\.workbuddy\binaries\python\envs\default\Scripts\python.exe scripts\dev.py test
> ```

### 1.3 确认 WSL 就绪（一次性）

```bash
wsl -d Ubuntu-22.04 -- bash -lc "which binwalk unsquashfs sasquatch"
```

能看到三个路径就说明解包工具 OK。如果报错，先 `wsl --shutdown` 再试一次（WSL 偶尔抽风，重启就好）。

### 1.4 自检（跑通证明环境 OK）

```bat
C:\Users\22067\.workbuddy\binaries\python\envs\default\Scripts\python.exe scripts\dev.py test
```

最后一行看到 `188 passed` 就说明一切正常，可以开始挖洞了。

---

## 2. 第一步：选目标品牌，下载固件

结合你们队复现过的 CVE 品牌，优先选**还在更新固件的**产品（最新固件才有挖新洞的价值）。

| 品牌             | 复现过的型号（历史 CVE）                     | 官方固件下载入口                                               | 说明                                                |
| -------------- | ---------------------------------- | ------------------------------------------------------ | ------------------------------------------------- |
| **Tenda 腾达**   | AC15（CVE-2020-10987）               | <https://www.tenda.com.cn/api/product/help/AC15>       | AC15 最新 V15.03.05.19（2017 后未更新，可换 AC 系列新型号）       |
| **D-Link**     | DIR-859（CVE-2019-17621）、DIR-850L 等 | <https://support.dlink.com（FTP>: ftp://ftp2.dlink.com） | DIR 系列仍在更新，DIR-X 新系列也可看                           |
| **NETGEAR 网件** | R7000（CVE-2021-31802）              | <https://www.netgear.com/support/product/R7000.aspx>   | R7000 最新 1.0.11.216 / 1.0.12.216（2025-07 仍在发安全更新） |
| **TP-Link**    | Archer 系列（CVE-2020-9373）           | <https://www.tp-link.com/cn/support/download/>         | 搜索型号即可                                            |
| **华为**         | HG532e（CVE-2017-17215）             | <https://support.huawei.com>                           | 企业级产品更新频繁，可挖                                      |
| **MikroTik**   | RouterOS（CVE-2023-32154）           | <https://mikrotik.com/download>                        | RouterOS 7.x 持续更新，靶子多                             |

**新手建议选**：D-Link DIR-859（有现成复现经验 + 固件还在更新）或 NETGEAR R7000（官方持续发安全补丁，说明漏洞在被修，同类新洞概率高）。

下载时注意：

1. 选 **Router Firmware / 升级软件** 那一栏，别下用户手册；
2. 文件一般是 `.zip` 或 `.bin`，下载完**解压 zip**，拿到真正的 `.bin` 固件文件；
3. 记录下载的**版本号**（如 V1.0.12.216），后面报告要用。

---

## 3. 第二步：把固件放到指定文件夹

在项目根目录下建一个 `firmware_samples` 文件夹（CLI 的安全白名单允许目录），把你下载的固件放进去：

```
C:\Users\22067\Desktop\揭榜挂帅——网络安全\firmware_samples\
    └── DIR-859_Ax_FW_113b03.bin     ← 你的固件（举例）
```

> 注意：安全策略只允许分析 `firmware_samples/`、`runs/`、`tmp/`、`tests/fixtures/` 下的文件。固件放别处会被拒绝。

---

## 4. 第三步：解包固件（WSL 执行，关键一步）

固件是个"打包文件"，解包后才能看到里面的程序（httpd、upnpd、cgi 等）。**这一步必须在 WSL 里跑**。

在 cmd 窗口执行下面命令（一条搞定，会自动把 Windows 路径转成 WSL 路径）：

```bash
wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全 && binwalk -e -M firmware_samples/DIR-859_Ax_FW_113b03.bin -C /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全/tmp/unpacked"
```

参数解释：

- `-e` 提取；`-M` 递归提取（固件里可能还有嵌套的压缩层）
- `-C` 指定输出目录

跑完后检查解包结果：

```bash
wsl -d Ubuntu-22.04 -- bash -lc "ls /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全/tmp/unpacked"
```

**找 rootfs 目录**：一般叫 `squashfs-root`、`_rootfs`、`_squashfs`，里面有 `bin/`、`etc/`、`usr/`、`www/` 等目录。**后面分析就认准这个目录**。

> 如果 binwalk 没解出 squashfs-root：用 `sasquatch` 单独解：
>
> ```bash
> wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/c/.../tmp && sasquatch <固件名>.bin"
> ```
>
> 或者把固件文件本身拖进 WSL 里 `binwalk -e` 后人工找。

---

## 5. 第四步：跑 CLI 静态分析（重点！）

解包出 rootfs 后，回到 **Windows cmd**，执行：

```bat
C:\Users\22067\.workbuddy\binaries\python\envs\default\Scripts\python.exe -m fsa.cli analyze C:\Users\22067\Desktop\揭榜挂帅——网络安全\tmp\unpacked\<你找到的rootfs目录> --input-type rootfs --authorization-holder "设备所有者" --run-id hunt1
```

> 把 `<你找到的rootfs目录>` 换成第 4 步找到的路径，例如 `tmp\unpacked\_DIR-859_Ax_FW_113b03.bin.extracted\squashfs-root`。

命令会自动依次执行（内部按 目录清单 → Web 枚举 → 启动脚本 → ELF 分析 → 注入检测 → 评分排序 的顺序跑完），**最后直接打印一份 Markdown 报告**，看到：

```
Artifacts written to ...\runs\hunt1
```

就成功了。报告也会自动保存成文件（见下一步）。

---

## 6. 第五步：看报告（人工审计开始）

直接用记事本/浏览器打开 `runs\hunt1\report.md`（也可以直接拖给 WorkBuddy 让它给你渲染成网页）。报告开头就是整个分析结果的摘要：

**报告怎么看（小白版）：**

1. **看「检出候选」表**：有没有 HIGH/CRITICAL 的候选？Sink 是不是 `system`/`eval`？
   ```
   | 候选                      | 二进制      | Sink   | 分数 | 等级 |
   | e2e-elf-httpd            | bin\httpd   | system | 23   | HIGH |
   ```
2. **看分数**：≥24 CRITICAL、18–23 HIGH。HIGH 以上才值得花时间人工审。
3. **看证据链**：报告会写清楚 source（输入在哪）→ sink（危险函数在哪）。

---

## 7. 第六步：人工审计（第二队同学的核心工作）

CLI 负责"找可疑点"，**人工审计负责"确认真漏洞"**。对每个 HIGH 以上候选，按下面 10 问逐一排查（Skill 05 的方法论）：

| #  | 问题        | 怎么查                                   |
| -- | --------- | ------------------------------------- |
| 1  | 输入真的来自外部？ | 是 HTTP 参数 / Header / Cookie / SOAP 吗？ |
| 2  | 攻击者能控制吗？  | 值能被请求里任意设置吗？                          |
| 3  | 真的到危险函数了？ | 反编译看调用链：handler → ... → system        |
| 4  | 中间有过滤吗？   | 有没有白名单 / 黑名单 / 长度检查？                  |
| 5  | 调用链可达吗？   | 这个 handler 有没有被 httpd 路由注册？           |
| 6  | 程序启动了吗？   | etc/init.d 或 rcS 里有它吗？                |
| 7  | 需要认证吗？    | 登录后才有权限，还是有认证绕过？                      |
| 8  | 是调试功能吗？   | 函数名含 debug/test/diag？                 |
| 9  | 有平台限制吗？   | 编译开关 / 特定硬件才走这条路径？                    |
| 10 | 有矛盾证据吗？   | 有没有证据说明它不可达？                          |

**人工审计工具**（都在 WSL 里）：

```bash
# 反编译（任选）
ghidra 或：objdump -d httpd | grep -A 20 formexeCommand

# 看字符串（找可疑的命令拼接模板）
strings httpd | grep -E "%s|system|reboot"

# 看导入（确认调用了 system）
readelf -s httpd | grep system
```

**判定规则**（写报告时用）：

- 10 问全过 → `confirmed-issue`（确认漏洞）
- 有认证/过滤但可绕过 → `high-confidence-candidate`
- 有一项不满足 → 降级或 `false-positive`，别硬报

---

## 8. 第七步（可选进阶）：动态验证

如果想证明漏洞"真的能触发"，在 WSL 里做本地仿真（安全门四项全过才放行：授权 + 本地实验 + 私有网段 + 基线就绪）：

```bash
# 在 WSL 里（qemu 用户态模式，适合单程序）
qemu-mips-static -L rootfs ./usr/sbin/upnpd
```

**红线（必须遵守）**：

- 只打自己下载的固件，目标 IP 必须私有网段
- 只发无害 payload（`id`、`touch /tmp/lab_marker`），**禁止反弹 shell、持久化、下载执行**
- 验证完不留后门、不改系统

---

## 9. 常见问题（小白高频踩坑）

| 问题                           | 原因                | 解决                                                                            |
| ---------------------------- | ----------------- | ----------------------------------------------------------------------------- |
| `python` 不是内部或外部命令           | 没用完整路径            | 用 `C:\Users\22067\.workbuddy\binaries\python\envs\default\Scripts\python.exe` |
| `binwalk: command not found` | WSL 里工具链没装/路径不对   | `bash scripts/setup_wsl.sh` 重装                                                |
| `rootfs not found: xxx`      | rootfs 路径写错了      | 先 `ls tmp\unpacked` 确认目录存在                                                    |
| `Policy rejected command`    | 固件放白名单外 / 命令含黑名单词 | 固件放 `firmware_samples/`，别用 `rm -rf`                                           |
| 解包没出 rootfs                  | 固件加密/特殊格式         | 换 sasquatch 手动解，或搜该型号"固件解包教程"                                                 |
| WSL 卡死/超时                    | WSL 服务抽风（已知问题）    | `wsl --shutdown` 重启再试                                                         |
| 报告全是 LOW/无候选                 | 固件没漏洞或目标太老        | 换个还在更新的型号，或加大 rootfs 分析范围                                                     |

---

## 10. 完整流程速查（复制粘贴版）

```bat
:: ① 自检（环境 OK 后每次可跳过）
C:\Users\22067\.workbuddy\binaries\python\envs\default\Scripts\python.exe scripts\dev.py test

:: ② 固件放 firmware_samples\ 后，WSL 解包
wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全 && binwalk -e -M firmware_samples/<固件名>.bin -C /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全/tmp/unpacked"

:: ③ 找 rootfs：ls tmp\unpacked 找 squashfs-root

:: ④ Windows 跑分析
C:\Users\22067\.workbuddy\binaries\python\envs\default\Scripts\python.exe -m fsa.cli analyze <rootfs路径> --input-type rootfs --authorization-holder "设备所有者" --run-id hunt1

:: ⑤ 看报告
::    直接打开 runs\hunt1\report.md，或拖给 WorkBuddy 渲染
```

**祝你挖到新洞！挖到后记得：**

1. 记录复现路径（哪个请求、哪个参数、哪条调用链）
2. 写进报告（Skills 07 会自动整理 20 节格式）
3. 沉淀成新的 Skill（04-audit 下新增，让下次更快）
