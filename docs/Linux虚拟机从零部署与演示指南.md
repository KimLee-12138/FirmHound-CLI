# FirmHound Linux 虚拟机从零部署与演示指南

> 适用场景：你刚装好一台 Linux 虚拟机，希望把 FirmHound 从 GitHub 下载下来，配置环境，并跑通演示视频里的完整 CLI 流程。

本文默认使用 Ubuntu 22.04 / Ubuntu 24.04 / Debian 系 Linux。其他发行版也能用，但包管理命令需要替换。

## 0. 演示目标

本指南跑通以下内容：

1. 在 Linux 虚拟机中安装系统依赖。
2. 从 GitHub 下载 FirmHound 项目。
3. 创建 Python 虚拟环境。
4. 安装 FirmHound CLI。
5. 安装固件解包工具：binwalk、unsquashfs、sasquatch。
6. 运行环境自检。
7. 复制真实固件样本。
8. 运行 AC15、OpenWrt、BE3LPro 三个演示案例。
9. 查看报告、证据链和测试结果。

## 1. 前置准备

你需要准备：

- 一台刚装好的 Linux 虚拟机。
- 可以联网。
- 已安装 Git，或者允许通过 `apt` 安装。
- 三个授权固件样本：
  - `US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin`
  - `openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin`
  - `US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin`
- GitHub 仓库地址：

```text
https://github.com/KimLee-12138/FirmHound-CLI.git
```

## 2. 更新系统

打开 Linux 终端，执行：

```bash
sudo apt update
sudo apt upgrade -y
```

如果系统提示输入密码，输入你安装虚拟机时设置的用户密码即可。

## 3. 安装基础依赖

```bash
sudo apt install -y \
  git \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  build-essential \
  make \
  gcc \
  g++ \
  file \
  binutils \
  curl \
  wget \
  unzip \
  p7zip-full \
  cpio \
  squashfs-tools \
  binwalk \
  tree
```

检查版本：

```bash
python3 --version
git --version
binwalk --help | head
unsquashfs -version
```

建议 Python 版本为 3.11 或更高。如果你的系统是 Python 3.10，通常也能装，但正式比赛材料建议写 3.11+。

## 4. 安装 sasquatch

很多路由器固件使用非标准 SquashFS，普通 `unsquashfs` 可能解不开，所以建议安装 `sasquatch`。

```bash
cd /tmp
git clone --depth 1 https://github.com/onekey-sec/sasquatch.git
cd sasquatch
make
sudo make install
```

验证：

```bash
which sasquatch
sasquatch -version || sasquatch -h | head
```

如果 `git clone` 太慢，可以先跳过 sasquatch，但 Tenda AC15 这类固件可能无法完整解包。比赛演示建议务必装好。

## 5. 从 GitHub 下载项目

建议把项目放在用户目录下：

```bash
cd ~
git clone https://github.com/KimLee-12138/FirmHound-CLI.git
cd FirmHound-CLI
```

查看项目结构：

```bash
ls
tree -L 2 | head -120
```

你应该能看到这些目录：

```text
fsa/
tools/
skills/
schemas/
config/
tests/
benchmarks/
docs/
scripts/
```

如果以后要更新代码：

```bash
cd ~/FirmHound-CLI
git pull
```

## 6. 创建 Python 虚拟环境

进入项目目录：

```bash
cd ~/FirmHound-CLI
```

创建虚拟环境：

```bash
python3 -m venv .venv
```

激活虚拟环境：

```bash
source .venv/bin/activate
```

激活后，终端前面通常会出现：

```text
(.venv)
```

升级 pip：

```bash
python -m pip install --upgrade pip setuptools wheel
```

安装依赖：

```bash
pip install -r requirements.txt
pip install -e .
```

验证 CLI 是否安装成功：

```bash
fsa --help
```

如果提示 `fsa: command not found`，使用下面的方式也可以：

```bash
python -m fsa.cli --help
```

## 7. 第一次环境自检

执行：

```bash
fsa doctor --json-output
```

或者：

```bash
python -m fsa.cli doctor --json-output
```

正常情况下应该看到类似：

```json
{
  "status": "ok",
  "checks": {
    "paths": {"status": "ok"},
    "schemas": {"status": "ok"},
    "runtime": {"status": "ok"},
    "commands": {
      "status": "ok"
    }
  }
}
```

重点看：

- `paths.status=ok`
- `schemas.status=ok`
- `runtime.status=ok`
- `binwalk=true`
- `unsquashfs=true`

如果 `analyzeHeadless=false` 或 `klee=false`，这是可以接受的。Ghidra 和 KLEE 是可选深度分析工具，不影响基础演示。

## 8. 运行基础测试

先跑一组轻量测试：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
```

再跑完整测试：

```bash
python scripts/dev.py test
```

代码风格检查：

```bash
python -m ruff check .
```

如果完整测试耗时较久，拍演示视频时可以只展示：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
python -m ruff check .
```

## 9. 准备固件样本目录

FirmHound 默认安全策略只允许读取白名单目录。固件样本建议统一放到：

```bash
~/FirmHound-CLI/firmware_samples/
```

创建目录：

```bash
cd ~/FirmHound-CLI
mkdir -p firmware_samples
```

## 10. 把 Windows 里的固件复制到 Linux 虚拟机

根据你的虚拟机类型，选择一种方式。

### 方式 A：VMware / VirtualBox 共享文件夹

如果你配置了共享文件夹，假设共享目录挂载在：

```text
/mnt/hgfs/share
```

或：

```text
/media/sf_share
```

复制：

```bash
cp /mnt/hgfs/share/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin firmware_samples/
cp /mnt/hgfs/share/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin firmware_samples/
cp /mnt/hgfs/share/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin firmware_samples/
```

如果你的共享目录不同，把 `/mnt/hgfs/share` 换成实际路径。

### 方式 B：用 U 盘复制

插入 U 盘后，Linux 通常会挂载到 `/media/<用户名>/` 下。

查看：

```bash
ls /media/$USER
```

假设 U 盘目录是 `/media/$USER/USB`：

```bash
cp /media/$USER/USB/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin firmware_samples/
cp /media/$USER/USB/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin firmware_samples/
cp /media/$USER/USB/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin firmware_samples/
```

### 方式 C：用 scp 从 Windows 传到 Linux

先在 Linux 中查看 IP：

```bash
ip addr
```

找到类似 `192.168.x.x` 的地址。

然后在 Windows PowerShell 里执行：

```powershell
scp "D:\揭榜挂帅——网络安全\US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin" <linux用户名>@<linux虚拟机IP>:~/FirmHound-CLI/firmware_samples/
scp "D:\揭榜挂帅——网络安全\openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin" <linux用户名>@<linux虚拟机IP>:~/FirmHound-CLI/firmware_samples/
scp "D:\揭榜挂帅——网络安全\US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin" <linux用户名>@<linux虚拟机IP>:~/FirmHound-CLI/firmware_samples/
```

把 `<linux用户名>` 和 `<linux虚拟机IP>` 换成你自己的。

如果 Linux 没有开 SSH 服务，先执行：

```bash
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
```

## 11. 确认固件已经放好

```bash
cd ~/FirmHound-CLI
ls -lh firmware_samples
```

应该能看到：

```text
US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin
openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin
US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin
```

## 12. 演示 1：任务规划

这个命令展示“智能体如何把自然语言任务转成执行计划”。

```bash
fsa plan \
  --task "分析 Tenda AC15 路由器固件，已获得授权，执行完整固件漏洞挖掘流程" \
  --firmware-path firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --depth full \
  --json-output
```

讲解重点：

- `plan` 只规划，不执行。
- 展示任务理解能力。
- 展示授权主体。
- 展示 full depth 阶段。

## 13. 演示 2：分析 Tenda AC15 固件

这是最推荐拍视频的主案例。

```bash
fsa analyze firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --run-id demo-ac15-linux \
  --json-output
```

查看状态：

```bash
fsa status demo-ac15-linux --json-output
```

查看输出目录：

```bash
find runs/demo-ac15-linux -maxdepth 3 -type f | sort | head -120
```

查看报告：

```bash
sed -n '1,220p' runs/demo-ac15-linux/report.md
```

查重点候选：

```bash
grep -n "候选\|httpd\|formWifiConfigGet\|NEED_DYNAMIC\|system\|CRITICAL\|HIGH" runs/demo-ac15-linux/report.md | head -50
```

讲解重点：

- AC15 能完整解包。
- 系统会生成 rootfs、攻击面、二进制摘要、候选、报告。
- 发现的是静态候选，不直接等同确认漏洞。
- 报告会提示待动态验证事实。

## 14. 演示 3：查看证据链和决策链

查看运行目录：

```bash
ls runs/demo-ac15-linux
ls runs/demo-ac15-linux/artifacts
ls runs/demo-ac15-linux/state
```

查看决策文件：

```bash
find runs/demo-ac15-linux/decisions -type f | head -5
```

打开第一个决策文件：

```bash
python -m json.tool "$(find runs/demo-ac15-linux/decisions -type f | head -1)"
```

查看证据文件：

```bash
find runs/demo-ac15-linux/evidence -type f | head -5
```

打开第一个证据文件：

```bash
python -m json.tool "$(find runs/demo-ac15-linux/evidence -type f | head -1)"
```

讲解重点：

- FirmHound 不只是输出最终结论。
- 每个阶段有 evidence 和 decision。
- 评委可以复核每条判断的来源。

也可以直接使用新增的“漏洞证据账本”命令：

```bash
fsa explain demo-ac15-linux --format markdown --limit 5
```

如果只想解释某一个候选：

```bash
fsa explain demo-ac15-linux --candidate-id <candidate-id> --format markdown
```

讲解重点：

- `explain` 会把候选的 source、sink、调用链、支持证据、反证、十维评分和下一步建议集中展示。
- 这体现的是“不是让大模型直接下结论，而是让系统建立可复核证据链”。

## 15. 演示 4：分析 OpenWrt WE826 固件

这个案例用于展示“正常固件完整跑通，但不乱报高危”。

```bash
fsa analyze firmware_samples/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor OpenWrt \
  --model zbt-we826-16m \
  --version 23.05.0 \
  --run-id demo-openwrt-linux \
  --json-output
```

查看报告：

```bash
sed -n '1,180p' runs/demo-openwrt-linux/report.md
```

讲解重点：

- OpenWrt 样本可完整解包。
- 安全工具不应该为了演示而强行报漏洞。
- 无高危候选也是可信结果的一部分。

## 16. 演示 5：分析 BE3LPro 加密固件

这个案例用于展示加密固件识别和诚实降级。

先做解包性诊断：

```bash
fsa unpack-diagnose firmware_samples/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin \
  --json-output
```

讲解重点：

- `unpack-diagnose` 不执行完整分析，只判断固件可解包性。
- 对加密固件，它会提示 OpenSSL Salted/加密载荷、魔数 offset、提取器状态和下一步所需材料。

```bash
fsa analyze firmware_samples/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model BE3LPro \
  --version V16.03.60.62_cn_TDC01 \
  --run-id demo-be3lpro-linux \
  --json-output
```

查看状态：

```bash
fsa status demo-be3lpro-linux --json-output
```

查找加密切片：

```bash
find tmp -iname "*encrypted*" -o -iname "*openssl*" | head
```

讲解重点：

- BE3LPro 检测到 OpenSSL Salted 加密载荷。
- 没有密钥/密码/厂商升级工具解密逻辑时，不伪造解包成功。
- 系统会保存加密切片并提示需要解密材料。
- 这体现的是逆向分析里的“边界识别”和“诚实降级”。

## 17. 演示 6：安全策略

查看安全配置：

```bash
sed -n '1,220p' config/safety.yaml
```

运行安全测试：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_sanitize.py -q
```

讲解重点：

- 路径白名单。
- 命令黑名单。
- 私有 IP 限制。
- 动态验证必须授权。
- 危险 payload 会被拒绝或脱敏。

## 18. 演示 7：工程质量

查看 CI：

```bash
sed -n '1,220p' .github/workflows/ci.yml
```

运行测试：

```bash
python scripts/dev.py test
```

运行 lint：

```bash
python -m ruff check .
```

查看 CVE 基准：

```bash
ls benchmarks/CVEs
find benchmarks/CVEs -maxdepth 2 -type f | sort | head -80
```

打开一个 CVE candidate：

```bash
python -m json.tool benchmarks/CVEs/CVE-2017-17215/candidate.json | head -120
```

讲解重点：

- 项目有自动化测试。
- 有 CI。
- 有历史 CVE fixture。
- 有 Schema 契约。
- 不是一次性脚本。

## 19. 视频拍摄推荐顺序

建议按这个顺序拍：

```bash
cd ~/FirmHound-CLI
source .venv/bin/activate

fsa doctor --json-output

fsa plan \
  --task "分析 Tenda AC15 路由器固件，已获得授权，执行完整固件漏洞挖掘流程" \
  --firmware-path firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --depth full \
  --json-output

fsa analyze firmware_samples/US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model AC15 \
  --version V15.03.05.19_multi_TD01 \
  --run-id demo-ac15-linux \
  --json-output

fsa status demo-ac15-linux --json-output
sed -n '1,220p' runs/demo-ac15-linux/report.md
find runs/demo-ac15-linux -maxdepth 3 -type f | sort | head -120

fsa analyze firmware_samples/openwrt-23.05.0-ramips-mt7620-zbtlink_zbt-we826-16m-squashfs-sysupgrade.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor OpenWrt \
  --model zbt-we826-16m \
  --version 23.05.0 \
  --run-id demo-openwrt-linux \
  --json-output

fsa analyze firmware_samples/US_BE3LProV1.0mt_V16.03.60.62_cn_TDC01.bin \
  --input-type firmware \
  --depth standard \
  --authorization-holder "team-authorized" \
  --vendor Tenda \
  --model BE3LPro \
  --version V16.03.60.62_cn_TDC01 \
  --run-id demo-be3lpro-linux \
  --json-output

fsa status demo-be3lpro-linux --json-output

python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
python -m ruff check .
```

## 20. 常见问题

### 20.1 `fsa: command not found`

确认虚拟环境已激活：

```bash
source .venv/bin/activate
```

如果仍然不行，用：

```bash
python -m fsa.cli --help
```

### 20.2 `binwalk` 或 `unsquashfs` 找不到

重新安装：

```bash
sudo apt install -y binwalk squashfs-tools
```

### 20.3 AC15 解包失败

大概率缺 `sasquatch`。重新安装：

```bash
cd /tmp
git clone --depth 1 https://github.com/onekey-sec/sasquatch.git
cd sasquatch
make
sudo make install
```

### 20.4 BE3LPro 为什么失败？

这是正常现象。该样本是加密固件，没有密钥或厂商解密逻辑时不能完整解包。演示时应把它讲成“加密固件识别和诚实降级能力”。

### 20.5 `pytest` 很慢怎么办？

视频里可以只跑轻量测试：

```bash
python -m pytest tests/unit/test_safety.py tests/unit/test_schemas.py -q
```

完整测试可作为截图或补充材料展示。

### 20.6 GitHub 下载很慢怎么办？

可以在 Windows 先下载 zip，然后复制到 Linux：

```bash
unzip FirmHound-CLI-main.zip
cd FirmHound-CLI-main
```

但正式演示更推荐 `git clone`，显得更规范。

## 21. 推荐视频总结词

可以这样收尾：

> FirmHound 展示的是一个完整的固件漏洞挖掘 CLI 智能体流程。它可以从自然语言任务规划开始，自动完成固件解包、攻击面识别、二进制审计、风险评分、反证验证和报告生成；同时通过安全策略、证据链和决策链保证分析过程可复现、可解释、可降级。对于正常固件，它能稳定跑通；对于加密固件，它不会伪造结果，而是明确提示需要解密材料。这正是我们面向比赛提交的核心产品能力。
