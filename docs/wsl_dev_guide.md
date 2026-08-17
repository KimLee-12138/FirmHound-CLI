# WSL2 开发指南

本项目依赖大量 Linux-native 工具链，强烈建议在 WSL2 Ubuntu 22.04 中运行测试与完整流水线。

## 1. 进入 WSL

```powershell
wsl -d Ubuntu-22.04
```

项目路径在 WSL 中对应：

```bash
cd /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全
```

## 2. 安装工具链

```bash
bash scripts/setup_wsl.sh
```

如果 GitHub 访问不畅，脚本会自动回退到 apt 版 `binwalk`，并跳过 `sasquatch` 源码编译。

## 3. 创建 Python 虚拟环境

```bash
cd /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 4. 运行测试

```bash
# 全部测试
python -m pytest tests/ -v

# 仅单元测试
python -m pytest tests/unit/ -v

# 仅集成测试（需要 binwalk/readelf 等）
python -m pytest tests/integration/ -v
```

## 5. 常用命令对照

| 功能 | Windows (PowerShell) | WSL (Bash) |
|------|---------------------|-----------|
| 进入 WSL | `wsl -d Ubuntu-22.04` | - |
| 跑测试 | `python scripts/dev.py test` | `python -m pytest tests/ -v` |
| 解包固件 | - | `binwalk -e firmware.bin` |
| 查看 ELF 头 | - | `readelf -h ./bin/httpd` |

## 6. 已知问题

- `wsl: 检测到 localhost 代理配置...` 是代理警告，不影响使用。
- GitHub 访问超时会导致 `sasquatch` 安装失败，可先跳过；标准 `unsquashfs` 能处理大多数 SquashFS。
