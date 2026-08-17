#!/usr/bin/env bash
# setup_wsl.sh — 在 WSL2 Ubuntu 22.04 上一键安装固件分析工具链
# 用法：wsl -d Ubuntu-22.04 -- bash /mnt/c/Users/22067/Desktop/揭榜挂帅——网络安全/scripts/setup_wsl.sh
set -euo pipefail

echo "[setup] Updating package index..."
sudo apt update

echo "[setup] Installing base apt packages..."
sudo apt install -y \
    binwalk \
    squashfs-tools \
    cpio \
    p7zip-full \
    p7zip-rar \
    file \
    build-essential \
    binutils \
    qemu-user-static \
    qemu-system-x86 \
    qemu-system-arm \
    liblzma-dev \
    liblzo2-dev \
    zlib1g-dev \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

echo "[setup] Installing Python tools..."
# jefferson: JFFS2 extraction
sudo pip3 install jefferson

# If you have GitHub access, install latest binwalk from source.
# Fallback: the apt binwalk above is already available.
if command -v git >/dev/null && curl -sI --max-time 10 https://github.com >/dev/null 2>&1; then
    echo "[setup] GitHub reachable, installing latest binwalk from source..."
    cd /tmp
    rm -rf binwalk
    git clone --depth 1 https://github.com/ReFirmLabs/binwalk.git
    cd binwalk
    sudo pip3 install .
else
    echo "[setup] GitHub not reachable, keeping apt binwalk."
fi

# sasquatch: non-standard SquashFS extraction (optional but strongly recommended).
if command -v git >/dev/null && curl -sI --max-time 10 https://github.com >/dev/null 2>&1; then
    echo "[setup] GitHub reachable, building sasquatch from source..."
    cd /tmp
    rm -rf sasquatch
    git clone --depth 1 https://github.com/onekey-sec/sasquatch.git
    cd sasquatch
    make
    sudo make install
else
    echo "[setup] GitHub not reachable, skipping sasquatch. Standard unsquashfs will be used."
fi

echo "[setup] Verifying installation..."
for tool in binwalk jefferson mksquashfs unsquashfs readelf objdump strings file cpio 7z qemu-arm-static qemu-system-x86_64; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  OK: $tool -> $(command -v "$tool")"
    else
        echo "  MISSING: $tool"
    fi
done

echo "[setup] Done."
