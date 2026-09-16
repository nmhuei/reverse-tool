#!/usr/bin/env bash
# Quick launcher for reverse-tool daemon
set -e

# Elevate with sudo once if not root
if [ "$EUID" -ne 0 ]; then
    echo -e "\x1b[1;34m[*] Yeu cau quyen sudo de ap dung routing va firewall...\x1b[0m"
    exec sudo "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/target/release/reversed"

if [ ! -f "$BIN" ]; then
    echo -e "\x1b[1;33m[!] Chua tim thay binary, dang tien hanh build release...\x1b[0m"
    CARGO_TARGET_DIR=/tmp/reverse_build cargo build --release --manifest-path "$DIR/Cargo.toml"
    mkdir -p "$DIR/target/release"
    cp /tmp/reverse_build/release/reversed "$DIR/target/release/"
    cp /tmp/reverse_build/release/reverse-tool "$DIR/target/release/"
fi

echo -e "\x1b[1;32m[+] Khoi dong reversed daemon thanh cong!\x1b[0m"
echo -e "\x1b[1;36m[i] Chinh sach tu .env da duoc kich hoat ngam ngay lap tuc.\x1b[0m"
echo -e "\x1b[1;33m[!] Daemon da duoc tach chay ngam. Ban co the dong cua so terminal nay thoai mai.\x1b[0m"
echo -e "\x1b[1;35m[i] Khi nao muon tat: go './stop.sh' hoac 'sudo reverse-tool stop'\x1b[0m\n"
exec "$BIN" "$@"
