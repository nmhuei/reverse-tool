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
echo -e "\x1b[1;36m[i] Chinh sach tu .env da duoc kich hoat ngay lap tuc.\x1b[0m"
echo -e "\x1b[1;33m[!] Nhan Ctrl+C bat cu luc nao de tat va tu dong khoi phuc 100% mang ve ban dau.\x1b[0m\n"
exec "$BIN" "$@"
