#!/usr/bin/env bash
# One-line installer for LAN CLI
set -euo pipefail

RAW_URL="https://raw.githubusercontent.com/nmhuei/reverse-tool/minhngo-revtool/lan.sh"
TARGET_BIN="/usr/local/bin/lan"

echo -e "\033[1;34m[*] Đang tải và cài đặt LAN CLI...\033[0m"

TMP_FILE=$(mktemp /tmp/lan.XXXXXX.sh)
trap 'rm -f "$TMP_FILE"' EXIT

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$RAW_URL" -o "$TMP_FILE"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_FILE" "$RAW_URL"
else
    echo -e "\033[1;31m[-] Cần curl hoặc wget để tải về.\033[0m" >&2
    exit 1
fi

chmod +x "$TMP_FILE"

if [ "$EUID" -eq 0 ]; then
    install -m 755 "$TMP_FILE" "$TARGET_BIN"
else
    sudo install -m 755 "$TMP_FILE" "$TARGET_BIN"
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || echo "$HOME")
[ -d "$REAL_HOME/.local/bin" ] && ln -sf "$TARGET_BIN" "$REAL_HOME/.local/bin/lan" 2>/dev/null || true

echo -e "\033[1;32m[+] Cài đặt thành công LAN CLI tại $TARGET_BIN\033[0m"
echo -e "Lệnh sử dụng:"
echo -e "  sudo lan term       - Mở Terminal LAN"
echo -e "  sudo lan browser    - Mở Chromium LAN"
echo -e "  sudo lan run <cmd>  - Chạy lệnh trong LAN"
echo -e "  sudo lan stop       - Khôi phục card mạng"
