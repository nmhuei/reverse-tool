#!/usr/bin/env bash
# ==============================================================================
# One-line installer for LAN CLI - Antigravity
# https://github.com/nmhuei/reverse-tool/tree/minhngo-revtool
# ==============================================================================

set -euo pipefail

RAW_URL="https://raw.githubusercontent.com/nmhuei/reverse-tool/minhngo-revtool/lan.sh"
TARGET_BIN="/usr/local/bin/lan"

echo -e "\033[1;34m[*] Dang tai va cai dat LAN CLI tu GitHub (branch minhngo-revtool)...\033[0m"

TMP_FILE=$(mktemp /tmp/lan.XXXXXX.sh)
trap 'rm -f "$TMP_FILE"' EXIT

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$RAW_URL" -o "$TMP_FILE"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_FILE" "$RAW_URL"
else
    echo -e "\033[1;31m[-] Yeu cau can co 'curl' hoac 'wget' de tai ve.\033[0m" >&2
    exit 1
fi

chmod +x "$TMP_FILE"

# Kiem tra quyen ghi vao /usr/local/bin
if [ "$EUID" -eq 0 ]; then
    install -m 755 "$TMP_FILE" "$TARGET_BIN"
else
    sudo install -m 755 "$TMP_FILE" "$TARGET_BIN"
fi

# Tao symlink bo sung trong ~/.local/bin neu thu muc ton tai
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || echo "$HOME")
if [ -d "$REAL_HOME/.local/bin" ]; then
    ln -sf "$TARGET_BIN" "$REAL_HOME/.local/bin/lan" 2>/dev/null || true
fi

echo -e "\033[1;32m[+] Cai dat thanh cong LAN CLI tai: $TARGET_BIN\033[0m"
echo -e "\033[1;36m============================================================\033[0m"
echo -e "Ban co the go lenh truc tiep o bat ky thu muc nao tren may:"
echo -e "  \033[1;32msudo lan term\033[0m             -> Mo Terminal ket noi mang LAN"
echo -e "  \033[1;32msudo lan browser\033[0m          -> Mo Chromium ket noi mang LAN"
echo -e "  \033[1;32msudo lan run nc ...\033[0m       -> Chay netcat qua mang LAN"
echo -e "  \033[1;31msudo lan stop\033[0m             -> Dong ket noi va khoi phuc card mang"
echo -e "  \033[1;33mlan --help\033[0m                -> Xem huong dan su dung"
echo -e "\033[1;36m============================================================\033[0m"
