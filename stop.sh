#!/usr/bin/env bash
# Quick script to stop reversed daemon and restore normal network
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/target/release/reverse-tool"

if [ -f "$BIN" ]; then
    sudo "$BIN" stop
elif which reverse-tool >/dev/null 2>&1; then
    sudo reverse-tool stop
else
    echo "[!] reverse-tool binary not found"
    exit 1
fi
