#!/bin/bash
# 用法: build.sh aarch64|x86_64
set -euo pipefail
SP="$(cd "$(dirname "$0")" && pwd)"
case "$1" in
  aarch64) ARCH=arm64;  MINOS=11.0 ;;
  x86_64)  ARCH=x86_64; MINOS=10.15 ;;
esac
export ZLC_SRC="$SP/src-patched" ZLC_ARCH="$ARCH" ZLC_MINOS="$MINOS" ZLC_ENT="$SP/entitlements.plist"
export ZLC_IDENT="Developer ID Application: Yixiao Wang (5CS6HUB4P2)"
export PYTHONDONTWRITEBYTECODE=1
rm -rf "$SP/work-$1" "$SP/dist-$1"
"$SP/venv-$1/bin/pyinstaller" --clean --noconfirm \
  --workpath "$SP/work-$1" --distpath "$SP/dist-$1" "$SP/zcode-leak-check.spec"
