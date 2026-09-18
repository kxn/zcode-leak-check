#!/usr/bin/env bash
# ZCode 快照外传检查器 - macOS / Linux 启动脚本
# macOS 上可另存为 start_checker.command 双击运行
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  exec python3 zcode_snapshot_audit.py "$@"
fi
if command -v python >/dev/null 2>&1; then
  exec python zcode_snapshot_audit.py "$@"
fi
echo "未找到 Python3。请先安装（macOS: brew install python-tk；Linux: sudo apt install python3-tk）"
exit 1
