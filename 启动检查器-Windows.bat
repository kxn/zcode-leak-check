@echo off
rem ZCode 快照外传检查器 - Windows 双击启动
chcp 65001 >nul
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw zcode_snapshot_audit.py
  exit /b 0
)
where python >nul 2>nul
if %errorlevel%==0 (
  python zcode_snapshot_audit.py
  if errorlevel 1 pause
  exit /b 0
)
where py >nul 2>nul
if %errorlevel%==0 (
  py zcode_snapshot_audit.py
  if errorlevel 1 pause
  exit /b 0
)
echo 未找到 Python。请安装 Python 3.8+（python.org 安装包自带 tkinter）。
pause
