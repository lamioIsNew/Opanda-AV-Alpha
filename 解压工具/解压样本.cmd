@echo off
chcp 936 >nul
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0解压样本.ps1" %*
echo.
echo 解压结束。报告见本目录 解压报告.csv
pause
