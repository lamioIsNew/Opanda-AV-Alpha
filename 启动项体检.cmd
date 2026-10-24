@echo off
chcp 936 >nul
cd /d "%~dp0"
echo 启动项体检 - 枚举并扫描自启动位置（约 1-2 分钟）...
echo 结果同时写入 startup_audit_^<时间^>.txt
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan_startup.ps1"
echo.
pause
