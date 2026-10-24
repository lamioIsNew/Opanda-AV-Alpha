@echo off
rem ===== 恶意软件扫描器：拖拽扫描入口 =====
if not "%~1"=="" goto scan
echo.
echo 用法：把要扫描的文件 / 文件夹 / 压缩包 拖到本文件上松开
echo （或者双击 scan.exe 打开菜单模式）
echo.
pause
exit /b
:scan
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan_any.ps1" "%~1"
echo.
pause
