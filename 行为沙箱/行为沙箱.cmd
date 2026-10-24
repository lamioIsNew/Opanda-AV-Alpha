@echo off
chcp 936 >nul
setlocal
title 行为沙箱 - 恶意软件动态观察
echo ================================================
echo            行为沙箱（最小版）
echo   把样本放进一次性隔离的 Windows 沙箱里跑一遍
echo   观察它起了什么进程 / 写了什么文件 / 加了什么启动项
echo ================================================
echo.
set "SAMPLE=%~1"
if "%SAMPLE%"=="" set /p SAMPLE=请输入样本文件或目录的完整路径: 
if "%SAMPLE%"=="" ( echo 未输入路径，已退出。 & pause & exit /b 1 )
if not exist "%SAMPLE%" ( echo 路径不存在: %SAMPLE% & pause & exit /b 1 )
echo.
set "NET="
set /p ANS=是否允许沙箱内联网以观察外联地址？(y/N): 
if /i "%ANS%"=="y" set "NET=-Network"
echo.
echo 即将在 Windows 沙箱中观察: %SAMPLE%
echo （会弹出一个沙箱窗口，观察完成后沙箱自动关闭）
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sandbox_run.ps1" -Sample "%SAMPLE%" %NET%
echo.
echo 完成。报告保存在本目录的 reports\ 下。
pause
