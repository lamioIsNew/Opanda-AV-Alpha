@echo off
chcp 936 >nul
setlocal
title 自动化行为分析 - 静态选靶 + 沙箱动态观察
echo ================================================
echo         自动化行为分析（静态 + 动态）
echo   先用扫描器选靶，再逐个丢进 Windows 沙箱真跑，
echo   最后把静态结论与动态行为合并成最终结论。
echo ================================================
echo.
set "TARGET=%~1"
if "%TARGET%"=="" set /p TARGET=请输入要分析的 文件 或 目录 路径: 
if "%TARGET%"=="" ( echo 未输入路径，已退出。 & pause & exit /b 1 )
if not exist "%TARGET%" ( echo 路径不存在: %TARGET% & pause & exit /b 1 )
echo.
set /p TOPN=最多分析几个样本? (直接回车默认 5): 
if "%TOPN%"=="" set "TOPN=5"
set "NET="
set /p ANS=是否放通沙箱网络以观察外联地址? (y/N): 
if /i "%ANS%"=="y" set "NET=-Network"
echo.
echo 开始分析: %TARGET%
echo 每分析一个样本约需 1-2 分钟，请耐心等待...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0auto_analyze.ps1" -Target "%TARGET%" -Top %TOPN% %NET%
echo.
echo 完成。汇总报告在 本目录\分析结果\ 下。
pause
