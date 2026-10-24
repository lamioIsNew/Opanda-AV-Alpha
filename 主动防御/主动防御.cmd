@echo off
chcp 936 >nul
setlocal enabledelayedexpansion
title 主动防御 - 目录实时监控（folder_guard）

set "GUARD=%~dp0folder_guard.exe"
set "ROOT=%~dp0.."
set "SCAN=%ROOT%\scan.exe"
set "SCALER=%ROOT%\scaler.txt"

if not exist "%GUARD%"  ( echo [错误] 找不到 folder_guard.exe & pause & exit /b 1 )
if not exist "%SCAN%"   ( echo [错误] 找不到扫描器 scan.exe & echo 位置: %ROOT% & pause & exit /b 1 )
if not exist "%SCALER%" ( echo [错误] 找不到特征库 scaler.txt & echo 位置: %ROOT% & pause & exit /b 1 )

:menu
cls
echo ================================================================
echo   目录主动防御  folder_guard（用户态·第一版）
echo ----------------------------------------------------------------
echo   监控范围 : 下载 与 桌面（可另选目录）
echo   关注文件 : 新落地的 .exe .dll .sys .ps1 .cmd .vbs .js .hta 等
echo   动作     : 调 scan.exe 静态扫描，命中 [HIGH RISK] 立即告警
echo   扫描器   : %SCAN%
echo ================================================================
echo.
echo   [1] 仅告警（安全，建议先用这个看效果）
echo   [2] 高危文件自动置为只读（落地即拦截）
echo   [3] 监控自定义目录
echo   [4] 查看用法
echo   [0] 退出
echo.
set "CH="
set /p "CH=请选择 [0-4]: "

if "%CH%"=="1" goto warn
if "%CH%"=="2" goto lock
if "%CH%"=="3" goto custom
if "%CH%"=="4" goto usage
if "%CH%"=="0" goto quit
goto menu

:warn
cls
echo [启动] 仅告警模式 —— 按 Ctrl+C 停止
echo.
"%GUARD%" --scan "%SCAN%" --scaler "%SCALER%"
echo.
pause
goto menu

:lock
cls
echo [启动] 高危文件自动置只读 —— 按 Ctrl+C 停止
echo.
"%GUARD%" --scan "%SCAN%" --scaler "%SCALER%" --lock
echo.
pause
goto menu

:custom
cls
set "DIR="
set /p "DIR=请输入要监控的目录（直接回车＝取消）: "
if "%DIR%"=="" goto menu
if not exist "%DIR%" ( echo [错误] 目录不存在: %DIR% & pause & goto menu )
cls
echo [启动] 监控目录: %DIR%  —— 按 Ctrl+C 停止
echo.
"%GUARD%" --scan "%SCAN%" --scaler "%SCALER%" --dir "%DIR%"
echo.
pause
goto menu

:usage
cls
echo ================================================================
echo   folder_guard 命令行用法（本启动器已自动带上正确路径）
echo ----------------------------------------------------------------
echo   folder_guard.exe                          默认监控 下载+桌面，仅告警
echo   folder_guard.exe --lock                   高危文件自动置为只读
echo   folder_guard.exe --recursive              连子目录一起监控
echo   folder_guard.exe --dir "D:\某目录"          改成监控指定目录（可写多次）
echo   folder_guard.exe --scan  scan.exe路径      指定扫描器（默认取本程序同目录）
echo   folder_guard.exe --scaler scaler.txt路径   指定特征库
echo.
echo   说明: 直接双击 folder_guard.exe 时，它会去"本程序所在目录"找 scan.exe；
echo         而 scan.exe 在上层目录，所以请用本启动器，或显式加 --scan 参数。
echo ================================================================
echo.
pause
goto menu

:quit
endlocal
exit /b 0