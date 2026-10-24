@echo off
chcp 936 >nul
setlocal
title 脚本块审计 - PowerShell 内存脚本事后查杀

set "PS1=%~dp0脚本块审计.ps1"
set "ROOT=%~dp0..\.."

:menu
cls
echo ================================================================
echo   脚本块审计（AMSI 的用户态等效替代）
echo ----------------------------------------------------------------
echo   PowerShell 引擎会把每个要执行的脚本块记进 4104 事件，
echo   本工具把这些脚本块重新交给 scan.exe 静态扫描，命中就告警。
echo   能抓到 -enc / IEX / DownloadString 这类"内存马"脚本。
echo ----------------------------------------------------------------
echo   注意：这是"执行后审计"；真 AMSI 是"执行前拦截"（需签名，见说明）
echo ================================================================
echo.
echo   [1] 审计最近 1 小时
echo   [2] 审计最近 6 小时
echo   [3] 持续监视（每 30 秒一轮，挂着跑）
echo   [4] 打开脚本块日志记录（需管理员，一次性）
echo   [0] 退出
echo.
set "CH="
set /p "CH=请选择 [0-4]: "

if "%CH%"=="1" goto h1
if "%CH%"=="2" goto h6
if "%CH%"=="3" goto follow
if "%CH%"=="4" goto enable
if "%CH%"=="0" goto quit
goto menu

:h1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Minutes 60
echo.
pause
goto menu

:h6
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Minutes 360
echo.
pause
goto menu

:follow
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Minutes 30 -Follow
echo.
pause
goto menu

:enable
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%PS1%','-EnableLogging'"
pause
goto menu

:quit
endlocal
exit /b 0