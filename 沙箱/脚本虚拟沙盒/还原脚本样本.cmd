@echo off
chcp 936 >nul
setlocal
set HERE=%~dp0
if "%~1"=="" goto usage
set OUT=%~2
if "%OUT%"=="" set OUT=%HERE%out\%~n1
echo [*] 样本: %~1
echo [*] 输出: %OUT%
echo.
python "%HERE%unbox_js.py" "%~1" "%OUT%" --run-seconds 15
if errorlevel 1 goto failed
echo.
echo [OK] 完成。中文报告: %OUT%\report.txt
goto :eof

:failed
echo [!] 执行失败，退出码 %errorlevel%
exit /b %errorlevel%

:usage
echo.
echo  用法: 还原脚本样本.cmd "样本文件路径" ["输出目录"]
echo  例:   还原脚本样本.cmd "C:\样本\abc.js" "%~dp0out\abc"
echo.
echo  说明: 只处理脚本类样本 .js .jse .vbs .vbe .wsf ，全程不联网、不落地、不执行任何系统调用。
echo.
exit /b 2