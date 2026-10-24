@echo off
setlocal
cd /d C:\opanda_test
net session >nul 2>&1
if errorlevel 1 (
  echo Please run this script as Administrator.
  pause
  exit /b 1
)

if exist hips_target_info.txt del hips_target_info.txt
start "" HipsTestTarget.exe
timeout /t 3 >nul
if not exist hips_target_info.txt (
  echo HipsTestTarget did not write hips_target_info.txt
  pause
  exit /b 1
)
echo Target info:
type hips_target_info.txt

echo [1/2] Delete while the file is mapped (POSIX disposition)
call :runsystem hips_delete.cmd
if exist hips_delete.txt type hips_delete.txt

echo [2/2] Terminate the target process
call :runsystem hips_kill.cmd
if exist hips_kill.txt type hips_kill.txt

echo.
echo Expected: delete reports success (or a documented sharing error),
echo and the target process is gone. The file name should be unlinked.
pause
exit /b 0

:runsystem
schtasks /Create /TN OpandaHips_%1 /TR "C:\opanda_test\%1" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F >nul
schtasks /Run /TN OpandaHips_%1 >nul
timeout /t 5 >nul
schtasks /Delete /TN OpandaHips_%1 /F >nul
exit /b 0
