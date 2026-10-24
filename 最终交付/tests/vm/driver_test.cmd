@echo off
setlocal
cd /d C:\opanda_test
net session >nul 2>&1
if errorlevel 1 (
  echo Please run this script as Administrator.
  pause
  exit /b 1
)

echo [1/5] Import test signing certificate
certutil -addstore -f Root OpandaTest.cer >nul
certutil -addstore -f TrustedPublisher OpandaTest.cer >nul

echo [2/5] Enable test signing
bcdedit /set testsigning on
if errorlevel 1 (
  echo bcdedit failed. Secure Boot may be enabled; use a VM with Secure Boot off.
  pause
  exit /b 1
)

echo [3/5] Install driver service
copy /Y HipsDriver.sys "%SystemRoot%\System32\drivers\HipsDriver.sys" >nul
sc query HipsDriver >nul 2>&1
if errorlevel 1 (
  sc create HipsDriver type= kernel start= demand binPath= "%SystemRoot%\System32\drivers\HipsDriver.sys" DisplayName= "Opanda HIPS Driver"
)
sc start HipsDriver
sc query HipsDriver

echo [4/5] Run HipsClient version as SYSTEM
call :runsystem hips_version.cmd
if exist hips_version.txt type hips_version.txt

echo [5/5] Done. If sc start failed with 577/1275, reboot and run this script again.
pause
exit /b 0

:runsystem
schtasks /Create /TN OpandaHips_%1 /TR "C:\opanda_test\%1" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F >nul
schtasks /Run /TN OpandaHips_%1 >nul
timeout /t 5 >nul
schtasks /Delete /TN OpandaHips_%1 /F >nul
exit /b 0
