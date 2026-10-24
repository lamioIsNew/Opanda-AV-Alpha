@echo off
cd /d C:\opanda_test
for /f "tokens=2 delims==" %%A in ('findstr /b "PID=" hips_target_info.txt') do set PID=%%A
HipsClient.exe kill %PID% > hips_kill.txt 2>&1
