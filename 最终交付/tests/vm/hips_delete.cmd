@echo off
cd /d C:\opanda_test
for /f "tokens=2 delims==" %%A in ('findstr /b "PATH=" hips_target_info.txt') do set FPATH=%%A
HipsClient.exe delete "%FPATH%" > hips_delete.txt 2>&1
