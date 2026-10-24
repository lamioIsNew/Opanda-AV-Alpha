@echo off
cd /d C:\opanda_test
start "" ScannerUI.exe --page overview
timeout /t 8 >nul
