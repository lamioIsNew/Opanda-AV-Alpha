@echo off
setlocal
cd /d "%~dp0bin"
if not exist "ScannerUI.exe" (
  echo [ERROR] ScannerUI.exe not found.
  pause
  exit /b 1
)
if not exist "scanner.dll" (
  echo [ERROR] scanner.dll not found next to ScannerUI.exe.
  pause
  exit /b 1
)
start "" "ScannerUI.exe" %*
endlocal