# build_gui.ps1 -- rebuild ScannerUI.exe (Win32 + Direct2D) from src/gui
# Windows PowerShell 5.1, x64, MinGW-w64. Requires bin\scanner.dll at runtime.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Src  = Join-Path $Root 'src\gui'
$Sdk  = Join-Path $Root 'sdk'
$Bin  = Join-Path $Root 'bin'

$Gxx = 'G:\mingw64\bin\g++.exe'
if (-not (Test-Path -LiteralPath $Gxx)) { $Gxx = 'g++' }
$GxxDir = Split-Path -Parent $Gxx
if ($GxxDir -and (Test-Path -LiteralPath $GxxDir)) { $env:Path = $GxxDir + ';' + $env:Path }
$Windres = 'G:\mingw64\bin\windres.exe'
if (-not (Test-Path -LiteralPath $Windres)) { $Windres = 'windres' }

New-Item -ItemType Directory -Force -Path $Bin | Out-Null
Push-Location $Src
try {
    Write-Host '[1/2] manifest resource'
    $res = Join-Path $Src 'ScannerUI.res.o'
    & $Windres 'ScannerUI.rc' '-O' 'coff' '-o' $res
    if ($LASTEXITCODE -ne 0) { throw "windres failed ($LASTEXITCODE)" }

    Write-Host '[2/2] ScannerUI.exe'
    $out = Join-Path $Bin 'ScannerUI.exe'
    $a = @('-std=c++17', '-O2', '-municode', '-mwindows', '-static', '-static-libgcc', '-static-libstdc++',
           '-finput-charset=UTF-8', '-I.', ('-I' + $Sdk),
           'main.cpp', 'scan.cpp', 'ui.cpp', $res,
           '-o', $out,
           '-ld2d1', '-ldwrite', '-ldwmapi', '-lole32', '-luuid', '-lshell32', '-lshlwapi',
           '-lcomctl32', '-lcomdlg32', '-luser32', '-lgdi32', '-ladvapi32')
    & $Gxx @a
    if ($LASTEXITCODE -ne 0) { throw "ScannerUI.exe build failed (g++ $LASTEXITCODE)" }
    $h = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash
    Write-Host ''
    Write-Host "Build complete: $h  ScannerUI.exe"
} finally {
    Pop-Location
}