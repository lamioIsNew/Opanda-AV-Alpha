# build_gui_msvc.ps1 -- rebuild ScannerUI.exe with MSVC (x64, Win32 + Direct2D)
# Windows PowerShell 5.1. Requires VS BuildTools + Windows SDK 10.0.26100.
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Gui  = Join-Path $Root 'src\gui'
$Sdk  = Join-Path $Root 'sdk'
$Bin  = Join-Path $Root 'bin'
$Obj  = Join-Path $PSScriptRoot 'obj\gui'

$VcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $VcVars)) { throw "vcvars64.bat not found: $VcVars" }
$lines = & cmd.exe /c "`"$VcVars`" >nul 2>&1 && set"
foreach ($line in $lines) {
    if ($line -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
}
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw 'cl.exe not found after vcvars64' }

New-Item -ItemType Directory -Force -Path $Bin, $Obj | Out-Null

Write-Host '[RC] ScannerUI.manifest'
$res = Join-Path $Obj 'ScannerUI.res'
& rc.exe /nologo /I"$Gui" /fo"$res" (Join-Path $Gui 'ScannerUI.rc')
if ($LASTEXITCODE -ne 0) { throw "rc.exe failed ($LASTEXITCODE)" }

$srcs = @('main.cpp', 'scan.cpp', 'ui.cpp', 'qtn_crypto.cpp')
$objs = @()
foreach ($s in $srcs) {
    $in = Join-Path $Gui $s
    $out = Join-Path $Obj ([IO.Path]::GetFileNameWithoutExtension($s) + '.obj')
    $objs += $out
    Write-Host "[C++] $s"
    & cl.exe /nologo /c /O2 /W3 /MT /utf-8 /EHsc /std:c++17 `
        /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS `
        /I"$Gui" /I"$Sdk" /Fo"$out" "$in"
    if ($LASTEXITCODE -ne 0) { throw "compile failed: $s ($LASTEXITCODE)" }
}

Write-Host '[LINK] ScannerUI.exe'
& link.exe /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /ENTRY:wWinMainCRTStartup `
    /OUT:"$Bin\ScannerUI.exe" $objs $res `
    d2d1.lib dwrite.lib dwmapi.lib ole32.lib uuid.lib shell32.lib shlwapi.lib `
    comctl32.lib comdlg32.lib user32.lib gdi32.lib advapi32.lib bcrypt.lib ncrypt.lib
if ($LASTEXITCODE -ne 0) { throw "link failed ($LASTEXITCODE)" }

$h = (Get-FileHash -LiteralPath (Join-Path $Bin 'ScannerUI.exe') -Algorithm SHA256).Hash
Write-Host "Build complete: $h  ScannerUI.exe"
