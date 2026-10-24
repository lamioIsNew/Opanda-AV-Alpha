# build_scanner_msvc.ps1 -- rebuild scanner.dll with MSVC (x64)
# Windows PowerShell 5.1. Requires VS BuildTools + Windows SDK 10.0.26100.
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Src  = Join-Path $Root 'src'
$Sdk  = Join-Path $Root 'sdk'
$Bin  = Join-Path $Root 'bin'
$Obj  = Join-Path $PSScriptRoot 'obj\scanner'

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

$srcs = @(
    'scanner_api.c', 'scan_output.c', 'scan_main.c',
    'feature_extractor.c', 'signature_scan.c', 'detector.c',
    'lgb_model.c', 'script_scan.c', 'lnk_scan.c',
    'trust_check.c', 'verdict_cache.c', 'risk_name.c', 'hash_list.c',
    'hardware.c'
)

$objs = @()
foreach ($s in $srcs) {
    $in = Join-Path $Src $s
    $out = Join-Path $Obj ([IO.Path]::GetFileNameWithoutExtension($s) + '.obj')
    $objs += $out
    Write-Host "[C] $s"
    & cl.exe /nologo /c /O1 /W3 /MT /utf-8 /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS `
        /DSCANNER_BUILD_DLL /D_WIN32_WINNT=0x0A00 `
        /I"$Src" /I"$Sdk" /Fo"$out" "$in"
    if ($LASTEXITCODE -ne 0) { throw "compile failed: $s ($LASTEXITCODE)" }
}

Write-Host '[LINK] scanner.dll'
& link.exe /nologo /DLL /MACHINE:X64 /OUT:"$Bin\scanner.dll" `
    $objs `
    tbs.lib crypt32.lib wintrust.lib advapi32.lib ole32.lib shell32.lib shlwapi.lib `
    comdlg32.lib user32.lib gdi32.lib
if ($LASTEXITCODE -ne 0) { throw "link failed ($LASTEXITCODE)" }

Copy-Item (Join-Path $Src 'scaler.txt') (Join-Path $Bin 'scaler.txt') -Force
$h = (Get-FileHash -LiteralPath (Join-Path $Bin 'scanner.dll') -Algorithm SHA256).Hash
Write-Host "Build complete: $h  scanner.dll"
