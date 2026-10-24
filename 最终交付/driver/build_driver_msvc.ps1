# build_driver_msvc.ps1 -- build HipsDriver.sys + HipsClient.exe + HipsTestTarget.exe
# Requires VS BuildTools + WDK 10.0.26100 (km headers/libs).
$ErrorActionPreference = 'Stop'

$Here = $PSScriptRoot
$VcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$Wdk = 'C:\Program Files (x86)\Windows Kits\10'
$WdkVer = '10.0.26100.0'
$WdkInc = Join-Path $Wdk "Include\$WdkVer"
$WdkLib = Join-Path $Wdk "Lib\$WdkVer\km\x64"
$Obj = Join-Path $Here 'build'

if (-not (Test-Path -LiteralPath $VcVars)) { throw "vcvars64.bat not found: $VcVars" }
if (-not (Test-Path -LiteralPath (Join-Path $WdkInc 'km\wdm.h'))) { throw "WDK km headers not found: $WdkInc" }

$lines = & cmd.exe /c "`"$VcVars`" >nul 2>&1 && set"
foreach ($line in $lines) {
    if ($line -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
}
New-Item -ItemType Directory -Force -Path $Obj | Out-Null

Write-Host '[C] HipsDriver.c'
& cl.exe /nologo /c /kernel /GS- /Zl /Oi /W4 /utf-8 `
    /D_AMD64_ /DAMD64 /DWIN64 /D_WIN64 `
    /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 `
    /I"$WdkInc\km" /I"$WdkInc\shared" /I"$WdkInc\km\crt" /I"$Here" `
    /Fo"$Obj\HipsDriver.obj" "$Here\HipsDriver.c"
if ($LASTEXITCODE -ne 0) { throw "driver compile failed ($LASTEXITCODE)" }

Write-Host '[LINK] HipsDriver.sys'
& link.exe /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry `
    /NODEFAULTLIB /OUT:"$Here\HipsDriver.sys" "$Obj\HipsDriver.obj" `
    "$WdkLib\wdmsec.lib" "$WdkLib\ntoskrnl.lib" "$WdkLib\hal.lib" "$WdkLib\BufferOverflowK.lib"
if ($LASTEXITCODE -ne 0) { throw "driver link failed ($LASTEXITCODE)" }

Write-Host '[C] HipsClient.c'
& cl.exe /nologo /O2 /MT /utf-8 /DUNICODE /D_UNICODE /I"$Here" `
    /Fe:"$Here\HipsClient.exe" "$Here\HipsClient.c"
if ($LASTEXITCODE -ne 0) { throw "client compile failed ($LASTEXITCODE)" }

Write-Host '[C] HipsTestTarget.c'
& cl.exe /nologo /O2 /MT /utf-8 /DUNICODE /D_UNICODE /I"$Here" `
    /Fe:"$Here\HipsTestTarget.exe" "$Here\HipsTestTarget.c"
if ($LASTEXITCODE -ne 0) { throw "test target compile failed ($LASTEXITCODE)" }

Get-ChildItem -LiteralPath $Here -File | Where-Object { $_.Name -match '^(HipsDriver\.sys|HipsClient\.exe|HipsTestTarget\.exe)$' } |
    ForEach-Object {
        $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        Write-Host ("{0}  {1}" -f $h, $_.Name)
    }
Write-Host 'Driver build complete.'
