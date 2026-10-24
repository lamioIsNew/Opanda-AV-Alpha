# build_all.ps1 -- rebuild engine + GUI with MSVC (x64)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build_scanner_msvc.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'build_gui_msvc.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'All builds completed.'
