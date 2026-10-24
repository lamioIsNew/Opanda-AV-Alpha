# build_all.ps1 -- rebuild engine + GUI
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build_scanner_dll.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'build_gui.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'All builds completed.'