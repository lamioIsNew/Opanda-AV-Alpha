# build_scanner_dll.ps1 -- 重建 scanner.dll / scanner_test.exe / sigdb_builder.exe
# 适用：Windows PowerShell 5.1，x64，MinGW-w64 gcc
# 用法：右键“使用 PowerShell 运行”，或在 PowerShell 中执行本文件。

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Src  = Join-Path $Root 'src'
$Bin  = Join-Path $Root 'bin'
$Db   = Join-Path $Root 'db'

$Gcc = 'G:\mingw64\bin\gcc.exe'
if (-not (Test-Path -LiteralPath $Gcc)) { $Gcc = 'gcc' }
$GccDir = Split-Path -Parent $Gcc
if ($GccDir -and (Test-Path -LiteralPath $GccDir)) { $env:Path = $GccDir + ';' + $env:Path }

New-Item -ItemType Directory -Force -Path $Bin, $Db | Out-Null
Push-Location $Src
try {
    $srcs = @(
        'scanner_api.c', 'scan_output.c', 'scan_main.c',
        'feature_extractor.c', 'signature_scan.c', 'detector.c',
        'lgb_model.c', 'script_scan.c', 'lnk_scan.c',
        'trust_check.c', 'verdict_cache.c', 'risk_name.c', 'hash_list.c'
    )
    $libs = @('-lcomdlg32', '-lole32', '-lshell32', '-lshlwapi', '-lcrypt32', '-lwintrust', '-ladvapi32')

    Write-Host '[1/3] scanner.dll'
    $a = @('-shared', '-Os', '-s', '-static', '-DSCANNER_BUILD_DLL', '-o', (Join-Path $Bin 'scanner.dll')) +
         $srcs + @('-Wl,--out-implib=libscanner.a') + $libs
    & $Gcc @a
    if ($LASTEXITCODE -ne 0) { throw "scanner.dll 编译失败（gcc $LASTEXITCODE）" }

    Write-Host '[2/3] scanner_test.exe'
    $a = @('scanner_test.c', '-municode', '-Os', '-s', '-static',
           '-I.', '-L.', '-lscanner', '-o', (Join-Path $Bin 'scanner_test.exe'))
    & $Gcc @a
    if ($LASTEXITCODE -ne 0) { throw "scanner_test.exe 编译失败（gcc $LASTEXITCODE）" }

    Write-Host '[3/3] sigdb_builder.exe + signatures.db'
    $a = @('sigdb_builder.c', 'signature_scan.c', '-Os', '-s', '-static',
           '-o', (Join-Path $Bin 'sigdb_builder.exe'))
    & $Gcc @a
    if ($LASTEXITCODE -ne 0) { throw "sigdb_builder.exe 编译失败（gcc $LASTEXITCODE）" }
    & (Join-Path $Bin 'sigdb_builder.exe') (Join-Path $Db 'signatures.db') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signatures.db 生成失败" }

    Copy-Item (Join-Path $Src 'scaler.txt') (Join-Path $Bin 'scaler.txt') -Force
    Write-Host ''
    Write-Host '构建完成。SHA256：'
    Get-ChildItem -LiteralPath $Bin -File | ForEach-Object {
        $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        '{0}  {1}' -f $h, $_.Name
    }
} finally {
    Pop-Location
}
