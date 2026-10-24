# 虚拟执行.ps1 -- scan.exe「一般扫描流程」的 PE 虚拟执行联动脚本
# ------------------------------------------------------------------
# 用法（一般不用手动敲，scan.exe 扫完会自动调用）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File 虚拟执行.ps1 -ListFile <路径清单.txt> -OutDir <产物目录>
#   powershell -NoProfile -ExecutionPolicy Bypass -File 虚拟执行.ps1 -Target <文件|目录>
#   powershell -NoProfile -ExecutionPolicy Bypass -File 虚拟执行.ps1 -Target <目录> -All
#
# 说明：
#   · 只做静态筛选 + 用户态虚拟执行，不开虚拟机、不落真机、不真跑样本。
#   · 解释器含 x86-32 / x86-64 两条通路；.NET 会明确写一行"跳过 + 原因"。
#   · 输出中文人性化；解壳产物另存到 <OutDir>，并自动再交 scan.exe 复扫一遍。
# ------------------------------------------------------------------
param(
    [string]$ListFile = '',
    [string]$Target = '',
    [string]$OutDir = '',
    [string]$ScanRoot = '',
    [string]$ScanExe = '',
    [string]$Scaler = '',
    [int]$MaxInsn = 30000000,
    [int]$MaxSec = 60,
    [switch]$All,
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'

$lib = Join-Path $PSScriptRoot 'pevm_lib.ps1'
if (-not (Test-Path -LiteralPath $lib)) { Write-Host "[错误] 找不到 pevm_lib.ps1（应与本脚本同目录）"; exit 2 }
. $lib

# ---- 定位扫描器根目录与 scan.exe ----
if (-not $ScanRoot) {
    $cand = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
    if (Test-Path -LiteralPath (Join-Path $cand 'scan.exe')) { $ScanRoot = $cand }
    elseif (Test-Path -LiteralPath 'C:\Users\17265\Desktop\恶意软件扫描器\scan.exe') { $ScanRoot = 'C:\Users\17265\Desktop\恶意软件扫描器' }
}
if (-not $ScanExe) {
    if ($ScanRoot) { $ScanExe = Join-Path $ScanRoot 'scan.exe' }
}
if (-not $Scaler) {
    if ($ScanRoot) { $Scaler = Join-Path $ScanRoot 'scaler.txt' }
    if (-not (Test-Path -LiteralPath $Scaler)) { $Scaler = 'scaler.txt' }
}

# ---- 收集待分析文件 ----
$targets = @()
$srcDesc = ''
if ($ListFile) {
    if (-not (Test-Path -LiteralPath $ListFile)) { Write-Host "[错误] 清单文件不存在: $ListFile"; exit 2 }
    $targets = @([IO.File]::ReadAllLines($ListFile, [Text.Encoding]::UTF8) | Where-Object { $_.Trim() -ne '' })
    $srcDesc = "静态扫描判定的加壳 PE（清单: $ListFile）"
} elseif ($Target) {
    if (-not (Test-Path -LiteralPath $Target)) { Write-Host "[错误] 目标不存在: $Target"; exit 2 }
    $isDir = (Get-Item -LiteralPath $Target).PSIsContainer
    if (-not $isDir) {
        $targets = @((Resolve-Path -LiteralPath $Target).Path)
        $srcDesc = '指定的单个文件'
    } else {
        if (-not (Test-Path -LiteralPath $ScanExe)) { Write-Host "[错误] 找不到 scan.exe：$ScanExe"; exit 2 }
        $csvTmp = Join-Path $env:TEMP ('pevm_sel_' + [guid]::NewGuid().ToString('N') + '.csv')
        Write-Host "[虚拟执行] 先用 scan.exe 静态筛选（只挑 PE，不执行）..."
        $null = Invoke-NativeUtf8 -Exe $ScanExe -ArgList @($Scaler, $Target, '--log', $csvTmp, '--no-pevm')
        if (Test-Path -LiteralPath $csvTmp) {
            $rows = @(Import-Csv -LiteralPath $csvTmp -Encoding UTF8)
            foreach ($r in $rows) {
                $p = $r.'完整路径'
                if (-not $p) { continue }
                if ($All) {
                    if ((Get-PeKind $p)) { $targets += $p }
                } elseif ($r.'判定' -match '\[PACKED\]') {
                    $targets += $p
                }
            }
            Remove-Item -LiteralPath $csvTmp -Force -ErrorAction SilentlyContinue
        }
        $srcDesc = "目录内静态判定为加壳的 PE（目录: $Target）"
    }
} else {
    Write-Host "[错误] 请给出 -ListFile 或 -Target"
    exit 2
}

$targets = @($targets | Select-Object -Unique)

# ---- 产物目录 ----
if (-not $OutDir) {
    $base = $Target
    if (-not $base -and $targets.Count -gt 0) { $base = Split-Path -Parent $targets[0] }
    if ($base) {
        if ((Test-Path -LiteralPath $base) -and (Get-Item -LiteralPath $base).PSIsContainer) {
            $OutDir = Join-Path $base '_虚拟执行'
        } else {
            $OutDir = Join-Path (Split-Path -Parent $base) '_虚拟执行'
        }
    } else {
        $OutDir = Join-Path $env:TEMP 'pevm_out'
    }
}

# ---- 日志出口：控制台 + 报告文件 ----
$script:reportLines = New-Object System.Collections.ArrayList
$sink = {
    param($s)
    if (-not $Quiet) { Write-Host $s }
    [void]$script:reportLines.Add([string]$s)
}

$ctx = New-PevmContext -SearchRoot $ScanRoot -ScanExe $ScanExe -Scaler $Scaler `
                       -MaxInsn $MaxInsn -MaxSec $MaxSec -All:$All -OutRoot $OutDir -Sink $sink

if (-not $Quiet) {
    Write-Host ""
    Write-Host "===== PE 虚拟执行（用户态 x86-32 / x86-64 解释器，不落真机、不调真 API）====="
    Write-Host ("  来源    : {0}" -f $srcDesc)
    Write-Host ("  样本数  : {0}" -f $targets.Count)
    if ($ctx.Exe) { Write-Host ("  解释器  : {0}" -f $ctx.Exe) } else { Write-Host "  解释器  : 未找到 pe_vm.exe" }
    Write-Host ("  产物目录: {0}" -f $OutDir)
    Write-Host ("  预算    : {0:N0} 条指令 / {1} 秒" -f $MaxInsn, $MaxSec)
}

$i = 0
foreach ($f in $targets) {
    $i++
    if (-not $Quiet) { Write-Host ("" + "  --- [{0}/{1}] {2}" -f $i, $targets.Count, (Split-Path $f -Leaf)) }
    $kind = Get-PeKind $f
    if (-not $kind) {
        if (-not $Quiet) { Write-Host "  【虚拟执行】跳过：不是 PE 文件" }
        continue
    }
    if ($kind -ne 'x86' -and $kind -ne 'x64') { Skip-Vm -Ctx $ctx -Kind $kind; continue }
    Invoke-Pevm -Ctx $ctx -File $f -StaticToken 'PACK'
}

Write-VmLine $ctx ""
Show-VmSummary -Ctx $ctx
Write-VmLine $ctx ""

# ---- 落一份报告 ----
try {
    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $rp = Join-Path $OutDir '虚拟执行报告.txt'
    $head = @(
        "PE 虚拟执行报告（用户态 x86-32 / x86-64 解释器，不落真机、不调真 API）",
        ("时间  : " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
        ("来源  : " + $srcDesc),
        ("样本数: " + $targets.Count),
        ("解释器: " + $ctx.Exe),
        ""
    )
    $report = [System.Collections.Generic.List[string]]::new()
    foreach ($x in $head) { [void]$report.Add([string]$x) }
    foreach ($x in $script:reportLines) { [void]$report.Add([string]$x) }
    [IO.File]::WriteAllText($rp, ($report -join "`r`n"), ([System.Text.UTF8Encoding]::new($true)))
    if (-not $Quiet) { Write-Host ("[虚拟执行] 报告已保存: {0}" -f $rp) }
} catch {
    if (-not $Quiet) { Write-Host ("[提示] 报告写入失败: " + $_.Exception.Message) }
}
