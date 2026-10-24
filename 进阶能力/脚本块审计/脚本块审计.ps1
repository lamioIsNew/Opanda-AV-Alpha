#requires -Version 5.1
<#
    脚本块审计（PowerShell ScriptBlock 审计）
    ---------------------------------------------------------------
    作用：把 PowerShell 引擎记录下来的每一个"脚本块"（Event ID 4104，
          包含 -enc / IEX / 下载执行 这类内存马脚本）拉出来，
          逐个丢给本项目的 scan.exe 静态扫描，命中高危就告警。

    为什么用它代替"真 AMSI 提供程序"：
      * 真 AMSI 需要注册一个 in-proc COM 组件（HKLM 权限 + 数字签名），
        且要在每个宿主进程里被引擎加载；
      * 脚本块日志是 Windows 自带的机制，零驱动、零注册表、零签名，
        覆盖 PowerShell 内的内存脚本（AMSI 覆盖不了的落盘脚本也能抓）；
      * 代价：它是"执行后审计"，不是"执行前拦截"（真 AMSI 才是拦截）。

    用法：
      .\脚本块审计.ps1                    审计最近 1 小时的脚本块
      .\脚本块审计.ps1 -Minutes 360       回看 6 小时
      .\脚本块审计.ps1 -Follow            持续盯（每 30 秒扫一次新增）
      .\脚本块审计.ps1 -EnableLogging     打开脚本块日志记录（需管理员）
      .\脚本块审计.ps1 -Scanner <scan.exe> -Scaler <scaler.txt>
#>
param(
    [string]$Scanner = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'scan.exe'),
    [string]$Scaler  = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'scaler.txt'),
    [int]$Minutes = 60,
    [switch]$Follow,
    [switch]$EnableLogging
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch {}

$LOGNAME = 'Microsoft-Windows-PowerShell/Operational'
$POLKEY  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

function Write-Head($t) { Write-Host ""; Write-Host ("=== " + $t + " ===") -ForegroundColor Cyan }

# ---------- 1. 前置检查 ----------
if (-not (Test-Path -LiteralPath $Scanner)) { Write-Host ("[错误] 找不到扫描器: " + $Scanner) -ForegroundColor Red; exit 1 }
if (-not (Test-Path -LiteralPath $Scaler))  { Write-Host ("[错误] 找不到特征库: " + $Scaler)  -ForegroundColor Red; exit 1 }

$enabled = $null
try { $enabled = (Get-ItemProperty -Path $POLKEY -Name EnableScriptBlockLogging -ErrorAction Stop).EnableScriptBlockLogging } catch {}

if ($EnableLogging) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Host "[错误] 打开脚本块日志需要管理员权限，请右键以管理员身份运行。" -ForegroundColor Red; exit 2 }
    if (-not (Test-Path $POLKEY)) { New-Item -Path $POLKEY -Force | Out-Null }
    Set-ItemProperty -Path $POLKEY -Name EnableScriptBlockLogging -Value 1 -Type DWord
    Write-Host "[已开启] PowerShell 脚本块日志（重启 PowerShell 会话后对新脚本块生效）" -ForegroundColor Green
    $enabled = 1
}

Write-Head '脚本块审计'
Write-Host ("  扫描器   : " + $Scanner)
Write-Host ("  特征库   : " + $Scaler)
Write-Host ("  脚本块日志: " + $(if ($enabled -eq 1) { '已启用' } else { '未启用（下面会把现有日志也过一遍，但可能没有内容）' }))
Write-Host ("  回看窗口 : 最近 " + $Minutes + " 分钟")

# ---------- 2. 已经审计过的脚本块（按 ScriptBlockId+MessageNumber 去重） ----------
$seen = @{}
$seenFile = Join-Path $env:TEMP 'scriptblock_audit_seen.txt'
if (Test-Path -LiteralPath $seenFile) {
    Get-Content -LiteralPath $seenFile -ErrorAction SilentlyContinue | ForEach-Object { if ($_) { $seen[$_.Trim()] = $true } }
}

$tmpDir = Join-Path $env:TEMP ('sbaudit_' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

function Get-ScriptBlocks([int]$minAgo) {
    $since = (Get-Date).AddMinutes(-1 * $minAgo)
    $filter = @{ LogName = $LOGNAME; Id = 4104; StartTime = $since }
    $evts = @()
    try { $evts = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) } catch { $evts = @() }
    $out = New-Object System.Collections.ArrayList
    foreach ($e in $evts) {
        $txt = $null
        try { $txt = [string]$e.Properties[2].Value } catch {}
        if (-not $txt) { continue }
        $id  = ''
        try { $id = [string]$e.Properties[3].Value } catch {}
        $num = ''
        try { $num = [string]$e.Properties[0].Value } catch {}
        $key = $e.TimeCreated.ToString('s') + '|' + $id + '|' + $num
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$out.Add([pscustomobject]@{ Time = $e.TimeCreated; Key = $key; Text = $txt })
    }
    return ,$out
}

function Invoke-AuditOnce([int]$minAgo, [bool]$quiet) {
    $blocks = Get-ScriptBlocks $minAgo
    if ($blocks.Count -eq 0) {
        if (-not $quiet) { Write-Host "  最近 $minAgo 分钟内没有新的脚本块记录。" }
        return 0
    }
    if (-not $quiet) { Write-Host ("  本次待审脚本块: " + $blocks.Count + " 个") }
    $bad = 0
    $i = 0
    foreach ($b in $blocks) {
        $i++
        $f = Join-Path $tmpDir ('blk_' + $i + '.ps1')
        try { [IO.File]::WriteAllText($f, $b.Text, [System.Text.UTF8Encoding]::new($false)) } catch { continue }
        $out = & $Scanner $Scaler $f 2>&1
        $verdict = ''
        $name = ''
        foreach ($line in $out) {
            $s = [string]$line
            if ($s -match '【判定】') { $verdict = $s.Trim() }
            if ($s -match '【检测名】') { $name = $s.Trim() }
        }
        if ($verdict -match '高危|HIGH RISK' -or $verdict -match '疑似|SUSPICIOUS') {
            $bad++
            $tag = if ($verdict -match '高危|HIGH RISK') { '【高危】' } else { '【疑似】' }
            Write-Host ""
            Write-Host ("  " + $tag + " " + $b.Time.ToString('MM-dd HH:mm:ss') + "  " + $name) -ForegroundColor $(if ($tag -eq '【高危】') { 'Red' } else { 'Yellow' })
            # 只展示前 240 个字符，避免刷屏
            $snip = $b.Text -replace "`r?`n", ' '
            if ($snip.Length -gt 240) { $snip = $snip.Substring(0, 240) + ' …' }
            Write-Host ("      脚本内容: " + $snip)
        }
    }
    # 落盘"已看过"清单，避免重复审计
    try { $seen.Keys | Set-Content -LiteralPath $seenFile -Encoding UTF8 } catch {}
    return $bad
}

$totalBad = Invoke-AuditOnce $Minutes $false

if ($Follow) {
    Write-Head '持续监视模式（每 30 秒一轮，Ctrl+C 停止）'
    while ($true) {
        Start-Sleep -Seconds 30
        $n = Invoke-AuditOnce 2 $true
        if ($n -gt 0) { Write-Host ("  [新增告警] " + $n + " 个  " + (Get-Date).ToString('HH:mm:ss')) -ForegroundColor Red }
    }
} else {
    Write-Head '结论'
    if ($totalBad -gt 0) {
        Write-Host ("  本轮共发现 " + $totalBad + " 个可疑/恶意脚本块，详情见上方。") -ForegroundColor Red
    } else {
        Write-Host "  本轮未发现可疑脚本块。" -ForegroundColor Green
    }
    Write-Host "  提示：加 -Follow 可持续盯；加 -EnableLogging（管理员）可打开脚本块日志。"
}

Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
