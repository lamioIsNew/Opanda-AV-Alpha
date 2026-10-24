# scan_startup.ps1 -- 启动项 / 感染点 体检
# 枚举系统自启动位置（注册表 Run、启动文件夹、计划任务、自动服务、Winlogon），
# 逐个交给同目录 scan.exe 扫描（PE / 脚本 / LNK 三类都会识别）。
# scan.exe 输出为中文人性化格式：本脚本解析【检测名】/【数字签名】/【命中特征】/
# 【风险名称】/【判定】行，并用 [HIGH RISK] 等机器标记做统计。
# 用法: powershell -ExecutionPolicy Bypass -File scan_startup.ps1
# 输出: 控制台 + 同目录 startup_audit_<时间>.txt（UTF-8）

$ErrorActionPreference = 'Continue'
# 以 UTF-8 解码 scan.exe 的中文输出（否则中文会乱码）
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$Root   = $PSScriptRoot
$Scan   = Join-Path $Root 'scan.exe'
$Scaler = Join-Path $Root 'scaler.txt'

foreach ($tool in @($Scan, $Scaler)) {
    if (-not (Test-Path $tool)) { Write-Host "缺少组件: $tool"; exit 1 }
}

$logPath = Join-Path $Root ('startup_audit_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($logPath, '', $utf8)

function Log([string]$line) {
    [IO.File]::AppendAllText($logPath, $line + [Environment]::NewLine, $utf8)
    Write-Host $line
}

Log ('== 启动项体检开始 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' ==')
Log ''

$items = New-Object System.Collections.ArrayList
function Add-Item([string]$src, [string]$name, [string]$cmd) {
    if ([string]::IsNullOrWhiteSpace($cmd)) { return }
    [void]$items.Add([pscustomobject]@{ Src = $src; Name = $name; Cmd = $cmd.Trim() })
}

# ---- 1) 注册表 Run / RunOnce（HKLM/HKCU + Wow6432Node）----
$runKeys = @(
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
    @('HKLM', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'),
    @('HKLM', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'),
    @('HKCU', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
    @('HKCU', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
    @('HKCU', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')
)
foreach ($k in $runKeys) {
    $ps = $k[0] + ':\' + $k[1]
    if (-not (Test-Path $ps)) { continue }
    $props = Get-ItemProperty -Path $ps -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        Add-Item ($k[0] + ' Run: ' + $k[1]) $p.Name ([string]$p.Value)
    }
}

# ---- 2) Winlogon Shell / Userinit ----
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path $wl) {
    $w = Get-ItemProperty $wl -ErrorAction SilentlyContinue
    Add-Item 'Winlogon' 'Shell' ([string]$w.Shell)
    Add-Item 'Winlogon' 'Userinit' ([string]$w.Userinit)
}

# ---- 3) 启动文件夹（用户 + 公共，含 .lnk）----
$startupDirs = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
)
$wsh = New-Object -ComObject WScript.Shell
foreach ($fd in $startupDirs) {
    if (-not (Test-Path $fd)) { continue }
    foreach ($f in (Get-ChildItem $fd -File -ErrorAction SilentlyContinue)) {
        $desc = $f.FullName
        if ($f.Extension -ieq '.lnk') {
            try {
                $sc = $wsh.CreateShortcut($f.FullName)
                $desc = $f.FullName + '  ->  ' + $sc.TargetPath + ' ' + $sc.Arguments
            } catch { }
        }
        Add-Item 'StartupFolder' $f.Name $desc
    }
}

# ---- 4) 计划任务（跳过 Windows 内置目录）----
if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($t in $tasks) {
        if ($t.State -eq 'Disabled') { continue }
        if ($t.TaskPath -like '\Microsoft\Windows\*') { continue }
        foreach ($a in $t.Actions) {
            $exe = [string]$a.Execute
            if ([string]::IsNullOrWhiteSpace($exe)) { continue }
            $arg = [string]$a.Arguments
            Add-Item ('Task: ' + $t.TaskPath + $t.TaskName) $t.TaskName ($exe.Trim() + ' ' + $arg.Trim())
        }
    }
}

# ---- 5) 自动启动服务 ----
$svcs = Get-CimInstance Win32_Service -Filter "StartMode='Auto'" -ErrorAction SilentlyContinue
foreach ($s in $svcs) {
    if ($s.PathName) { Add-Item 'Service' $s.Name ([string]$s.PathName) }
}

# ---- 去重 ----
$items = @($items | Sort-Object Cmd -Unique)

# ---- 工具函数 ----
function Get-ExePath([string]$cmd) {
    $c = $cmd.Trim()
    $r = ''
    if ($c.StartsWith('"')) {
        $i = $c.IndexOf('"', 1)
        if ($i -gt 0) { $r = $c.Substring(1, $i - 1) }
    }
    if (-not $r) {
        $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|lnk))(\s|$)', 'IgnoreCase')
        if ($m.Success) { $r = $m.Groups[1].Value } else { $r = ($c -split '\s+')[0] }
    }
    return $r.TrimEnd(' ', ',', ';')
}

function Resolve-Path2([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($p.Trim())
    if ($p -like '\SystemRoot\*') { $p = $env:SystemRoot + $p.Substring(12) }
    if ($p -notmatch '^[A-Za-z]:') {
        if ($p -notmatch '\\') {
            $c1 = Join-Path $env:SystemRoot ('System32\' + $p)
            if (Test-Path $c1) { return $c1 }
            if (Test-Path ($c1 + '.exe')) { return $c1 + '.exe' }
            $c2 = Join-Path $env:SystemRoot $p
            if (Test-Path $c2) { return $c2 }
            if (Test-Path ($c2 + '.exe')) { return $c2 + '.exe' }
            $gc = Get-Command $p -ErrorAction SilentlyContinue
            if ($gc -and $gc.Source) { return $gc.Source }
        }
        return $null
    }
    return $p
}

# ---- 逐个解析并扫描 ----
$n = 0
$sumHr = 0; $sumSus = 0; $sumNorm = 0; $sumTrust = 0; $sumMiss = 0; $sumSkip = 0
$scanned = @{}

foreach ($it in $items) {
    $n++
    Log ('[' + $n + '] ' + $it.Src + ' | ' + $it.Name)
    Log ('     Cmd: ' + $it.Cmd)

    $exe = Resolve-Path2 (Get-ExePath $it.Cmd)
    if (-not $exe) { Log '     [SKIP] 无法解析路径'; $sumSkip++; continue }
    if (-not (Test-Path $exe)) { Log ('     [MISSING] 文件不存在: ' + $exe); $sumMiss++; continue }

    if ($scanned.ContainsKey($exe)) {
        Log ('     （已扫描过: ' + $exe + '）')
        continue
    }
    $scanned[$exe] = $true

    $fi = Get-Item $exe -ErrorAction SilentlyContinue
    if ($fi -and $fi.Length -gt 200MB) { Log '     [SKIP] 文件过大'; $sumSkip++; continue }

    Log ('     File: ' + $exe)
    $out = & $Scan $Scaler $exe --no-pevm 2>$null | Out-String
    $lines = ($out -split "`n")
    $det  = ($lines | Where-Object { $_ -match '【检测名】' } | Select-Object -First 1)
    $sig  = ($lines | Where-Object { $_ -match '【数字签名】|【命中特征】' } | Select-Object -First 1)
    $risk = ($lines | Where-Object { $_ -match '【风险名称】' } | Select-Object -First 1)
    $verd = ($lines | Where-Object { $_ -match '\[(HIGH RISK|SUSPICIOUS|NORMAL|TRUSTED|PACKED)' } | Select-Object -First 1)
    if ($sig)  { Log ('     ' + $sig.Trim()) }
    if ($det)  { Log ('     ' + $det.Trim()) }
    if ($risk) { Log ('     ' + $risk.Trim()) }
    if ($verd) { Log ('     ' + $verd.Trim()) }

    $v = ([string]$verd) + ([string]$det)
    if ($v -match 'HIGH RISK')      { $sumHr++ }
    elseif ($v -match 'SUSPICIOUS') { $sumSus++ }
    elseif ($v -match 'TRUSTED')    { $sumTrust++ }
    elseif ($v -match 'PACKED')     { $sumSus++ }
    elseif ($v -match 'NORMAL')     { $sumNorm++ }
    else                            { $sumSkip++ }
}

Log ''
Log ('== 汇总: 总计 ' + $n + ' 项 | 高危 ' + $sumHr + ' | 疑似 ' + $sumSus + ' | 正常 ' + $sumNorm + ' | 可信签名 ' + $sumTrust + ' | 缺失 ' + $sumMiss + ' | 跳过 ' + $sumSkip + ' ==')
Log ('== 完成 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' ==')
Log ''
Log ('详细日志: ' + $logPath)
