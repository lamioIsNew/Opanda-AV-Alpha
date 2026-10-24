# guest_monitor.ps1 -- Windows Sandbox 内部行为监控 v5
# 由 sandbox_lib.ps1 生成的 .wsb 通过 LogonCommand 调用。
# 只做观察，不主动联网：记录 进程创建(含短命进程) / 文件落地 / 持久化 / 网络连接尝试。
# v5 新增：网络"归因"——按【样本进程树】逐 PID 抓 TCP 连接（远端 IP / 端口 / 状态），
#          写入报告新字段 network_events；只认样本进程树发起的连接，系统基线流量不计。
# 兼容 Windows PowerShell 5.1（沙箱内即是 5.1）。所有结果写入 C:\Out（宿主可写映射）。
param(
    [int]$TimeoutSeconds = 45,
    [switch]$EnableNetwork,
    [switch]$AutoShutdown
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$Out       = 'C:\Out'
$Samples   = 'C:\Samples'
$Report    = Join-Path $Out 'behavior_report.txt'
$JsonPath  = Join-Path $Out 'behavior_report.json'
$DonePath  = Join-Path $Out '_DONE'
$EventFile = Join-Path $Out 'proc_events.jsonl'
$Artifacts = Join-Path $Out 'artifacts'
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
Remove-Item -LiteralPath $DonePath, $Report, $JsonPath, $EventFile, (Join-Path $Out 'event_dump.txt'), (Join-Path $Out 'json_error.txt') -Force -ErrorAction SilentlyContinue

$lines = New-Object System.Collections.Generic.List[string]
function Log([string]$s) { $lines.Add([string]$s) | Out-Null }

# 系统自身产生的噪声（错误报告转储、系统包缓存等），不算样本行为
function Is-Noise([string]$p) {
    foreach ($n in @('\Windows\WER\', '\Microsoft\Windows\WER\', '\AppData\Local\Packages\',
                     'ModuleAnalysisCache', '\LocalState\Search\settings.db', '\SoftwareDistribution\',
                     '\Windows\CSC\', '\Windows\Prefetch\', '\Windows\Logs\', '\Windows\Temp\',
                     '\AppData\Local\Microsoft\Windows\INetCache\', '\AppData\Local\ConnectedDevicesPlatform\')) {
        if ($p -like ('*' + $n + '*')) { return $true }
    }
    return $false
}
# 常见可执行/脚本扩展名（宿主判定"落地即执行"用；这里也给个标记）
function Is-ExecExt([string]$p) {
    $e = ([IO.Path]::GetExtension($p)).ToLower()
    return @('.exe','.dll','.scr','.com','.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.wsf','.wsh','.hta','.msi','.lnk','.sys','.pif').Contains($e)
}

Log "========== 行为沙箱报告 =========="
Log ("开始时间 : " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Log ("计算机   : " + $env:COMPUTERNAME + "    用户: " + $env:USERNAME)
if ($EnableNetwork) { Log "网络     : 已启用（观察出站连接尝试）" } else { Log "网络     : 已禁用（隔离）" }
Log ("监控时长 : " + $TimeoutSeconds + " 秒")
Log ""

# ---------- 监控目录 ----------
$watchDirs = @(
    $env:TEMP, $env:TMP, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData,
    'C:\Users\Public', 'C:\Users\Public\Downloads', "$env:USERPROFILE\Desktop",
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
) | Where-Object { $_ } | Select-Object -Unique

# ---------- 进程采集策略 ----------
# 说明：Windows PowerShell 5.1 下 Register-CimIndicationEvent 的 -Action 拿不到事件
#       属性（$event 绑定的是 watcher 对象）。故不使用 WMI 事件订阅，改为 250ms
#       高频轮询 Win32_Process —— 既能取到命令行，也能覆盖绝大多数短命进程。
$eventOk = $false
Log "进程采集: 高频轮询（250ms）"
Log ""

# ---------- 采样前快照：文件 ----------
$before = @{}
foreach ($d in $watchDirs) {
    if (Test-Path -LiteralPath $d) {
        Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $before[$_.FullName] = [long]$_.Length
        }
    }
}

# ---------- 采样前快照：注册表自启动 ----------
$regKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$regBefore = @{}
foreach ($k in $regKeys) {
    if (Test-Path $k) {
        (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { $regBefore["$k|$($_.Name)"] = [string]$_.Value }
    }
}

# ---------- 采样前快照：计划任务 / 服务 ----------
$taskBefore = @{}
foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) { $taskBefore[$t.TaskPath + $t.TaskName] = $true }
$svcBefore = @{}
foreach ($s in (Get-Service -ErrorAction SilentlyContinue)) { $svcBefore[$s.Name] = $true }

# ---------- 进程基线 + 事件/轮询采集 ----------
$procSeen = @{}
foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $procSeen[[int]$p.ProcessId] = $true }
$pollNew  = New-Object System.Collections.ArrayList
function SnapshotProcs {
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $id = [int]$p.ProcessId
        if (-not $procSeen.ContainsKey($id)) {
            $procSeen[$id] = $true
            $pollNew.Add([pscustomobject]@{
                PID  = $id
                PPID = [int]$p.ParentProcessId
                Name = [string]$p.Name
                Cmd  = [string]$p.CommandLine
            }) | Out-Null
        }
    }
}

# ---------- 样本进程树（网络归因用）----------
# 我方启动的样本进程 + 其全部子孙（按 PPID 做闭包）。网络事件只在这个集合里抓；
# 不在集合里的连接一律视为系统基线流量（DNS 客户端/Windows Update 等），不记录。
function Get-SampleTreePids {
    $set = New-Object System.Collections.Generic.HashSet[int]
    foreach ($p in $launched) { [void]$set.Add([int]$p.Id) }
    $grow = $true
    while ($grow) {
        $grow = $false
        foreach ($e in $pollNew) {
            $id = [int]$e.PID
            if (-not $set.Contains($id) -and $set.Contains([int]$e.PPID)) { [void]$set.Add($id); $grow = $true }
        }
    }
    return ,$set
}

# ---------- 启动样本 ----------
$targets = @(Get-ChildItem -LiteralPath $Samples -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
$launched = New-Object System.Collections.ArrayList
$sampleInfo = New-Object System.Collections.ArrayList
$launchInfo = New-Object System.Collections.ArrayList   # 我方启动样本所用的进程（评判阶段据此排除自检伪命中）
$netEvents   = New-Object System.Collections.ArrayList   # 网络归因：样本进程树发起的 TCP 连接事件
$netSeenKeys = New-Object System.Collections.Generic.HashSet[string]  # 去重键 pid|remote|port|state
$launcherPidSet = New-Object System.Collections.Generic.HashSet[int]  # 我方启动样本的 PID（网络事件里标注 via=launcher）
$treePidSet  = New-Object System.Collections.Generic.HashSet[int]     # 最近一次算出的样本进程树 PID

function Start-Sample($f) {
    $ext = $f.Extension.ToLower()
    switch ($ext) {
        '.ps1' { Start-Process -FilePath 'powershell.exe' -ArgumentList @('-ExecutionPolicy','Bypass','-NoProfile','-File', $f.FullName) -PassThru }
        '.vbs' { Start-Process -FilePath 'wscript.exe' -ArgumentList @($f.FullName) -PassThru }
        '.vbe' { Start-Process -FilePath 'wscript.exe' -ArgumentList @($f.FullName) -PassThru }
        '.js'  { Start-Process -FilePath 'wscript.exe' -ArgumentList @($f.FullName) -PassThru }
        '.jse' { Start-Process -FilePath 'wscript.exe' -ArgumentList @($f.FullName) -PassThru }
        '.wsf' { Start-Process -FilePath 'wscript.exe' -ArgumentList @($f.FullName) -PassThru }
        '.wsh' { Start-Process -FilePath 'wscript.exe' -ArgumentList @($f.FullName) -PassThru }
        '.hta' { Start-Process -FilePath 'mshta.exe' -ArgumentList @($f.FullName) -PassThru }
        '.bat' { Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $f.FullName) -PassThru }
        '.cmd' { Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $f.FullName) -PassThru }
        '.msi' { Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $f.FullName, '/qn') -PassThru }
        '.lnk' { Start-Process -FilePath $f.FullName -PassThru }
        default { Start-Process -FilePath $f.FullName -PassThru }
    }
}

Log "---------- 样本启动 ----------"
if ($targets.Count -eq 0) { Log "（C:\Samples 下没有可运行样本）" }
foreach ($f in $targets) {
    $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    $sampleInfo.Add([pscustomobject]@{ path = $f.FullName; size = [long]$f.Length; sha256 = $h }) | Out-Null
    Log ("启动 : " + $f.FullName + "  (" + $f.Length + " 字节" + $(if ($h) { ", SHA256=" + $h.Substring(0,16) + "…" } else { "" }) + ")")
    $p = Start-Sample $f
    if ($p) {
        $launched.Add($p) | Out-Null
        # 记录我方启动进程的命令行：例如 .ps1 是用 powershell -ExecutionPolicy Bypass -File 起的，
        # 不清掉会让"可疑 PowerShell 执行"规则误判成样本行为。
        $lc = ''
        try {
            $pi = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $p.Id) -ErrorAction SilentlyContinue
            if ($pi) { $lc = [string]$pi.CommandLine }
        } catch {}
        $launchInfo.Add([pscustomobject]@{ pid = [int]$p.Id; name = [string]$p.ProcessName; cmd = $lc }) | Out-Null
    }
    # 启动后立刻进入短间隔轮询：短命样本的子进程可能只存活几百毫秒
    for ($k = 0; $k -lt 5; $k++) { SnapshotProcs; Start-Sleep -Milliseconds 180 }
}
Log ""

# ---------- 监控循环 ----------
$netLog   = New-Object System.Collections.Generic.List[string]
foreach ($li in $launchInfo) { [void]$launcherPidSet.Add([int]$li.pid) }
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$netTick  = 0
while ((Get-Date) -lt $deadline) {
    SnapshotProcs
    $netTick++
    # 网络归因：约每秒一次，对【样本进程树】里的每个 PID 单独查"它自己"发起的 TCP 连接。
    # 用 -OwningProcess 精确归因：DNS 客户端 / Windows Update / 我们的监控进程都不在样本树里，
    # 系统基线流量天然被过滤；不做全网罗列，避免噪声淹没真信号。
    if ($EnableNetwork -and ($netTick % 4 -eq 0)) {
        $treePidSet = Get-SampleTreePids
        $ownNames = @{}
        foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $ownNames[[int]$p.ProcessId] = [string]$p.Name }
        foreach ($spId in @($treePidSet)) {
            foreach ($c in (Get-NetTCPConnection -OwningProcess $spId -ErrorAction SilentlyContinue)) {
                $ra = [string]$c.RemoteAddress
                if (-not $ra) { continue }
                if (@('0.0.0.0','127.0.0.1','::','::1','0:0:0:0:0:0:0:0','::ffff:127.0.0.1') -contains $ra) { continue }
                $st  = [string]$c.State
                $key = ('{0}|{1}|{2}|{3}' -f $spId, $ra, [int]$c.RemotePort, $st)
                if ($netSeenKeys.Add($key)) {
                    $via = 'sample'
                    if ($launcherPidSet.Contains([int]$spId)) { $via = 'launcher' }
                    $pn = ''; if ($ownNames.ContainsKey([int]$spId)) { $pn = $ownNames[[int]$spId] }
                    $netEvents.Add([pscustomobject]@{
                        pid = [int]$spId; proc = $pn; via = $via
                        remote = $ra; port = [int]$c.RemotePort; state = $st
                        at = (Get-Date -Format 'HH:mm:ss')
                    }) | Out-Null
                    $s = "{0}:{1}" -f $ra, [int]$c.RemotePort
                    if (-not $netLog.Contains($s)) { $netLog.Add($s) | Out-Null }
                }
            }
        }
    }
    Start-Sleep -Milliseconds 250
}
SnapshotProcs

# ---------- 终止样本（含子进程树）----------
foreach ($p in $launched) { & taskkill.exe /T /F /PID $p.Id 2>$null | Out-Null }
Start-Sleep -Milliseconds 800
SnapshotProcs

# 收尾事件订阅
try { Unregister-Event -SourceIdentifier 'SBXProc' -ErrorAction SilentlyContinue } catch {}

# ---------- 汇总进程（事件 + 轮询，按 PID 合并，补命令行）----------
$procMap = @{}
foreach ($e in $pollNew) {
    $procMap[[int]$e.PID] = [pscustomobject]@{ PID = [int]$e.PID; PPID = [int]$e.PPID; Name = $e.Name; Cmd = $e.Cmd }
}
if ($eventOk -and (Test-Path -LiteralPath $EventFile)) {
    foreach ($ln in (Get-Content -LiteralPath $EventFile -ErrorAction SilentlyContinue)) {
        if (-not $ln) { continue }
        try { $o = $ln | ConvertFrom-Json } catch { continue }
        $id = [int]$o.pid
        if (-not $procMap.ContainsKey($id)) {
            $procMap[$id] = [pscustomobject]@{ PID = $id; PPID = [int]$o.ppid; Name = [string]$o.name; Cmd = '' }
        } elseif (-not $procMap[$id].Cmd) {
            # 事件里有名字但没命令行时，用事件名补齐
        }
    }
}
# 标记"来自样本"的进程：由已启动 PID 或其子孙派生
$samplePids = New-Object System.Collections.Generic.HashSet[int]
foreach ($p in $launched) { [void]$samplePids.Add([int]$p.Id) }
$changed = $true
while ($changed) {
    $changed = $false
    foreach ($k in $procMap.Keys) {
        if (-not $samplePids.Contains($k) -and $samplePids.Contains([int]$procMap[$k].PPID)) {
            [void]$samplePids.Add($k); $changed = $true
        }
    }
}
$procs = @()
foreach ($k in ($procMap.Keys | Sort-Object)) {
    $e = $procMap[$k]
    $procs += [pscustomobject]@{
        pid        = [int]$e.PID
        ppid       = [int]$e.PPID
        name       = [string]$e.Name
        cmd        = [string]$e.Cmd
        fromSample = [bool]$samplePids.Contains([int]$e.PID)
    }
}

# ---------- 结果：新增/修改文件（去重 + 降噪 + 归档）----------
$seenPath = New-Object System.Collections.Generic.HashSet[string]
$newFiles = New-Object System.Collections.ArrayList
$modFiles = New-Object System.Collections.ArrayList
$noiseCnt = 0
foreach ($d in $watchDirs) {
    if (Test-Path -LiteralPath $d) {
        Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not $seenPath.Add($_.FullName)) { return }
            if (Is-Noise $_.FullName) { $noiseCnt++; return }
            if (-not $before.ContainsKey($_.FullName)) {
                $newFiles.Add($_) | Out-Null
            } elseif ($before[$_.FullName] -ne [long]$_.Length) {
                $modFiles.Add($_) | Out-Null
            }
        }
    }
}
function Save-Artifact($f) {
    $dest = Join-Path $Artifacts ($f.Name)
    $i = 1
    while (Test-Path -LiteralPath $dest) { $dest = Join-Path $Artifacts ($f.BaseName + "_$i" + $f.Extension); $i++ }
    if ($f.Length -le 32MB) {
        Copy-Item -LiteralPath $f.FullName -Destination $dest -ErrorAction SilentlyContinue
        return (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    }
    return $null
}
$newOut = New-Object System.Collections.ArrayList
foreach ($f in ($newFiles | Sort-Object Length -Descending)) {
    $h = Save-Artifact $f
    $newOut.Add([pscustomobject]@{
        path = $f.FullName; size = [long]$f.Length; sha256 = $h; exec = (Is-ExecExt $f.FullName)
    }) | Out-Null
}
$modOut = New-Object System.Collections.ArrayList
foreach ($f in $modFiles) {
    $modOut.Add([pscustomobject]@{ path = $f.FullName; size = [long]$f.Length; exec = (Is-ExecExt $f.FullName) }) | Out-Null
}

# ---------- 结果：注册表自启动 ----------
$regAdded = New-Object System.Collections.Generic.List[string]
foreach ($k in $regKeys) {
    if (Test-Path $k) {
        (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object {
                $key = "$k|$($_.Name)"
                if (-not $regBefore.ContainsKey($key)) { $regAdded.Add("$k  ->  $($_.Name) = $($_.Value)") | Out-Null }
            }
    }
}

# ---------- 结果：计划任务 / 服务 ----------
$taskAdded = New-Object System.Collections.Generic.List[string]
foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    $key = $t.TaskPath + $t.TaskName
    if (-not $taskBefore.ContainsKey($key)) { $taskAdded.Add($key) | Out-Null }
}
$svcAdded = New-Object System.Collections.Generic.List[string]
foreach ($s in (Get-Service -ErrorAction SilentlyContinue)) {
    if (-not $svcBefore.ContainsKey($s.Name)) { $svcAdded.Add($s.Name) | Out-Null }
}

# ---------- 输出（文本报告）----------
Log "---------- 新进程（监控期间新起）----------"
$launchPidSet = New-Object System.Collections.Generic.HashSet[int]
foreach ($li in $launchInfo) { [void]$launchPidSet.Add([int]$li.pid) }
$sampleProcs = @($procs | Where-Object { $_.fromSample })
$otherProcs  = @($procs | Where-Object { -not $_.fromSample })
if ($sampleProcs.Count -eq 0) { Log "  （样本未派生新进程）" }
foreach ($e in $sampleProcs) {
    $cmd = $e.cmd
    if ($cmd -and $cmd.Length -gt 300) { $cmd = $cmd.Substring(0,300) + ' …' }
    $mark = '★'
    if ($launchPidSet.Contains([int]$e.pid)) { $mark = '★（我方启动命令，不计入行为评分）' }
    Log ("  {0} [{1}] {2}" -f $mark, $e.name, $cmd)
}
if ($otherProcs.Count -gt 0) {
    Log ("  （另有非样本来源的新进程 " + $otherProcs.Count + " 个，多为系统后台，已省略）")
}

Log ""
Log "---------- 落地文件（样本写入/生成）----------"
if ($newOut.Count -eq 0) { Log "  （无）" }
foreach ($f in $newOut) {
    $tag = ''; if ($f.exec) { $tag = '  [可执行]' }
    $hs = ''; if ($f.sha256) { $hs = '  SHA256=' + $f.sha256 }
    Log ("  {0}  ({1} 字节){2}{3}" -f $f.path, $f.size, $tag, $hs)
}

Log ""
Log "---------- 被修改文件 ----------"
if ($modOut.Count -eq 0) { Log "  （无）" }
foreach ($f in $modOut) { Log ("  " + $f.path) }

Log ""
Log "---------- 持久化：注册表自启动 ----------"
if ($regAdded.Count -eq 0) { Log "  （无）" }
foreach ($r in $regAdded) { Log ("  " + $r) }

Log ""
Log "---------- 持久化：计划任务 / 服务 ----------"
if ($taskAdded.Count -eq 0 -and $svcAdded.Count -eq 0) { Log "  （无）" }
foreach ($t in $taskAdded) { Log ("  计划任务: " + $t) }
foreach ($s in $svcAdded) { Log ("  服务    : " + $s) }

Log ""
Log "---------- 网络连接尝试（按样本进程归因）----------"
if (-not $EnableNetwork) { Log "  （网络已禁用，未监控）" }
elseif ($netEvents.Count -eq 0) { Log "  （样本进程树未观察到出站 TCP 连接）" }
else {
    foreach ($e in $netEvents) {
        $tag = ''
        if ($e.via -eq 'launcher') { $tag = '   [我方启动的进程；其连接仍源自样本代码]' }
        Log ("  PID {0} {1}  ->  {2}:{3}  [{4}]  @{5}{6}" -f $e.pid, $e.proc, $e.remote, $e.port, $e.state, $e.at, $tag)
    }
}

Log ""
Log ("（已过滤系统噪声文件 " + $noiseCnt + " 个）")
Log ("结束时间 : " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Log "================================="

[System.IO.File]::WriteAllLines($Report, $lines.ToArray(), (New-Object System.Text.UTF8Encoding($true)))

# ---------- 构造数据对象 ----------
$buildErr = ''
$json = $null
try {
    $json = [ordered]@{
        schema        = 5
        start         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        host          = [string]$env:COMPUTERNAME
        user          = [string]$env:USERNAME
        network       = [bool]$EnableNetwork
        timeout       = [int]$TimeoutSeconds
        eventCapture  = [bool]$eventOk
        samples       = @($sampleInfo)
        launch        = @($launchInfo)
        processes     = @($procs)
        newFiles      = @($newOut)
        modFiles      = @($modOut)
        regAdded      = @($regAdded)
        tasksAdded    = @($taskAdded)
        servicesAdded = @($svcAdded)
        netConns      = @($netLog)
        network_events = @($netEvents)
        networkEvents = @($netEvents)
        noiseFiltered = [int]$noiseCnt
    }
} catch {
    $buildErr = ($_ | Out-String)
}

# ---------- 写 JSON（首选）----------
$jsonText = ''
if ($null -ne $json) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try { $jsonText = ConvertTo-Json -InputObject $json -Depth 8 }
    catch { $buildErr += "`nJSON-ERR: " + ($_ | Out-String) }
    $ErrorActionPreference = $old
    if (-not [string]::IsNullOrEmpty($jsonText)) {
        [IO.File]::WriteAllText($JsonPath, $jsonText, (New-Object System.Text.UTF8Encoding($true)))
    }
}

# ---------- 写 CLIXML（兜底：跨 PS 版本、对任意对象都稳）----------
if ($null -ne $json) {
    try { $json | Export-Clixml -Path (Join-Path $Out 'behavior_report.xml') -Force } catch { $buildErr += "`nCLIXML-ERR: " + ($_ | Out-String) }
}

# 仅在出错时留诊断
if ($buildErr) {
    [IO.File]::WriteAllText((Join-Path $Out 'json_diag.txt'), ($buildErr + "`nJSON长度=" + ([string]$jsonText).Length), (New-Object System.Text.UTF8Encoding($true)))
}

# ---------- 完成哨兵 ----------
[IO.File]::WriteAllText($DonePath, "done", (New-Object System.Text.UTF8Encoding($false)))

if ($AutoShutdown) {
    Start-Sleep -Seconds 2
    & shutdown.exe /s /t 3 /f 2>$null | Out-Null
}
