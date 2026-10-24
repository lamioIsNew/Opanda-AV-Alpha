# auto_analyze.ps1 -- 自动化行为分析（静态选靶 + 沙箱动态观察 + 合并结论）
# ---------------------------------------------------------------------------
# 一条命令跑完：
#   1) 先用 scan.exe 做静态扫描，挑出"需要动态确认"的文件（默认高危/疑似/加壳/跳过）；
#   2) 逐个丢进 Windows Sandbox 真跑一遍，抓 进程/落地/持久化/网络；
#   3) 用行为规则给每个样本打分；
#   4) 把"静态结论 + 动态结论"合并成最终结论；
#   5) 输出汇总报告（Markdown + CSV）与每个样本的详细行为报告。
# 支持断点续跑（按 SHA256 缓存行为结果，重复运行不会重复开沙箱）。
#
# 用法：
#   .\auto_analyze.ps1 -Target <样本目录或文件> [-Top 10] [-Network] [-Verdicts HIGH,SUSPICIOUS]
#   .\auto_analyze.ps1 -Target <文件> -NoStatic              # 不做静态，直接动态观察
#   .\auto_analyze.ps1 -ScanCsv <scan_log_xxx.csv> -Top 20   # 复用已有扫描日志选靶
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)][string]$Target,
    [string]$ScanCsv,
    [string[]]$Verdicts = @('HIGH','SUSPICIOUS','PACKED','SKIP'),
    [string[]]$Exts = @(),
    [int]$Top = 10,
    [int]$TimeoutSeconds = 45,
    [switch]$Network,
    [int]$WaitMinutes = 8,
    [switch]$All,
    [switch]$NoStatic,
    [string]$ScannerDir,
    [string]$OutDir,
    [switch]$KeepWork
)

$ErrorActionPreference = 'Continue'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'sandbox_lib.ps1')
$GuestSrc    = Join-Path $Here 'guest_monitor.ps1'
$WorkRoot    = Join-Path $Here '_work'
$ReportsRoot = Join-Path $Here 'reports'
$CacheDir    = Join-Path $Here 'behavior_cache'
$CacheFile   = Join-Path $CacheDir 'cache.json'
if (-not $OutDir) { $OutDir = Join-Path $Here '分析结果' }
New-Item -ItemType Directory -Force -Path $WorkRoot, $ReportsRoot, $CacheDir, $OutDir | Out-Null

function Say($s) { Write-Host $s }
function Clip { param([string]$s, [int]$n = 120) if ($s -and $s.Length -gt $n) { return $s.Substring(0, $n) + '…' } return $s }

# ---------------- 原生进程输出按 UTF-8 解码 ----------------
function Invoke-Utf8([string]$exe, [string[]]$argList) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    # 用 Arguments 字符串（Windows PowerShell 5.1 的 ProcessStartInfo 没有 ArgumentList）
    $quoted = @()
    foreach ($a in $argList) { $quoted += ('"' + ([string]$a).Replace('"', '\"') + '"') }
    $psi.Arguments = ($quoted -join ' ')
    $p = [System.Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $errTask.GetAwaiter().GetResult()
    $p.WaitForExit()
    if ($err) { $out = $out + [Environment]::NewLine + $err }
    return $out
}

# ---------------- 静态扫描结果解析 ----------------
function Get-VerTok([string]$bracket) {
    if ($bracket -match '\[HIGH RISK')  { return 'HIGH' }
    if ($bracket -match '\[SUSPICIOUS') { return 'SUSPICIOUS' }
    if ($bracket -match '\[NORMAL')     { return 'NORMAL' }
    if ($bracket -match '\[TRUSTED')    { return 'TRUSTED' }
    if ($bracket -match '\[PACKED')     { return 'PACKED' }
    if ($bracket -match '\[SKIP')       { return 'SKIP' }
    return 'OTHER'
}
function Get-VerCn([string]$tok) {
    switch ($tok) {
        'HIGH'       { '高危' }
        'SUSPICIOUS' { '疑似' }
        'NORMAL'     { '正常' }
        'TRUSTED'    { '可信' }
        'PACKED'     { '加壳/无法判定' }
        'SKIP'       { '跳过/无法识别' }
        default      { '未知' }
    }
}
function Read-ScanCsv([string]$csv) {
    $rows = @()
    if (-not (Test-Path -LiteralPath $csv)) { return ,@() }
    $all = @(Import-Csv -LiteralPath $csv -Encoding utf8)
    foreach ($r in $all) {
        $v = @($r.PSObject.Properties.Value)
        if ($v.Count -ge 11 -and ([string]$v[0]) -notmatch '^#') { $rows += ,$v }
    }
    return ,@($rows)
}

function Find-Scanner {
    if ($ScannerDir) {
        $e = Join-Path $ScannerDir 'scan.exe'; $s = Join-Path $ScannerDir 'scaler.txt'
        if ((Test-Path -LiteralPath $e) -and (Test-Path -LiteralPath $s)) {
            return [pscustomobject]@{ Exe = (Resolve-Path $e).Path; Scaler = (Resolve-Path $s).Path; Dir = (Resolve-Path $ScannerDir).Path }
        }
    }
    # 多个候选时选“最新编译”的 scan.exe，避免误用旧版副本
    $dirs = @($Here, (Join-Path $Here '..\04_c'), (Join-Path $Here '..'),
              'F:\SVM项目\04_c', 'C:\Users\17265\Desktop\恶意软件扫描器') | Where-Object { $_ }
    $best = $null
    foreach ($c in $dirs) {
        $e = Join-Path $c 'scan.exe'; $s = Join-Path $c 'scaler.txt'
        if ((Test-Path -LiteralPath $e) -and (Test-Path -LiteralPath $s)) {
            $t = (Get-Item -LiteralPath $e).LastWriteTime
            if ($null -eq $best -or $t -gt $best.T) {
                $best = [pscustomobject]@{ T = $t; Exe = (Resolve-Path $e).Path; Scaler = (Resolve-Path $s).Path; Dir = (Resolve-Path $c).Path }
            }
        }
    }
    return $best
}

# ---------------- 行为规则打分 ----------------
function Score-Behavior {
    param($Data)
    $hits = New-Object System.Collections.ArrayList
    $seen = New-Object System.Collections.Generic.HashSet[string]
    function Add-Hit([int]$w, [string]$t) { if ($seen.Add($t)) { $hits.Add([pscustomobject]@{ w = $w; t = $t }) | Out-Null } }

    if (-not $Data) { return [pscustomobject]@{ Score = 0; Verdict = '未获数据'; Findings = @('（沙箱未产出行为数据）'); Behs = @(); Net = @() } }

    $procs      = @($Data.processes)
    $newFiles   = @($Data.newFiles)
    $regAdded   = @($Data.regAdded)
    $tasksAdded = @($Data.tasksAdded)
    $svcAdded   = @($Data.servicesAdded)
    $netConns   = @($Data.netConns)
    # 网络归因（schema>=5 的新字段 network_events）；旧报告（schema<=4）没有该字段，
    # 退化为下面那个"全局枚举"的 netConns。
    $netEvents  = @()
    if ($Data.PSObject.Properties['network_events']) { $netEvents = @($Data.network_events | Where-Object { $_ }) }
    if ($netEvents.Count -eq 0 -and $Data.PSObject.Properties['networkEvents']) { $netEvents = @($Data.networkEvents | Where-Object { $_ }) }
    $samples    = @($Data.samples)
    $sampleSha  = @($samples | ForEach-Object { [string]$_.sha256 } | Where-Object { $_ })
    $samplePaths = @($samples | ForEach-Object { [string]$_.path } | Where-Object { $_ })

    # 排除"我方启动样本"的进程：例如 .ps1 是用
    #   powershell.exe -ExecutionPolicy Bypass -NoProfile -File <样本>
    # 起的，.hta 是用 mshta.exe <样本> 起的。不清掉会被下面的规则误判成样本行为。
    # 判定顺序：① 新版报告里 guest 直接记录的启动 PID；② 兜底——按我方固定启动命令的
    # 精确形态（含参数顺序）识别；样本自己派生出来的同名进程参数顺序不同，仍会被正常计分。
    $launcherPids = New-Object System.Collections.Generic.HashSet[int]
    foreach ($la in @($Data.launch)) { if ($la -and $la.pid) { [void]$launcherPids.Add([int]$la.pid) } }
    foreach ($p in $procs) {
        $pn = ([string]$p.name).ToLower()
        $pc = [string]$p.cmd
        if (-not $pc) { continue }
        foreach ($sp in $samplePaths) {
            $e = [regex]::Escape($sp)
            if ($pn -match '^powershell' -and $pc -match ('(?i)-executionpolicy\s+bypass\s+-noprofile\s+-file\s+"?' + $e + '"?\s*$')) { [void]$launcherPids.Add([int]$p.pid); break }
            if ($pn -eq 'mshta.exe'  -and $pc -match ('(?i)mshta(\.exe)?\s+"?' + $e + '"?\s*$')) { [void]$launcherPids.Add([int]$p.pid); break }
        }
    }

    foreach ($p in $procs) {
        if ($launcherPids.Contains([int]$p.pid)) { continue }   # 我方启动进程，不算样本行为
        $n = ([string]$p.name).ToLower()
        $c = [string]$p.cmd
        if ($n -eq 'powershell.exe' -or $n -eq 'pwsh.exe') {
            if ($c -match '(?i)(-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/=]{40,}|-windowstyle\s+hidden|-w\s+hidden|-noprofile|-executionpolicy\s+bypass|-ep\s+bypass|downloadstring|downloadfile|invoke-expression|\biex\b|frombase64string|-bxor|hidden)') {
                Add-Hit 35 ("可疑 PowerShell 执行: " + (Clip $c 140))
            }
        }
        elseif ($n -eq 'mshta.exe')   { Add-Hit 30 ("mshta 执行脚本: " + (Clip $c 120)) }
        elseif ($n -eq 'rundll32.exe'){ Add-Hit 25 ("rundll32 间接执行: " + (Clip $c 120)) }
        elseif ($n -eq 'regsvr32.exe' -and $c -match '(?i)http|scrobj') { Add-Hit 35 ("regsvr32 远程/脚本执行: " + (Clip $c 120)) }
        elseif ($n -eq 'regsvr32.exe'){ Add-Hit 20 "regsvr32 间接执行" }
        elseif ($n -eq 'certutil.exe' -and $c -match '(?i)-urlcache|-decode|-encode|http') { Add-Hit 35 ("certutil 下载/解码: " + (Clip $c 120)) }
        elseif ($n -eq 'bitsadmin.exe') { Add-Hit 30 "bitsadmin 下载" }
        elseif ($n -eq 'wmic.exe' -and $c -match '(?i)process\s+call\s+create') { Add-Hit 30 "wmic 创建进程（横向/远程常用）" }
        elseif ($n -eq 'schtasks.exe' -and $c -match '(?i)/create') { Add-Hit 30 ("创建计划任务: " + (Clip $c 140)) }
        elseif ($n -eq 'vssadmin.exe' -and $c -match '(?i)delete\s+shadows') { Add-Hit 45 "删除卷影副本（勒索特征）" }
        elseif ($n -eq 'wbadmin.exe' -and $c -match '(?i)delete') { Add-Hit 40 "删除系统备份（勒索特征）" }
        elseif ($n -eq 'bcdedit.exe') { Add-Hit 35 "修改启动配置" }
        elseif ($n -eq 'wevtutil.exe' -and $c -match '(?i)\bcl\b') { Add-Hit 30 "清除系统日志" }
        elseif ($n -eq 'reg.exe' -and $c -match '(?i)\badd\b.*\\run') { Add-Hit 25 "注册表添加自启动" }
        elseif ($n -eq 'net.exe' -and $c -match '(?i)localgroup.*/add|user\s+\S+\s+/add') { Add-Hit 20 "创建本地账号" }
        elseif ($n -eq 'cipher.exe' -and $c -match '(?i)/w') { Add-Hit 30 "擦除磁盘空闲空间" }
    }

    # 名称级兜底：短命进程可能没抓到命令行，仅凭"高风险系统程序被拉起"也给分
    foreach ($p in $procs) {
        if ($launcherPids.Contains([int]$p.pid)) { continue }   # 我方启动进程，不算样本行为
        $n = ([string]$p.name).ToLower()
        if (-not [string]$p.cmd) {
            if (@('certutil.exe','bitsadmin.exe','mshta.exe','rundll32.exe','regsvr32.exe','msbuild.exe','installutil.exe','regasm.exe','regsvcs.exe','wmic.exe') -contains $n) {
                Add-Hit 15 ("出现高风险系统程序（未取到命令行）: " + $n)
            }
        }
    }

    if ($regAdded.Count -gt 0)   { Add-Hit 30 ("新增开机自启动项 " + $regAdded.Count + " 个") }
    if ($tasksAdded.Count -gt 0) { Add-Hit 30 ("新增计划任务 " + $tasksAdded.Count + " 个") }
    if ($svcAdded.Count -gt 0)   { Add-Hit 25 ("新增系统服务 " + $svcAdded.Count + " 个") }

    $startupDrop = @($newFiles | Where-Object { $_.path -match '(?i)\\Start Menu\\Programs\\Startup\\' })
    if ($startupDrop.Count -gt 0) { Add-Hit 30 "向启动文件夹投放文件" }

    $execDrops = @($newFiles | Where-Object { $_.exec })
    if ($execDrops.Count -gt 0) { Add-Hit ([Math]::Min(20, 10 * $execDrops.Count)) ("落地可执行/脚本文件 " + $execDrops.Count + " 个") }

    if ($sampleSha.Count -gt 0) {
        $selfCopy = @($newFiles | Where-Object { $_.sha256 -and ($sampleSha -contains $_.sha256) })
        if ($selfCopy.Count -gt 0) { Add-Hit 15 "样本自我复制到其它位置" }
    }

    # 网络：优先用"可归因到样本进程"的新数据（schema>=5）；旧报告退化为全局枚举。
    # 归因后的信号更可信（确系样本进程树发起），所以权重高于旧的全局枚举。
    $extNet = @($netEvents | Where-Object { -not ([string]$_.remote -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|127\.|::1)') })
    if ($netEvents.Count -gt 0) {
        if ($extNet.Count -gt 0) {
            $eps = @($extNet | ForEach-Object { ([string]$_.remote + ':' + [string]$_.port + '[' + [string]$_.state + ']') } | Select-Object -Unique)
            Add-Hit 30 ("样本进程外联 " + $extNet.Count + " 次（可归因）: " + (($eps | Select-Object -First 4) -join ', '))
        } else {
            Add-Hit 12 "样本进程仅有内网/回环连接（未见公网目标）"
        }
    }
    elseif ($netConns.Count -gt 0) { Add-Hit 25 ("存在外联连接尝试（全局枚举，未归因） " + $netConns.Count + " 个") }

    $total = 0
    foreach ($h in $hits) { $total += $h.w }
    if ($total -gt 100) { $total = 100 }
    $verdict = '未见明显恶意行为'
    if ($total -ge 55) { $verdict = '确认恶意行为' }
    elseif ($total -ge 22) { $verdict = '可疑行为' }

    $findings = @($hits | ForEach-Object { "[+" + $_.w + "] " + $_.t })
    return [pscustomobject]@{ Score = $total; Verdict = $verdict; Findings = $findings; Behs = $hits; Net = $extNet }
}

function Merge-Verdict([string]$staticTok, [string]$behVerdict) {
    $sc = Get-VerCn $staticTok
    if ($behVerdict -eq '确认恶意行为') {
        if ($staticTok -eq 'HIGH') { return '确认恶意（静态高危 + 动态确认）' }
        return ("动态确认恶意（静态为「$sc」，靠行为分析抓到）")
    }
    if ($behVerdict -eq '可疑行为') {
        if ($staticTok -eq 'HIGH') { return '高度可疑（静态高危，动态亦见可疑行为）' }
        if ($staticTok -eq 'SUSPICIOUS') { return '可疑（静态 + 动态均可疑）' }
        return ("动态发现可疑行为（静态为「$sc」）")
    }
    if ($behVerdict -eq '未获数据') {
        if ($staticTok -eq 'HIGH' -or $staticTok -eq 'SUSPICIOUS') { return ("静态判为「$sc」（动态未取得数据）") }
        return ("无法确认（静态「$sc」，动态未取得数据）")
    }
    # 未见明显恶意行为
    if ($staticTok -eq 'HIGH' -or $staticTok -eq 'SUSPICIOUS') { return ("静态判为「$sc」，动态未复现（可能需特定环境/网络/触发条件）") }
    if ($staticTok -eq 'PACKED' -or $staticTok -eq 'SKIP') { return ("静态无法判定「$sc」，动态亦未见异常（仍建议谨慎）") }
    return '未见异常（静态 + 动态一致）'
}

# ---------------- 行为结果缓存 ----------------
function Load-Cache {
    if (Test-Path -LiteralPath $CacheFile) {
        try { return @((Get-Content -LiteralPath $CacheFile -Raw -Encoding utf8 | ConvertFrom-Json)) } catch { return @() }
    }
    return @()
}
function Save-Cache($entries) {
    try { ($entries | ConvertTo-Json -Depth 5) | Out-File -FilePath $CacheFile -Encoding utf8 } catch { }
}

# ============================ 主流程 ============================
if (-not (Test-Path -LiteralPath $GuestSrc)) { throw "缺少 guest_monitor.ps1：$GuestSrc" }
if (-not (Test-Path -LiteralPath $Target))   { throw "目标不存在：$Target" }

$avail = Test-SandboxAvailable
if (-not $avail.Ok) { Say $avail.Reason; exit 2 }
$left = Close-AllSandboxes
if ($left -gt 0) { Say ("[*] 已关闭残留的沙箱实例 " + $left + " 个（保证本次从干净状态开始）") }

$isDir = (Get-Item -LiteralPath $Target).PSIsContainer
$title = if ($isDir) { "目录" } else { "文件" }
Say "============================================================"
Say "        自动化行为分析（静态选靶 → 沙箱动态观察 → 合并结论）"
Say "============================================================"
Say ("目标    : " + $Target + "  (" + $title + ")")
Say ("网络     : " + $(if ($Network) { "沙箱内放通（观察外联）" } else { "禁用（隔离）" }))
Say ("单样本观察时长 : " + $TimeoutSeconds + " 秒")
Say ""

# ---------- 1) 静态选靶 ----------
$candidates = New-Object System.Collections.ArrayList
if ($ScanCsv) {
    Say ("[1/4] 读取已有扫描日志选靶: " + $ScanCsv)
    $data = Read-ScanCsv $ScanCsv
    foreach ($v in $data) {
        $tok = Get-VerTok ([string]$v[6])
        $candidates.Add([pscustomobject]@{
            path = [string]$v[1]; name = [string]$v[2]; size = [long]($(if ($v[3]) { $v[3] } else { 0 }))
            sha = [string]$v[4]; kind = [string]$v[5]; staticBracket = [string]$v[6]
            staticScore = [string]$v[7]; staticTok = $tok; detail = [string]$v[10]
        }) | Out-Null
    }
}
elseif (-not $NoStatic) {
    $scanner = Find-Scanner
    if (-not $scanner) { throw "找不到 scan.exe / scaler.txt，请用 -ScannerDir 指定扫描器目录。" }
    Say ("[1/4] 静态扫描选靶（" + $scanner.Exe + "）...")
    $csv = Join-Path $WorkRoot ('static_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.csv')
    $null = Invoke-Utf8 $scanner.Exe @($scanner.Scaler, $Target, '--log', $csv, '--no-pevm')
    if (-not (Test-Path -LiteralPath $csv)) {
        throw ("静态扫描未生成日志：" + $csv + "`n    可能是扫描器版本过旧（缺少 --log 参数），请用 -ScannerDir 指向最新 scan.exe，或加 -NoStatic。")
    }
    $data = Read-ScanCsv $csv
    foreach ($v in $data) {
        $tok = Get-VerTok ([string]$v[6])
        $candidates.Add([pscustomobject]@{
            path = [string]$v[1]; name = [string]$v[2]; size = [long]($(if ($v[3]) { $v[3] } else { 0 }))
            sha = [string]$v[4]; kind = [string]$v[5]; staticBracket = [string]$v[6]
            staticScore = [string]$v[7]; staticTok = $tok; detail = [string]$v[10]
        }) | Out-Null
    }
    Say ("      静态结果 " + $candidates.Count + " 个文件")
}
else {
    Say "[1/4] -NoStatic：跳过静态扫描，直接枚举目标"
    $items = @()
    if ($isDir) {
        $items = @(Get-ChildItem -LiteralPath $Target -Recurse -File -ErrorAction SilentlyContinue)
    } else {
        $items = @(Get-Item -LiteralPath $Target)
    }
    foreach ($f in $items) {
        $candidates.Add([pscustomobject]@{
            path = $f.FullName; name = $f.Name; size = [long]$f.Length; sha = ''
            kind = ''; staticBracket = ''; staticScore = ''; staticTok = 'OTHER'; detail = ''
        }) | Out-Null
    }
}

# ---------- 2) 过滤 + 排序 + 上限 ----------
$execExt = @('.exe','.dll','.sys','.scr','.com','.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.wsf','.wsh','.hta','.msi','.lnk','.pif','.cpl','.jar')
$picked = New-Object System.Collections.ArrayList
$seenPath = New-Object System.Collections.Generic.HashSet[string]
foreach ($c in $candidates) {
    if (-not (Test-Path -LiteralPath $c.path)) { continue }
    if (-not $seenPath.Add($c.path)) { continue }
    $ext = ([IO.Path]::GetExtension($c.path)).ToLower()
    if (-not ($execExt -contains $ext)) { continue }        # 压缩包等不送沙箱
    if ($Exts.Count -gt 0 -and -not ($Exts -contains $ext)) { continue }  # 指定扩展名过滤（如只跑 .exe）
    if (-not $All) {
        if (-not ($Verdicts -contains $c.staticTok)) { continue }
    }
    if ($c.size -gt 100MB) { Say ("      [跳过] " + $c.name + "（超过 100MB）"); continue }
    $picked.Add($c) | Out-Null
}
# 按静态评分降序（无评分置底）
$sorted = @($picked | Sort-Object -Property @{ Expression = { $s = 0.0; [void][double]::TryParse([string]$_.staticScore, [ref]$s); $s } } -Descending)
if ($Top -gt 0 -and $sorted.Count -gt $Top) { $sorted = $sorted[0..($Top - 1)] }

if ($sorted.Count -eq 0) {
    Say ""
    Say "没有符合条件的样本需要动态分析（可加 -All 或调整 -Verdicts）。"
    exit 0
}
Say ("      选中 " + $sorted.Count + " 个样本进入沙箱分析")
Say ""

# ---------- 3) 逐个沙箱观察 ----------
$cache = @(Load-Cache)
$cacheMap = @{}
foreach ($e in $cache) { if ($e.sha) { $cacheMap[[string]$e.sha] = $e } }
$cacheDirty = $false

$results = New-Object System.Collections.ArrayList
$idx = 0
foreach ($c in $sorted) {
    $idx++
    Say ("------------------------------------------------------------")
    Say ("[" + $idx + "/" + $sorted.Count + "] " + $c.name)
    Say ("      静态: " + (Get-VerCn $c.staticTok) + "  评分 " + $c.staticScore + "  " + (Clip $c.detail 90))

    $data = $null
    $reportDir = $null
    $reused = $false
    if ($c.sha -and $cacheMap.ContainsKey($c.sha)) {
        $ce = $cacheMap[$c.sha]
        $rd = [string]$ce.reportDir
        if ($rd -and (Test-Path -LiteralPath (Join-Path $rd 'behavior_report.json'))) {
            $reportDir = $rd; $reused = $true
            try { $data = (Get-Content -LiteralPath (Join-Path $rd 'behavior_report.json') -Raw -Encoding utf8 | ConvertFrom-Json) } catch { $data = $null }
        }
    }

    if ($reused) {
        Say "      （命中行为缓存，跳过沙箱）"
    } else {
        $null = Wait-NoSandboxRunning -TimeoutSec 180
        Say "      正在沙箱中观察（约 1-2 分钟）..."
        $res = Invoke-SandboxSample -Sample $c.path -WorkRoot $WorkRoot -GuestScript $GuestSrc `
                                    -Tag 'auto' -TimeoutSeconds $TimeoutSeconds -Network:$Network -WaitMinutes $WaitMinutes
        if (-not $res.Ok) {
            Say "      [失败] 沙箱未产出报告，跳过。"
            $results.Add([pscustomobject]@{
                Name = $c.name; Path = $c.path; Size = $c.size; Sha = $c.sha
                StaticTok = $c.staticTok; StaticScore = $c.staticScore; StaticBracket = $c.staticBracket
                BehScore = -1; BehVerdict = '未获数据'; Final = (Merge-Verdict $c.staticTok '未获数据')
                Findings = @('（沙箱未产出报告）'); ReportDir = ''; Net = @()
            }) | Out-Null
            if (-not $KeepWork) { $null = Remove-SandboxRun -RunDir $res.RunDir }
            continue
        }
        $reportDir = Save-SandboxRun -RunDir $res.RunDir -ReportsRoot $ReportsRoot -Name $c.name
        $data = $res.Data
        # 补算 SHA（静态可能没给出）
        if (-not $c.sha -and $data -and $data.samples) {
            $c.sha = [string](@($data.samples)[0].sha256)
        }
        if ($c.sha) {
            $cacheMap[$c.sha] = [pscustomobject]@{ sha = $c.sha; name = $c.name; reportDir = $reportDir }
            $cacheDirty = $true
        }
        if (-not $KeepWork) { $null = Remove-SandboxRun -RunDir $res.RunDir }
    }

    $beh = Score-Behavior $data
    $final = Merge-Verdict $c.staticTok $beh.Verdict
    Say ("      动态: " + $beh.Verdict + "  评分 " + $beh.Score)
    foreach ($f in $beh.Findings) { Say ("        · " + $f) }
    Say ("      最终: " + $final)
    Say ("      行为报告: " + $reportDir)

    $results.Add([pscustomobject]@{
        Name = $c.name; Path = $c.path; Size = $c.size; Sha = $c.sha
        StaticTok = $c.staticTok; StaticScore = $c.staticScore; StaticBracket = $c.staticBracket
        BehScore = $beh.Score; BehVerdict = $beh.Verdict; Final = $final
        Findings = $beh.Findings; ReportDir = $reportDir; Net = @($beh.Net)
    }) | Out-Null
}

if ($cacheDirty) { Save-Cache @($cacheMap.Values) }

# ---------- 4) 输出汇总报告 ----------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$mdPath = Join-Path $OutDir ("自动分析报告_" + $stamp + ".md")
$csvPath = Join-Path $OutDir ("结论_" + $stamp + ".csv")

$md = New-Object System.Collections.Generic.List[string]
$md.Add("# 自动化行为分析报告")
$md.Add("")
$md.Add("- 生成时间: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$md.Add("- 目标: ``" + $Target + "``")
$md.Add("- 沙箱网络: " + $(if ($Network) { "启用（按样本进程归因观察外联）" } else { "禁用（隔离）" }))
$md.Add("- 单样本观察: " + $TimeoutSeconds + " 秒")
$md.Add("- 样本数: " + $results.Count)
$md.Add("")
$md.Add("## 结论一览")
$md.Add("")
$md.Add("| 文件 | 静态 | 动态 | 行为分 | 最终结论 |")
$md.Add("|---|---|---|---|---|")
foreach ($r in $results) {
    $md.Add("| " + $r.Name + " | " + (Get-VerCn $r.StaticTok) + " | " + $r.BehVerdict + " | " + $r.BehScore + " | " + $r.Final + " |")
}
$md.Add("")
$md.Add("## 逐样本明细")
foreach ($r in $results) {
    $md.Add("")
    $md.Add("### " + $r.Name)
    $md.Add("")
    $md.Add("- 路径: ``" + $r.Path + "``")
    $md.Add("- 大小: " + $r.Size + " 字节")
    $md.Add("- SHA256: ``" + $r.Sha + "``")
    $md.Add("- 静态结论: " + (Get-VerCn $r.StaticTok) + "（" + $r.StaticBracket + "）评分 " + $r.StaticScore)
    $md.Add("- 动态结论: " + $r.BehVerdict + "（行为评分 " + $r.BehScore + "/100）")
    $md.Add("- **最终结论: " + $r.Final + "**")
    if ($r.Findings.Count -gt 0) {
        $md.Add("- 关键行为:")
        foreach ($f in $r.Findings) { $md.Add("  - " + $f) }
    }
    if ($r.Net -and @($r.Net).Count -gt 0) {
        $md.Add("- 网络归因（样本进程树发起的连接）:")
        foreach ($n in @($r.Net)) {
            $via = ''; if ($n.via -eq 'launcher') { $via = "（经我方启动进程）" }
            $md.Add("  - PID " + $n.pid + " " + $n.proc + $via + " -> " + $n.remote + ":" + $n.port + " [" + $n.state + "] @" + $n.at)
        }
    }
    if ($r.ReportDir) {
        $txt = Join-Path $r.ReportDir 'behavior_report.txt'
        if (Test-Path -LiteralPath $txt) {
            $md.Add("- 详细行为报告: ``" + $txt + "``")
            $md.Add("")
            $md.Add("<details><summary>点开查看原始行为报告</summary>")
            $md.Add("")
            $md.Add('```text')
            foreach ($ln in (Get-Content -LiteralPath $txt -Encoding utf8)) { $md.Add($ln) }
            $md.Add('```')
            $md.Add("</details>")
        }
    }
}
[System.IO.File]::WriteAllLines($mdPath, $md.ToArray(), (New-Object System.Text.UTF8Encoding($true)))

$csv = New-Object System.Collections.Generic.List[string]
$csv.Add("文件名,完整路径,大小,SHA256,静态判定,静态评分,行为判定,行为评分,最终结论,关键行为,行为报告目录")
function CsvEsc([string]$s) { if ($null -eq $s) { return '""' }; return '"' + ($s -replace '"','""') + '"' }
foreach ($r in $results) {
    $csv.Add((@($r.Name, $r.Path, $r.Size, $r.Sha, $r.StaticBracket, $r.StaticScore, $r.BehVerdict, $r.BehScore, $r.Final, ($r.Findings -join ' | '), $r.ReportDir) | ForEach-Object { CsvEsc ([string]$_) }) -join ',')
}
[System.IO.File]::WriteAllLines($csvPath, $csv.ToArray(), (New-Object System.Text.UTF8Encoding($true)))

# ---------- 控制台汇总 ----------
$nConfirmed = @($results | Where-Object { $_.BehVerdict -eq '确认恶意行为' }).Count
$nSuspect   = @($results | Where-Object { $_.BehVerdict -eq '可疑行为' }).Count
$nClean     = @($results | Where-Object { $_.BehVerdict -eq '未见明显恶意行为' }).Count
$nFail      = @($results | Where-Object { $_.BehVerdict -eq '未获数据' }).Count
Say ""
Say "============================================================"
Say "自动行为分析完成"
Say ("  动态度  : 确认恶意 " + $nConfirmed + " / 可疑 " + $nSuspect + " / 未见异常 " + $nClean + " / 未获数据 " + $nFail)
Say ("  汇总报告: " + $mdPath)
Say ("  结论表格: " + $csvPath)
Say "============================================================"
