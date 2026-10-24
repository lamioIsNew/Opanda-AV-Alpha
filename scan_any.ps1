# scan_any.ps1 -- universal scanning entry (PE / scripts / archives)
# ------------------------------------------------------------------
#  * Archive members are decompressed straight into a memory pipe and scanned
#    by stream_scan.exe -- nothing malicious ever touches disk (AV-proof).
#  * stream_scan.exe auto-routes: PE  -> signature/pack/model pipeline;
#    LNK shortcuts -> heuristic LNK engine (promo/malicious cmds);
#    text scripts (bat/cmd/ps1/vbs/js/wsf/hta...) -> heuristic script engine.
#  * scan.exe (file mode) additionally checks Authenticode/catalog signatures:
#    files signed by known vendors are reported [TRUSTED]. Verdict caching
#    (SHA256 -> verdict, file "verdict_cache.txt" in the working dir) skips
#    re-analysis of already-scanned files.
#  * Nested archives are extracted to a temp dir and scanned recursively
#    (depth / size limits apply).
#  * Native tool output is captured via .NET Process with explicit UTF-8
#    decoding; 7z runs with -sccUTF-8 -- Chinese results land correctly in
#    the console and in the UTF-8 log file.
#  * Result blocks are printed in friendly Chinese (risk name + advice);
#    machine tokens ([HIGH RISK] / [SUSPICIOUS] / [NORMAL] / [TRUSTED] /
#    PACKED) stay unchanged -- the summary below counts them from the log.
#  * 虚拟执行联动（PE 专用）：静态判为 [PACKED] 的 PE（或 -PevmAll 时的所有 PE）
#    自动交给 pe_vm.exe 做用户态解释执行（x86-32 / x86-64 两条通路）—— 不落真机、不调真 API，
#    由解释器还原解壳/行为（写注册表、自启动、联网、落地 PE）。
#    动态结论用独立标记 [VM: ...] 输出，不干扰上面的机器标记与统计口径；
#    解壳产物会自动再走一次静态引擎，若报毒则记为「动态找回」。
# Usage:
#   & .\scan_any.ps1 <file | directory | archive> [-Recurse] [-MaxDepth 3]
#   & .\scan_any.ps1 <file | directory> [-Sandbox] [-SandboxTop 5] [-SandboxNetwork]
#     -Sandbox  扫描结束后，自动把高危/疑似/加壳/跳过 的文件送 Windows 沙箱
#               真跑一遍（静态 + 动态合并结论），需要已启用“Windows 沙箱”功能。
#   & .\scan_any.ps1 <file | directory> [-NoPevm] [-PevmAll] [-PevmMaxInsn N]
#                          [-PevmMaxSec N] [-PevmOutDir 路径]
#     -NoPevm      关闭虚拟执行联动（只做静态）
#     -PevmAll     所有 PE 都做虚拟执行（默认只做加壳的）
#     -PevmMaxInsn 每个样本的指令预算，默认 30000000
#     -PevmMaxSec  每个样本的秒数预算，默认 60
#     -PevmOutDir  解壳产物落地目录，默认 <目标>\_虚拟执行
# ------------------------------------------------------------------
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Target,
    [string[]]$Password = @('infected', 'malware', 'password'),
    [int]$MaxDepth = 3,
    [switch]$Recurse,
    [switch]$Sandbox,
    [int]$SandboxTop = 5,
    [switch]$SandboxNetwork,
    [switch]$NoPevm,
    [switch]$PevmAll,
    [int]$PevmMaxInsn = 30000000,
    [int]$PevmMaxSec = 60,
    [string]$PevmOutDir = ''
)

$ErrorActionPreference = 'Continue'
$Root    = $PSScriptRoot
$SevenZ  = 'C:\Program Files\7-Zip\7z.exe'
$ScanExe = Join-Path $Root 'scan.exe'
$Stream  = Join-Path $Root 'stream_scan.exe'
$Scaler  = Join-Path $Root 'scaler.txt'
$TmpDir  = Join-Path $env:TEMP 'opencode\scan_any_tmp'
$ArcExts = @('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.tgz')
$MaxMemberBytes = 200MB
$MaxTotalBytes  = 1GB

foreach ($tool in @($SevenZ, $ScanExe, $Stream, $Scaler)) {
    if (-not (Test-Path $tool)) { Write-Host "缺少依赖文件: $tool"; exit 1 }
}
New-Item -ItemType Directory -Force $TmpDir | Out-Null

# ---------------- logging ----------------
$script:logPath = $null
function Set-Log([string]$p) {
    $dir = Split-Path $p -Parent
    if (-not $dir) { $dir = (Get-Location).Path }
    $name = [IO.Path]::GetFileName($p)
    $script:logPath = Join-Path $dir ($name + '.scanlog.txt')
    [IO.File]::WriteAllText($script:logPath, "", (New-Object System.Text.UTF8Encoding($false)))
}
function Log([string]$line) {
    $line = [string]$line
    if ($script:logPath) {
        [IO.File]::AppendAllText($script:logPath, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
    }
    Write-Host $line.TrimEnd()
}

# ---------------- native process helpers (explicit UTF-8 decode) ----------------
function New-NativePsi([string]$exe, [string[]]$argList) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    if ($psi.PSObject.Properties['ArgumentList']) {
        foreach ($a in $argList) { [void]$psi.ArgumentList.Add([string]$a) }
    } else {
        $parts = foreach ($a in $argList) {
            $s = [string]$a
            if ($s -match '[\s"]') { '"' + ($s -replace '"', '\"') + '"' } else { $s }
        }
        $psi.Arguments = ($parts -join ' ')
    }
    return $psi
}

$script:lastExit = 0
function Invoke-Utf8([string]$exe, [string[]]$argList) {
    $psi = New-NativePsi $exe $argList
    $p = [System.Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $errTask.GetAwaiter().GetResult()
    $p.WaitForExit()
    $script:lastExit = $p.ExitCode
    if ($err) { $out = $out + [Environment]::NewLine + $err }
    return $out
}

# 7z stdout bytes -> stream_scan stdin bytes (memory pipe, nothing on disk)
function Invoke-PipeScan([string]$zip, [string]$pw, [string]$member) {
    $leaf = Split-Path $member -Leaf
    $psiA = New-NativePsi $SevenZ @('x', '-so', "-p$pw", $zip, $member)
    $psiB = New-NativePsi $Stream @($Scaler, $leaf)
    $psiB.RedirectStandardInput = $true
    $pa = [System.Diagnostics.Process]::Start($psiA)
    $pb = [System.Diagnostics.Process]::Start($psiB)
    $errTaskB = $pb.StandardError.ReadToEndAsync()
    try {
        $pa.StandardOutput.BaseStream.CopyTo($pb.StandardInput.BaseStream)
    } catch { }
    try { $pb.StandardInput.Close() } catch { }
    $out = $pb.StandardOutput.ReadToEnd()
    $errB = $errTaskB.GetAwaiter().GetResult()
    try { $null = $pa.StandardError.ReadToEnd() } catch { }
    $pa.WaitForExit()
    $pb.WaitForExit()
    if ($errB) { $out = $out + [Environment]::NewLine + $errB }
    return $out
}

# ---------------- archive helpers ----------------
function Get-FirstBytes([string]$p, [int]$n = 8) {
    $fs = [IO.File]::OpenRead($p)
    try {
        $b = New-Object byte[] $n
        $c = $fs.Read($b, 0, $n)
        if ($c -le 0) { return @() }
        return $b[0..($c - 1)]
    } finally { $fs.Dispose() }
}

function Test-IsArchive([string]$p) {
    $ext = [IO.Path]::GetExtension($p).ToLower()
    if ($ext -in $ArcExts) { return $true }
    $b = Get-FirstBytes $p 8
    if ($b.Count -ge 4) {
        if ($b[0] -eq 0x50 -and $b[1] -eq 0x4B) { return $true }                                       # PK (zip)
        if ($b[0] -eq 0x52 -and $b[1] -eq 0x61 -and $b[2] -eq 0x72 -and $b[3] -eq 0x21) { return $true }  # Rar!
        if ($b[0] -eq 0x37 -and $b[1] -eq 0x7A) { return $true }                                        # 7z
    }
    if ($b.Count -ge 2 -and $b[0] -eq 0x1F -and $b[1] -eq 0x8B) { return $true }                        # gzip
    return $false
}

# ---------------- 虚拟执行（pe_vm 联动）----------------
# 逻辑内核与 scan.exe「一般扫描流程」的联动脚本共用同一份：
#   沙箱\PE虚拟执行沙盒\pevm_lib.ps1
# 这里只负责「找到解释器 + 建上下文」，怎么跑、怎么判恶意、解壳产物怎么复扫
# 全部在核心里实现，两边行为不会漂移。
$script:PevmExe = $null
$script:VmCtx   = $null
$script:PevmLib = Join-Path $Root '沙箱\PE虚拟执行沙盒\pevm_lib.ps1'
if (-not $NoPevm) {
    if (Test-Path -LiteralPath $script:PevmLib) {
        . $script:PevmLib
        $script:VmCtx = New-PevmContext -SearchRoot $Root -ScanExe $ScanExe -Scaler $Scaler `
            -TmpDir $TmpDir -MaxInsn $PevmMaxInsn -MaxSec $PevmMaxSec -All:$PevmAll `
            -Sink { param($s) Log $s }
        $script:PevmExe = $script:VmCtx.Exe
        $script:vm = $script:VmCtx.Stat
    } else {
        Write-Host "虚拟执行: 未找到内核 $script:PevmLib（本次跳过）"
    }
}
function Find-ZipPassword([string]$zip) {
    $cands = @()
    $pf = [IO.Path]::ChangeExtension($zip, '.pass')
    if (Test-Path $pf) { $cands += (Get-Content $pf -TotalCount 1).Trim() }
    $cands += $Password
    foreach ($p in ($cands | Select-Object -Unique)) {
        $null = Invoke-Utf8 $SevenZ @('t', "-p$p", $zip)
        if ($script:lastExit -eq 0) { return $p }
    }
    return $null
}

# NOTE: the "Folder" field is only present for some formats (zip/tar); 7z and
# gzip entries have no Folder line. So an entry counts as a FILE when it has a
# "Size" field and is not marked "Folder = +".
function Get-ZipMembers([string]$zip, [string]$pw) {
    $txt = Invoke-Utf8 $SevenZ @('-sccUTF-8', 'l', '-slt', "-p$pw", $zip)
    $items = @()
    $props = @{}
    foreach ($raw in ($txt -split "`r?`n")) {
        $ln = ([string]$raw).TrimEnd()
        if ($ln -like 'Path = *') {
            if ($props.Count -gt 0 -and $props.ContainsKey('Size') -and $props['Folder'] -ne '+') {
                $sz = 0
                [void][long]::TryParse($props['Size'], [ref]$sz)
                $items += [pscustomobject]@{ Path = $props['Path']; Size = $sz }
            }
            $props = @{ Path = $ln.Substring(7) }
        }
        elseif ($ln -like 'Folder = *') { $props['Folder'] = $ln.Substring(9) }
        elseif ($ln -like 'Size = *') { $props['Size'] = $ln.Substring(7) }
    }
    if ($props.Count -gt 0 -and $props.ContainsKey('Size') -and $props['Folder'] -ne '+') {
        $sz = 0
        [void][long]::TryParse($props['Size'], [ref]$sz)
        $items += [pscustomobject]@{ Path = $props['Path']; Size = $sz }
    }
    return ,$items
}

function Invoke-Archive([string]$path, [int]$depth) {
    Log ""
    Log "===== 压缩包: $path  （第 $depth 层）====="
    $pw = Find-ZipPassword $path
    if (-not $pw) {
        Log "  未找到可用密码（已尝试 .pass 与默认密码），跳过"
        return
    }
    Log "  密码正确: [$pw]"
    $members = Get-ZipMembers $path $pw
    if (-not $members -or $members.Count -eq 0) { Log "  包内没有可扫描的文件"; return }
    $total = 0
    foreach ($m in $members) {
        $leaf = Split-Path $m.Path -Leaf
        if ($m.Size -gt $MaxMemberBytes) { Log "  [跳过] $($m.Path)（超过 200MB）"; continue }
        $total += [Math]::Max($m.Size, 0)
        if ($total -gt $MaxTotalBytes) { Log "  [停止] 累计大小超过 1GB 上限"; break }
        $mExt = [IO.Path]::GetExtension($leaf).ToLower()
        if (($mExt -in $ArcExts) -and ($depth -lt $MaxDepth)) {
            Log ""
            Log "  --- 嵌套压缩包: $($m.Path)"
            $tmpd = Join-Path $TmpDir ([Guid]::NewGuid().ToString())
            New-Item -ItemType Directory -Force $tmpd | Out-Null
            $null = Invoke-Utf8 $SevenZ @('x', '-y', "-p$pw", $path, $m.Path, "-o$tmpd")
            $nested = Get-ChildItem $tmpd -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($nested) { Invoke-Archive $nested.FullName ($depth + 1) }
            else { Log "  （嵌套解压失败）" }
            Remove-Item $tmpd -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Log ""
            Log "  --- 包内文件: $($m.Path)"
            $r = Invoke-PipeScan $path $pw $m.Path
            if ($r) { foreach ($ln in ($r -split "`r?`n")) { Log $ln } }
            else { Log "  （无输出 —— 解压或扫描失败）" }
            if ($script:PevmExe) {
                $tok = Get-StaticToken $r
                if ($tok -eq 'PACK' -or ($PevmAll -and $tok)) {
                    # 虚拟执行要有真文件：只把这一个成员解到临时目录，跑完即删
                    $tmpd = Join-Path $TmpDir ([Guid]::NewGuid().ToString())
                    New-Item -ItemType Directory -Force $tmpd | Out-Null
                    $null = Invoke-Utf8 $SevenZ @('x', '-y', "-p$pw", $path, $m.Path, "-o$tmpd")
                    $mat = Get-ChildItem $tmpd -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($mat) {
                        $kind = Get-PeKind $mat.FullName
                        if ($kind -eq 'x86' -or $kind -eq 'x64') { Invoke-Pevm -Ctx $script:VmCtx -File $mat.FullName -StaticToken $tok }
                        elseif ($kind) { Skip-Vm -Ctx $script:VmCtx -Kind $kind }
                    } else { Log "  （虚拟执行：成员落地失败，跳过）" }
                    Remove-Item $tmpd -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Invoke-One([string]$path, [int]$depth) {
    if (Test-IsArchive $path) { Invoke-Archive $path $depth; return }
    $out = Invoke-Utf8 $ScanExe @($Scaler, $path, '--no-pevm')
    foreach ($ln in ($out -split "`r?`n")) { Log $ln }
    if ($script:PevmExe) {
        $tok = Get-StaticToken $out
        if ($tok -eq 'PACK' -or ($PevmAll -and $tok)) {
            $kind = Get-PeKind $path
            if ($kind -eq 'x86' -or $kind -eq 'x64') { Invoke-Pevm -Ctx $script:VmCtx -File $path -StaticToken $tok }
            elseif ($kind) { Skip-Vm -Ctx $script:VmCtx -Kind $kind }
        }
    }
}

# ---------------- main ----------------
if (Test-Path -PathType Container $Target) {
    Set-Log (Join-Path $Target 'scan_dir')
    if ($script:VmCtx) { if ($PevmOutDir) { $script:VmCtx.OutRoot = $PevmOutDir } else { $script:VmCtx.OutRoot = Join-Path $Target '_虚拟执行' } }
    Log "== scan_any（目录模式）开始 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') =="
    Log "目标: $Target"
    if ($script:PevmExe) { Log "虚拟执行: 已启用（$script:PevmExe）" } else { Log "虚拟执行: 关闭" }
    $files = Get-ChildItem $Target -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
             Where-Object { $_.Length -gt 0 -and $_.Name -notlike '*.scanlog.txt' -and $_.FullName -notlike "*\_虚拟执行\*" }
    foreach ($f in $files) { Invoke-One $f.FullName 0 }
} else {
    $p = (Resolve-Path $Target).Path
    Set-Log $p
    if ($script:VmCtx) { if ($PevmOutDir) { $script:VmCtx.OutRoot = $PevmOutDir } else { $script:VmCtx.OutRoot = Join-Path (Split-Path -Parent $p) '_虚拟执行' } }
    Log "== scan_any 开始 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') =="
    Log "目标: $p"
    if ($script:PevmExe) { Log "虚拟执行: 已启用（$script:PevmExe）" } else { Log "虚拟执行: 关闭" }
    Invoke-One $p 0
}

# ---------------- summary ----------------
$sumHr = $sumSus = $sumNorm = $sumPack = $sumTrust = $sumSkip = 0
$content = [IO.File]::ReadAllText($script:logPath, [System.Text.Encoding]::UTF8)
if ($content) {
    $sumHr    = ([regex]::Matches($content, '\[HIGH RISK')).Count
    $sumSus   = ([regex]::Matches($content, '\[SUSPICIOUS')).Count
    $sumNorm  = ([regex]::Matches($content, '\[NORMAL\]')).Count
    $sumTrust = ([regex]::Matches($content, '\[TRUSTED')).Count
    $sumPack  = ([regex]::Matches($content, 'File appears to be PACKED')).Count
    $sumSkip  = ([regex]::Matches($content, '\[SKIP\]')).Count
}
Log ""
Log ("== 汇总: 高危 {0} / 疑似 {1} / 正常 {2} / 可信 {3} / 加壳 {4} / 跳过 {5} ==" -f $sumHr, $sumSus, $sumNorm, $sumTrust, $sumPack, $sumSkip)
$sumJudged = $sumHr + $sumSus + $sumNorm + $sumTrust + $sumPack
$rateJudged = if ($sumJudged -gt 0) { [math]::Round(100.0 * ($sumHr + $sumSus) / $sumJudged, 1) } else { 0.0 }
$rateAll = if (($sumJudged + $sumSkip) -gt 0) { [math]::Round(100.0 * ($sumHr + $sumSus) / ($sumJudged + $sumSkip), 1) } else { 0.0 }
Log ("== 报毒率: (高危+疑似)/已判定 = {0}%（已判定 {1} 个）; 含跳过口径 = {2}% ==" -f $rateJudged, $sumJudged, $rateAll)
if ($script:PevmExe) {
    if ($script:vm.Total -gt 0) {
        Log ("== 虚拟执行: 恶意 {0} / 未见异常 {1} / 无法定论 {2}（其中 x64 解释执行 {3}、.NET 跳过 {4}）；解壳产物 {5} 个 ==" -f `
             $script:vm.Mal, $script:vm.Clean, $script:vm.Unknown, $script:vm.X64, $script:vm.Net, $script:vm.Dumps)
        Log ("== 动态找回: 静态未报毒、虚拟执行确认恶意 {0} 个（这批样本静态判定为加壳/正常/跳过）==" -f $script:vm.Upgraded)
    } else {
        Log "== 虚拟执行: 本轮没有需要动态分析的加壳 PE =="
    }
} else {
    Log "== 虚拟执行: 未启用（-NoPevm）或未找到 pe_vm.exe =="
}
Log "== 完成 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') =="

# ---------------- 行为沙箱联动（可选） ----------------
if ($Sandbox) {
    Log ""
    if (Test-IsArchive $Target) {
        Log "== 行为沙箱: 压缩包不适用（请先解压再分析），已跳过 =="
    } else {
        $BehaviorDir = @(
            (Join-Path $Root '行为沙箱'),
            (Join-Path $Root 'behavior'),
            (Join-Path $Root '..\behavior'),
            'F:\SVM项目\behavior'
        ) | Where-Object { $_ -and (Test-Path (Join-Path $_ 'auto_analyze.ps1')) } | Select-Object -First 1
        if (-not $BehaviorDir) {
            Log "== 行为沙箱: 未找到 auto_analyze.ps1，已跳过 =="
        } else {
            $aa = Join-Path $BehaviorDir 'auto_analyze.ps1'
            Log "== 转入自动化行为分析（Windows 沙箱）... =="
            $sbArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $aa,
                        '-Target', $Target, '-Top', [string]$SandboxTop)
            if ($SandboxNetwork) { $sbArgs += '-Network' }
            & powershell.exe @sbArgs
            Log "== 行为分析结束 =="
        }
    }
}

Write-Host ""
Write-Host "日志已保存 -> $($script:logPath)"
