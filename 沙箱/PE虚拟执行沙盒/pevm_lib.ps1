# pevm_lib.ps1 -- PE 用户态虚拟执行（pe_vm）联动内核
# ------------------------------------------------------------------
# 谁 dot-source 本文件都能用：
#   · scan_any.ps1（扫描器统一入口 / 拖拽扫描）
#   · 虚拟执行.ps1（scan.exe 一般扫描流程的联动脚本）
# 设计：不使用 $script: 作用域技巧，配置与统计全部放在显式传入的 $Ctx 对象里，
#       两个调用方各持一份，互不串状态；日志出口用 -Sink 脚本块注入。
#
# 安全性（重点）：pe_vm 是用户态 x86-32 / x86-64 解释器（PE32+ 虚拟装载时按
#   ImageBase 低 32 位定位）—— 镜像在进程内虚拟装载、内存访问逐次校验、
#   Windows API 全部是假实现。它不加载真 DLL、不碰真注册表/网络，
#   样本的机器码也绝不会真的跑起来，因此不存在"漏洞脚本穿透"的问题。
# ------------------------------------------------------------------

function New-PevmContext {
    param(
        [string]$SearchRoot = '',
        [string]$ScanExe = '',
        [string]$Scaler = '',
        [string]$TmpDir = '',
        [long]$MaxMemberBytes = 200MB,
        [int]$MaxInsn = 30000000,
        [int]$MaxSec = 60,
        [switch]$All,
        [string]$OutRoot = '',
        [scriptblock]$Sink = $null
    )

    $ctx = [pscustomobject]@{
        Exe            = $null
        ScanExe        = $ScanExe
        Scaler         = $Scaler
        TmpDir         = $TmpDir
        MaxMemberBytes = $MaxMemberBytes
        MaxInsn        = $MaxInsn
        MaxSec         = $MaxSec
        All            = [bool]$All
        OutRoot        = $OutRoot
        Sink           = $Sink
        Stat           = @{ Total = 0; Mal = 0; Clean = 0; Unknown = 0; Upgraded = 0; Dumps = 0; X64 = 0; Net = 0 }
    }

    $cands = @()
    if ($SearchRoot) {
        $cands += (Join-Path $SearchRoot '沙箱\PE虚拟执行沙盒\pe_vm.exe')
        $cands += (Join-Path $SearchRoot 'pe_vm.exe')
        $cands += (Join-Path $SearchRoot '..\沙箱\PE虚拟执行沙盒\pe_vm.exe')
    }
    $cands += 'C:\Users\17265\Desktop\恶意软件扫描器\沙箱\PE虚拟执行沙盒\pe_vm.exe'
    $cands += 'F:\SVM项目\behavior\pev\pe_vm.exe'
    foreach ($c in $cands) {
        if ($c -and (Test-Path -LiteralPath $c)) { $ctx.Exe = (Resolve-Path -LiteralPath $c).Path; break }
    }

    if (-not $ctx.TmpDir) { $ctx.TmpDir = Join-Path $env:TEMP 'opencode\pevm_tmp' }
    if ($ctx.MaxMemberBytes -le 0) { $ctx.MaxMemberBytes = 200MB }
    return $ctx
}

function Write-VmLine {
    param($Ctx, [string]$Text)
    if ($Ctx.Sink) { & $Ctx.Sink $Text } else { Write-Host $Text }
}

# 统一的原生进程调用（显式 UTF-8 解码，避免中文乱码）
function Invoke-NativeUtf8 {
    param([string]$Exe, [string[]]$ArgList, [string]$WorkDir = '', [int]$TimeoutMs = 0)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Exe
    if ($WorkDir) { $psi.WorkingDirectory = $WorkDir }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    if ($psi.PSObject.Properties['ArgumentList']) {
        foreach ($a in $ArgList) { [void]$psi.ArgumentList.Add([string]$a) }
    } else {
        $parts = foreach ($a in $ArgList) {
            $s = [string]$a
            if ($s -match '[\s"]') { '"' + ($s -replace '"', '\"') + '"' } else { $s }
        }
        $psi.Arguments = ($parts -join ' ')
    }
    $p = [System.Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $errTask.GetAwaiter().GetResult()
    if ($TimeoutMs -gt 0) { $null = $p.WaitForExit($TimeoutMs) } else { $p.WaitForExit() }
    $code = -1
    try { $code = $p.ExitCode } catch { }
    if ($err) { $out = $out + [Environment]::NewLine + $err }
    return [pscustomobject]@{ Text = $out; ExitCode = $code }
}

# 只读 PE 头（e_lfanew → PE\0\0 → Machine + CLR 数据目录），不为了判类型去复制上百 MB
# 返回 'x86' / 'x64' / 'net' / ''（不是 PE）
function Get-PeKind {
    param([string]$Path)
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            if ($fs.Length -lt 0x40) { return '' }
            $br = New-Object IO.BinaryReader($fs)
            $fs.Position = 0x3C
            $lfanew = $br.ReadUInt32()
            if ($lfanew -le 0 -or ($lfanew + 24) -gt $fs.Length) { return '' }
            $fs.Position = $lfanew
            if ($br.ReadUInt32() -ne 0x00004550) { return '' }
            $machine = $br.ReadUInt16()
            $null = $br.ReadUInt16()
            $null = $br.ReadUInt32()
            $null = $br.ReadUInt32()
            $null = $br.ReadUInt32()
            $sizeOpt = $br.ReadUInt16()
            if ($sizeOpt -lt 0xE0) { return '' }
            $opt = $lfanew + 24
            $fs.Position = $opt
            $magic = $br.ReadUInt16()
            if ($magic -eq 0x10B) { $dd = $opt + 0x60 }
            elseif ($magic -eq 0x20B) { $dd = $opt + 0x70 }
            else { return '' }
            $fs.Position = $dd + 14 * 8
            if ($br.ReadUInt32() -ne 0) { return 'net' }
            if ($machine -eq 0x8664) { return 'x64' }
            return 'x86'
        } finally { $fs.Dispose() }
    } catch { return '' }
}

# 把静态输出压成一个标记
function Get-StaticToken {
    param([string]$ScanText)
    if ($ScanText -match '\[HIGH RISK') { return 'HR' }
    if ($ScanText -match '\[SUSPICIOUS') { return 'SUS' }
    if ($ScanText -match 'File appears to be PACKED') { return 'PACK' }
    if ($ScanText -match '\[NORMAL\]') { return 'NORM' }
    if ($ScanText -match '\[SKIP\]') { return 'SKIP' }
    return ''
}

# 读 pe_vm 的 --trace（TSV：类别 \t 内容），只挑与判定有关的几类
function Get-VmBehavior {
    param([string]$TraceFile)
    $r = @{ ExecStar = 0; Run = 0; NetStar = 0; Drop = 0; Anti = 0; AntiStar = 0
            ExecTxt = @(); RunTxt = @(); NetTxt = @(); AntiTxt = @() }
    if (-not (Test-Path -LiteralPath $TraceFile)) { return $r }
    foreach ($ln in [IO.File]::ReadAllLines($TraceFile, [Text.Encoding]::UTF8)) {
        $t = $ln.IndexOf("`t")
        if ($t -le 0) { continue }
        $kind = $ln.Substring(0, $t)
        $text = $ln.Substring($t + 1)
        if ($kind -eq '执行') {
            if ($text -match '★') { $r.ExecStar++; if ($r.ExecTxt.Count -lt 4) { $r.ExecTxt += ($text -replace '^★', '') } }
        }
        elseif ($kind -eq '注册表') {
            if ($text -match 'Run|Winlogon|Policies\\|Image File Execution') {
                $r.Run++
                if ($r.RunTxt.Count -lt 4) { $r.RunTxt += ($text -replace '^★', '') }
            }
        }
        elseif ($kind -eq '网络') {
            if ($text -match '★') { $r.NetStar++; if ($r.NetTxt.Count -lt 4) { $r.NetTxt += ($text -replace '^★', '') } }
        }
        elseif ($kind -eq '落盘') { $r.Drop++ }
        elseif ($kind -eq '反调试' -or $kind -eq '反虚拟机') {
            $r.Anti++
            if ($text -match '★') {
                $r.AntiStar++
                if ($r.AntiTxt.Count -lt 2) { $r.AntiTxt += ($text -replace '^★', '') }
            }
        }
    }
    return $r
}

# 不支持的类型：只写一行结论，不做任何复制/执行
function Skip-Vm {
    param($Ctx, [string]$Kind)
    $Ctx.Stat.Total++
    $Ctx.Stat.Unknown++
    Write-VmLine $Ctx ""
    if ($Kind -eq 'x64') {
        Write-VmLine $Ctx "  【虚拟执行】pe_vm —— 跳过：64 位 PE（PE32+）未送入解释器（正常流程不会出现，请反馈）    [VM: 无法定论]"
    } else {
        $Ctx.Stat.Net++
        Write-VmLine $Ctx "  【虚拟执行】pe_vm —— 跳过：.NET 程序集（CLR 头非空），需按 IL 分析    [VM: 无法定论]"
    }
}

# 单个 PE 的虚拟执行 + 解壳产物复扫 + 结构化输出
function Invoke-Pevm {
    param($Ctx, [string]$File, [string]$StaticToken)

    if (-not $Ctx.Exe) { return }

    $stem = [IO.Path]::GetFileNameWithoutExtension($File)
    $work = Join-Path $Ctx.TmpDir 'pevm'
    New-Item -ItemType Directory -Force $work | Out-Null
    $tag   = [guid]::NewGuid().ToString('N')
    $trace = Join-Path $work ($tag + '.tsv')
    $vmOut = Join-Path $work ($tag + '.out')

    # 中文路径坑：pe_vm 的 argv 会走 CRT 的 ANSI 转换，非 ASCII 文件名会坏。
    # 文件名本身是 ASCII 时不用复制（工作目录给父目录，CWD 由系统按 Unicode 解析）。
    $leaf = [IO.Path]::GetFileName($File)
    $sampleArg = $leaf
    $psiWork   = Split-Path -Parent $File
    $proxyExe  = $null
    if ($leaf -notmatch '^[\x20-\x7E]+$') {
        $proxyExe  = Join-Path $work ($tag + '.exe')
        Copy-Item -LiteralPath $File -Destination $proxyExe -Force
        $psiWork   = $work
        $sampleArg = $tag + '.exe'
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $res = Invoke-NativeUtf8 -Exe $Ctx.Exe -WorkDir $psiWork -ArgList @(
        $sampleArg, '--outdir', $vmOut, '--trace', $trace,
        '--max-insn', [string]$Ctx.MaxInsn, '--max-sec', [string]$Ctx.MaxSec)
    $sw.Stop()
    $txt = $res.Text

    $is64  = ($txt -match '交给 x86-64 解释器')
    $isNet = ($txt -match '\[托管\] ★')
    $stop = ''
    if ($txt -match '停机：([^\r\n（]+)') { $stop = $Matches[1].Trim() }
    $insn = 0
    if ($txt -match '共执行 (\d+) 条指令') { $insn = [int64]$Matches[1] }
    $oep = ([regex]::Matches($txt, '\[疑似 OEP\]')).Count
    $beh = Get-VmBehavior $trace

    $dumps = @()
    if (Test-Path -LiteralPath $vmOut) {
        $dumps = @(Get-ChildItem -LiteralPath $vmOut -File -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.Length -gt 0 -and $_.Length -le $Ctx.MaxMemberBytes })
    }

    # 解壳产物再走一次静态引擎（结果只写成中文，绝不复用机器标记，免得污染统计）
    $dumpLines = @()
    $dumpMal = 0
    foreach ($d in $dumps) {
        $risk = ''
        $dv = '未报毒'
        if ($Ctx.ScanExe -and (Test-Path -LiteralPath $Ctx.ScanExe)) {
            $dr = (Invoke-NativeUtf8 -Exe $Ctx.ScanExe -ArgList @($Ctx.Scaler, $d.FullName, '--no-pevm')).Text
            if ($dr -match '【风险名称】([^\r\n]+)') { $risk = $Matches[1].Trim() }
            if ($dr -match 'File appears to be PACKED') { $dv = '仍加壳' }
            elseif ($dr -match '\[HIGH RISK') { $dv = '高危' }
            elseif ($dr -match '\[SUSPICIOUS') { $dv = '疑似' }
            elseif ($dr -match '\[SKIP\]') { $dv = '无法识别' }
        } else { $dv = '未复扫' }
        if ($dv -eq '高危' -or $dv -eq '疑似') { $dumpMal++ }
        $suffix = ''
        if ($risk) { $suffix = ' / ' + $risk }
        $dumpLines += ('    · {0}  ({1:N0} 字节)  复扫：{2}{3}' -f $d.Name, $d.Length, $dv, $suffix)
    }

    # 把解壳产物复制到用户可见目录
    if ($dumps.Count -gt 0 -and $Ctx.OutRoot) {
        $dst = Join-Path $Ctx.OutRoot $stem
        New-Item -ItemType Directory -Force $dst | Out-Null
        foreach ($d in $dumps) { Copy-Item -LiteralPath $d.FullName -Destination $dst -Force }
    }

    $mal = ($beh.ExecStar -gt 0) -or ($beh.Run -gt 0) -or ($beh.NetStar -gt 0) -or ($beh.AntiStar -gt 0) -or ($oep -gt 0 -and $beh.Drop -gt 0)
    if ($isNet) { $v = '无法定论'; $why = '.NET 程序集，需按 IL 分析' }
    elseif ($mal -or $dumpMal -gt 0) { $v = '恶意行为'; $why = '' }
    elseif ($insn -gt 0 -and ($stop -match '正常退出|正常返回|ExitProcess')) { $v = '未见异常'; $why = '' }
    elseif ($insn -gt 0) { $v = '无法定论'; $why = '执行未正常结束（停机：' + $stop + '），未观察到恶意行为' }
    else { $v = '无法定论'; $why = '未能进入样本代码' }

    $Ctx.Stat.Total++
    if ($is64) { $Ctx.Stat.X64++ }
    if ($v -eq '恶意行为') {
        $Ctx.Stat.Mal++
        if ($StaticToken -ne 'HR' -and $StaticToken -ne 'SUS') { $Ctx.Stat.Upgraded++ }
    }
    elseif ($v -eq '未见异常') { $Ctx.Stat.Clean++ }
    else { $Ctx.Stat.Unknown++ }
    $Ctx.Stat.Dumps += $dumps.Count

    Write-VmLine $Ctx ""
    $archName = if ($is64) { 'x86-64' } else { 'x86-32' }
    Write-VmLine $Ctx "  【虚拟执行】pe_vm —— 用户态 $archName 解释执行（不落真机、不调真 API）"
    Write-VmLine $Ctx ("    执行情况 : {0:N0} 条指令 / {1} 秒   停机：{2}" -f $insn, [math]::Round($sw.Elapsed.TotalSeconds, 1), $stop)
    Write-VmLine $Ctx ("    动态结论 : {0}    [VM: {1}]" -f $v, $v)
    if ($why) { Write-VmLine $Ctx ("    原因     : {0}" -f $why) }
    foreach ($e in $beh.ExecTxt) {
        $t = ([string]$e).TrimEnd()
        if ($t -eq '' -or $t -match '：$') { $t = $t + '（解释器未记录到命令行）' }
        Write-VmLine $Ctx ("    · {0}" -f $t)
    }
    foreach ($e in $beh.RunTxt)  { Write-VmLine $Ctx ("    · 注册表敏感项：{0}" -f $e) }
    foreach ($e in $beh.NetTxt)  { Write-VmLine $Ctx ("    · 网络通信    ：{0}" -f $e) }
    if ($oep -gt 0) { Write-VmLine $Ctx ("    · 写后执行（解壳完成）命中 {0} 处" -f $oep) }
    if ($beh.Anti -gt 0) { Write-VmLine $Ctx ("    · 反调试/反虚拟机动作 {0} 次" -f $beh.Anti) }
    foreach ($e in $beh.AntiTxt) { Write-VmLine $Ctx ("    · 反调试证据：{0}" -f $e) }
    if ($dumpLines.Count -gt 0) {
        Write-VmLine $Ctx ("    解壳产物 : {0} 个" -f $dumps.Count)
        foreach ($l in $dumpLines) { Write-VmLine $Ctx $l }
    }
    Write-VmLine $Ctx "    说明     : 全程在用户态解释器内完成，未加载真 DLL、未访问真注册表/网络。"

    Remove-Item -LiteralPath $trace -Force -ErrorAction SilentlyContinue
    if ($proxyExe) { Remove-Item -LiteralPath $proxyExe -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $vmOut -Recurse -Force -ErrorAction SilentlyContinue
}

function Show-VmSummary {
    param($Ctx)
    if (-not $Ctx.Exe) {
        Write-VmLine $Ctx "== 虚拟执行: 未启用或未找到 pe_vm.exe =="
        return
    }
    if ($Ctx.Stat.Total -gt 0) {
        Write-VmLine $Ctx ("== 虚拟执行: 恶意 {0} / 未见异常 {1} / 无法定论 {2}（其中 x64 解释执行 {3}、.NET 跳过 {4}）；解壳产物 {5} 个 ==" -f `
            $Ctx.Stat.Mal, $Ctx.Stat.Clean, $Ctx.Stat.Unknown, $Ctx.Stat.X64, $Ctx.Stat.Net, $Ctx.Stat.Dumps)
        Write-VmLine $Ctx ("== 动态找回: 静态未报毒、虚拟执行确认恶意 {0} 个 ==" -f $Ctx.Stat.Upgraded)
    } else {
        Write-VmLine $Ctx "== 虚拟执行: 本轮没有需要动态分析的加壳 PE =="
    }
}
