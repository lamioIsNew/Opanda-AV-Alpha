# sandbox_run.ps1 -- 行为沙箱（单样本，交互式）
#
# 把一个样本（或整个目录）放进 Windows Sandbox 里"跑一遍"，观察它的行为：
#   进程创建 / 文件落地 / 持久化(注册表·计划任务·服务) / 网络连接尝试
# 沙箱与真机完全隔离，且是一次性的（关掉沙箱即销毁）。
#
# 用法：
#   .\sandbox_run.ps1 -Sample <样本文件或目录> [-TimeoutSeconds 60] [-Network] [-WaitMinutes 8] [-NoLaunch]
#
# 批量自动化请用 auto_analyze.ps1；本脚本负责"跑一个并当场看报告"。

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)][string]$Sample,
    [int]$TimeoutSeconds = 60,
    [switch]$Network,
    [int]$WaitMinutes = 8,
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
$Here     = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'sandbox_lib.ps1')
$GuestSrc = Join-Path $Here 'guest_monitor.ps1'
$WorkRoot = Join-Path $Here '_work'
$ReportsRoot = Join-Path $Here 'reports'

function Say($s) { Write-Host $s }

if (-not (Test-Path -LiteralPath $GuestSrc)) { throw "缺少 guest_monitor.ps1：$GuestSrc" }
if (-not (Test-Path -LiteralPath $Sample))   { throw "样本路径不存在：$Sample" }

$avail = Test-SandboxAvailable
if (-not $avail.Ok) { Write-Host $avail.Reason -ForegroundColor Yellow; exit 2 }

$SampleName = Split-Path -Leaf (Resolve-Path -LiteralPath $Sample)
$run = New-SandboxRun -Sample $Sample -WorkRoot $WorkRoot -GuestScript $GuestSrc `
                      -Tag 'single' -TimeoutSeconds $TimeoutSeconds -Network:$Network
Say ("[*] 样本已就绪 -> " + $run.SamplesDir)

if ($NoLaunch) {
    Say "[*] -NoLaunch：仅生成配置，未启动沙箱。"
    Say ("    配置文件: " + $run.Wsb)
    Say ("    报告将出现在: " + $run.OutDir)
    exit 0
}

Say "[*] 启动 Windows Sandbox（首次启动约需 20-60 秒）..."
$before = @(Get-RunningSandboxProcess | Select-Object -ExpandProperty Id)
$proc = Start-SandboxRun -Wsb $run.Wsb
Say "[*] 沙箱已拉起，等待行为报告..."
$ok = Wait-SandboxReport -RunDir $run.RunDir -WaitMinutes $WaitMinutes
$res = Get-SandboxResult -RunDir $run.RunDir
Stop-NewSandboxes -Before $before | Out-Null
if ($proc -and -not $proc.HasExited) { $null = $proc.WaitForExit(30000) }
if (-not $res.Ok) {
    Write-Host "[!] 未收到有效报告（可能沙箱启动慢或样本卡住）。" -ForegroundColor Yellow
    Write-Host ("    请手动查看映射目录: " + $run.OutDir)
    exit 3
}

$dest = Save-SandboxRun -RunDir $run.RunDir -ReportsRoot $ReportsRoot -Name $SampleName
Say ("[*] 报告已保存: " + $dest)
Say ""
Say "================= 行为报告 ================="
foreach ($ln in ($res.ReportText -split "`r?`n")) { Say $ln }
Say "============================================"
Say ""
Say "[*] 观察完毕。若沙箱窗口仍在，可直接关闭（关闭即销毁）。"
$null = Remove-SandboxRun -RunDir $run.RunDir
