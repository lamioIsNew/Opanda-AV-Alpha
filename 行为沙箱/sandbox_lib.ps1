# sandbox_lib.ps1 -- 行为沙箱共用内核
# 被 sandbox_run.ps1（单样本交互）与 auto_analyze.ps1（批量自动化）共同引用。
# 提供：可用性检测 / 准备运行目录 / 生成 .wsb / 启动沙箱 / 等报告 / 回收结果。
# 兼容 Windows PowerShell 5.1 与 PowerShell 7。

function Get-SandboxExe {
    return (Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe')
}

function Test-SandboxAvailable {
    # 返回 @{ Ok = $bool; Reason = '...' }
    $ws = Get-SandboxExe
    if (-not (Test-Path -LiteralPath $ws)) {
        return [pscustomobject]@{ Ok = $false; Reason = "未检测到 Windows 沙箱（$ws）。需要 Windows 10/11 专业版/企业版，并以管理员运行：Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All，然后重启。" }
    }
    # Hyper-V 计算服务（沙箱依赖）
    $vmc = Get-Service -Name vmcompute -ErrorAction SilentlyContinue
    if (-not $vmc) {
        return [pscustomobject]@{ Ok = $false; Reason = "未找到 Hyper-V 计算服务 vmcompute，Windows 沙箱可能未正确启用。" }
    }
    return [pscustomobject]@{ Ok = $true; Reason = '' }
}

# 是否有沙箱正在运行（同一时刻只跑一个，避免资源争用与映射冲突）
# 注意：Windows 沙箱会同时起 WindowsSandbox.exe / WindowsSandboxClient.exe 等进程，
#       只杀 UI 进程（WindowsSandbox.exe）不会销毁沙箱、映射目录也会被锁住，必须一并结束。
function Get-RunningSandboxProcess {
    return @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'WindowsSandbox*' })
}

function Wait-NoSandboxRunning {
    param([int]$TimeoutSec = 180)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ((Get-RunningSandboxProcess).Count -eq 0) { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}

# 强制关闭本机所有 Windows 沙箱实例（宿主侧结束进程 = 销毁沙箱；含 Client 子进程）
function Close-AllSandboxes {
    $killed = 0
    foreach ($p in (Get-RunningSandboxProcess)) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $killed++ } catch {}
    }
    if ($killed -gt 0) { Start-Sleep -Seconds 3 }
    return $killed
}

# 只关掉"本次运行期间新起"的沙箱实例（不动运行前已存在的）
function Stop-NewSandboxes {
    param([int[]]$Before)
    $killed = 0
    for ($pass = 0; $pass -lt 3; $pass++) {
        $new = @(Get-RunningSandboxProcess | Where-Object { $Before -notcontains $_.Id })
        if ($new.Count -eq 0) { break }
        foreach ($p in $new) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $killed++ } catch {}
        }
        Start-Sleep -Seconds 2
    }
    return $killed
}

# 准备一次运行：建目录、拷样本、放监控脚本、写 .wsb
function New-SandboxRun {
    param(
        [Parameter(Mandatory)][string]$Sample,      # 文件或目录
        [Parameter(Mandatory)][string]$WorkRoot,    # run_* 存放根目录
        [Parameter(Mandatory)][string]$GuestScript, # guest_monitor.ps1 路径
        [string]$Tag = 'run',
        [int]$TimeoutSeconds = 45,
        [switch]$Network
    )
    $stamp  = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $runDir = Join-Path $WorkRoot ("run_" + $Tag + "_" + $stamp)
    $samplesDir = Join-Path $runDir 'Samples'
    $outDir     = Join-Path $runDir 'Out'
    New-Item -ItemType Directory -Force -Path $samplesDir, $outDir | Out-Null

    $item = Get-Item -LiteralPath $Sample
    if ($item.PSIsContainer) {
        Copy-Item -Path (Join-Path $item.FullName '*') -Destination $samplesDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Copy-Item -LiteralPath $item.FullName -Destination $samplesDir -Force
    }
    Copy-Item -LiteralPath $GuestScript -Destination (Join-Path $outDir 'guest_monitor.ps1') -Force

    $net = 'Disable'; if ($Network) { $net = 'Enable' }
    $wsb = @"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>$net</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$samplesDir</HostFolder>
      <SandboxFolder>C:\Samples</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$outDir</HostFolder>
      <SandboxFolder>C:\Out</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\Out\guest_monitor.ps1 -TimeoutSeconds $TimeoutSeconds$(if ($Network) { ' -EnableNetwork' }) -AutoShutdown</Command>
  </LogonCommand>
</Configuration>
"@
    $wsbPath = Join-Path $runDir 'run.wsb'
    [System.IO.File]::WriteAllText($wsbPath, $wsb, (New-Object System.Text.UTF8Encoding($false)))

    return [pscustomobject]@{
        RunDir     = $runDir
        SamplesDir = $samplesDir
        OutDir     = $outDir
        Wsb        = $wsbPath
    }
}

function Start-SandboxRun {
    param([Parameter(Mandatory)][string]$Wsb)
    $ws = Get-SandboxExe
    return (Start-Process -FilePath $ws -ArgumentList ('"' + $Wsb + '"') -PassThru)
}

# 等沙箱产出报告：优先看 _DONE 哨兵，其次看 json 是否稳定
function Wait-SandboxReport {
    param(
        [Parameter(Mandatory)][string]$RunDir,
        [int]$WaitMinutes = 8
    )
    $out  = Join-Path $RunDir 'Out'
    $done = Join-Path $out '_DONE'
    $json = Join-Path $out 'behavior_report.json'
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -LiteralPath $done) -and (Test-Path -LiteralPath $json)) { return $true }
        Start-Sleep -Milliseconds 1500
    }
    return (Test-Path -LiteralPath $json)
}

function Get-SandboxResult {
    param([Parameter(Mandatory)][string]$RunDir)
    $out  = Join-Path $RunDir 'Out'
    $txt  = Join-Path $out 'behavior_report.txt'
    $json = Join-Path $out 'behavior_report.json'
    $text = ''
    if (Test-Path -LiteralPath $txt) { $text = Get-Content -LiteralPath $txt -Raw -Encoding utf8 }
    $obj = $null
    if (Test-Path -LiteralPath $json) {
        try { $obj = (Get-Content -LiteralPath $json -Raw -Encoding utf8 | ConvertFrom-Json) } catch { $obj = $null }
    }
    return [pscustomobject]@{
        Ok         = [bool]($obj -ne $null)
        ReportText = $text
        Data       = $obj
        OutDir     = $out
    }
}

# 把运行目录整体归档到持久目录（保留报告 + artifacts）
function Save-SandboxRun {
    param(
        [Parameter(Mandatory)][string]$RunDir,
        [Parameter(Mandatory)][string]$ReportsRoot,
        [Parameter(Mandatory)][string]$Name
    )
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dest  = Join-Path $ReportsRoot ($Name + '_' + $stamp)
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -Path (Join-Path $RunDir 'Out\*') -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
    return $dest
}

# 删除运行目录（沙箱退出后再删，避免映射锁）
function Remove-SandboxRun {
    param([Parameter(Mandatory)][string]$RunDir)
    for ($i = 0; $i -lt 5; $i++) {
        try {
            Remove-Item -LiteralPath $RunDir -Recurse -Force -ErrorAction Stop
            return $true
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    return $false
}

# 高层封装：跑一个样本，返回结果对象（含 RunDir/ReportText/Data/Ok）
function Invoke-SandboxSample {
    param(
        [Parameter(Mandatory)][string]$Sample,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][string]$GuestScript,
        [string]$Tag = 'run',
        [int]$TimeoutSeconds = 45,
        [switch]$Network,
        [int]$WaitMinutes = 8
    )
    $before = @(Get-RunningSandboxProcess | Select-Object -ExpandProperty Id)
    $run = New-SandboxRun -Sample $Sample -WorkRoot $WorkRoot -GuestScript $GuestScript `
                          -Tag $Tag -TimeoutSeconds $TimeoutSeconds -Network:$Network
    $proc = Start-SandboxRun -Wsb $run.Wsb
    $ok = Wait-SandboxReport -RunDir $run.RunDir -WaitMinutes $WaitMinutes
    # 先把结果读进内存，再关闭沙箱（报告已落在宿主映射目录，关掉不丢数据）
    $res = Get-SandboxResult -RunDir $run.RunDir
    Stop-NewSandboxes -Before $before | Out-Null
    if ($proc -and -not $proc.HasExited) { $null = $proc.WaitForExit(30000) }
    $res | Add-Member -NotePropertyName RunDir -NotePropertyValue $run.RunDir -Force
    return $res
}
