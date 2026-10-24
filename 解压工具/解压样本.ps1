<#
  解压样本.ps1  ——  批量解压 AES 加密 ZIP 样本包（默认密码 infected）

  设计原则
    · 只做“解压”这一件事：全程不执行任何被解压出来的文件。
    · 密码、来源目录、输出目录、报告路径都可传参；不写死。
    · 兼容 PowerShell 5.1（不用 ??、不用 -Encoding utf8NoBOM 等新语法）。
    · 报告 CSV 以 UTF-8 + BOM 写出，中文不糊。
    · 断点可续：已存在且大小一致的目标文件直接跳过。

  用法
    powershell -ExecutionPolicy Bypass -File 解压样本.ps1
    powershell -ExecutionPolicy Bypass -File 解压样本.ps1 -Src H:\新建文件夹 -Dst H:\新建文件夹\_已解压
    powershell -ExecutionPolicy Bypass -File 解压样本.ps1 -ListOnly     # 只列表、不解压
#>
[CmdletBinding()]
param(
  [string]$Src = 'H:\新建文件夹',
  [string]$Dst = '',
  [string]$Pwd = 'infected',
  [string]$Csv = '',
  [switch]$ListOnly
)

$ErrorActionPreference = 'Continue'
# 说明：这里刻意不改 [Console]::OutputEncoding。
# 本目录的 解压样本.cmd 会先 chcp 936，PowerShell 默认就按控制台代码页输出，
# 中文自然正确；若强行设成 UTF-8，反而会在 936 控制台上显示成乱码。

if ([string]::IsNullOrWhiteSpace($Dst)) { $Dst = Join-Path $Src '_已解压' }
if ([string]::IsNullOrWhiteSpace($Csv)) {
  if ($PSScriptRoot) { $Csv = Join-Path $PSScriptRoot '解压报告.csv' }
  else { $Csv = Join-Path $Src '_解压报告.csv' }
}

# ---------- 找 7-Zip ----------
function Find-SevenZip {
  $cands = @(
    'C:\Program Files\7-Zip\7z.exe',
    'C:\Program Files (x86)\7-Zip\7z.exe',
    (Join-Path $env:ProgramFiles '7-Zip\7z.exe'),
    (Join-Path ${env:ProgramFiles(x86)} '7-Zip\7z.exe')
  )
  foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
  foreach ($n in @('7z', '7za', '7zr')) {
    $p = Get-Command $n -ErrorAction SilentlyContinue
    if ($p) { return $p.Source }
  }
  return $null
}

$sevenZip = Find-SevenZip
if (-not $sevenZip) {
  Write-Host '× 未找到 7-Zip（7z.exe）。AES-128 加密的 ZIP 无法用系统自带解压或 Python zipfile 打开。' -ForegroundColor Red
  Write-Host '  请安装 7-Zip 后重试：https://www.7-zip.org/' -ForegroundColor Yellow
  exit 2
}
Write-Host "√ 解压引擎: $sevenZip" -ForegroundColor DarkGray

if (-not (Test-Path -LiteralPath $Src)) { Write-Host "× 来源目录不存在: $Src" -ForegroundColor Red; exit 2 }
if (-not $ListOnly) {
  if (-not (Test-Path -LiteralPath $Dst)) { New-Item -ItemType Directory -Path $Dst -Force | Out-Null }
}

# ---------- 判断解压出来的东西归哪一类 ----------
function Get-Kind([string]$name) {
  $e = [IO.Path]::GetExtension($name).ToLower()
  switch ($e) {
    '.exe' { 'PE(可执行)' }
    '.dll' { 'PE(动态库)' }
    '.sys' { 'PE(驱动)' }
    '.scr' { 'PE(屏保)' }
    '.msi' { 'MSI(安装包)' }
    '.js'  { '脚本(JS)' }
    '.jse' { '脚本(JS-加密)' }
    '.vbs' { '脚本(VBS)' }
    '.vbe' { '脚本(VBS-加密)' }
    '.hta' { '脚本(HTA)' }
    '.cmd' { '脚本(CMD)' }
    '.bat' { '脚本(BAT)' }
    '.ps1' { '脚本(PS1)' }
    '.jar' { 'Java(JAR)' }
    '.lnk' { '快捷方式' }
    default { if ($e) { "其它$e" } else { '无扩展名' } }
  }
}

# 本扫描器/沙箱能“分析”的类型（静态扫描 + 虚拟执行）
function Get-Scannable([string]$name) {
  $e = [IO.Path]::GetExtension($name).ToLower()
  switch ($e) {
    '.exe' { '可以（scan.exe + PE虚拟执行）' }
    '.dll' { '可以（scan.exe + PE虚拟执行）' }
    '.sys' { '可以（scan.exe + PE虚拟执行）' }
    '.scr' { '可以（scan.exe + PE虚拟执行）' }
    '.js'  { '可以（stream_scan + 脚本虚拟执行）' }
    '.jse' { '可以（stream_scan + 脚本虚拟执行）' }
    '.vbs' { '可以（stream_scan + 脚本虚拟执行）' }
    '.vbe' { '可以（stream_scan + 脚本虚拟执行）' }
    '.hta' { '可以（stream_scan + 脚本虚拟执行）' }
    '.cmd' { '可以（stream_scan + 脚本虚拟执行）' }
    '.bat' { '可以（stream_scan + 脚本虚拟执行）' }
    '.ps1' { '部分（当文本按规则扫）' }
    '.msi' { '仅哈希/字符串（无专用解析）' }
    '.jar' { '仅哈希/字符串（无专用解析）' }
    '.lnk' { '仅哈希/字符串（无专用解析）' }
    default { '仅哈希/字符串' }
  }
}

$rows = New-Object System.Collections.Generic.List[object]
$files = @(Get-ChildItem -LiteralPath $Src -Force -File | Sort-Object Name)
$i = 0
foreach ($f in $files) {
  $i++
  $line = '{0}/{1}  {2}' -f $i, $files.Count, $f.Name
  Write-Progress -Activity '解压样本' -Status $line -PercentComplete ([int](100 * $i / [Math]::Max(1, $files.Count)))

  $kind = Get-Kind $f.Name
  $note = ''
  $inner = ''
  $innerKind = ''
  $outPath = ''
  $result = '否'

  if ($f.Extension.ToLower() -ne '.zip') {
    # 非 zip：只记录，不解压
    $result = '否（非 ZIP）'
    $note = '非 ZIP 文件（长度 ' + $f.Length + ' 字节），无可解压内容'
  }
  else {
    # 用 7z 列表，取出内含条目名。
    # 注意：7z 的 -slt 输出用一行“----------”把“压缩包自身信息”和“条目信息”隔开；
    # 且它对中文路径的输出编码可能与 PowerShell 不一致，所以不用字符串比较去过滤，
    # 而是直接从分隔线之后开始解析，避免把压缩包自身当成一条条目。
    $lst = & $sevenZip l -p"$Pwd" -slt -- $f.FullName 2>&1
    $code = $LASTEXITCODE
    $names = New-Object System.Collections.Generic.List[string]
    $cur = $null
    $inBody = $false
    foreach ($ln in $lst) {
      if (-not $inBody) {
        if ($ln -match '^-{5,}$') { $inBody = $true }
        continue
      }
      if ($ln -match '^Path = (.*)$') { $cur = $Matches[1] }
      elseif ($ln -eq '' -and $cur) { [void]$names.Add($cur); $cur = $null }
    }
    if ($cur) { [void]$names.Add($cur) }
    # 条目名前可能带 "./" 或 ".\" 前缀，规整一下
    $names = @($names | ForEach-Object { $_ -replace '^\.\\', '' -replace '^\./', '' } | Where-Object { $_ -ne '' })
    if ($code -ne 0) { $note = "7z 列表失败（退出码 $code）" }

    if ($names.Count -gt 0) {
      $inner = ($names -join ' ; ')
      $innerKind = ((@($names | ForEach-Object { Get-Kind $_ }) | Select-Object -Unique) -join '/')
    }

    if ($ListOnly) {
      $result = '未解压（仅列表）'
    }
    elseif ($code -ne 0) {
      $result = '否'
      if (-not $note) { $note = '无法读取加密目录' }
    }
    else {
      $targets = @()
      $allOk = $true
      foreach ($nm in $names) {
        $safe = $nm -replace '/', '\'
        $destFile = Join-Path $Dst $safe
        $targets += $destFile
      }
      # 已存在且非空则跳过
      $need = $false
      foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t)) { $need = $true; break }
        if ((Get-Item -LiteralPath $t).Length -le 0) { $need = $true; break }
      }
      if (-not $need) {
        $result = '是（已存在，跳过）'
      }
      else {
        $out = & $sevenZip x -p"$Pwd" -y -o"$Dst" -- $f.FullName 2>&1
        $xcode = $LASTEXITCODE
        if ($xcode -eq 0) { $result = '是' }
        else {
          $result = '否'
          $msg = ($out | Select-String -Pattern 'Wrong password|Cannot open|ERROR|Error' | Select-Object -First 1)
          if ($msg) { $note = ($msg.Line -replace '\s+', ' ').Trim() }
          else { $note = "7z 解压失败（退出码 $xcode）" }
        }
      }
      $outPath = ($targets | ForEach-Object { if (Test-Path -LiteralPath $_) { $_ } }) -join ' ; '
    }
  }

  $rows.Add([pscustomobject]@{
    包名         = $f.Name
    包大小       = $f.Length
    包类型       = $kind
    内含文件     = $inner
    内含类型     = $innerKind
    可解压       = $result
    解压后路径   = $outPath
    内含文件能否分析 = if ($inner) { Get-Scannable (($inner -split ' ; ')[0]) } else { '' }
    说明         = $note
  })
}
Write-Progress -Activity '解压样本' -Completed

# ---------- 写报告（UTF-8 + BOM）----------
$cols = @('包名', '包大小', '包类型', '内含文件', '内含类型', '可解压', '解压后路径', '内含文件能否分析', '说明')
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine(($cols -join ','))
foreach ($r in $rows) {
  $cells = foreach ($c in $cols) {
    $v = [string]$r.$c
    '"' + ($v -replace '"', '""') + '"'
  }
  [void]$sb.AppendLine(($cells -join ','))
}
[IO.File]::WriteAllText($Csv, $sb.ToString(), (New-Object Text.UTF8Encoding($true)))

# ---------- 屏幕小结 ----------
$okCnt    = @($rows | Where-Object { $_.可解压 -like '是*' }).Count
$skipCnt  = @($rows | Where-Object { $_.可解压 -like '否*' }).Count
$totOut   = ($rows | Where-Object { $_.可解压 -like '是*' } | ForEach-Object { $_.包大小 } | Measure-Object -Sum).Sum
Write-Host ''
Write-Host ('包总数       : {0}' -f $rows.Count)
Write-Host ('可解压       : {0}' -f $okCnt) -ForegroundColor Green
Write-Host ('不可解压     : {0}' -f $skipCnt) -ForegroundColor $(if ($skipCnt) { 'Yellow' } else { 'DarkGray' })
Write-Host ('解压报告     : {0}' -f $Csv)
if (-not $ListOnly) { Write-Host ('解压输出目录 : {0}' -f $Dst) }
Write-Host ''
Write-Host '明细如下：' -ForegroundColor Cyan
$rows | Select-Object 包名, 内含文件, 内含类型, 可解压, 内含文件能否分析 |
  Format-Table -AutoSize | Out-String -Width 220 | Write-Host
