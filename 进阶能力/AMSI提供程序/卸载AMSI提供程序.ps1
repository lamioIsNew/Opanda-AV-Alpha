#requires -Version 5.1
<#
    注销本项目的 AMSI 提供程序（需管理员）
    用 regsvr32 /u 摘掉；若 DLL 已丢失，则直接删注册表键。
#>
param([switch]$Yes)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch {}

$CLSID = '{7F3C1A20-9B4E-4C6D-A1F2-5E8D3B0C7A91}'
$DLL   = Join-Path $PSScriptRoot 'amsi_provider.dll'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[错误] 需要管理员权限。" -ForegroundColor Red; exit 1 }

Write-Host "=== 注销 AMSI 提供程序 ===" -ForegroundColor Cyan
if (-not $Yes) {
    $ans = Read-Host "确认注销请输入 YES"
    if ($ans -ne 'YES') { Write-Host "已取消。"; exit 3 }
}

if (Test-Path -LiteralPath $DLL) {
    $p = Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/u', '/s', ('"' + $DLL + '"') -Wait -PassThru
    Write-Host ("  regsvr32 /u 退出码: " + $p.ExitCode)
} else {
    Write-Host "  DLL 不在，直接删注册表。"
}

Remove-Item -Path ('HKLM:\SOFTWARE\Microsoft\AMSI\Providers\' + $CLSID) -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path ('HKLM:\SOFTWARE\Classes\CLSID\' + $CLSID) -Recurse -Force -ErrorAction SilentlyContinue

$k1 = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\' + $CLSID
$k2 = 'HKLM:\SOFTWARE\Classes\CLSID\' + $CLSID
Write-Host ("  Providers 键 : " + $(if (Test-Path $k1) { '★仍在（检查权限）' } else { '已清除' }))
Write-Host ("  CLSID 键     : " + $(if (Test-Path $k2) { '★仍在（检查权限）' } else { '已清除' }))
Write-Host "注销完成。若宿主进程仍缓存着旧 provider，重启宿主即可。" -ForegroundColor Green