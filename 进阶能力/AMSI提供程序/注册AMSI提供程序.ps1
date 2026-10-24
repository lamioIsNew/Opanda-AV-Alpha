#requires -Version 5.1
<#
    注册本项目的 AMSI 提供程序（需管理员 + 已签名的 DLL）
    ---------------------------------------------------------------
    前置条件：
      1. 已用 MSVC + Windows SDK 编译出 amsi_provider.dll
         cl /LD /EHsc /DUNICODE /D_UNICODE amsi_provider.c ole32.lib oleaut32.lib
      2. 该 DLL 已经用受信任证书签名（自签名只在你自己机器上有意义）
      3. 明白风险：提供程序运行在 PowerShell/Office/VBScript 宿主进程内，
         它崩溃会拖死宿主。建议先在测试机验证，并准备好本目录的注销脚本。

    注册内容（可对照检查）：
      HKLM\SOFTWARE\Microsoft\AMSI\Providers\{7F3C1A20-9B4E-4C6D-A1F2-5E8D3B0C7A91}
      HKLM\SOFTWARE\Classes\CLSID\{...}\InprocServer32 = <DLL 完整路径>
#>
param([switch]$Yes)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch {}

$CLSID = '{7F3C1A20-9B4E-4C6D-A1F2-5E8D3B0C7A91}'
$DLL   = Join-Path $PSScriptRoot 'amsi_provider.dll'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[错误] 注册 AMSI 提供程序需要管理员权限，请右键以管理员身份运行。" -ForegroundColor Red; exit 1 }

Write-Host "=== 注册 AMSI 提供程序 ===" -ForegroundColor Cyan
Write-Host ("  DLL      : " + $DLL)
Write-Host ("  CLSID    : " + $CLSID)
Write-Host  "  将写入   : HKLM\SOFTWARE\Microsoft\AMSI\Providers\$CLSID"

if (-not (Test-Path -LiteralPath $DLL)) {
    Write-Host ""
    Write-Host "[未就绪] 还没有 amsi_provider.dll。" -ForegroundColor Yellow
    Write-Host "         请先用 MSVC + Windows SDK 编译 amsi_provider.c："
    Write-Host "           cl /LD /EHsc /DUNICODE /D_UNICODE amsi_provider.c ole32.lib oleaut32.lib"
    Write-Host "         编译后签名，再回来运行本脚本。"
    Write-Host ""
    Write-Host "（说明：本项按"给出源码、由你决定何时启用"的原则交付，未替你注册。）"
    exit 2
}

Write-Host ""
Write-Host "[风险提示] 提供程序会加载进 PowerShell / Office / VBScript 等宿主进程；" -ForegroundColor Yellow
Write-Host "           若它崩溃或死锁，宿主动作会被一起卡死。" -ForegroundColor Yellow
Write-Host "           请确认已在测试机验证过。卸载脚本：卸载AMSI提供程序.ps1" -ForegroundColor Yellow

if (-not $Yes) {
    $ans = Read-Host "确认注册请输入 YES"
    if ($ans -ne 'YES') { Write-Host "已取消。"; exit 3 }
}

$p = Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/s', ('"' + $DLL + '"') -Wait -PassThru
Write-Host ("regsvr32 退出码: " + $p.ExitCode)

$k1 = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\' + $CLSID
$k2 = 'HKLM:\SOFTWARE\Classes\CLSID\' + $CLSID + '\InprocServer32'
Write-Host ("  AMSI\Providers 键 : " + $(if (Test-Path $k1) { '已写入 OK' } else { '未写入' }))
Write-Host ("  InprocServer32  : " + $(if (Test-Path $k2) { (Get-ItemProperty $k2).'(default)' } else { '未写入' }))
Write-Host ""
Write-Host "注册流程结束。新开的 PowerShell 会话里的脚本块会被交给本提供程序检查。" -ForegroundColor Green
Write-Host "投稿：先跑一段无害的 -enc 命令验证（应被拦），再跑正常命令验证（应放行）。"