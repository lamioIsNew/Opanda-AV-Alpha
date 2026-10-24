# make_test_iso.ps1 -- 生成只读 VM 测试 ISO（不包含恶意样本、不包含私钥）
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Bin = Join-Path $Root 'bin'
$Db = Join-Path $Root 'db'
$Drv = Join-Path $Root 'driver'
$Tests = Join-Path $Root 'tests'
$PeVm = Join-Path (Split-Path -Parent $Root) '沙箱\PE虚拟执行沙盒'
$Payload = Join-Path $env:LOCALAPPDATA 'Temp\opencode\opanda_iso_payload'
$Iso = Join-Path $env:LOCALAPPDATA 'Temp\opencode\opanda_test.iso'

if (Test-Path -LiteralPath $Payload) { Remove-Item -LiteralPath $Payload -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Payload | Out-Null

$files = @(
    @{ Src = (Join-Path $Bin 'ScannerUI.exe');      Dst = 'ScannerUI.exe' },
    @{ Src = (Join-Path $Bin 'scanner.dll');        Dst = 'scanner.dll' },
    @{ Src = (Join-Path $Bin 'scaler.txt');         Dst = 'scaler.txt' },
    @{ Src = (Join-Path $Db 'signatures.db');       Dst = 'signatures.db' },
    @{ Src = (Join-Path $Tests 'hw_probe.exe');     Dst = 'hw_probe.exe' },
    @{ Src = (Join-Path $Drv 'HipsDriver.sys');     Dst = 'HipsDriver.sys' },
    @{ Src = (Join-Path $Drv 'HipsDriver.inf');     Dst = 'HipsDriver.inf' },
    @{ Src = (Join-Path $Drv 'HipsClient.exe');     Dst = 'HipsClient.exe' },
    @{ Src = (Join-Path $Drv 'HipsTestTarget.exe'); Dst = 'HipsTestTarget.exe' },
    @{ Src = (Join-Path $Drv 'OpandaTest.cer');     Dst = 'OpandaTest.cer' },
    @{ Src = (Join-Path $PeVm 'build\pe_vm_msvc.exe'); Dst = 'pe_vm_msvc.exe' },
    @{ Src = (Join-Path $PeVm 'pe_vm.exe');         Dst = 'pe_vm.exe' },
    @{ Src = (Join-Path $PeVm 'test\pevm_jmp_test.exe'); Dst = 'pevm_jmp_test.exe' }
)

foreach ($f in $files) {
    if (-not (Test-Path -LiteralPath $f.Src)) { throw "missing input: $($f.Src)" }
    Copy-Item -LiteralPath $f.Src -Destination (Join-Path $Payload $f.Dst) -Force
}

$scripts = @(
    'run_tests.cmd', 'run_gui.cmd',
    'driver_test.cmd', 'driver_full_test.cmd',
    'hips_version.cmd', 'hips_selftest.cmd',
    'hips_kill.cmd', 'hips_delete.cmd',
    'README_VM_TESTS.txt'
)
foreach ($s in $scripts) {
    $src = Join-Path $PSScriptRoot $s
    if (-not (Test-Path -LiteralPath $src)) { throw "missing script: $src" }
    Copy-Item -LiteralPath $src -Destination (Join-Path $Payload $s) -Force
}

if (Test-Path -LiteralPath $Iso) { Remove-Item -LiteralPath $Iso -Force }

Write-Host '[ISO] creating ...'
$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
try {
    $fsi.FileSystemsToCreate = 3          # ISO9660 + Joliet
    $fsi.VolumeName = 'OPANDA_TEST'
    $fsi.Root.AddTree($Payload, $false)
    $result = $fsi.CreateResultImage()
    $stream = $result.ImageStream
    # PowerShell 5.1/VBScript 对 IMAPI2 的 IStream 不暴露 SaveToFile；
    # 用 .NET 的 IStream.Read 把结果流写到文件。
    if (-not ('IsoSaver' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class IsoSaver {
    public static void Save(object imageStream, string path) {
        IStream s = (IStream)imageStream;
        using (FileStream fs = File.Create(path)) {
            byte[] buf = new byte[65536];
            IntPtr read = Marshal.AllocHGlobal(4);
            try {
                while (true) {
                    s.Read(buf, buf.Length, read);
                    int n = Marshal.ReadInt32(read);
                    if (n <= 0) break;
                    fs.Write(buf, 0, n);
                }
            } finally { Marshal.FreeHGlobal(read); }
        }
    }
}
"@
    }
    [IsoSaver]::Save($stream, $Iso)
} finally {
    if ($stream) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($stream) }
    if ($result) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($result) }
    if ($fsi) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($fsi) }
}

$h = (Get-FileHash -LiteralPath $Iso -Algorithm SHA256).Hash
Write-Host "ISO ready: $Iso"
Write-Host "SHA256: $h"
