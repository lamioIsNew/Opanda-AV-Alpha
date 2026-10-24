# sign_test_driver.ps1 -- create/reuse a self-signed code-signing cert and sign HipsDriver.sys
# Test use only. Never install this driver on a production host.
$ErrorActionPreference = 'Stop'

$Here = $PSScriptRoot
$Sys = Join-Path $Here 'HipsDriver.sys'
$Pfx = Join-Path $Here 'OpandaTest.pfx'
$Cer = Join-Path $Here 'OpandaTest.cer'
$Password = 'opanda'

if (-not (Test-Path -LiteralPath $Sys)) { throw "HipsDriver.sys not found. Run build_driver_msvc.ps1 first." }

$cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq 'CN=Opanda Test Driver' -and $_.HasPrivateKey } |
        Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=Opanda Test Driver' `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(2)
}

$secure = ConvertTo-SecureString -String $Password -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $Pfx -Password $secure | Out-Null
Export-Certificate -Cert $cert -FilePath $Cer | Out-Null

$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
if (-not (Test-Path -LiteralPath $signtool)) { $signtool = 'signtool.exe' }

& $signtool sign /fd SHA256 /f $Pfx /p $Password $Sys
if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }

Write-Host "Signed: $Sys"
Write-Host "Certificate: $Cer"
Write-Host "PFX (test only, keep private): $Pfx"
