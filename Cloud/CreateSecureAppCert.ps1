#=======================================================================================
#region PARAMETERS
#=======================================================================================
Param(
    [string]$TenantName,
    [string]$ExportPrivateKey,
    [string]$ExportPath
    )
#endregion
#=======================================================================================

$DateTime = (Get-Date -Format "yyyyMMdd-HHmmss").tostring()
$ShortTenantName = ($TenantName -split "\.")[0]

# Where to export the certificate without the private key
$CerOutputPath     = "$ExportPath\$DateTime-$ShortTenantName-AppCert"

# Expiration date of the new certificate
$ExpirationDate    = (Get-Date).AddYears(2)

# Splat for readability
$CreateCertificateSplat = @{
    FriendlyName      = "PSCC-$TenantName-App"
    DnsName           = $TenantName
    CertStoreLocation = "Cert:\CurrentUser\My"
    NotAfter          = $ExpirationDate
    KeyExportPolicy   = "Exportable"
    KeySpec           = "Signature"
    Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    HashAlgorithm     = "SHA256"
}

# Create certificate
$Certificate = New-SelfSignedCertificate @CreateCertificateSplat

# Get certificate path
$CertificatePath = Join-Path -Path "Cert:\CurrentUser\My" -ChildPath $Certificate.Thumbprint

# Export certificate without private key
Export-Certificate -Cert $CertificatePath -FilePath "$CerOutputPath.cer" | Out-Null
if($ExportPrivateKey -eq $true)
{
    Write-Host "Please create a password for the certificate which will be exported with the private key: " -ForegroundColor Yellow -NoNewline
    $Password = Read-Host -AsSecureString
    # Export certificate with private key
    Export-PfxCertificate -Cert $CertificatePath -FilePath "$CerOutputPath.pfx" -Password $Password | Out-Null
}

Write-Host "Certificate validity    : $($Certificate.NotBefore) through $($Certificate.NotAfter) "
Write-Host "Certificate thumbprint  : $($Certificate.Thumbprint)"
Write-Host "Certificate exported to : $CerOutputPath"

