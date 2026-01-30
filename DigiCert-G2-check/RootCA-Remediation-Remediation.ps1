# ============================================
# RootCA-Remediation-Remediation.ps1
# Intune Remediation - Remediation Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Installs the DigiCert Global Root G2 certificate
# into the Trusted Root CA store.
#
# Downloads the certificate from DigiCert and
# installs it via certutil.
#
# Required for Exchange Online mail flow.
# Deadline: April 30, 2026
# Reference: https://aka.ms/DigiCertRootG2
#
# Thumbprint: DF3C24F9BFD666761B268073FE06D1CC8D4F82A4
#
# Exit Codes:
#   0 = Success (certificate installed)
#   1 = Error (installation failed)
#
# ============================================

$Thumbprint = "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"
$DownloadUrl = "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt"
$TempFile = Join-Path $env:TEMP "DigiCertGlobalRootG2.crt"

# Check if already installed
$existing = Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object { $_.Thumbprint -eq $Thumbprint }
if ($existing) {
    Write-Output "Certificate already present. No action needed."
    exit 0
}

# Download certificate
try {
    Write-Output "Downloading DigiCert Global Root G2 certificate..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($DownloadUrl, $TempFile)
    Write-Output "Download complete: $TempFile"
}
catch {
    Write-Output "ERROR: Failed to download certificate. $($_.Exception.Message)"
    exit 1
}

# Verify downloaded file exists
if (-not (Test-Path $TempFile)) {
    Write-Output "ERROR: Downloaded file not found at $TempFile."
    exit 1
}

# Install certificate
try {
    Write-Output "Installing certificate to Trusted Root CA store..."
    $result = certutil -addstore Root $TempFile 2>&1
    Write-Output $result
}
catch {
    Write-Output "ERROR: certutil failed. $($_.Exception.Message)"
    Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue
    exit 1
}

# Cleanup temp file
Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue

# Verify installation
$verify = Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object { $_.Thumbprint -eq $Thumbprint }
if ($verify) {
    Write-Output "SUCCESS: DigiCert Global Root G2 certificate installed."
    Write-Output "Subject: $($verify.Subject)"
    Write-Output "NotAfter: $($verify.NotAfter)"
    exit 0
}
else {
    Write-Output "ERROR: Certificate installation could not be verified."
    exit 1
}
