# ============================================
# RootCA-Remediation-Detection.ps1
# Intune Remediation - Detection Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Checks if the DigiCert Global Root G2 certificate
# is present in the Trusted Root CA store.
#
# Required for Exchange Online mail flow.
# Deadline: April 30, 2026
# Reference: https://aka.ms/DigiCertRootG2
#
# Thumbprint: DF3C24F9BFD666761B268073FE06D1CC8D4F82A4
#
# Exit Codes:
#   0 = Compliant (certificate found)
#   1 = Non-Compliant (certificate missing)
#
# ============================================

$Thumbprint = "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"

try {
    $cert = Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object { $_.Thumbprint -eq $Thumbprint }

    if ($cert) {
        Write-Output "COMPLIANT: DigiCert Global Root G2 certificate found."
        Write-Output "Subject: $($cert.Subject)"
        Write-Output "NotAfter: $($cert.NotAfter)"
        exit 0
    }
    else {
        Write-Output "NON-COMPLIANT: DigiCert Global Root G2 certificate not found (Thumbprint: $Thumbprint)."
        exit 1
    }
}
catch {
    Write-Output "ERROR: Failed to check certificate store. $($_.Exception.Message)"
    exit 1
}
