# ============================================
# BitLocker-SecureBoot-Inventory-Detection.ps1
# Intune Remediation - Detection Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Detects BitLocker + Secure Boot + KB5075941 status
# and compares it with the value stored in a device
# extension attribute in Entra ID.
#
# This variant uses DPAPI-encrypted credentials from
# the registry (Graph-Credentials-Setup required).
#
# If the local status differs from the stored value,
# remediation is triggered to update the extension
# attribute via Graph API.
#
# Status Tags (semicolon-separated):
#   - BitLocker:         BitLocker protection enabled on C:
#   - SecureBoot:        Secure Boot is enabled
#   - KB5075941:         February 2026 update installed
#   - TPM:               TPM is owned and ready
#   - RISK:              Device at risk for BitLocker recovery prompt
#
# RISK = BitLocker + SecureBoot + TPM + NOT KB5075941
#
# Exit Codes:
#   0 = Compliant (extension attribute matches current status)
#   1 = Non-Compliant (mismatch, remediation needed)
#
# Requirement:
#   Graph-Credentials-Setup needs to be installed before
#   App Registration needs Device.ReadWrite.All permission
#
# Extension Attribute used: extensionAttribute2
#
# ============================================

# ============================================
# CONFIGURATION
# ============================================

# Which extension attribute to use (1-15)
$ExtensionAttributeNumber = 14

# ============================================
# DO NOT CHANGE BELOW THIS LINE
# ============================================

$CredentialsRegistryPath = "HKLM:\SOFTWARE\Company\GraphAPI"

Add-Type -AssemblyName System.Security

function Unprotect-DPAPIString {
    param([string]$EncryptedBase64)

    try {
        $encrypted = [Convert]::FromBase64String($EncryptedBase64)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
    catch {
        return $null
    }
}

function Get-GraphCredentials {
    if (-not (Test-Path $CredentialsRegistryPath)) {
        return $null
    }

    $reg = Get-ItemProperty -Path $CredentialsRegistryPath -ErrorAction SilentlyContinue
    if (-not ($reg.TenantId -and $reg.ClientId -and $reg.ClientSecret)) {
        return $null
    }

    $tenant = Unprotect-DPAPIString $reg.TenantId
    $client = Unprotect-DPAPIString $reg.ClientId
    $secret = Unprotect-DPAPIString $reg.ClientSecret

    if ($tenant -and $client -and $secret) {
        return @{
            TenantId     = $tenant
            ClientId     = $client
            ClientSecret = $secret
        }
    }

    return $null
}

function Get-GraphToken {
    param($Credentials)

    $body = @{
        grant_type    = "client_credentials"
        client_id     = $Credentials.ClientId
        client_secret = $Credentials.ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $uri = "https://login.microsoftonline.com/$($Credentials.TenantId)/oauth2/v2.0/token"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        return $null
    }
}

function Get-EntraDeviceId {
    try {
        $dsregOutput = dsregcmd /status 2>&1
        foreach ($line in $dsregOutput) {
            if ($line -match "DeviceId\s*:\s*(.+)") {
                return $Matches[1].Trim()
            }
        }
        return $null
    }
    catch {
        return $null
    }
}

function Get-DeviceExtensionAttribute {
    param(
        [string]$Token,
        [string]$DeviceId,
        [int]$AttributeNumber
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $uri = "https://graph.microsoft.com/v1.0/devices(deviceId='$DeviceId')?`$select=extensionAttributes"

    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        $attrName = "extensionAttribute$AttributeNumber"
        return $result.extensionAttributes.$attrName
    }
    catch {
        return $null
    }
}

function Get-LocalSecurityStatus {
    $status = @()

    # BitLocker Status
    try {
        $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($blv -and $blv.ProtectionStatus -eq "On") {
            $status += "BitLocker"
        }
    }
    catch {
        # BitLocker not available
    }

    # Secure Boot Status
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot -eq $true) {
            $status += "SecureBoot"
        }
    }
    catch {
        # Secure Boot not available (legacy BIOS)
    }

    # KB5075941 installed?
    try {
        $kb = Get-HotFix -Id "KB5075941" -ErrorAction SilentlyContinue
        if ($kb) {
            $status += "KB5075941"
        }
    }
    catch {
        # KB not installed
    }

    # TPM Ownership
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmOwned -eq $true) {
            $status += "TPM"
        }
    }
    catch {
        # TPM not available
    }

    # Risk Assessment
    # RISK = BitLocker + SecureBoot + TPM + NOT KB5075941
    if (($status -contains "BitLocker") -and
        ($status -contains "SecureBoot") -and
        ($status -contains "TPM") -and
        ($status -notcontains "KB5075941")) {
        $status += "RISK"
    }

    return $status | Sort-Object
}

# ============================================
# MAIN
# ============================================

try {
    # Check credentials
    $creds = Get-GraphCredentials
    if (-not $creds) {
        Write-Output "No credentials found - skipping"
        exit 0
    }

    # Get Entra ID device ID
    $entraDeviceId = Get-EntraDeviceId
    if (-not $entraDeviceId) {
        Write-Output "Could not determine Entra ID device ID"
        exit 0
    }

    # Get local security status
    $localStatus = Get-LocalSecurityStatus

    # Build semicolon-separated string
    if ($localStatus.Count -gt 0) {
        $localTag = ($localStatus -join ";")
    }
    else {
        $localTag = ""
    }

    Write-Output "Local Status: $localTag"

    # Get token and check current attribute value
    $token = Get-GraphToken -Credentials $creds
    if (-not $token) {
        Write-Output "Authentication failed"
        exit 0
    }

    $currentTag = Get-DeviceExtensionAttribute -Token $token -DeviceId $entraDeviceId -AttributeNumber $ExtensionAttributeNumber
    Write-Output "Current extensionAttribute$($ExtensionAttributeNumber): $currentTag"

    # Compare
    if ($localTag -eq $currentTag) {
        Write-Output "COMPLIANT: Extension attribute is up to date"
        exit 0
    }
    else {
        Write-Output "NON-COMPLIANT: Extension attribute needs update"
        Write-Output "  Expected: $localTag"
        Write-Output "  Current:  $currentTag"
        exit 1
    }
}
catch {
    Write-Output "Error: $($_.Exception.Message)"
    exit 0
}
