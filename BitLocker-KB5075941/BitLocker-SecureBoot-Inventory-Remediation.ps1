# ============================================
# BitLocker-SecureBoot-Inventory-Remediation.ps1
# Intune Remediation - Remediation Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Updates the device extension attribute in Entra ID
# with the current BitLocker + Secure Boot status.
#
# This script is triggered by the Detection script when
# the local status differs from the stored value.
#
# Status Tags (semicolon-separated):
#   - BitLocker:         BitLocker protection enabled on C:
#   - SecureBoot:        Secure Boot is enabled
#   - KB5075941:         February 2026 update installed
#   - TPM:               TPM is owned and ready
#   - RISK:              Device at risk for BitLocker recovery prompt
#
# Exit Codes:
#   0 = Success (extension attribute updated)
#   1 = Failure (update failed)
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

function Get-EntraDeviceObjectId {
    param(
        [string]$Token,
        [string]$DeviceId
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $uri = "https://graph.microsoft.com/v1.0/devices(deviceId='$DeviceId')?`$select=id"

    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $result.id
    }
    catch {
        return $null
    }
}

function Set-DeviceExtensionAttribute {
    param(
        [string]$Token,
        [string]$ObjectId,
        [int]$AttributeNumber,
        [string]$Value
    )

    $headers = @{
        Authorization  = "Bearer $Token"
        "Content-Type" = "application/json"
    }

    $attrName = "extensionAttribute$AttributeNumber"
    $body = @{
        extensionAttributes = @{
            $attrName = $Value
        }
    } | ConvertTo-Json

    $uri = "https://graph.microsoft.com/v1.0/devices/$ObjectId"

    try {
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Patch -Body $body | Out-Null
        return $true
    }
    catch {
        Write-Output "ERROR: Failed to update extension attribute: $($_.Exception.Message)"
        return $false
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
        Write-Output "ERROR: No credentials found"
        exit 1
    }

    # Get Entra ID device ID
    $entraDeviceId = Get-EntraDeviceId
    if (-not $entraDeviceId) {
        Write-Output "ERROR: Could not determine Entra ID device ID"
        exit 1
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

    # Get token
    $token = Get-GraphToken -Credentials $creds
    if (-not $token) {
        Write-Output "ERROR: Authentication failed"
        exit 1
    }

    # Get device object ID
    $objectId = Get-EntraDeviceObjectId -Token $token -DeviceId $entraDeviceId
    if (-not $objectId) {
        Write-Output "ERROR: Could not get device object ID"
        exit 1
    }

    # Update extension attribute
    $success = Set-DeviceExtensionAttribute -Token $token -ObjectId $objectId -AttributeNumber $ExtensionAttributeNumber -Value $localTag

    if ($success) {
        Write-Output "SUCCESS: Extension attribute updated to: $localTag"
        exit 0
    }
    else {
        Write-Output "ERROR: Failed to update extension attribute"
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
