# ============================================
# Check-BitLocker-KB5075941-Risk-Interactive.ps1
# One-Time Risk Assessment for KB5075941 BitLocker Issue
# PowerShell 5.1 / ASCII
# ============================================
#
# Interactive version - uses browser-based authentication
# instead of DPAPI credentials from registry.
#
# Queries all Intune managed devices and checks which devices
# are at RISK for BitLocker recovery prompt when KB5075941
# (February 2026 Patch Tuesday) is installed.
#
# RISK Criteria:
#   - Device has extensionAttribute14 containing "RISK" tag
#   - OR: Device has BitLocker + SecureBoot + TPM but not KB5075941
#
# This script requires the Extension Attribute Inventory
# remediation to be deployed first to tag all devices.
#
# Authentication:
#   - Interactive device code flow (browser-based)
#   - Requires user with permissions to read devices
#
# Required Graph API Permissions (Delegated):
#   - DeviceManagementManagedDevices.Read.All
#   - Device.Read.All
#
# Usage:
#   .\Check-BitLocker-KB5075941-Risk-Interactive.ps1
#   .\Check-BitLocker-KB5075941-Risk-Interactive.ps1 -ExportCsv "C:\Temp\BitLocker-Risk-Report.csv"
#
# Parameters:
#   -ExportCsv    Export results to CSV file
#
# ============================================

param(
    [string]$ExportCsv
)

# ============================================
# Interactive Authentication Functions
# ============================================

function Get-DeviceCodeToken {
    param(
        [string]$TenantId = "common",
        [string]$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools
    )

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Interactive Authentication Required" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    $scope = "https://graph.microsoft.com/.default"
    $deviceCodeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # Request device code
    $deviceCodeBody = @{
        client_id = $ClientId
        scope     = $scope
    }

    try {
        $deviceCodeResponse = Invoke-RestMethod -Uri $deviceCodeUrl -Method Post -Body $deviceCodeBody -ContentType "application/x-www-form-urlencoded"
    }
    catch {
        Write-Host "ERROR: Failed to get device code: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }

    # Display user instructions
    Write-Host "To sign in, use a web browser to open the page:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    $($deviceCodeResponse.verification_uri)" -ForegroundColor Green
    Write-Host ""
    Write-Host "and enter the code:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    $($deviceCodeResponse.user_code)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Waiting for authentication..." -ForegroundColor Cyan
    Write-Host ""

    # Poll for token
    $interval = $deviceCodeResponse.interval
    $expiresIn = $deviceCodeResponse.expires_in
    $startTime = Get-Date

    $tokenBody = @{
        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
        client_id   = $ClientId
        device_code = $deviceCodeResponse.device_code
    }

    while ($true) {
        Start-Sleep -Seconds $interval

        try {
            $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
            Write-Host "SUCCESS: Authentication successful!" -ForegroundColor Green
            Write-Host ""
            return $tokenResponse.access_token
        }
        catch {
            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue

            if ($errorResponse.error -eq "authorization_pending") {
                # Still waiting for user to authenticate
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                if ($elapsed -gt $expiresIn) {
                    Write-Host "ERROR: Authentication timeout. Please try again." -ForegroundColor Red
                    return $null
                }
                # Continue polling
            }
            elseif ($errorResponse.error -eq "authorization_declined") {
                Write-Host "ERROR: Authentication declined by user." -ForegroundColor Red
                return $null
            }
            elseif ($errorResponse.error -eq "expired_token") {
                Write-Host "ERROR: Device code expired. Please try again." -ForegroundColor Red
                return $null
            }
            else {
                Write-Host "ERROR: Authentication failed: $($errorResponse.error_description)" -ForegroundColor Red
                return $null
            }
        }
    }
}

# ============================================
# Graph API Functions
# ============================================

function Get-AllEntraDevicesWithExtensionAttributes {
    param([string]$Token)

    $headers = @{ Authorization = "Bearer $Token" }
    $uri = "https://graph.microsoft.com/v1.0/devices?`$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,extensionAttributes"

    $devices = @()

    try {
        do {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            $devices += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)

        return $devices
    }
    catch {
        Write-Host "ERROR: Failed to retrieve devices: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ============================================
# MAIN
# ============================================

Write-Output ""
Write-Output "============================================"
Write-Output "  KB5075941 BitLocker Risk Assessment"
Write-Output "  Interactive Version"
Write-Output "============================================"
Write-Output ""

# Interactive authentication
$token = Get-DeviceCodeToken
if (-not $token) {
    Write-Output "ERROR: Authentication failed"
    exit 1
}

Write-Output "Retrieving all Entra ID devices..."
$devices = Get-AllEntraDevicesWithExtensionAttributes -Token $token
if (-not $devices) {
    Write-Output "ERROR: Failed to retrieve devices"
    exit 1
}

Write-Output "Total devices retrieved: $($devices.Count)"
Write-Output ""

# Analyze risk
$riskDevices = @()
$safeDevices = @()
$unknownDevices = @()

foreach ($device in $devices) {
    $extAttr14 = $device.extensionAttributes.extensionAttribute14

    if ($extAttr14) {
        # Device has been inventoried
        if ($extAttr14 -like "*RISK*") {
            $riskDevices += $device
        }
        else {
            $safeDevices += $device
        }
    }
    else {
        # Device not yet inventoried
        $unknownDevices += $device
    }
}

# Results
Write-Output "============================================"
Write-Output "Risk Assessment Results:"
Write-Output "============================================"
Write-Output ""
Write-Output "AT RISK:     $($riskDevices.Count) devices"
Write-Output "SAFE:        $($safeDevices.Count) devices"
Write-Output "UNKNOWN:     $($unknownDevices.Count) devices (not yet inventoried)"
Write-Output ""

if ($riskDevices.Count -gt 0) {
    Write-Output "============================================"
    Write-Output "Devices AT RISK for BitLocker recovery:"
    Write-Output "============================================"
    Write-Output ""

    foreach ($device in $riskDevices) {
        $displayName = if ($device.displayName) { $device.displayName } else { "(No name)" }
        $os = if ($device.operatingSystem) { $device.operatingSystem } else { "Unknown" }
        $osVersion = if ($device.operatingSystemVersion) { $device.operatingSystemVersion } else { "Unknown" }
        $status = $device.extensionAttributes.extensionAttribute14

        Write-Output "  Device:  $displayName"
        Write-Output "  OS:      $os $osVersion"
        Write-Output "  Status:  $status"
        Write-Output "  ID:      $($device.deviceId)"
        Write-Output ""
    }
}

if ($unknownDevices.Count -gt 0) {
    Write-Output "============================================"
    Write-Output "WARNING: $($unknownDevices.Count) devices not yet inventoried"
    Write-Output "============================================"
    Write-Output "Deploy the Extension Attribute Inventory remediation"
    Write-Output "to all devices to complete the risk assessment."
    Write-Output ""
}

# Export to CSV
if ($ExportCsv) {
    Write-Output "============================================"
    Write-Output "Exporting to CSV: $ExportCsv"
    Write-Output "============================================"

    $csvData = @()

    foreach ($device in $riskDevices) {
        $csvData += [PSCustomObject]@{
            RiskLevel = "AT RISK"
            DeviceName = $device.displayName
            DeviceId = $device.deviceId
            OperatingSystem = $device.operatingSystem
            OSVersion = $device.operatingSystemVersion
            Status = $device.extensionAttributes.extensionAttribute14
        }
    }

    foreach ($device in $safeDevices) {
        $csvData += [PSCustomObject]@{
            RiskLevel = "SAFE"
            DeviceName = $device.displayName
            DeviceId = $device.deviceId
            OperatingSystem = $device.operatingSystem
            OSVersion = $device.operatingSystemVersion
            Status = $device.extensionAttributes.extensionAttribute14
        }
    }

    foreach ($device in $unknownDevices) {
        $csvData += [PSCustomObject]@{
            RiskLevel = "UNKNOWN"
            DeviceName = $device.displayName
            DeviceId = $device.deviceId
            OperatingSystem = $device.operatingSystem
            OSVersion = $device.operatingSystemVersion
            Status = "Not inventoried"
        }
    }

    try {
        $csvData | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding ASCII
        Write-Output "SUCCESS: CSV exported to $ExportCsv"
        Write-Output ""
    }
    catch {
        Write-Output "ERROR: Failed to export CSV: $($_.Exception.Message)"
    }
}

Write-Output "============================================"
Write-Output "Recommendations:"
Write-Output "============================================"
Write-Output ""

if ($riskDevices.Count -gt 0) {
    Write-Output "1. URGENT: Deploy 'BitLocker Suspend' Proactive Remediation"
    Write-Output "   to the $($riskDevices.Count) at-risk devices BEFORE KB5075941 installs"
    Write-Output ""
    Write-Output "2. Create Dynamic Group in Entra ID:"
    Write-Output "   Rule: (device.extensionAttribute14 -contains `"RISK`")"
    Write-Output ""
    Write-Output "3. Assign BitLocker Suspend remediation to this group"
    Write-Output ""
    Write-Output "4. Monitor deployment and ensure all devices are remediated"
    Write-Output "   before approving KB5075941 in your Windows Update rings"
    Write-Output ""
}
else {
    Write-Output "GOOD NEWS: No devices at risk detected!"
    Write-Output ""
    Write-Output "Either KB5075941 is already installed on all devices,"
    Write-Output "or no devices meet the risk criteria."
    Write-Output ""
}

if ($unknownDevices.Count -gt 0) {
    Write-Output "5. Deploy Extension Attribute Inventory to remaining"
    Write-Output "   $($unknownDevices.Count) devices to complete assessment"
    Write-Output ""
}

Write-Output "============================================"
Write-Output ""
