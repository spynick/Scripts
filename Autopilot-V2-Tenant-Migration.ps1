# ============================================
# Autopilot-V2-Tenant-Migration.ps1
# Migrates Autopilot devices between tenants (V2 - no hardware hash needed)
# PowerShell 5.1 / ASCII
# ============================================
#
# Workflow:
#   1. Export from source tenant (serial + group tag only)
#   2. Delete from source tenant
#   3. Wait until deleted
#   4. Import into target tenant (serial + group tag)
#   5. Devices will self-register with hardware hash on next boot
#
# Usage:
#   Single device:  .\script.ps1 -SerialNumber "ABC123"
#   Bulk from CSV:  .\script.ps1 -CsvPath "devices.csv"
#   Export only:    .\script.ps1 -ExportOnly -OutputCsv "export.csv"
#
# CSV Format:
#   SerialNumber,GroupTag
#   ABC123,Production-Line-01
#   XYZ789,Office-EMEA
#
# Exit Codes:
#   0 = Success
#   1 = Error
#
# ============================================

param(
    [Parameter(ParameterSetName="Single")]
    [string]$SerialNumber,
    
    [Parameter(ParameterSetName="Bulk")]
    [string]$CsvPath,
    
    [Parameter(ParameterSetName="Export")]
    [switch]$ExportOnly,
    
    [Parameter(ParameterSetName="Export")]
    [string]$OutputCsv = "autopilot-export.csv",
    
    [Parameter()]
    [switch]$WhatIf
)

# --- SOURCE TENANT CONFIGURATION ---
$SourceTenant = @{
    TenantId     = "OLD-TENANT-ID"
    ClientId     = "OLD-APP-CLIENT-ID"
    ClientSecret = "OLD-APP-CLIENT-SECRET"
}

# --- TARGET TENANT CONFIGURATION ---
$TargetTenant = @{
    TenantId     = "NEW-TENANT-ID"
    ClientId     = "NEW-APP-CLIENT-ID"
    ClientSecret = "NEW-APP-CLIENT-SECRET"
}

# --- SETTINGS ---
$MaxWaitMinutes = 10
$CheckIntervalSeconds = 30

# ============================================
# FUNCTIONS
# ============================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-GraphToken {
    param($TenantConfig)

    $body = @{
        grant_type    = "client_credentials"
        client_id     = $TenantConfig.ClientId
        client_secret = $TenantConfig.ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $uri = "https://login.microsoftonline.com/$($TenantConfig.TenantId)/oauth2/v2.0/token"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Log "Token error: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-AutopilotDevice {
    param([string]$Token, [string]$SerialNumber)

    $headers = @{ Authorization = "Bearer $Token" }
    $escaped = $SerialNumber -replace "'","''"
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$escaped')"

    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        if ($result.value.Count -eq 0) {
            return $null
        }
        
        if ($result.value.Count -gt 1) {
            Write-Log "Warning: Multiple devices found for '$SerialNumber', using first one" "WARN"
        }
        
        return $result.value[0]
    }
    catch {
        Write-Log "Search error: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-AllAutopilotDevices {
    param([string]$Token)

    $headers = @{ Authorization = "Bearer $Token" }
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities"
    $devices = @()

    try {
        do {
            $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            $devices += $result.value
            $uri = $result.'@odata.nextLink'
        } while ($uri)
        
        return $devices
    }
    catch {
        Write-Log "Error fetching devices: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Remove-AutopilotDevice {
    param([string]$Token, [string]$DeviceId)

    $headers = @{ Authorization = "Bearer $Token" }
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$DeviceId"

    try {
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Delete | Out-Null
        return $true
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        Write-Log "Delete error (HTTP $status): $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Wait-DeviceDeleted {
    param([string]$Token, [string]$SerialNumber, [int]$TimeoutMinutes)

    $waited = 0
    $maxSeconds = $TimeoutMinutes * 60
    
    Write-Log "Waiting for deletion confirmation (max. $TimeoutMinutes minutes)..."

    while ($waited -lt $maxSeconds) {
        Start-Sleep -Seconds $CheckIntervalSeconds
        $waited += $CheckIntervalSeconds
        
        $device = Get-AutopilotDevice -Token $Token -SerialNumber $SerialNumber
        
        if (-not $device) {
            Write-Log "Device deleted (after $waited seconds)" "SUCCESS"
            return $true
        }
        
        if ($waited % 60 -eq 0) {
            Write-Log "Still waiting... ($waited/$maxSeconds seconds)"
        }
    }
    
    Write-Log "Timeout: Device not deleted after $TimeoutMinutes minutes" "ERROR"
    return $false
}

function Import-AutopilotV2Device {
    param([string]$Token, [string]$SerialNumber, [string]$GroupTag)

    $headers = @{
        Authorization  = "Bearer $Token"
        "Content-Type" = "application/json"
    }

    # V2: Only serial number and group tag needed
    $body = @{
        serialNumber = $SerialNumber
        groupTag     = if ($GroupTag) { $GroupTag } else { "" }
    } | ConvertTo-Json

    # V2 Endpoint
    $uri = "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities"

    try {
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body | Out-Null
        return $true
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        
        if ($status -eq 409) {
            Write-Log "Device already registered in target tenant" "WARN"
            return $true
        }
        
        Write-Log "Import error (HTTP $status): $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Export-AutopilotDevices {
    param([string]$Token, [string]$OutputPath)

    Write-Log "Exporting all Autopilot devices..." "INFO"
    
    $devices = Get-AllAutopilotDevices -Token $Token
    
    if (-not $devices) {
        Write-Log "No devices found or export failed" "ERROR"
        return $false
    }

    $exportData = $devices | Select-Object `
        @{Name='SerialNumber';Expression={$_.serialNumber}},
        @{Name='GroupTag';Expression={$_.groupTag}},
        @{Name='Model';Expression={$_.model}},
        @{Name='Manufacturer';Expression={$_.manufacturer}}

    try {
        $exportData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($devices.Count) devices to: $OutputPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Export failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Migrate-SingleDevice {
    param([string]$SerialNumber)

    Write-Log "=== MIGRATING SINGLE DEVICE ===" "INFO"
    Write-Log "Serial Number: $SerialNumber"
    Write-Log ""

    # Get source token
    $sourceToken = Get-GraphToken -TenantConfig $SourceTenant
    if (-not $sourceToken) {
        Write-Log "Source tenant authentication failed" "ERROR"
        return $false
    }

    # Find device in source
    $device = Get-AutopilotDevice -Token $sourceToken -SerialNumber $SerialNumber
    if (-not $device) {
        Write-Log "Device not found in source tenant" "ERROR"
        return $false
    }

    Write-Log "Device found:" "SUCCESS"
    Write-Log "  - Serial: $($device.serialNumber)"
    Write-Log "  - Model: $($device.model)"
    Write-Log "  - Group Tag: $($device.groupTag)"
    Write-Log ""

    # Delete from source
    if ($WhatIf) {
        Write-Log "WHATIF: Would delete device from source" "WARN"
    } else {
        Write-Log "Deleting from source tenant..." "INFO"
        $deleted = Remove-AutopilotDevice -Token $sourceToken -DeviceId $device.id
        if (-not $deleted) {
            return $false
        }
        
        $confirmed = Wait-DeviceDeleted -Token $sourceToken -SerialNumber $SerialNumber -TimeoutMinutes $MaxWaitMinutes
        if (-not $confirmed) {
            Write-Log "Migration aborted - device still in source tenant" "ERROR"
            return $false
        }
    }

    # Import to target
    Write-Log ""
    Write-Log "Importing to target tenant..." "INFO"
    
    $targetToken = Get-GraphToken -TenantConfig $TargetTenant
    if (-not $targetToken) {
        Write-Log "Target tenant authentication failed" "ERROR"
        return $false
    }

    if ($WhatIf) {
        Write-Log "WHATIF: Would import device to target" "WARN"
    } else {
        $imported = Import-AutopilotV2Device -Token $targetToken -SerialNumber $device.serialNumber -GroupTag $device.groupTag
        if (-not $imported) {
            return $false
        }
        
        Write-Log "Device imported (will self-register on next boot)" "SUCCESS"
    }

    return $true
}

function Migrate-BulkDevices {
    param([string]$CsvPath)

    if (-not (Test-Path $CsvPath)) {
        Write-Log "CSV file not found: $CsvPath" "ERROR"
        return $false
    }

    $devices = Import-Csv -Path $CsvPath

    if ($devices.Count -eq 0) {
        Write-Log "No devices found in CSV" "ERROR"
        return $false
    }

    Write-Log "=== BULK MIGRATION ===" "INFO"
    Write-Log "Devices to migrate: $($devices.Count)"
    Write-Log ""

    # Get tokens once
    $sourceToken = Get-GraphToken -TenantConfig $SourceTenant
    if (-not $sourceToken) {
        Write-Log "Source tenant authentication failed" "ERROR"
        return $false
    }

    $targetToken = Get-GraphToken -TenantConfig $TargetTenant
    if (-not $targetToken) {
        Write-Log "Target tenant authentication failed" "ERROR"
        return $false
    }

    $success = 0
    $failed = 0

    foreach ($device in $devices) {
        $serial = $device.SerialNumber
        $groupTag = $device.GroupTag

        Write-Log "Processing: $serial" "INFO"

        # Find in source
        $sourceDevice = Get-AutopilotDevice -Token $sourceToken -SerialNumber $serial
        if (-not $sourceDevice) {
            Write-Log "  Not found in source tenant" "WARN"
            $failed++
            continue
        }

        # Delete from source
        if (-not $WhatIf) {
            $deleted = Remove-AutopilotDevice -Token $sourceToken -DeviceId $sourceDevice.id
            if (-not $deleted) {
                $failed++
                continue
            }

            $confirmed = Wait-DeviceDeleted -Token $sourceToken -SerialNumber $serial -TimeoutMinutes $MaxWaitMinutes
            if (-not $confirmed) {
                Write-Log "  Delete timeout" "WARN"
                $failed++
                continue
            }
        }

        # Import to target
        if (-not $WhatIf) {
            $imported = Import-AutopilotV2Device -Token $targetToken -SerialNumber $serial -GroupTag $groupTag
            if ($imported) {
                Write-Log "  Migrated successfully" "SUCCESS"
                $success++
            } else {
                $failed++
            }
        } else {
            Write-Log "  WHATIF: Would migrate" "WARN"
            $success++
        }

        # Rate limiting
        Start-Sleep -Milliseconds 500
    }

    Write-Log ""
    Write-Log "=== BULK MIGRATION COMPLETE ===" "INFO"
    Write-Log "Success: $success"
    Write-Log "Failed: $failed"

    return ($failed -eq 0)
}

# ============================================
# MAIN PROGRAM
# ============================================

# Export only mode
if ($ExportOnly) {
    Write-Log "=== EXPORT MODE ===" "INFO"
    
    $sourceToken = Get-GraphToken -TenantConfig $SourceTenant
    if (-not $sourceToken) {
        Write-Log "Authentication failed" "ERROR"
        exit 1
    }

    $success = Export-AutopilotDevices -Token $sourceToken -OutputPath $OutputCsv
    exit $(if ($success) { 0 } else { 1 })
}

# Single device mode
if ($SerialNumber) {
    $success = Migrate-SingleDevice -SerialNumber $SerialNumber
    exit $(if ($success) { 0 } else { 1 })
}

# Bulk mode
if ($CsvPath) {
    $success = Migrate-BulkDevices -CsvPath $CsvPath
    exit $(if ($success) { 0 } else { 1 })
}

# No parameters provided
Write-Log "Usage:" "INFO"
Write-Log "  Single:  .\script.ps1 -SerialNumber 'ABC123'" "INFO"
Write-Log "  Bulk:    .\script.ps1 -CsvPath 'devices.csv'" "INFO"
Write-Log "  Export:  .\script.ps1 -ExportOnly -OutputCsv 'export.csv'" "INFO"
exit 1
