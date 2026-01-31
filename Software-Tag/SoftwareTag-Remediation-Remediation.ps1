# ============================================
# SoftwareTag-Remediation-Remediation.ps1
# Intune Remediation - Remediation Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Writes installed software (from a configurable list)
# as a semicolon-separated string into a device
# extension attribute in Entra ID via Graph API.
#
# This allows dynamic Entra ID groups to use
# -contains "SoftwareName" rules for targeting.
#
# Exit Codes:
#   0 = Success (extension attribute updated)
#   1 = Error (update failed)
#
# Requirement:
#   App Registration needs Device.ReadWrite.All permission
#
# ============================================

# ============================================
# CONFIGURATION - Adjust these values
# IMPORTANT: Must match Detection script!
# ============================================

# Graph API Credentials (inline)
$TenantId     = "YOUR-TENANT-ID"
$ClientId     = "YOUR-CLIENT-ID"
$ClientSecret = "YOUR-CLIENT-SECRET"

# Software names to look for (matched against DisplayName in registry)
# Use wildcard patterns (*) for flexible matching
$SoftwareList = @(
    "7-Zip*"
    "Adobe Acrobat*"
    "Citrix Workspace*"
    "Google Chrome*"
    "Microsoft 365 Apps*"
    "Microsoft Visual Studio*"
    "Mozilla Firefox*"
    "Notepad++*"
    "TeamViewer*"
    "VLC media player*"
    "Zoom*"
)

# Which extension attribute to use (1-15)
$ExtensionAttributeNumber = 1

# ============================================
# DO NOT CHANGE BELOW THIS LINE
# ============================================

function Get-GraphToken {
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        return $null
    }
}

function Get-InstalledSoftware {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $installed = @()
    foreach ($path in $registryPaths) {
        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            if (-not [string]::IsNullOrWhiteSpace($item.DisplayName)) {
                $installed += $item.DisplayName
            }
        }
    }

    return $installed | Sort-Object -Unique
}

function Get-MatchingSoftware {
    param(
        [string[]]$InstalledSoftware,
        [string[]]$SearchList
    )

    $matches = @()
    foreach ($pattern in $SearchList) {
        foreach ($sw in $InstalledSoftware) {
            if ($sw -like $pattern) {
                # Store the clean pattern name (without wildcards) for the tag
                $cleanName = $pattern -replace '\*', ''
                $cleanName = $cleanName.Trim()
                if ($matches -notcontains $cleanName) {
                    $matches += $cleanName
                }
                break
            }
        }
    }

    return $matches | Sort-Object
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
    } | ConvertTo-Json -Depth 3

    $uri = "https://graph.microsoft.com/v1.0/devices/$ObjectId"

    try {
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Patch -Body $body | Out-Null
        return $true
    }
    catch {
        Write-Output "API Error: $($_.Exception.Message)"
        return $false
    }
}

# ============================================
# MAIN
# ============================================

try {
    # Validate configuration
    if ($TenantId -eq "YOUR-TENANT-ID" -or $ClientId -eq "YOUR-CLIENT-ID" -or $ClientSecret -eq "YOUR-CLIENT-SECRET") {
        Write-Output "Error: Graph API credentials not configured"
        exit 1
    }

    # Get Entra ID device ID
    $entraDeviceId = Get-EntraDeviceId
    if (-not $entraDeviceId) {
        Write-Output "Error: Could not determine Entra ID device ID"
        exit 1
    }

    # Get installed software
    $installed = Get-InstalledSoftware
    $matching = Get-MatchingSoftware -InstalledSoftware $installed -SearchList $SoftwareList

    # Build semicolon-separated string
    if ($matching.Count -gt 0) {
        $softwareTag = ($matching -join ";")
    }
    else {
        $softwareTag = ""
    }

    Write-Output "Software tag to write: $softwareTag"
    Write-Output "Tag length: $($softwareTag.Length) / 1024 chars"

    # Safety check: 1024 char limit
    if ($softwareTag.Length -gt 1024) {
        Write-Output "Error: Software tag exceeds 1024 character limit ($($softwareTag.Length) chars)"
        exit 1
    }

    # Get token
    $token = Get-GraphToken
    if (-not $token) {
        Write-Output "Error: Authentication failed"
        exit 1
    }

    # Get Entra ID object ID (needed for PATCH)
    $objectId = Get-EntraDeviceObjectId -Token $token -DeviceId $entraDeviceId
    if (-not $objectId) {
        Write-Output "Error: Device not found in Entra ID"
        exit 1
    }

    # Update extension attribute
    $success = Set-DeviceExtensionAttribute -Token $token -ObjectId $objectId -AttributeNumber $ExtensionAttributeNumber -Value $softwareTag

    if ($success) {
        Write-Output "SUCCESS: extensionAttribute$ExtensionAttributeNumber updated"
        Write-Output "Value: $softwareTag"
        exit 0
    }
    else {
        Write-Output "Error: Failed to update extension attribute"
        exit 1
    }
}
catch {
    Write-Output "Error: $($_.Exception.Message)"
    exit 1
}
