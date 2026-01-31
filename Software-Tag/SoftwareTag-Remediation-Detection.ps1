# ============================================
# SoftwareTag-Remediation-Detection.ps1
# Intune Remediation - Detection Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Detects installed software from a configurable list
# and compares it with the value stored in a device
# extension attribute in Entra ID.
#
# If the local software list differs from the stored
# value, remediation is triggered to update the
# extension attribute via Graph API.
#
# The extension attribute can then be used in dynamic
# Entra ID groups with the -contains operator.
#
# Exit Codes:
#   0 = Compliant (extension attribute matches installed software)
#   1 = Non-Compliant (mismatch, remediation needed)
#
# Requirement:
#   App Registration needs Device.ReadWrite.All permission
#
# ============================================

# ============================================
# CONFIGURATION - Adjust these values
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
    # Get the Entra ID device ID from the local device
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

# ============================================
# MAIN
# ============================================

try {
    # Validate configuration
    if ($TenantId -eq "YOUR-TENANT-ID" -or $ClientId -eq "YOUR-CLIENT-ID" -or $ClientSecret -eq "YOUR-CLIENT-SECRET") {
        Write-Output "Error: Graph API credentials not configured"
        exit 0
    }

    # Get Entra ID device ID
    $entraDeviceId = Get-EntraDeviceId
    if (-not $entraDeviceId) {
        Write-Output "Could not determine Entra ID device ID"
        exit 0
    }

    # Get installed software
    $installed = Get-InstalledSoftware
    $matching = Get-MatchingSoftware -InstalledSoftware $installed -SearchList $SoftwareList

    # Build semicolon-separated string
    if ($matching.Count -gt 0) {
        $localTag = ($matching -join ";")
    }
    else {
        $localTag = ""
    }

    Write-Output "Installed (matching): $localTag"

    # Get token and check current attribute value
    $token = Get-GraphToken
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
