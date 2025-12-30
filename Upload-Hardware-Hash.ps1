# Upload Hardware Hash to Intune Autopilot
# PowerShell 5.1 compatible - ASCII encoding
#
# Run as Administrator on the target device

  $tenantId = ""
  $clientId = ""
  $clientSecret = ""

# Optional: Group Tag to assign
$GroupTag = ""

# === DO NOT MODIFY BELOW ===

# Get Hardware Hash from WMI
Write-Host "Collecting hardware information..." -ForegroundColor Cyan

$serial = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$hardwareHash = (Get-WmiObject -Namespace "root/cimv2/mdm/dmmap" -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction Stop).DeviceHardwareData

if (-not $hardwareHash) {
    Write-Host "ERROR: Could not retrieve hardware hash. Run as Administrator!" -ForegroundColor Red
    exit 1
}

Write-Host "Serial Number: $serial" -ForegroundColor Green
Write-Host "Hardware Hash: $($hardwareHash.Substring(0, 50))..." -ForegroundColor Gray

# Get Access Token
Write-Host "`nAuthenticating with Azure AD..." -ForegroundColor Cyan

$tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$tokenBody = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
    grant_type    = "client_credentials"
}

try {
    $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
    $accessToken = $tokenResponse.access_token
    Write-Host "Authentication successful!" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Authentication failed - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Prepare device data
$deviceData = @{
    "@odata.type" = "#microsoft.graph.importedWindowsAutopilotDeviceIdentity"
    serialNumber = $serial
    hardwareIdentifier = $hardwareHash
}

if ($GroupTag) {
    $deviceData.groupTag = $GroupTag
}

$jsonBody = $deviceData | ConvertTo-Json -Depth 10

# Upload to Intune
Write-Host "`nUploading to Intune Autopilot..." -ForegroundColor Cyan

$uploadUrl = "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities"
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

try {
    $response = Invoke-RestMethod -Method Post -Uri $uploadUrl -Headers $headers -Body $jsonBody

    Write-Host "`n=== SUCCESS ===" -ForegroundColor Green
    Write-Host "Device uploaded to Autopilot!" -ForegroundColor Green
    Write-Host "ID: $($response.id)" -ForegroundColor Gray
    Write-Host "Serial: $($response.serialNumber)" -ForegroundColor Gray
    Write-Host "State: $($response.state.deviceImportStatus)" -ForegroundColor Gray

    if ($GroupTag) {
        Write-Host "Group Tag: $GroupTag" -ForegroundColor Gray
    }
}
catch {
    $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
    $errorMsg = if ($errorDetails.error.message) { $errorDetails.error.message } else { $_.Exception.Message }

    Write-Host "`nERROR: Upload failed" -ForegroundColor Red
    Write-Host $errorMsg -ForegroundColor Red

    if ($errorMsg -like "*already exists*") {
        Write-Host "`nDevice is already registered in Autopilot." -ForegroundColor Yellow
    }

    exit 1
}

Write-Host "`nNote: It may take a few minutes for the device to appear in Intune." -ForegroundColor Yellow
