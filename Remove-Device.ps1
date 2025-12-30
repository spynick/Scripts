<#
.SYNOPSIS
    Loescht Enrollment-Reste eines Geraets aus Intune und Entra ID
    
.PARAMETER SerialNumber
    Die Seriennummer des Geraets (z.B. "PF5JS2E2")
    
.PARAMETER WhatIf
    Zeigt an was passieren wuerde, fuehrt aber keine Aenderungen durch
    
.EXAMPLE
    .\Reset-DeviceEnrollment.ps1 -SerialNumber "PF5JS2E2" -WhatIf
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SerialNumber,
    
    [switch]$WhatIf
)

# ============================================================
# CREDENTIALS - HIER EINTRAGEN
# ============================================================
$TenantId     = ""           # Azure AD Tenant ID
$ClientId     = ""           # App Registration Client ID  
$ClientSecret = ""       # App Registration Client Secret

# ============================================================

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Web

# Token als Script-Variable
$script:GraphToken = $null

function Get-GraphToken {
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $script:ClientId
        client_secret = $script:ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    
    $response = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$($script:TenantId)/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body $body
    
    $script:GraphToken = $response.access_token
}

function Invoke-Graph {
    param(
        [string]$Method = "GET",
        [string]$Endpoint,
        [switch]$Beta
    )
    
    $baseUrl = "https://graph.microsoft.com/v1.0"
    if ($Beta) {
        $baseUrl = "https://graph.microsoft.com/beta"
    }
    
    $uri = "$baseUrl$Endpoint"
    
    $headers = @{
        "Authorization" = "Bearer $($script:GraphToken)"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
        return $response
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            return $null
        }
        throw
    }
}

# ============================================================
# HAUPTPROGRAMM
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DEVICE ENROLLMENT RESET" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Seriennummer: $SerialNumber" -ForegroundColor White

if ($WhatIf) {
    Write-Host "MODUS: WhatIf (keine Aenderungen)" -ForegroundColor Yellow
}

Write-Host ""

# 1. Token holen
Write-Host "[1/5] Authentifizierung..." -ForegroundColor Gray
Get-GraphToken
Write-Host "      OK" -ForegroundColor Green

# 2. Managed Device suchen
Write-Host "[2/5] Suche Managed Device in Intune..." -ForegroundColor Gray
$filter = [System.Web.HttpUtility]::UrlEncode("serialNumber eq '$SerialNumber'")
$managedDevices = Invoke-Graph -Endpoint "/deviceManagement/managedDevices?`$filter=$filter" -Beta

$managedDevice = $null
if ($managedDevices -and $managedDevices.value -and $managedDevices.value.Count -gt 0) {
    $managedDevice = $managedDevices.value[0]
    Write-Host "      Gefunden: $($managedDevice.deviceName)" -ForegroundColor Green
    Write-Host "      ID: $($managedDevice.id)" -ForegroundColor Gray
    Write-Host "      Entra Device ID: $($managedDevice.azureADDeviceId)" -ForegroundColor Gray
} else {
    Write-Host "      Nicht gefunden" -ForegroundColor Yellow
}

# 3. Entra ID Device suchen
Write-Host "[3/5] Suche Device in Entra ID..." -ForegroundColor Gray
$entraDevice = $null

if ($managedDevice -and $managedDevice.azureADDeviceId) {
    $deviceFilter = [System.Web.HttpUtility]::UrlEncode("deviceId eq '$($managedDevice.azureADDeviceId)'")
    $entraDevices = Invoke-Graph -Endpoint "/devices?`$filter=$deviceFilter"
    
    if ($entraDevices -and $entraDevices.value -and $entraDevices.value.Count -gt 0) {
        $entraDevice = $entraDevices.value[0]
        Write-Host "      Gefunden: $($entraDevice.displayName)" -ForegroundColor Green
        Write-Host "      Object ID: $($entraDevice.id)" -ForegroundColor Gray
    }
}

if (-not $entraDevice) {
    # Fallback: Nach displayName suchen
    $displayNameFilter = [System.Web.HttpUtility]::UrlEncode("startswith(displayName,'$SerialNumber')")
    $entraDevices = Invoke-Graph -Endpoint "/devices?`$filter=$displayNameFilter"
    
    if ($entraDevices -and $entraDevices.value -and $entraDevices.value.Count -gt 0) {
        $entraDevice = $entraDevices.value[0]
        Write-Host "      Gefunden (via Name): $($entraDevice.displayName)" -ForegroundColor Green
    } else {
        Write-Host "      Nicht gefunden" -ForegroundColor Yellow
    }
}

# Zusammenfassung
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ZUSAMMENFASSUNG" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($managedDevice) {
    Write-Host "Managed Device (Intune):" -ForegroundColor White
    Write-Host "  Name:     $($managedDevice.deviceName)" -ForegroundColor Gray
    Write-Host "  ID:       $($managedDevice.id)" -ForegroundColor Gray
    Write-Host "  Status:   WIRD GELOESCHT" -ForegroundColor Red
} else {
    Write-Host "Managed Device (Intune): Nicht vorhanden" -ForegroundColor Gray
}

Write-Host ""

if ($entraDevice) {
    Write-Host "Entra ID Device:" -ForegroundColor White
    Write-Host "  Name:     $($entraDevice.displayName)" -ForegroundColor Gray
    Write-Host "  ID:       $($entraDevice.id)" -ForegroundColor Gray
    Write-Host "  Status:   WIRD GELOESCHT" -ForegroundColor Red
} else {
    Write-Host "Entra ID Device: Nicht vorhanden" -ForegroundColor Gray
}

Write-Host ""

# Nichts zu tun?
if (-not $managedDevice -and -not $entraDevice) {
    Write-Host "Nichts zu loeschen. Device ist bereits sauber." -ForegroundColor Green
    exit 0
}

# WhatIf - hier stoppen
if ($WhatIf) {
    Write-Host ""
    Write-Host "WhatIf: Keine Aenderungen durchgefuehrt." -ForegroundColor Yellow
    Write-Host "Entferne -WhatIf um die Loeschung durchzufuehren." -ForegroundColor Yellow
    exit 0
}

# Bestaetigung
Write-Host ""
Write-Host "WARNUNG: Diese Aktion kann nicht rueckgaengig gemacht werden!" -ForegroundColor Red
Write-Host ""
Write-Host "Folgendes wird geloescht:" -ForegroundColor Yellow
Write-Host "  - Managed Device Enrollment" -ForegroundColor Yellow
Write-Host "  - Entra ID Device Object" -ForegroundColor Yellow
Write-Host "  - Compliance Status" -ForegroundColor Yellow
Write-Host "  - Zugewiesene Policies" -ForegroundColor Yellow
Write-Host ""
Write-Host "Das Autopilot Device bleibt erhalten!" -ForegroundColor Green
Write-Host ""

$confirm = Read-Host "Zum Bestaetigen Seriennummer eingeben [$SerialNumber]"
if ($confirm -ne $SerialNumber) {
    Write-Host "Abgebrochen." -ForegroundColor Yellow
    exit 1
}

# 4. Managed Device loeschen
if ($managedDevice) {
    Write-Host ""
    Write-Host "[4/5] Loesche Managed Device..." -ForegroundColor Gray
    try {
        Invoke-Graph -Method DELETE -Endpoint "/deviceManagement/managedDevices/$($managedDevice.id)" -Beta
        Write-Host "      Geloescht" -ForegroundColor Green
    }
    catch {
        Write-Host "      Fehler: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[4/5] Managed Device: Uebersprungen (nicht vorhanden)" -ForegroundColor Gray
}

# 5. Entra Device loeschen
if ($entraDevice) {
    Write-Host "[5/5] Loesche Entra ID Device..." -ForegroundColor Gray
    try {
        Invoke-Graph -Method DELETE -Endpoint "/devices/$($entraDevice.id)"
        Write-Host "      Geloescht" -ForegroundColor Green
    }
    catch {
        Write-Host "      Fehler: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[5/5] Entra ID Device: Uebersprungen (nicht vorhanden)" -ForegroundColor Gray
}

# Fertig
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  FERTIG" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Naechste Schritte:" -ForegroundColor White
Write-Host "  1. Geraet neu starten" -ForegroundColor White
Write-Host "  2. OOBE startet automatisch" -ForegroundColor White
Write-Host "  3. Autopilot wird automatisch erkannt" -ForegroundColor White
Write-Host ""
