# ============================================
# BitLocker-Suspend-Detection.ps1
# Intune Proactive Remediation - Detection Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Detects devices that are at RISK for BitLocker recovery
# prompt due to KB5075941 (Secure Boot certificate update).
#
# Detection Strategy (in order):
#   1. PRIMARY: Check Extension Attribute 14 for "RISK" tag
#      - Most reliable (includes PCR4 fingerprint validation)
#      - Uses central inventory data
#      - Prevents false positives (e.g., devices with new boot manager already)
#
#   2. FALLBACK: Local checks if Extension Attribute not available
#      - BitLocker protection is ON on C:
#      - Secure Boot is ENABLED
#      - TPM is OWNED and ready
#      - KB5075941 is NOT YET installed
#
# If RISK detected, remediation will suspend BitLocker
# for 1 reboot to allow the boot manager update without
# triggering a recovery key prompt.
#
# Exit Codes:
#   0 = Compliant (no risk detected OR KB already installed)
#   1 = Non-Compliant (risk detected, BitLocker suspend needed)
#
# ============================================

# ============================================
# CONFIGURATION
# ============================================

# Which extension attribute to use (must match Inventory script)
$ExtensionAttributeNumber = 14

# Use Inventory-based detection (recommended for reliability)
$UseInventoryData = $true

# ============================================
# DO NOT CHANGE BELOW THIS LINE
# ============================================

$CredentialsRegistryPath = "HKLM:\SOFTWARE\Company\GraphAPI"

# Output buffer for Intune Remediation reporting
# (Intune only shows last Write-Output, so we collect all and output once at the end)
$script:logBuffer = @()

# Helper function to add log messages
function Write-Log {
    param([string]$Message)
    $script:logBuffer += $Message
}

# Helper function to exit with full log output
function Exit-WithLog {
    param([int]$ExitCode = 0)
    Write-Output ($script:logBuffer -join "`n")
    exit $ExitCode
}

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

        # IMPORTANT: For Hybrid-joined devices, there are TWO Device IDs:
        # - DeviceId (On-Prem AD) - does NOT work with Graph API
        # - AzureAdDeviceId (Entra ID) - this is what we need!
        # So we MUST prioritize AzureAdDeviceId over DeviceId

        $azureAdDeviceId = $null
        $fallbackDeviceId = $null

        foreach ($line in $dsregOutput) {
            # PRIORITY 1: AzureAdDeviceId (works for both Entra-joined and Hybrid-joined)
            # This field name should be consistent across all languages
            if ($line -match "AzureAdDeviceId\s*:\s*(.+)") {
                $id = $Matches[1].Trim()
                if ($id -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                    $azureAdDeviceId = $id
                }
            }

            # PRIORITY 2: DeviceId (fallback for pure Entra-joined)
            # This field name should be consistent across all languages
            if ($line -match "^DeviceId\s*:\s*(.+)" -or $line -match "^\s+DeviceId\s*:\s*(.+)") {
                $id = $Matches[1].Trim()
                if ($id -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                    if (-not $fallbackDeviceId) {
                        $fallbackDeviceId = $id
                    }
                }
            }
        }

        # PRIORITY 3: Language-independent fallback
        # Search for any line with pattern: <something-ID> : <GUID>
        # This catches localized field names like "Geraete-ID" (German), "ID de dispositivo" (Spanish), etc.
        if (-not $azureAdDeviceId -and -not $fallbackDeviceId) {
            foreach ($line in $dsregOutput) {
                # Match pattern: <word containing "id" or "ID"> : <GUID>
                if ($line -match "(?i)\S*id\S*\s*:\s*([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})") {
                    $id = $Matches[1].Trim()
                    # Validate GUID format
                    if ($id -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                        # Skip known non-device IDs (like CorrelationId, TenantId, etc.)
                        if ($line -notmatch "(?i)(CorrelationId|TenantId|ThumbPrint|Certificate)") {
                            if (-not $fallbackDeviceId) {
                                $fallbackDeviceId = $id
                            }
                        }
                    }
                }
            }
        }

        # Return in order of priority
        if ($azureAdDeviceId) {
            return $azureAdDeviceId
        }
        elseif ($fallbackDeviceId) {
            return $fallbackDeviceId
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
    Write-Log "Checking BitLocker KB5075941 risk status..."
    Write-Log ""

    # ========================================
    # PRIMARY DETECTION: Extension Attribute
    # ========================================

    if ($UseInventoryData) {
        Write-Log "Method 1: Checking Extension Attribute (Inventory-based)..."

        # Check credentials
        $creds = Get-GraphCredentials
        if ($creds) {
            # Get Entra ID device ID
            $entraDeviceId = Get-EntraDeviceId
            if ($entraDeviceId) {
                # Get token
                $token = Get-GraphToken -Credentials $creds
                if ($token) {
                    # Get Extension Attribute
                    $extAttr = Get-DeviceExtensionAttribute -Token $token -DeviceId $entraDeviceId -AttributeNumber $ExtensionAttributeNumber

                    if ($extAttr) {
                        Write-Log "  Extension Attribute value: $extAttr"

                        # Check for RISK tag
                        if ($extAttr -like "*RISK*") {
                            Write-Log ""
                            Write-Log "=========================================="
                            Write-Log "RISK DETECTED (Inventory-based)!"
                            Write-Log "=========================================="
                            Write-Log "Device is tagged as AT RISK in central inventory:"
                            Write-Log ""
                            Write-Log "  Status: $extAttr"
                            Write-Log ""
                            Write-Log "This means:"
                            Write-Log "  - Device has old boot manager (validated via PCR4 fingerprint)"
                            Write-Log "  - BitLocker + Secure Boot + TPM enabled"
                            Write-Log "  - KB5075941 not yet installed"
                            Write-Log ""
                            Write-Log "Remediation needed: Suspend BitLocker for 1 reboot"
                            Write-Log "=========================================="
                            Exit-WithLog 1
                        }
                        else {
                            Write-Log "  [OK] No RISK tag found in inventory"
                            Write-Log ""
                            Write-Log "COMPLIANT: Device is not at risk according to inventory"
                            Write-Log "(either KB installed, or new boot manager detected via PCR4)"
                            Exit-WithLog 0
                        }
                    }
                    else {
                        Write-Log "  [WARN] Extension Attribute is empty - device not yet inventoried"
                        Write-Log "  Falling back to local detection..."
                        Write-Log ""
                    }
                }
                else {
                    Write-Log "  [WARN] Graph authentication failed"
                    Write-Log "  Falling back to local detection..."
                    Write-Log ""
                }
            }
            else {
                Write-Log "  [WARN] Could not get Entra Device ID"
                Write-Log "  Falling back to local detection..."
                Write-Log ""
            }
        }
        else {
            Write-Log "  [WARN] No Graph credentials found"
            Write-Log "  Falling back to local detection..."
            Write-Log ""
        }
    }

    # ========================================
    # FALLBACK DETECTION: Local Checks
    # ========================================

    Write-Log "Method 2: Local security checks (fallback)..."
    Write-Log ""

    # Check 1: BitLocker protection enabled on C:?
    $bitlockerEnabled = $false
    try {
        $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($blv -and $blv.ProtectionStatus -eq "On") {
            $bitlockerEnabled = $true
            Write-Log "  [OK] BitLocker protection is ON"
        }
        else {
            Write-Log "  [SKIP] BitLocker protection is OFF - no risk"
            Exit-WithLog 0
        }
    }
    catch {
        Write-Log "  [SKIP] BitLocker not available - no risk"
        Exit-WithLog 0
    }

    # Check 2: Secure Boot enabled?
    $secureBootEnabled = $false
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot -eq $true) {
            $secureBootEnabled = $true
            Write-Log "  [OK] Secure Boot is ENABLED"
        }
        else {
            Write-Log "  [SKIP] Secure Boot is DISABLED - no risk"
            Exit-WithLog 0
        }
    }
    catch {
        Write-Log "  [SKIP] Secure Boot not available (legacy BIOS) - no risk"
        Exit-WithLog 0
    }

    # Check 3: TPM owned?
    $tpmOwned = $false
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmOwned -eq $true) {
            $tpmOwned = $true
            Write-Log "  [OK] TPM is owned and ready"
        }
        else {
            Write-Log "  [SKIP] TPM not owned - no risk"
            Exit-WithLog 0
        }
    }
    catch {
        Write-Log "  [SKIP] TPM not available - no risk"
        Exit-WithLog 0
    }

    # Check 4: KB5075941 already installed?
    $kbInstalled = $false
    try {
        $kb = Get-HotFix -Id "KB5075941" -ErrorAction SilentlyContinue
        if ($kb) {
            $kbInstalled = $true
            Write-Log "  [OK] KB5075941 already installed - no risk"
            Exit-WithLog 0
        }
        else {
            Write-Log "  [WARN] KB5075941 NOT installed yet"
        }
    }
    catch {
        Write-Log "  [WARN] KB5075941 NOT installed yet"
    }

    # Risk Assessment (Fallback)
    if ($bitlockerEnabled -and $secureBootEnabled -and $tpmOwned -and -not $kbInstalled) {
        Write-Log ""
        Write-Log "=========================================="
        Write-Log "RISK DETECTED (Local checks - fallback)!"
        Write-Log "=========================================="
        Write-Log "This device meets all criteria for BitLocker recovery prompt"
        Write-Log "when KB5075941 is installed:"
        Write-Log "  - BitLocker: ON"
        Write-Log "  - Secure Boot: ENABLED"
        Write-Log "  - TPM: OWNED"
        Write-Log "  - KB5075941: NOT INSTALLED"
        Write-Log ""
        Write-Log "NOTE: Using fallback detection (inventory data not available)"
        Write-Log "      For more reliable detection, ensure Inventory remediation is running"
        Write-Log ""
        Write-Log "Remediation needed: Suspend BitLocker for 1 reboot"
        Write-Log "=========================================="
        Exit-WithLog 1
    }

    # No risk detected
    Write-Log ""
    Write-Log "COMPLIANT: No risk detected"
    Exit-WithLog 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Exit-WithLog 0
}
