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

# ============================================
# MAIN
# ============================================

try {
    Write-Output "Checking BitLocker KB5075941 risk status..."
    Write-Output ""

    # ========================================
    # PRIMARY DETECTION: Extension Attribute
    # ========================================

    if ($UseInventoryData) {
        Write-Output "Method 1: Checking Extension Attribute (Inventory-based)..."

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
                        Write-Output "  Extension Attribute value: $extAttr"

                        # Check for RISK tag
                        if ($extAttr -like "*RISK*") {
                            Write-Output ""
                            Write-Output "=========================================="
                            Write-Output "RISK DETECTED (Inventory-based)!"
                            Write-Output "=========================================="
                            Write-Output "Device is tagged as AT RISK in central inventory:"
                            Write-Output ""
                            Write-Output "  Status: $extAttr"
                            Write-Output ""
                            Write-Output "This means:"
                            Write-Output "  - Device has old boot manager (validated via PCR4 fingerprint)"
                            Write-Output "  - BitLocker + Secure Boot + TPM enabled"
                            Write-Output "  - KB5075941 not yet installed"
                            Write-Output ""
                            Write-Output "Remediation needed: Suspend BitLocker for 1 reboot"
                            Write-Output "=========================================="
                            exit 1
                        }
                        else {
                            Write-Output "  [OK] No RISK tag found in inventory"
                            Write-Output ""
                            Write-Output "COMPLIANT: Device is not at risk according to inventory"
                            Write-Output "(either KB installed, or new boot manager detected via PCR4)"
                            exit 0
                        }
                    }
                    else {
                        Write-Output "  [WARN] Extension Attribute is empty - device not yet inventoried"
                        Write-Output "  Falling back to local detection..."
                        Write-Output ""
                    }
                }
                else {
                    Write-Output "  [WARN] Graph authentication failed"
                    Write-Output "  Falling back to local detection..."
                    Write-Output ""
                }
            }
            else {
                Write-Output "  [WARN] Could not get Entra Device ID"
                Write-Output "  Falling back to local detection..."
                Write-Output ""
            }
        }
        else {
            Write-Output "  [WARN] No Graph credentials found"
            Write-Output "  Falling back to local detection..."
            Write-Output ""
        }
    }

    # ========================================
    # FALLBACK DETECTION: Local Checks
    # ========================================

    Write-Output "Method 2: Local security checks (fallback)..."
    Write-Output ""

    # Check 1: BitLocker protection enabled on C:?
    $bitlockerEnabled = $false
    try {
        $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($blv -and $blv.ProtectionStatus -eq "On") {
            $bitlockerEnabled = $true
            Write-Output "  [OK] BitLocker protection is ON"
        }
        else {
            Write-Output "  [SKIP] BitLocker protection is OFF - no risk"
            exit 0
        }
    }
    catch {
        Write-Output "  [SKIP] BitLocker not available - no risk"
        exit 0
    }

    # Check 2: Secure Boot enabled?
    $secureBootEnabled = $false
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot -eq $true) {
            $secureBootEnabled = $true
            Write-Output "  [OK] Secure Boot is ENABLED"
        }
        else {
            Write-Output "  [SKIP] Secure Boot is DISABLED - no risk"
            exit 0
        }
    }
    catch {
        Write-Output "  [SKIP] Secure Boot not available (legacy BIOS) - no risk"
        exit 0
    }

    # Check 3: TPM owned?
    $tpmOwned = $false
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmOwned -eq $true) {
            $tpmOwned = $true
            Write-Output "  [OK] TPM is owned and ready"
        }
        else {
            Write-Output "  [SKIP] TPM not owned - no risk"
            exit 0
        }
    }
    catch {
        Write-Output "  [SKIP] TPM not available - no risk"
        exit 0
    }

    # Check 4: KB5075941 already installed?
    $kbInstalled = $false
    try {
        $kb = Get-HotFix -Id "KB5075941" -ErrorAction SilentlyContinue
        if ($kb) {
            $kbInstalled = $true
            Write-Output "  [OK] KB5075941 already installed - no risk"
            exit 0
        }
        else {
            Write-Output "  [WARN] KB5075941 NOT installed yet"
        }
    }
    catch {
        Write-Output "  [WARN] KB5075941 NOT installed yet"
    }

    # Risk Assessment (Fallback)
    if ($bitlockerEnabled -and $secureBootEnabled -and $tpmOwned -and -not $kbInstalled) {
        Write-Output ""
        Write-Output "=========================================="
        Write-Output "RISK DETECTED (Local checks - fallback)!"
        Write-Output "=========================================="
        Write-Output "This device meets all criteria for BitLocker recovery prompt"
        Write-Output "when KB5075941 is installed:"
        Write-Output "  - BitLocker: ON"
        Write-Output "  - Secure Boot: ENABLED"
        Write-Output "  - TPM: OWNED"
        Write-Output "  - KB5075941: NOT INSTALLED"
        Write-Output ""
        Write-Output "NOTE: Using fallback detection (inventory data not available)"
        Write-Output "      For more reliable detection, ensure Inventory remediation is running"
        Write-Output ""
        Write-Output "Remediation needed: Suspend BitLocker for 1 reboot"
        Write-Output "=========================================="
        exit 1
    }

    # No risk detected
    Write-Output ""
    Write-Output "COMPLIANT: No risk detected"
    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 0
}
