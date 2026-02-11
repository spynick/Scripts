# ============================================
# BitLocker-Suspend-Detection.ps1
# Intune Proactive Remediation - Detection Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Detects devices that are at RISK for BitLocker recovery
# prompt due to KB5075941 (Secure Boot certificate update).
#
# RISK Criteria:
#   - BitLocker protection is ON on C:
#   - Secure Boot is ENABLED
#   - TPM is OWNED and ready
#   - KB5075941 is NOT YET installed
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
# MAIN
# ============================================

try {
    Write-Output "Checking BitLocker KB5075941 risk status..."

    # Check 1: BitLocker protection enabled on C:?
    $bitlockerEnabled = $false
    try {
        $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($blv -and $blv.ProtectionStatus -eq "On") {
            $bitlockerEnabled = $true
            Write-Output "[OK] BitLocker protection is ON"
        }
        else {
            Write-Output "[SKIP] BitLocker protection is OFF - no risk"
            exit 0
        }
    }
    catch {
        Write-Output "[SKIP] BitLocker not available - no risk"
        exit 0
    }

    # Check 2: Secure Boot enabled?
    $secureBootEnabled = $false
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot -eq $true) {
            $secureBootEnabled = $true
            Write-Output "[OK] Secure Boot is ENABLED"
        }
        else {
            Write-Output "[SKIP] Secure Boot is DISABLED - no risk"
            exit 0
        }
    }
    catch {
        Write-Output "[SKIP] Secure Boot not available (legacy BIOS) - no risk"
        exit 0
    }

    # Check 3: TPM owned?
    $tpmOwned = $false
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmOwned -eq $true) {
            $tpmOwned = $true
            Write-Output "[OK] TPM is owned and ready"
        }
        else {
            Write-Output "[SKIP] TPM not owned - no risk"
            exit 0
        }
    }
    catch {
        Write-Output "[SKIP] TPM not available - no risk"
        exit 0
    }

    # Check 4: KB5075941 already installed?
    $kbInstalled = $false
    try {
        $kb = Get-HotFix -Id "KB5075941" -ErrorAction SilentlyContinue
        if ($kb) {
            $kbInstalled = $true
            Write-Output "[OK] KB5075941 already installed - no risk"
            exit 0
        }
        else {
            Write-Output "[WARN] KB5075941 NOT installed yet"
        }
    }
    catch {
        Write-Output "[WARN] KB5075941 NOT installed yet"
    }

    # Risk Assessment
    if ($bitlockerEnabled -and $secureBootEnabled -and $tpmOwned -and -not $kbInstalled) {
        Write-Output ""
        Write-Output "=========================================="
        Write-Output "RISK DETECTED!"
        Write-Output "=========================================="
        Write-Output "This device meets all criteria for BitLocker recovery prompt"
        Write-Output "when KB5075941 is installed:"
        Write-Output "  - BitLocker: ON"
        Write-Output "  - Secure Boot: ENABLED"
        Write-Output "  - TPM: OWNED"
        Write-Output "  - KB5075941: NOT INSTALLED"
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
