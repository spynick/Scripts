# ============================================
# BitLocker-Suspend-Remediation.ps1
# Intune Proactive Remediation - Remediation Script
# PowerShell 5.1 / ASCII
# ============================================
#
# Suspends BitLocker protection for 1 reboot to allow
# KB5075941 boot manager update without triggering
# BitLocker recovery key prompt.
#
# The suspension is TEMPORARY - BitLocker will automatically
# resume protection after the next reboot.
#
# Exit Codes:
#   0 = Success (BitLocker suspended)
#   1 = Failure (suspension failed)
#
# ============================================

# ============================================
# MAIN
# ============================================

try {
    Write-Output "Suspending BitLocker for 1 reboot..."

    # Check BitLocker status
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

    if ($blv.ProtectionStatus -ne "On") {
        Write-Output "INFO: BitLocker protection is not ON - nothing to suspend"
        exit 0
    }

    # Suspend BitLocker for 1 reboot
    Suspend-BitLocker -MountPoint "C:" -RebootCount 1 -ErrorAction Stop

    # Verify suspension
    $blvAfter = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

    if ($blvAfter.ProtectionStatus -eq "Off") {
        Write-Output ""
        Write-Output "=========================================="
        Write-Output "SUCCESS: BitLocker suspended for 1 reboot"
        Write-Output "=========================================="
        Write-Output "BitLocker protection is now SUSPENDED"
        Write-Output "Next reboot will:"
        Write-Output "  1. Allow boot manager update (KB5075941)"
        Write-Output "  2. NOT trigger BitLocker recovery prompt"
        Write-Output "  3. Automatically RESUME BitLocker protection"
        Write-Output ""
        Write-Output "Protection Status: $($blvAfter.ProtectionStatus)"
        Write-Output "Encryption Percentage: $($blvAfter.EncryptionPercentage)%"
        Write-Output "Volume Status: $($blvAfter.VolumeStatus)"
        Write-Output "=========================================="
        exit 0
    }
    else {
        Write-Output "ERROR: BitLocker suspension failed - protection status still: $($blvAfter.ProtectionStatus)"
        exit 1
    }
}
catch {
    Write-Output "ERROR: Failed to suspend BitLocker: $($_.Exception.Message)"
    exit 1
}
