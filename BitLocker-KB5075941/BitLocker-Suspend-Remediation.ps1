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

# ============================================
# MAIN
# ============================================

try {
    Write-Log "Suspending BitLocker for 1 reboot..."

    # Check BitLocker status
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

    if ($blv.ProtectionStatus -ne "On") {
        Write-Log "INFO: BitLocker protection is not ON - nothing to suspend"
        Exit-WithLog 0
    }

    # Suspend BitLocker for 1 reboot
    Suspend-BitLocker -MountPoint "C:" -RebootCount 1 -ErrorAction Stop

    # Verify suspension
    $blvAfter = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

    if ($blvAfter.ProtectionStatus -eq "Off") {
        Write-Log ""
        Write-Log "=========================================="
        Write-Log "SUCCESS: BitLocker suspended for 1 reboot"
        Write-Log "=========================================="
        Write-Log "BitLocker protection is now SUSPENDED"
        Write-Log "Next reboot will:"
        Write-Log "  1. Allow boot manager update (KB5075941)"
        Write-Log "  2. NOT trigger BitLocker recovery prompt"
        Write-Log "  3. Automatically RESUME BitLocker protection"
        Write-Log ""
        Write-Log "Protection Status: $($blvAfter.ProtectionStatus)"
        Write-Log "Encryption Percentage: $($blvAfter.EncryptionPercentage)%"
        Write-Log "Volume Status: $($blvAfter.VolumeStatus)"
        Write-Log "=========================================="
        Exit-WithLog 0
    }
    else {
        Write-Log "ERROR: BitLocker suspension failed - protection status still: $($blvAfter.ProtectionStatus)"
        Exit-WithLog 1
    }
}
catch {
    Write-Log "ERROR: Failed to suspend BitLocker: $($_.Exception.Message)"
    Exit-WithLog 1
}
