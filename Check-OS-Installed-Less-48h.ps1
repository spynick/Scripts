<#
.SYNOPSIS
    Checks if the Windows installation is less than 48 hours old
.DESCRIPTION
    Reads the installation date from Registry and compares with current time
.OUTPUTS
    Boolean - True if installation < 48h, False if >= 48h
#>

function Test-WindowsInstallationAge {
    [CmdletBinding()]
    param(
        [int]$MaxAgeHours = 48
    )
    
    try {
        # Method 1: InstallDate from Registry (most reliable)
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $installDateUnix = (Get-ItemProperty -Path $registryPath -Name InstallDate).InstallDate
        
        # Convert Unix Timestamp to DateTime
        $installDate = (Get-Date "1970-01-01 00:00:00").AddSeconds($installDateUnix)
        
        # Calculate time difference
        $timeDifference = (Get-Date) - $installDate
        $ageInHours = $timeDifference.TotalHours
        
        # Output for debugging
        Write-Verbose "Installation date: $installDate"
        Write-Verbose "Age in hours: $([math]::Round($ageInHours, 2))"
        
        # Return value
        return ($ageInHours -lt $MaxAgeHours)
        
    } catch {
        Write-Error "Error reading installation date: $_"
        return $false
    }
}

# Call with return value
$isNewInstallation = Test-WindowsInstallationAge -Verbose

# Output
if ($isNewInstallation) {
    Write-Host "Windows installation is less than 48 hours old." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Windows installation is older than 48 hours." -ForegroundColor Yellow
    exit 1
}
