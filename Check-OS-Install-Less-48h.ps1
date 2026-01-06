# Compact version for Detection Script
$installDateUnix = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallDate
$installDate = (Get-Date "1970-01-01").AddSeconds($installDateUnix)
$ageHours = ((Get-Date) - $installDate).TotalHours

if ($ageHours -lt 48) {
    Write-Host "New installation"
    exit 0  # Compliant
} else {
    Write-Host "Existing installation"
    exit 1  # Non-compliant
}
