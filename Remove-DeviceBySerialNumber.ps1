<#
.SYNOPSIS
    Remove device from Entra ID, Intune and Autopilot by serial number
.DESCRIPTION
    This script removes all device objects from Entra ID, Intune Managed Devices, 
    and Autopilot registration based on the provided serial number.
    Useful for cleaning up test devices before re-enrolling in different tenants.
.PARAMETER SerialNumber
    Device serial number to search and remove
.EXAMPLE
    .\Remove-DeviceBySerialNumber.ps1
.NOTES
    Author: Stefan
    Version: 1.0
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement, Microsoft.Graph.Identity.DirectoryManagement
#>

[CmdletBinding()]
param()

# ASCII encoding enforcement
[Console]::OutputEncoding = [System.Text.Encoding]::ASCII
$OutputEncoding = [System.Text.Encoding]::ASCII

#Requires -Version 5.1

# Function to check and install required modules
function Install-RequiredModules {
    Write-Host "Checking required modules..." -ForegroundColor Cyan
    
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.DeviceManagement", 
        "Microsoft.Graph.Identity.DirectoryManagement"
    )
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing module: $module" -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                Write-Host "Module $module installed successfully" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install module $module : $_"
                return $false
            }
        }
        else {
            Write-Host "Module $module already installed" -ForegroundColor Green
        }
    }
    return $true
}

# Function to connect to Microsoft Graph
function Connect-MicrosoftGraphAPI {
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $scopes = @(
        "Device.ReadWrite.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "DeviceManagementServiceConfig.ReadWrite.All"
    )
    
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome
        $context = Get-MgContext
        Write-Host "Connected to tenant: $($context.TenantId)" -ForegroundColor Green
        Write-Host "Account: $($context.Account)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        return $false
    }
}

# Function to find Autopilot device by serial number
function Get-AutopilotDeviceBySerial {
    param([string]$SerialNumber)
    
    Write-Host "`nSearching for Autopilot device with serial number: $SerialNumber" -ForegroundColor Cyan
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$SerialNumber')"
        $autopilotDevices = Invoke-MgGraphRequest -Method GET -Uri $uri
        
        if ($autopilotDevices.value.Count -gt 0) {
            Write-Host "Found $($autopilotDevices.value.Count) Autopilot device(s)" -ForegroundColor Yellow
            return $autopilotDevices.value
        }
        else {
            Write-Host "No Autopilot device found" -ForegroundColor Gray
            return $null
        }
    }
    catch {
        Write-Warning "Error searching Autopilot devices: $_"
        return $null
    }
}

# Function to find Intune managed device by serial number
function Get-IntuneDeviceBySerial {
    param([string]$SerialNumber)
    
    Write-Host "`nSearching for Intune managed device with serial number: $SerialNumber" -ForegroundColor Cyan
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=serialNumber eq '$SerialNumber'"
        $intuneDevices = Invoke-MgGraphRequest -Method GET -Uri $uri
        
        if ($intuneDevices.value.Count -gt 0) {
            Write-Host "Found $($intuneDevices.value.Count) Intune managed device(s)" -ForegroundColor Yellow
            return $intuneDevices.value
        }
        else {
            Write-Host "No Intune managed device found" -ForegroundColor Gray
            return $null
        }
    }
    catch {
        Write-Warning "Error searching Intune devices: $_"
        return $null
    }
}

# Function to find Entra ID device by serial number
function Get-EntraIDDeviceBySerial {
    param([string]$SerialNumber)
    
    Write-Host "`nSearching for Entra ID device with serial number: $SerialNumber" -ForegroundColor Cyan
    
    try {
        # Try physical IDs first (most reliable for Autopilot devices)
        $physicalId = "[OrderID]:$SerialNumber"
        $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=physicalIds/any(p:p eq '$physicalId')"
        $entraDevices = Invoke-MgGraphRequest -Method GET -Uri $uri
        
        if ($entraDevices.value.Count -eq 0) {
            # Fallback: search in device name or other attributes
            Write-Host "Trying alternative search methods..." -ForegroundColor Gray
            $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=startsWith(displayName,'$SerialNumber')"
            $entraDevices = Invoke-MgGraphRequest -Method GET -Uri $uri
        }
        
        if ($entraDevices.value.Count -gt 0) {
            Write-Host "Found $($entraDevices.value.Count) Entra ID device(s)" -ForegroundColor Yellow
            return $entraDevices.value
        }
        else {
            Write-Host "No Entra ID device found" -ForegroundColor Gray
            return $null
        }
    }
    catch {
        Write-Warning "Error searching Entra ID devices: $_"
        return $null
    }
}

# Function to remove Autopilot device
function Remove-AutopilotDevice {
    param($Device)
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$($Device.id)"
        Invoke-MgGraphRequest -Method DELETE -Uri $uri
        Write-Host "  [OK] Autopilot device removed: $($Device.serialNumber)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "  [FAILED] Could not remove Autopilot device: $_"
        return $false
    }
}

# Function to remove Intune managed device
function Remove-IntuneDevice {
    param($Device)
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($Device.id)"
        Invoke-MgGraphRequest -Method DELETE -Uri $uri
        Write-Host "  [OK] Intune managed device removed: $($Device.deviceName)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "  [FAILED] Could not remove Intune device: $_"
        return $false
    }
}

# Function to remove Entra ID device
function Remove-EntraIDDevice {
    param($Device)
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/devices/$($Device.id)"
        Invoke-MgGraphRequest -Method DELETE -Uri $uri
        Write-Host "  [OK] Entra ID device removed: $($Device.displayName)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "  [FAILED] Could not remove Entra ID device: $_"
        return $false
    }
}

# Main script execution
function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Device Cleanup Script for Test Tenants" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Check and install required modules
    if (-not (Install-RequiredModules)) {
        Write-Error "Required modules could not be installed. Exiting."
        return
    }
    
    # Connect to Microsoft Graph
    if (-not (Connect-MicrosoftGraphAPI)) {
        Write-Error "Could not connect to Microsoft Graph. Exiting."
        return
    }
    
    # Get serial number from user
    $serialNumber = Read-Host "`nEnter device serial number"
    
    if ([string]::IsNullOrWhiteSpace($serialNumber)) {
        Write-Error "Serial number cannot be empty. Exiting."
        Disconnect-MgGraph | Out-Null
        return
    }
    
    # Search for devices
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Searching for devices..." -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $autopilotDevices = Get-AutopilotDeviceBySerial -SerialNumber $serialNumber
    $intuneDevices = Get-IntuneDeviceBySerial -SerialNumber $serialNumber
    $entraDevices = Get-EntraIDDeviceBySerial -SerialNumber $serialNumber
    
    # Display found devices
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Search Results Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $totalDevices = 0
    
    if ($autopilotDevices) {
        $totalDevices += $autopilotDevices.Count
        Write-Host "Autopilot devices found: $($autopilotDevices.Count)" -ForegroundColor Yellow
        foreach ($device in $autopilotDevices) {
            Write-Host "  - ID: $($device.id)" -ForegroundColor Gray
            Write-Host "    Serial: $($device.serialNumber)" -ForegroundColor Gray
            Write-Host "    Model: $($device.model)" -ForegroundColor Gray
        }
    }
    
    if ($intuneDevices) {
        $totalDevices += $intuneDevices.Count
        Write-Host "Intune devices found: $($intuneDevices.Count)" -ForegroundColor Yellow
        foreach ($device in $intuneDevices) {
            Write-Host "  - ID: $($device.id)" -ForegroundColor Gray
            Write-Host "    Name: $($device.deviceName)" -ForegroundColor Gray
            Write-Host "    Serial: $($device.serialNumber)" -ForegroundColor Gray
        }
    }
    
    if ($entraDevices) {
        $totalDevices += $entraDevices.Count
        Write-Host "Entra ID devices found: $($entraDevices.Count)" -ForegroundColor Yellow
        foreach ($device in $entraDevices) {
            Write-Host "  - ID: $($device.id)" -ForegroundColor Gray
            Write-Host "    Name: $($device.displayName)" -ForegroundColor Gray
            Write-Host "    OS: $($device.operatingSystem)" -ForegroundColor Gray
        }
    }
    
    if ($totalDevices -eq 0) {
        Write-Host "`nNo devices found with serial number: $serialNumber" -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        return
    }
    
    # Confirm deletion
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "WARNING: About to delete $totalDevices device object(s)" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    
    $confirmation = Read-Host "Do you want to proceed with deletion? (YES to confirm)"
    
    if ($confirmation -ne "YES") {
        Write-Host "Operation cancelled by user" -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        return
    }
    
    # Perform deletion
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting deletion process..." -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $successCount = 0
    $failCount = 0
    
    # Remove Autopilot devices first
    if ($autopilotDevices) {
        Write-Host "`nRemoving Autopilot devices..." -ForegroundColor Cyan
        foreach ($device in $autopilotDevices) {
            if (Remove-AutopilotDevice -Device $device) {
                $successCount++
            }
            else {
                $failCount++
            }
            Start-Sleep -Seconds 1
        }
    }
    
    # Remove Intune managed devices
    if ($intuneDevices) {
        Write-Host "`nRemoving Intune managed devices..." -ForegroundColor Cyan
        foreach ($device in $intuneDevices) {
            if (Remove-IntuneDevice -Device $device) {
                $successCount++
            }
            else {
                $failCount++
            }
            Start-Sleep -Seconds 1
        }
    }
    
    # Remove Entra ID devices last
    if ($entraDevices) {
        Write-Host "`nRemoving Entra ID devices..." -ForegroundColor Cyan
        foreach ($device in $entraDevices) {
            if (Remove-EntraIDDevice -Device $device) {
                $successCount++
            }
            else {
                $failCount++
            }
            Start-Sleep -Seconds 1
        }
    }
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Deletion Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Successfully removed: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host "`nNote: It may take a few minutes for changes to fully propagate." -ForegroundColor Yellow
    Write-Host "The device can now be enrolled in a different tenant." -ForegroundColor Yellow
    
    # Disconnect
    Disconnect-MgGraph | Out-Null
    Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Gray
}

# Run main function
Main
