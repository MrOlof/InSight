<#
.SYNOPSIS
    Template for creating new InSight scripts.

.DESCRIPTION
    This template provides the structure for adding new functionality
    to the InSight.

.PARAMETER DeviceId
    Example parameter.

.EXAMPLE
    .\YourScriptName.ps1 -DeviceId "12345"

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Version: 1.0.0
    Required Permissions: DeviceManagementManagedDevices.Read.All
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeviceId
)

# Script metadata - used for registration with the GUI
$script:ScriptInfo = @{
    Name                = 'Script Template'
    Description         = 'A template for creating new scripts'
    Version             = '1.0.0'
    Author              = 'Your Name'
    Category            = 'Devices'  # Devices, Applications, Configuration, Compliance, Users, Groups, Reports
    RequiredPermissions = @('DeviceManagementManagedDevices.Read.All')
    Icon                = [char]0xE756  # Segoe Fluent Icons icon
}

#region Prerequisite Check
# Verify authentication module is loaded
if (-not (Get-Command -Name 'Get-AuthenticationState' -ErrorAction SilentlyContinue)) {
    throw "Authentication module not loaded. This script must be run from the InSight."
}

# Verify authentication
$authState = Get-AuthenticationState
if (-not $authState.IsAuthenticated) {
    throw "Not authenticated. Please sign in through the InSight."
}

# Check required permissions
foreach ($permission in $script:ScriptInfo.RequiredPermissions) {
    if (-not (Test-IntunePermission -Permission $permission)) {
        throw "Missing required permission: $permission"
    }
}
#endregion

#region Main Logic
try {
    Write-LogInfo -Message "Starting script: $($script:ScriptInfo.Name)" -Source $script:ScriptInfo.Name

    # Example: Fetch device information
    # $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$DeviceId"
    # $device = Invoke-GraphRequest -Uri $uri -Method GET

    # Your script logic here...

    # Example output object
    $result = [PSCustomObject]@{
        Success   = $true
        Message   = "Script executed successfully"
        Data      = $null
        Timestamp = Get-Date
    }

    Write-LogInfo -Message "Script completed successfully" -Source $script:ScriptInfo.Name

    return $result
}
catch {
    Write-LogError -Message "Script failed: $_" -Source $script:ScriptInfo.Name -Exception $_.Exception

    return [PSCustomObject]@{
        Success   = $false
        Message   = $_.Exception.Message
        Data      = $null
        Timestamp = Get-Date
    }
}
#endregion
