<#
.SYNOPSIS
    Analyzes device ownership for members of a specified Entra ID group.

.DESCRIPTION
    Analyzes Intune device ownership for users in a specified Entra ID group.
    Categorizes users into:
    - Users with NO devices
    - Users with MULTIPLE devices
    - Users with exactly 1 device

.PARAMETER GroupId
    The GUID of the Entra ID user group to analyze.

.EXAMPLE
    Get-GroupDeviceOwnershipAnalysis -GroupId "12345678-1234-1234-1234-123456789012"

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Version: 1.0.0
    Required Permissions:
        - DeviceManagementManagedDevices.Read.All
        - GroupMember.Read.All
        - User.Read.All
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$GroupId
)

# Script metadata - used for registration with the GUI
$script:ScriptInfo = @{
    Name                = 'Device Ownership Analysis'
    Description         = 'Analyzes device ownership for members of an Entra ID group (read-only)'
    Version             = '1.0.0'
    Author              = 'IntuneAdmin Tool'
    Category            = 'Reports'
    RequiredPermissions = @(
        'DeviceManagementManagedDevices.Read.All',
        'GroupMember.Read.All',
        'User.Read.All'
    )
    Icon                = [char]0xE9D9  # Segoe MDL2 Assets icon for analytics
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

#region Helper Functions
function Get-AllGroupMembers {
    <#
    .SYNOPSIS
        Gets all members of a group with pagination support.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $allMembers = [System.Collections.ArrayList]::new()
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,userPrincipalName,displayName,mail"

    try {
        while ($uri) {
            Write-LogInfo -Message "Fetching group members from: $uri" -Source 'DeviceOwnership'
            $response = Invoke-GraphRequest -Uri $uri -Method GET

            if ($response.value) {
                # Filter to only user objects (exclude devices, service principals, etc.)
                $users = $response.value | Where-Object {
                    $_.'@odata.type' -eq '#microsoft.graph.user' -or
                    $null -ne $_.userPrincipalName
                }
                foreach ($user in $users) {
                    [void]$allMembers.Add($user)
                }
                Write-LogInfo -Message "Retrieved $($users.Count) users, total so far: $($allMembers.Count)" -Source 'DeviceOwnership'
            }

            # Handle pagination
            $uri = $response.'@odata.nextLink'
        }

        return $allMembers
    }
    catch {
        Write-LogError -Message "Failed to get group members: $($_.Exception.Message)" -Source 'DeviceOwnership'
        throw
    }
}

function Get-UserManagedDevices {
    <#
    .SYNOPSIS
        Gets all Intune managed devices for a specific user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    $allDevices = [System.Collections.ArrayList]::new()
    $uri = "https://graph.microsoft.com/v1.0/users/$UserId/managedDevices?`$select=id,deviceName,operatingSystem,model,manufacturer,serialNumber,lastSyncDateTime"

    try {
        while ($uri) {
            $response = Invoke-GraphRequest -Uri $uri -Method GET

            if ($response.value) {
                foreach ($device in $response.value) {
                    [void]$allDevices.Add($device)
                }
            }

            # Handle pagination
            $uri = $response.'@odata.nextLink'
        }

        return $allDevices
    }
    catch {
        # User might not have any devices or might be unlicensed for Intune
        if ($_.Exception.Message -match 'does not have intune license|not found|404') {
            Write-LogInfo -Message "User $UserId has no Intune license or no devices" -Source 'DeviceOwnership'
            return @()
        }
        Write-LogError -Message "Failed to get devices for user $UserId`: $($_.Exception.Message)" -Source 'DeviceOwnership'
        return @()
    }
}
#endregion

#region Main Logic
try {
    Write-LogInfo -Message "Starting Device Ownership Analysis for group: $GroupId" -Source 'DeviceOwnership'

    # Initialize result collections
    $usersNoDevices = [System.Collections.ArrayList]::new()
    $usersMultipleDevices = [System.Collections.ArrayList]::new()
    $usersSingleDevice = [System.Collections.ArrayList]::new()
    $totalDeviceCount = 0
    $processedCount = 0
    $errorCount = 0

    # Get all group members
    Write-LogInfo -Message "Fetching group members..." -Source 'DeviceOwnership'
    $groupMembers = Get-AllGroupMembers -GroupId $GroupId

    if (-not $groupMembers -or $groupMembers.Count -eq 0) {
        Write-LogInfo -Message "No user members found in group" -Source 'DeviceOwnership'

        return [PSCustomObject]@{
            Success               = $true
            Message               = "No user members found in group"
            UsersWithNoDevices    = @()
            UsersWithMultipleDevices = @()
            UsersWithSingleDevice = @()
            Summary               = [PSCustomObject]@{
                TotalUsers            = 0
                TotalDevices          = 0
                UsersWithNoDevices    = 0
                UsersWithMultipleDevices = 0
                UsersWithSingleDevice = 0
                ProcessedSuccessfully = 0
                ProcessingErrors      = 0
            }
            Timestamp             = Get-Date
        }
    }

    Write-LogInfo -Message "Found $($groupMembers.Count) user members in group, analyzing device ownership..." -Source 'DeviceOwnership'

    # Process each user
    foreach ($user in $groupMembers) {
        $processedCount++

        try {
            Write-LogInfo -Message "Processing user $processedCount/$($groupMembers.Count): $($user.userPrincipalName)" -Source 'DeviceOwnership'

            # Get user's managed devices
            $userDevices = Get-UserManagedDevices -UserId $user.id
            $deviceCount = @($userDevices).Count
            $totalDeviceCount += $deviceCount

            # Create user info object
            $userInfo = [PSCustomObject]@{
                UserPrincipalName = $user.userPrincipalName
                DisplayName       = $user.displayName
                UserId            = $user.id
                Email             = $user.mail
            }

            # Categorize user based on device count
            if ($deviceCount -eq 0) {
                [void]$usersNoDevices.Add($userInfo)
            }
            elseif ($deviceCount -eq 1) {
                $singleDeviceUser = $userInfo | Add-Member -NotePropertyName 'DeviceCount' -NotePropertyValue 1 -PassThru
                $singleDeviceUser | Add-Member -NotePropertyName 'DeviceName' -NotePropertyValue $userDevices[0].deviceName
                $singleDeviceUser | Add-Member -NotePropertyName 'DeviceOS' -NotePropertyValue $userDevices[0].operatingSystem
                [void]$usersSingleDevice.Add($singleDeviceUser)
            }
            else {
                # Multiple devices
                $deviceNames = ($userDevices | ForEach-Object { $_.deviceName }) -join '; '
                $deviceDetails = $userDevices | ForEach-Object {
                    [PSCustomObject]@{
                        DeviceName      = $_.deviceName
                        OperatingSystem = $_.operatingSystem
                        Model           = $_.model
                        Manufacturer    = $_.manufacturer
                        SerialNumber    = $_.serialNumber
                        LastSync        = $_.lastSyncDateTime
                    }
                }

                $multiDeviceUser = $userInfo | Add-Member -NotePropertyName 'DeviceCount' -NotePropertyValue $deviceCount -PassThru
                $multiDeviceUser | Add-Member -NotePropertyName 'DeviceNames' -NotePropertyValue $deviceNames
                $multiDeviceUser | Add-Member -NotePropertyName 'Devices' -NotePropertyValue $deviceDetails
                [void]$usersMultipleDevices.Add($multiDeviceUser)
            }
        }
        catch {
            $errorCount++
            Write-LogError -Message "Error processing user $($user.userPrincipalName): $($_.Exception.Message)" -Source 'DeviceOwnership'
        }

        # Progress logging every 10 users
        if ($processedCount % 10 -eq 0) {
            Write-LogInfo -Message "Progress: $processedCount/$($groupMembers.Count) users processed" -Source 'DeviceOwnership'
        }
    }

    # Build summary
    $summary = [PSCustomObject]@{
        TotalUsers               = $groupMembers.Count
        TotalDevices             = $totalDeviceCount
        UsersWithNoDevices       = $usersNoDevices.Count
        UsersWithMultipleDevices = $usersMultipleDevices.Count
        UsersWithSingleDevice    = $usersSingleDevice.Count
        ProcessedSuccessfully    = $processedCount - $errorCount
        ProcessingErrors         = $errorCount
    }

    Write-LogInfo -Message "Analysis complete. Total users: $($summary.TotalUsers), No devices: $($summary.UsersWithNoDevices), Multiple devices: $($summary.UsersWithMultipleDevices), Single device: $($summary.UsersWithSingleDevice)" -Source 'DeviceOwnership'

    # Return result object
    $result = [PSCustomObject]@{
        Success                  = $true
        Message                  = "Device ownership analysis completed successfully"
        GroupId                  = $GroupId
        UsersWithNoDevices       = @($usersNoDevices)
        UsersWithMultipleDevices = @($usersMultipleDevices)
        UsersWithSingleDevice    = @($usersSingleDevice)
        Summary                  = $summary
        Timestamp                = Get-Date
    }

    return $result
}
catch {
    Write-LogError -Message "Device ownership analysis failed: $($_.Exception.Message)" -Source 'DeviceOwnership' -Exception $_.Exception

    return [PSCustomObject]@{
        Success                  = $false
        Message                  = $_.Exception.Message
        GroupId                  = $GroupId
        UsersWithNoDevices       = @()
        UsersWithMultipleDevices = @()
        UsersWithSingleDevice    = @()
        Summary                  = $null
        Timestamp                = Get-Date
    }
}
#endregion
