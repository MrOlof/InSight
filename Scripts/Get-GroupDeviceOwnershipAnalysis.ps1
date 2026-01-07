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

.PARAMETER IncludeNestedGroups
    If specified, includes members from nested groups (transitive membership).
    Default is $false (direct members only).

.EXAMPLE
    Get-GroupDeviceOwnershipAnalysis -GroupId "12345678-1234-1234-1234-123456789012"

.EXAMPLE
    Get-GroupDeviceOwnershipAnalysis -GroupId "12345678-1234-1234-1234-123456789012" -IncludeNestedGroups
    Analyzes device ownership including all nested group members.

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Version: 1.2.0
    Required Permissions:
        - DeviceManagementManagedDevices.Read.All
        - GroupMember.Read.All
        - User.Read.All
    Changelog:
        - v1.2.0: Added support for nested groups via -IncludeNestedGroups switch
        - v1.1.0: Major performance optimization using hash lookup instead of per-user API calls
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$GroupId,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNestedGroups
)

# Script metadata - used for registration with the GUI
$script:ScriptInfo = @{
    Name                = 'Device Ownership Analysis'
    Description         = 'Analyzes device ownership for members of an Entra ID group (supports nested groups)'
    Version             = '1.2.0'
    Author              = 'IntuneAdmin Tool'
    Category            = 'Reports'
    RequiredPermissions = @(
        'DeviceManagementManagedDevices.Read.All',
        'GroupMember.Read.All',
        'User.Read.All'
    )
    Icon                = [char]0xE9D9  # Segoe Fluent Icons icon for analytics
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
    .PARAMETER GroupId
        The GUID of the group to query.
    .PARAMETER IncludeNested
        If specified, uses transitiveMembers endpoint to include nested group members.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNested
    )

    $allMembers = [System.Collections.ArrayList]::new()

    # Use transitiveMembers for nested groups, otherwise use members for direct only
    $endpoint = if ($IncludeNested) { "transitiveMembers" } else { "members" }
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/$endpoint`?`$select=id,userPrincipalName,displayName,mail"

    try {
        $membershipType = if ($IncludeNested) { "transitive (nested)" } else { "direct" }
        Write-LogInfo -Message "Fetching $membershipType group members..." -Source 'DeviceOwnership'

        while ($uri) {
            $response = Invoke-GraphRequest -Uri $uri -Method GET

            if ($response.value) {
                # Filter to only user objects (exclude devices, service principals, groups, etc.)
                $users = $response.value | Where-Object {
                    $_.'@odata.type' -eq '#microsoft.graph.user' -or
                    $null -ne $_.userPrincipalName
                }
                foreach ($user in $users) {
                    # Deduplicate users (transitive members may return duplicates)
                    if (-not ($allMembers | Where-Object { $_.id -eq $user.id })) {
                        [void]$allMembers.Add($user)
                    }
                }
                Write-LogInfo -Message "Retrieved $($users.Count) users (batch), total unique: $($allMembers.Count)" -Source 'DeviceOwnership'
            }

            # Handle pagination
            $uri = $response.'@odata.nextLink'
        }

        Write-LogInfo -Message "Total unique $membershipType members: $($allMembers.Count)" -Source 'DeviceOwnership'
        return $allMembers
    }
    catch {
        Write-LogError -Message "Failed to get group members: $($_.Exception.Message)" -Source 'DeviceOwnership'
        throw
    }
}

function Get-AllManagedDevicesWithUserIndex {
    <#
    .SYNOPSIS
        Gets all Intune managed devices and indexes them by userId for fast lookup.
    .DESCRIPTION
        Fetches all devices in one API call (with pagination) and builds a hashtable
        indexed by userId. This is MUCH faster than calling per-user endpoints.
    .OUTPUTS
        Hashtable where keys are userIds and values are ArrayList of device objects
    #>
    [CmdletBinding()]
    param()

    try {
        Write-LogInfo -Message "Fetching ALL managed devices from tenant (optimized single call)..." -Source 'DeviceOwnership'

        $allDevices = [System.Collections.ArrayList]::new()
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,operatingSystem,model,manufacturer,serialNumber,lastSyncDateTime,userId"

        # Fetch all devices with pagination
        while ($uri) {
            $response = Invoke-GraphRequest -Uri $uri -Method GET

            if ($response.value) {
                foreach ($device in $response.value) {
                    [void]$allDevices.Add($device)
                }
                Write-LogInfo -Message "Retrieved $($response.value.Count) devices, total so far: $($allDevices.Count)" -Source 'DeviceOwnership'
            }

            # Handle pagination
            $uri = $response.'@odata.nextLink'
        }

        Write-LogInfo -Message "Total devices retrieved: $($allDevices.Count). Building userId index..." -Source 'DeviceOwnership'

        # Build hashtable indexed by userId for O(1) lookups
        $devicesByUser = @{}
        foreach ($device in $allDevices) {
            if ($device.userId) {
                if (-not $devicesByUser.ContainsKey($device.userId)) {
                    $devicesByUser[$device.userId] = [System.Collections.ArrayList]::new()
                }
                [void]$devicesByUser[$device.userId].Add($device)
            }
        }

        Write-LogInfo -Message "Index built. Mapped devices to $($devicesByUser.Count) unique users" -Source 'DeviceOwnership'
        return $devicesByUser
    }
    catch {
        Write-LogError -Message "Failed to get managed devices: $($_.Exception.Message)" -Source 'DeviceOwnership'
        throw
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

    # Get all group members (direct or transitive based on parameter)
    Write-LogInfo -Message "Fetching group members..." -Source 'DeviceOwnership'
    $groupMembers = Get-AllGroupMembers -GroupId $GroupId -IncludeNested:$IncludeNestedGroups

    if (-not $groupMembers -or $groupMembers.Count -eq 0) {
        Write-LogInfo -Message "No user members found in group" -Source 'DeviceOwnership'

        return [PSCustomObject]@{
            Success                  = $true
            Message                  = "No user members found in group"
            GroupId                  = $GroupId
            IncludeNestedGroups      = $IncludeNestedGroups.IsPresent
            UsersWithNoDevices       = @()
            UsersWithMultipleDevices = @()
            UsersWithSingleDevice    = @()
            Summary                  = [PSCustomObject]@{
                TotalUsers            = 0
                TotalDevices          = 0
                UsersWithNoDevices    = 0
                UsersWithMultipleDevices = 0
                UsersWithSingleDevice = 0
                ProcessedSuccessfully = 0
                ProcessingErrors      = 0
            }
            Timestamp                = Get-Date
        }
    }

    Write-LogInfo -Message "Found $($groupMembers.Count) user members in group, analyzing device ownership..." -Source 'DeviceOwnership'

    # OPTIMIZATION: Fetch ALL devices once and build userId index
    $devicesByUser = Get-AllManagedDevicesWithUserIndex

    # Process each user (NO API calls in this loop!)
    foreach ($user in $groupMembers) {
        $processedCount++

        try {
            Write-LogInfo -Message "Processing user $processedCount/$($groupMembers.Count): $($user.userPrincipalName)" -Source 'DeviceOwnership'

            # Get user's managed devices via O(1) hash lookup (no API call!)
            $userDevices = if ($devicesByUser.ContainsKey($user.id)) {
                $devicesByUser[$user.id]
            } else {
                @()
            }
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
        IncludeNestedGroups      = $IncludeNestedGroups.IsPresent
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
        IncludeNestedGroups      = $IncludeNestedGroups.IsPresent
        UsersWithNoDevices       = @()
        UsersWithMultipleDevices = @()
        UsersWithSingleDevice    = @()
        Summary                  = $null
        Timestamp                = Get-Date
    }
}
#endregion
