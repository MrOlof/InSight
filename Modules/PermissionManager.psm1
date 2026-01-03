<#
.SYNOPSIS
    Permission management module for InSight.

.DESCRIPTION
    Provides UI feature visibility control based on Graph API permissions.

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Version: 1.0.0
#>

#Requires -Version 5.1

# Feature definitions with required permissions
# Each feature maps to UI elements and their permission requirements
$script:FeatureDefinitions = @{
    # Device Management Features
    'Devices.View' = @{
        DisplayName         = 'View Devices'
        Description         = 'Browse and search managed devices'
        RequiredPermissions = @('DeviceManagementManagedDevices.Read.All')
        Category            = 'Devices'
        Icon                = 'Laptop'
        MenuPath            = 'Devices'
    }
    'Devices.Details' = @{
        DisplayName         = 'Device Details'
        Description         = 'View detailed device information'
        RequiredPermissions = @('DeviceManagementManagedDevices.Read.All')
        Category            = 'Devices'
        Icon                = 'Info'
        MenuPath            = 'Devices/Details'
    }
    'Devices.Sync' = @{
        DisplayName         = 'Sync Device'
        Description         = 'Trigger device synchronization'
        RequiredPermissions = @('DeviceManagementManagedDevices.ReadWrite.All')
        Category            = 'Devices'
        Icon                = 'Sync'
        MenuPath            = 'Devices/Actions'
    }
    'Devices.Retire' = @{
        DisplayName         = 'Retire Device'
        Description         = 'Retire a managed device'
        RequiredPermissions = @('DeviceManagementManagedDevices.ReadWrite.All')
        Category            = 'Devices'
        Icon                = 'Remove'
        MenuPath            = 'Devices/Actions'
    }
    'Devices.Wipe' = @{
        DisplayName         = 'Wipe Device'
        Description         = 'Factory reset a device'
        RequiredPermissions = @('DeviceManagementManagedDevices.PrivilegedOperations.All')
        Category            = 'Devices'
        Icon                = 'Delete'
        MenuPath            = 'Devices/Actions'
    }

    # Application Features
    'Apps.View' = @{
        DisplayName         = 'View Applications'
        Description         = 'Browse Intune applications'
        RequiredPermissions = @('DeviceManagementApps.Read.All')
        Category            = 'Applications'
        Icon                = 'Apps'
        MenuPath            = 'Applications'
    }
    'Apps.Assignments' = @{
        DisplayName         = 'View Assignments'
        Description         = 'View application assignments'
        RequiredPermissions = @('DeviceManagementApps.Read.All')
        Category            = 'Applications'
        Icon                = 'Assignment'
        MenuPath            = 'Applications/Assignments'
    }
    'Apps.DeploymentStatus' = @{
        DisplayName         = 'Deployment Status'
        Description         = 'View application deployment status'
        RequiredPermissions = @('DeviceManagementApps.Read.All')
        Category            = 'Applications'
        Icon                = 'Status'
        MenuPath            = 'Applications/Status'
    }

    # Configuration Features
    'Configuration.View' = @{
        DisplayName         = 'View Policies'
        Description         = 'Browse configuration policies'
        RequiredPermissions = @('DeviceManagementConfiguration.Read.All')
        Category            = 'Configuration'
        Icon                = 'Settings'
        MenuPath            = 'Configuration'
    }
    'Configuration.Details' = @{
        DisplayName         = 'Policy Details'
        Description         = 'View policy settings and assignments'
        RequiredPermissions = @('DeviceManagementConfiguration.Read.All')
        Category            = 'Configuration'
        Icon                = 'Detail'
        MenuPath            = 'Configuration/Details'
    }

    # Compliance Features
    'Compliance.View' = @{
        DisplayName         = 'View Compliance'
        Description         = 'View compliance policies and status'
        RequiredPermissions = @('DeviceManagementConfiguration.Read.All')
        Category            = 'Compliance'
        Icon                = 'CheckCircle'
        MenuPath            = 'Compliance'
    }

    # User Features
    'Users.View' = @{
        DisplayName         = 'View Users'
        Description         = 'Search and browse users'
        RequiredPermissions = @('User.Read.All')
        Category            = 'Users'
        Icon                = 'Person'
        MenuPath            = 'Users'
    }
    'Users.Devices' = @{
        DisplayName         = 'User Devices'
        Description         = 'View devices assigned to a user'
        RequiredPermissions = @('User.Read.All', 'DeviceManagementManagedDevices.Read.All')
        Category            = 'Users'
        Icon                = 'Devices'
        MenuPath            = 'Users/Devices'
    }

    # Group Features
    'Groups.View' = @{
        DisplayName         = 'View Groups'
        Description         = 'Browse groups and memberships'
        RequiredPermissions = @('Group.Read.All')
        Category            = 'Groups'
        Icon                = 'Group'
        MenuPath            = 'Groups'
    }

    # Reports
    'Reports.Export' = @{
        DisplayName         = 'Export Reports'
        Description         = 'Export data to CSV/JSON'
        RequiredPermissions = @()  # No special permission needed
        Category            = 'Reports'
        Icon                = 'Export'
        MenuPath            = 'Reports'
    }
}

# Category metadata for UI grouping
$script:CategoryDefinitions = @{
    'Devices' = @{
        DisplayName = 'Device Management'
        Description = 'Manage Intune enrolled devices'
        Icon        = 'Laptop'
        Order       = 1
        Color       = '#0078D4'  # Microsoft Blue
    }
    'Applications' = @{
        DisplayName = 'Applications'
        Description = 'Manage and monitor applications'
        Icon        = 'Apps'
        Order       = 2
        Color       = '#107C10'  # Green
    }
    'Configuration' = @{
        DisplayName = 'Configuration'
        Description = 'Device configuration policies'
        Icon        = 'Settings'
        Order       = 3
        Color       = '#5C2D91'  # Purple
    }
    'Compliance' = @{
        DisplayName = 'Compliance'
        Description = 'Compliance policies and status'
        Icon        = 'CheckCircle'
        Order       = 4
        Color       = '#008575'  # Teal
    }
    'Users' = @{
        DisplayName = 'Users'
        Description = 'User management and lookup'
        Icon        = 'Person'
        Order       = 5
        Color       = '#CA5010'  # Orange
    }
    'Groups' = @{
        DisplayName = 'Groups'
        Description = 'Group management'
        Icon        = 'Group'
        Order       = 6
        Color       = '#4A154B'  # Slack Purple
    }
    'Reports' = @{
        DisplayName = 'Reports'
        Description = 'Reporting and exports'
        Icon        = 'Export'
        Order       = 7
        Color       = '#6B6B6B'  # Gray
    }
}

function Get-FeatureDefinitions {
    <#
    .SYNOPSIS
        Returns all feature definitions.

    .DESCRIPTION
        Gets the complete list of features with their permission requirements.
        Optionally filters by category.

    .PARAMETER Category
        Filter features by category name.

    .OUTPUTS
        Hashtable of feature definitions.

    .EXAMPLE
        Get-FeatureDefinitions -Category 'Devices'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$Category
    )

    if ($Category) {
        $filtered = @{}
        foreach ($key in $script:FeatureDefinitions.Keys) {
            if ($script:FeatureDefinitions[$key].Category -eq $Category) {
                $filtered[$key] = $script:FeatureDefinitions[$key]
            }
        }
        return $filtered
    }

    return $script:FeatureDefinitions.Clone()
}

function Get-CategoryDefinitions {
    <#
    .SYNOPSIS
        Returns all category definitions.

    .DESCRIPTION
        Gets category metadata for UI organization.

    .OUTPUTS
        Hashtable of category definitions.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return $script:CategoryDefinitions.Clone()
}

function Test-FeatureAccess {
    <#
    .SYNOPSIS
        Tests if a specific feature is accessible.

    .DESCRIPTION
        Checks if the current authentication session has the required
        permissions for a specific feature.

    .PARAMETER FeatureId
        The feature identifier (e.g., 'Devices.View').

    .OUTPUTS
        PSCustomObject with access status and details.

    .EXAMPLE
        $access = Test-FeatureAccess -FeatureId 'Devices.Wipe'
        if ($access.HasAccess) { # Enable the wipe button }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FeatureId
    )

    $feature = $script:FeatureDefinitions[$FeatureId]

    if (-not $feature) {
        return [PSCustomObject]@{
            FeatureId         = $FeatureId
            HasAccess         = $false
            Reason            = 'Feature not found'
            MissingPermissions = @()
            Feature           = $null
        }
    }

    $requiredPerms = $feature.RequiredPermissions

    # No permissions required means always accessible
    if ($requiredPerms.Count -eq 0) {
        return [PSCustomObject]@{
            FeatureId          = $FeatureId
            HasAccess          = $true
            Reason             = 'No permissions required'
            MissingPermissions = @()
            Feature            = $feature
        }
    }

    # Check each required permission
    $missingPerms = @()
    foreach ($perm in $requiredPerms) {
        if (-not (Test-IntunePermission -Permission $perm)) {
            $missingPerms += $perm
        }
    }

    $hasAccess = $missingPerms.Count -eq 0

    return [PSCustomObject]@{
        FeatureId          = $FeatureId
        HasAccess          = $hasAccess
        Reason             = if ($hasAccess) { 'All permissions granted' } else { 'Missing required permissions' }
        MissingPermissions = $missingPerms
        Feature            = $feature
    }
}

function Get-AccessibleFeatures {
    <#
    .SYNOPSIS
        Returns all features accessible in the current session.

    .DESCRIPTION
        Enumerates all features and returns those that are accessible
        based on current permissions.

    .PARAMETER IncludeInaccessible
        Include inaccessible features in the output with HasAccess = $false.

    .OUTPUTS
        Array of feature access objects.

    .EXAMPLE
        $features = Get-AccessibleFeatures
        $features | Where-Object { $_.Category -eq 'Devices' }
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter()]
        [switch]$IncludeInaccessible
    )

    $results = @()

    foreach ($featureId in $script:FeatureDefinitions.Keys) {
        $access = Test-FeatureAccess -FeatureId $featureId

        if ($access.HasAccess -or $IncludeInaccessible) {
            $results += [PSCustomObject]@{
                FeatureId          = $featureId
                DisplayName        = $access.Feature.DisplayName
                Description        = $access.Feature.Description
                Category           = $access.Feature.Category
                Icon               = $access.Feature.Icon
                MenuPath           = $access.Feature.MenuPath
                HasAccess          = $access.HasAccess
                MissingPermissions = $access.MissingPermissions
            }
        }
    }

    return $results | Sort-Object {
        $cat = $script:CategoryDefinitions[$_.Category]
        if ($cat) { $cat.Order } else { 99 }
    }, DisplayName
}

function Get-CategoryAccessSummary {
    <#
    .SYNOPSIS
        Returns access summary grouped by category.

    .DESCRIPTION
        Provides a summary of feature accessibility for each category,
        useful for displaying category-level access indicators in the UI.

    .OUTPUTS
        Array of category access summaries.

    .EXAMPLE
        $summary = Get-CategoryAccessSummary
        $summary | Format-Table Category, AccessibleCount, TotalCount, AccessLevel
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $allFeatures = Get-AccessibleFeatures -IncludeInaccessible
    $categories = $allFeatures | Group-Object -Property Category

    $results = foreach ($cat in $categories) {
        $categoryDef = $script:CategoryDefinitions[$cat.Name]
        $accessible = ($cat.Group | Where-Object { $_.HasAccess }).Count
        $total = $cat.Group.Count

        $accessLevel = switch ($accessible) {
            0 { 'None' }
            { $_ -eq $total } { 'Full' }
            default { 'Partial' }
        }

        [PSCustomObject]@{
            Category        = $cat.Name
            DisplayName     = if ($categoryDef) { $categoryDef.DisplayName } else { $cat.Name }
            Description     = if ($categoryDef) { $categoryDef.Description } else { '' }
            Icon            = if ($categoryDef) { $categoryDef.Icon } else { 'Folder' }
            Color           = if ($categoryDef) { $categoryDef.Color } else { '#666666' }
            Order           = if ($categoryDef) { $categoryDef.Order } else { 99 }
            AccessibleCount = $accessible
            TotalCount      = $total
            AccessLevel     = $accessLevel
            Features        = $cat.Group
        }
    }

    return $results | Sort-Object Order
}

function Get-FeaturesByMenuPath {
    <#
    .SYNOPSIS
        Returns features organized by menu path.

    .DESCRIPTION
        Groups features by their menu path for building navigation menus.
        Returns a hierarchical structure suitable for TreeView or menu building.

    .OUTPUTS
        Hashtable with menu structure.

    .EXAMPLE
        $menu = Get-FeaturesByMenuPath
        $menu['Devices']  # Get all device-related features
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $allFeatures = Get-AccessibleFeatures -IncludeInaccessible
    $menuStructure = @{}

    foreach ($feature in $allFeatures) {
        $pathParts = $feature.MenuPath -split '/'
        $currentLevel = $menuStructure

        for ($i = 0; $i -lt $pathParts.Count; $i++) {
            $part = $pathParts[$i]

            if (-not $currentLevel.ContainsKey($part)) {
                $currentLevel[$part] = @{
                    Features    = @()
                    SubMenus    = @{}
                    HasAccess   = $false
                }
            }

            # Last part of path - add feature here
            if ($i -eq $pathParts.Count - 1) {
                $currentLevel[$part].Features += $feature
                if ($feature.HasAccess) {
                    $currentLevel[$part].HasAccess = $true
                }
            }
            else {
                $currentLevel = $currentLevel[$part].SubMenus
            }
        }
    }

    return $menuStructure
}

function Register-CustomFeature {
    <#
    .SYNOPSIS
        Registers a custom feature definition.

    .DESCRIPTION
        Allows scripts/modules to register additional features for
        permission-based UI control.

    .PARAMETER FeatureId
        Unique identifier for the feature.

    .PARAMETER DisplayName
        Human-readable feature name.

    .PARAMETER Description
        Feature description.

    .PARAMETER RequiredPermissions
        Array of required Graph API permissions.

    .PARAMETER Category
        Feature category for grouping.

    .PARAMETER Icon
        Icon identifier for UI display.

    .PARAMETER MenuPath
        Navigation menu path.

    .EXAMPLE
        Register-CustomFeature -FeatureId 'Custom.MyFeature' -DisplayName 'My Feature' `
            -RequiredPermissions @('User.Read.All') -Category 'Custom'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FeatureId,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter()]
        [string]$Description = '',

        [Parameter()]
        [string[]]$RequiredPermissions = @(),

        [Parameter()]
        [string]$Category = 'Custom',

        [Parameter()]
        [string]$Icon = 'Extension',

        [Parameter()]
        [string]$MenuPath = 'Custom'
    )

    $script:FeatureDefinitions[$FeatureId] = @{
        DisplayName         = $DisplayName
        Description         = $Description
        RequiredPermissions = $RequiredPermissions
        Category            = $Category
        Icon                = $Icon
        MenuPath            = $MenuPath
    }

    Write-Verbose "Registered custom feature: $FeatureId"
}

# Export module members
Export-ModuleMember -Function @(
    'Get-FeatureDefinitions',
    'Get-CategoryDefinitions',
    'Test-FeatureAccess',
    'Get-AccessibleFeatures',
    'Get-CategoryAccessSummary',
    'Get-FeaturesByMenuPath',
    'Register-CustomFeature'
)
