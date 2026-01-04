<#
.SYNOPSIS
    Launches the InSight WPF application.

.DESCRIPTION
    Main entry point for the InSight.

.PARAMETER LogLevel
    Logging level: Debug, Information, Warning, or Error.

.PARAMETER ConfigPath
    Path to custom configuration file.

.EXAMPLE
    .\Start-InSight.ps1

.EXAMPLE
    .\Start-InSight.ps1 -LogLevel Debug

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Requires: PowerShell 5.1+, Microsoft.Graph module
    Version: 1.0.0
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
    [string]$LogLevel = 'Information',

    [Parameter()]
    [string]$ConfigPath
)

# Hide PowerShell console window
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0) | Out-Null

# Set up PowerShell runspace for MSAL (required for MSAL.NET to work properly)
if (-not [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace) {
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $runspace.ApartmentState = 'STA'
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace = $runspace
}

$ErrorActionPreference = 'Stop'

#region Script Initialization
$ScriptRoot = $PSScriptRoot
$ModulesPath = Join-Path -Path $ScriptRoot -ChildPath 'Modules'
$ResourcesPath = Join-Path -Path $ScriptRoot -ChildPath 'Resources'

# Add required assemblies for WPF
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# Import modules
$modules = @(
    'LoggingManager',
    'ConfigurationManager',
    'AuthenticationManager',
    'PermissionManager',
    'ScriptManager',
    'AssignmentHelpers'
)

foreach ($module in $modules) {
    $modulePath = Join-Path -Path $ModulesPath -ChildPath "$module.psm1"
    if (Test-Path -Path $modulePath) {
        Import-Module $modulePath -Force -DisableNameChecking
        Write-Verbose "Imported module: $module"
    }
    else {
        throw "Required module not found: $modulePath"
    }
}

# Initialize logging and configuration
Initialize-Logging -LogLevel $LogLevel
Initialize-Configuration -ConfigPath $ConfigPath

Write-LogInfo -Message "InSight starting..." -Source 'Launcher'
#endregion

#region XAML Loading
$xamlPath = Join-Path -Path $ResourcesPath -ChildPath 'MainWindow.xaml'
if (-not (Test-Path -Path $xamlPath)) {
    throw "XAML file not found: $xamlPath"
}

$xamlContent = Get-Content -Path $xamlPath -Raw

# Create XML reader and load XAML
$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xamlContent))
$Window = [System.Windows.Markup.XamlReader]::Load($reader)
$reader.Close()

Write-LogInfo -Message "XAML loaded successfully" -Source 'Launcher'
#endregion

#region Control References
# Get references to named controls
$controls = @{}
$controlNames = @(
    # Header authentication controls
    'HeaderSignInButton', 'SigningInPanel', 'UserProfileSection', 'UserProfileButton', 'UserDropdownPopup',
    'HeaderUserInitials', 'HeaderUserName', 'HeaderUserEmail',
    # User dropdown menu
    'MenuRefreshToken', 'MenuSettings', 'MenuSignOut',
    # Search and Navigation
    'SearchBox', 'NavigationPanel',
    # Navigation buttons
    'NavDashboard', 'NavApps', 'NavConfiguration', 'NavAssignments', 'NavDeviceOwnership',
    'NavRemediation', 'NavBackup', 'NavReports',
    # Navigation lock icons
    'NavAppsLock', 'NavConfigurationLock', 'NavAssignmentsLock', 'NavDeviceOwnershipLock',
    'NavRemediationLock', 'NavBackupLock', 'NavReportsLock',
    # Views
    'WelcomeView', 'WelcomeSignInButton',
    'DashboardView', 'ApplicationsView', 'ConfigurationsView', 'AssignmentsView', 'DeviceOwnershipView', 'PlaceholderView', 'SettingsView', 'RemediationScriptsView', 'BackupView',
    'PlaceholderIcon', 'PlaceholderTitle', 'PlaceholderDescription', 'PlaceholderPermission',
    # Remediation Scripts view controls
    'RemediationSearchBox', 'RemediationCategoryFilter', 'RemediationResultsSummary', 'RemediationResultsCount',
    'RemediationScriptsContainer', 'RemediationNoResults',
    'CategoryAll', 'CategorySecurity', 'CategoryMaintenance', 'CategoryApplicationManagement',
    'CategorySystemConfiguration', 'CategoryNetwork', 'CategoryUserExperience', 'CategoryTroubleshooting',
    # Backup view controls
    'BackupPathTextBox', 'BrowseBackupPathButton', 'IncludeAssignmentsCheckBox', 'ExcludeBuiltInCheckBox',
    'BackupSelectAllCheckBox', 'BackupComplianceCheckBox', 'BackupConfigurationsCheckBox', 'BackupSettingsCatalogCheckBox',
    'BackupScriptsCheckBox', 'BackupRemediationsCheckBox', 'BackupApplicationsCheckBox', 'BackupAutopilotCheckBox',
    'BackupEndpointSecurityCheckBox', 'BackupAdminTemplatesCheckBox',
    'ApiVersionV1RadioButton', 'ApiVersionBetaRadioButton', 'StartBackupButton', 'BackupLoadingText',
    'BackupProgressCard', 'BackupProgressBar', 'BackupStatusText', 'BackupCurrentItemText',
    'BackupResultsCard', 'BackupResultIcon', 'BackupResultTitle', 'BackupResultMessage',
    'BackupStatsGrid', 'BackupItemsCount', 'BackupFilesCount', 'BackupDuration',
    'OpenBackupFolderButton', 'NewBackupButton',
    # Applications view controls
    'AppsDataGrid', 'AppsEmptyState', 'LoadAppsButton', 'CheckVersionsButton', 'ExportAppsButton',
    'AppsProgressCard', 'AppsProgressBar', 'AppsProgressText',
    # Configurations view controls
    'FetchAllConfigurationsButton', 'AdvancedSearchButton',
    'ConfigProfilesLoadingText', 'ExportConfigProfilesButton', 'FetchConfigProfilesButton', 'BenchmarkConfigProfilesButton', 'SettingsCatalogButton', 'SettingsCatalogCount',
    'DeviceRestrictionsButton', 'DeviceRestrictionsCount', 'AdminTemplatesButton', 'AdminTemplatesCount',
    'EndpointSecLoadingText', 'ExportEndpointSecButton', 'FetchEndpointSecButton', 'BenchmarkEndpointSecButton', 'FirewallButton', 'FirewallCount', 'EDRButton', 'EDRCount',
    'ASRButton', 'ASRCount', 'AccountProtectionButton', 'AccountProtectionCount',
    'ConditionalAccessButton', 'ConditionalAccessCount',
    'AppProtectionLoadingText', 'ExportAppProtectionButton', 'FetchAppProtectionButton', 'BenchmarkAppProtectionButton', 'AndroidAppProtectionButton', 'AndroidAppProtectionCount',
    'iOSAppProtectionButton', 'iOSAppProtectionCount',
    # Assignments view controls
    'SearchDeviceGroupsButton', 'DeviceGroupSearchBox', 'FetchDeviceGroupAssignmentsButton', 'DeviceGroupResultsPanel',
    'DeviceGroupRadio', 'SingleDeviceRadio', 'DeviceSearchInstructions',
    'SearchUserGroupsButton', 'UserGroupSearchBox', 'FetchUserGroupAssignmentsButton', 'UserGroupResultsPanel',
    'UserGroupRadio', 'SingleUserRadio', 'UserSearchInstructions',
    'FindOrphanedButton', 'OrphanedLoadingText', 'NoAssignmentsCount', 'EmptyGroupsCount', 'TotalOrphanedCount', 'ExportOrphanedButton',
    'ViewNoAssignmentsButton', 'ViewEmptyGroupsButton', 'ViewAllOrphanedButton',
    # Device Ownership view controls
    'SearchOwnershipGroupButton', 'OwnershipGroupSearchBox', 'AnalyzeOwnershipButton',
    'OwnershipLoadingText', 'OwnershipSummaryCards', 'OwnershipResultsPanel',
    'NoDevicesCount', 'MultipleDevicesCount', 'SingleDeviceCount',
    'ViewNoDevicesButton', 'ViewMultipleDevicesButton', 'ViewSingleDeviceButton', 'ExportOwnershipButton',
    # Dashboard elements
    'DeviceCountText', 'CompliantCountText', 'AppCountText', 'PolicyCountText',
    'PermissionsGrid', 'RefreshPermissionsButton',
    # Quick actions
    'QuickActionDeviceSearch', 'QuickActionUserLookup', 'QuickActionExport', 'QuickActionRefresh',
    # Settings
    'DarkModeToggle', 'AnimationsToggle', 'CachingToggle', 'ExportPathTextBox', 'BrowseExportPath', 'ViewLogsButton',
    # Status bar
    'ConnectionIndicator', 'ConnectionStatusText', 'StatusMessageText', 'LastRefreshText', 'CurrentTimeText'
)

foreach ($name in $controlNames) {
    $control = $Window.FindName($name)
    if ($control) {
        $controls[$name] = $control
    }
}

# Lock icon control mappings
$script:LockIcons = @{
    'Applications'  = $controls['NavAppsLock']
    'Configuration' = $controls['NavConfigurationLock']
    'Assignments'   = $controls['NavAssignmentsLock']
    'Remediation'   = $controls['NavRemediationLock']
    'Backup'        = $controls['NavBackupLock']
    'Reports'       = $controls['NavReportsLock']
}
#endregion

#region Theme Functions
function Update-Theme {
    param([bool]$IsDark)

    $colors = Get-ThemeColors
    $resources = $Window.Resources

    # Update brushes dynamically
    $brushMappings = @{
        'BackgroundBrush'          = 'Background'
        'BackgroundSecondaryBrush' = 'BackgroundSecondary'
        'HeaderBrush'              = 'BackgroundSecondary'
        'SurfaceBrush'             = 'Surface'
        'SurfaceHoverBrush'        = 'SurfaceHover'
        'AccentBrush'              = 'Accent'
        'AccentHoverBrush'         = 'AccentHover'
        'AccentDarkBrush'          = 'AccentDark'
        'TextPrimaryBrush'         = 'TextPrimary'
        'TextSecondaryBrush'       = 'TextSecondary'
        'TextTertiaryBrush'        = 'TextTertiary'
        'TextDisabledBrush'        = 'TextDisabled'
        'TextOnAccentBrush'        = 'TextOnAccent'
        'BorderBrush'              = 'Border'
        'BorderLightBrush'         = 'BorderLight'
        'DividerBrush'             = 'Divider'
        'NavBackgroundBrush'       = 'NavBackground'
        'NavItemHoverBrush'        = 'NavItemHover'
        'NavItemSelectedBrush'     = 'NavItemSelected'
        'SuccessBrush'             = 'Success'
        'WarningBrush'             = 'Warning'
        'ErrorBrush'               = 'Error'
        'InfoBrush'                = 'Info'
    }

    foreach ($brushName in $brushMappings.Keys) {
        $colorKey = $brushMappings[$brushName]
        if ($colors.ContainsKey($colorKey)) {
            $colorValue = $colors[$colorKey]
            try {
                $brush = $resources[$brushName]
                if ($brush -and $brush -is [System.Windows.Media.SolidColorBrush]) {
                    $brush.Color = [System.Windows.Media.ColorConverter]::ConvertFromString($colorValue)
                }
            }
            catch {
                Write-LogWarning -Message "Failed to update brush: $brushName" -Source 'Theme'
            }
        }
    }

    Write-LogDebug -Message "Theme updated to: $(if ($IsDark) { 'Dark' } else { 'Light' })" -Source 'Theme'
}
#endregion

#region Navigation Functions
$script:CurrentView = 'Welcome'
$script:NavButtons = @{
    'Dashboard'        = @{ Button = $controls['NavDashboard']; Icon = [char]0xE80F; Feature = $null; Lock = $null }
    'Applications'     = @{ Button = $controls['NavApps']; Icon = [char]0xE71D; Feature = 'Apps.View'; Lock = $controls['NavAppsLock'] }
    'Configuration'    = @{ Button = $controls['NavConfiguration']; Icon = [char]0xE713; Feature = 'Configuration.View'; Lock = $controls['NavConfigurationLock'] }
    'Assignments'      = @{ Button = $controls['NavAssignments']; Icon = [char]0xE8F4; Feature = 'Assignments.View'; Lock = $controls['NavAssignmentsLock'] }
    'Device Ownership' = @{ Button = $controls['NavDeviceOwnership']; Icon = [char]0xE770; Feature = $null; Lock = $controls['NavDeviceOwnershipLock'] }
    'Remediation'      = @{ Button = $controls['NavRemediation']; Icon = [char]0xE90F; Feature = $null; Lock = $controls['NavRemediationLock'] }
    'Backup'           = @{ Button = $controls['NavBackup']; Icon = [char]0xE8C8; Feature = $null; Lock = $controls['NavBackupLock'] }
    'Reports'          = @{ Button = $controls['NavReports']; Icon = [char]0xE9F9; Feature = 'Reports.Export'; Lock = $controls['NavReportsLock'] }
}

function Update-NavigationState {
    param([bool]$IsAuthenticated = $false)

    # Update navigation button enabled states based on authentication and permissions
    foreach ($viewName in $script:NavButtons.Keys) {
        $navInfo = $script:NavButtons[$viewName]
        $button = $navInfo.Button
        $featureId = $navInfo.Feature
        $lockIcon = $navInfo.Lock

        if ($button) {
            if ($viewName -eq 'Dashboard') {
                # Dashboard is always enabled
                $button.IsEnabled = $true
            }
            elseif (-not $IsAuthenticated) {
                # Not authenticated: all other buttons disabled
                $button.IsEnabled = $false
                if ($lockIcon) {
                    $lockIcon.Visibility = 'Visible'
                }
            }
            else {
                # Authenticated: check permissions
                if ([string]::IsNullOrEmpty($featureId)) {
                    $button.IsEnabled = $true
                    if ($lockIcon) {
                        $lockIcon.Visibility = 'Collapsed'
                    }
                }
                else {
                    $access = Test-FeatureAccess -FeatureId $featureId
                    $button.IsEnabled = $access.HasAccess
                    if ($lockIcon) {
                        $lockIcon.Visibility = if ($access.HasAccess) { 'Collapsed' } else { 'Visible' }
                    }
                }
            }
        }
    }

    # Enable search box when authenticated
    if ($controls['SearchBox']) {
        $controls['SearchBox'].IsEnabled = $IsAuthenticated
    }
}

function Show-View {
    param(
        [Parameter(Mandatory)]
        [string]$ViewName
    )

    # Hide all views
    if ($controls['WelcomeView']) { $controls['WelcomeView'].Visibility = 'Collapsed' }
    if ($controls['DashboardView']) { $controls['DashboardView'].Visibility = 'Collapsed' }
    if ($controls['ApplicationsView']) { $controls['ApplicationsView'].Visibility = 'Collapsed' }
    if ($controls['ConfigurationsView']) { $controls['ConfigurationsView'].Visibility = 'Collapsed' }
    if ($controls['AssignmentsView']) { $controls['AssignmentsView'].Visibility = 'Collapsed' }
    if ($controls['DeviceOwnershipView']) { $controls['DeviceOwnershipView'].Visibility = 'Collapsed' }
    if ($controls['PlaceholderView']) { $controls['PlaceholderView'].Visibility = 'Collapsed' }
    if ($controls['SettingsView']) { $controls['SettingsView'].Visibility = 'Collapsed' }
    if ($controls['RemediationScriptsView']) { $controls['RemediationScriptsView'].Visibility = 'Collapsed' }
    if ($controls['BackupView']) { $controls['BackupView'].Visibility = 'Collapsed' }

    $script:CurrentView = $ViewName

    switch ($ViewName) {
        'Welcome' {
            $controls['WelcomeView'].Visibility = 'Visible'
        }
        'Dashboard' {
            $controls['DashboardView'].Visibility = 'Visible'
            Update-DashboardData
        }
        'Applications' {
            $controls['ApplicationsView'].Visibility = 'Visible'
        }
        'Configuration' {
            $controls['ConfigurationsView'].Visibility = 'Visible'
        }
        'Assignments' {
            $controls['AssignmentsView'].Visibility = 'Visible'
        }
        'Device Ownership' {
            $controls['DeviceOwnershipView'].Visibility = 'Visible'
        }
        'Remediation' {
            $controls['RemediationScriptsView'].Visibility = 'Visible'
            if ($script:RemediationScripts.Count -eq 0) {
                Load-RemediationScripts
                Show-RemediationScripts -SearchText "" -Category "All"
            }
        }
        'Backup' {
            $controls['BackupView'].Visibility = 'Visible'
        }
        'Settings' {
            $controls['SettingsView'].Visibility = 'Visible'
        }
        default {
            # Show placeholder for features not yet implemented
            $navInfo = $script:NavButtons[$ViewName]
            $featureId = $navInfo.Feature

            if ($controls['PlaceholderIcon']) { $controls['PlaceholderIcon'].Text = [string]$navInfo.Icon }
            if ($controls['PlaceholderTitle']) { $controls['PlaceholderTitle'].Text = $ViewName }
            if ($controls['PlaceholderDescription']) {
                # Custom description for Reports
                if ($ViewName -eq 'Reports') {
                    $controls['PlaceholderDescription'].Text = "Generate beautiful HTML reports for Conditional Access policies, Intune configurations, compliance status, device inventory, application deployments, and much more. Export comprehensive documentation and compliance reports with rich formatting and interactive charts."
                }
                else {
                    $controls['PlaceholderDescription'].Text = "The $ViewName management feature will be available here. Add scripts to the Scripts folder to extend functionality."
                }
            }

            if ($featureId -and $controls['PlaceholderPermission']) {
                $access = Test-FeatureAccess -FeatureId $featureId
                if (-not $access.HasAccess) {
                    $controls['PlaceholderPermission'].Text = "Missing permissions: $($access.MissingPermissions -join ', ')"
                }
                else {
                    $controls['PlaceholderPermission'].Text = ""
                }
            }
            elseif ($controls['PlaceholderPermission']) {
                $controls['PlaceholderPermission'].Text = ""
            }

            $controls['PlaceholderView'].Visibility = 'Visible'
        }
    }

    Write-LogDebug -Message "View changed to: $ViewName" -Source 'Navigation'
}

function Update-SelectedNavButton {
    param([string]$ViewName)

    foreach ($name in $script:NavButtons.Keys) {
        $button = $script:NavButtons[$name].Button
        if ($button) {
            if ($name -eq $ViewName) {
                $button.Background = $Window.Resources['NavItemSelectedBrush']
                $button.Foreground = $Window.Resources['AccentBrush']
            }
            else {
                $button.Background = [System.Windows.Media.Brushes]::Transparent
                $button.Foreground = $Window.Resources['TextSecondaryBrush']
            }
        }
    }
}
#endregion

#region Dashboard Functions
function Update-DashboardData {
    # Dashboard is now a static welcome screen - no data loading needed
    # Just update permission display
    Update-PermissionsDisplay
}

function Get-StringSimilarity {
    param(
        [string]$String1,
        [string]$String2
    )

    # Simple similarity check - returns score 0-100
    $s1 = $String1.ToLower() -replace '[^a-z0-9]', ''
    $s2 = $String2.ToLower() -replace '[^a-z0-9]', ''

    if ($s1 -eq $s2) { return 100 }
    if ($s1.Contains($s2) -or $s2.Contains($s1)) { return 80 }

    # Check first few characters
    $minLen = [Math]::Min($s1.Length, $s2.Length)
    if ($minLen -gt 0) {
        $matchLen = 0
        for ($i = 0; $i -lt $minLen; $i++) {
            if ($s1[$i] -eq $s2[$i]) { $matchLen++ }
            else { break }
        }
        return [int](($matchLen / $minLen) * 60)
    }

    return 0
}

function Compare-AppVersion {
    param(
        [string]$CurrentVersion,
        [string]$LatestVersion
    )

    if ([string]::IsNullOrWhiteSpace($CurrentVersion) -or [string]::IsNullOrWhiteSpace($LatestVersion)) {
        return "Unknown"
    }

    try {
        # Try to parse as System.Version (handles x.y.z.w format)
        $current = [System.Version]::Parse($CurrentVersion)
        $latest = [System.Version]::Parse($LatestVersion)

        if ($latest -gt $current) {
            return "Yes ($LatestVersion)"
        }
        elseif ($latest -eq $current) {
            return "Up to date"
        }
        else {
            return "Newer installed"
        }
    }
    catch {
        # Version parsing failed, do simple string comparison
        if ($CurrentVersion -ne $LatestVersion) {
            return "Check ($LatestVersion)"
        }
        else {
            return "Same version"
        }
    }
}

# Load WinGet package mappings once
$script:WinGetMappings = $null

function Get-WinGetMappings {
    if ($null -eq $script:WinGetMappings) {
        try {
            $mappingPath = Join-Path $PSScriptRoot "Resources\WinGetPackageMappings.json"
            if (Test-Path $mappingPath) {
                $script:WinGetMappings = Get-Content -Path $mappingPath -Raw | ConvertFrom-Json
                Write-LogInfo -Message "Loaded $($script:WinGetMappings.mappings.Count) WinGet package mappings" -Source "WinGetMappings"
            }
            else {
                Write-LogWarning -Message "WinGet mappings file not found at: $mappingPath" -Source "WinGetMappings"
                $script:WinGetMappings = @{ mappings = @() }
            }
        }
        catch {
            Write-LogError -Message "Failed to load WinGet mappings: $($_.Exception.Message)" -Source "WinGetMappings"
            $script:WinGetMappings = @{ mappings = @() }
        }
    }
    return $script:WinGetMappings
}

function Update-MappingPackageId {
    param(
        [string]$AppName,
        [string]$PackageId
    )

    try {
        $mappingPath = Join-Path $PSScriptRoot "Resources\WinGetPackageMappings.json"

        if (-not (Test-Path $mappingPath)) {
            Write-LogWarning -Message "Mapping file not found, cannot update" -Source "WinGetMappings"
            return
        }

        # Load current mappings
        $json = Get-Content -Path $mappingPath -Raw | ConvertFrom-Json

        # Find and update the mapping
        $updated = $false
        foreach ($mapping in $json.mappings) {
            foreach ($commonName in $mapping.commonNames) {
                if ($commonName -eq $AppName) {
                    $mapping.packageId = $PackageId
                    $updated = $true
                    Write-LogInfo -Message "Updated mapping: '$AppName' -> $PackageId" -Source "WinGetMappings"
                    break
                }
            }
            if ($updated) { break }
        }

        if ($updated) {
            # Save updated mappings
            $json | ConvertTo-Json -Depth 10 | Set-Content -Path $mappingPath -Encoding UTF8
            # Invalidate cached mappings so they reload
            $script:WinGetMappings = $null
        }
    }
    catch {
        Write-LogError -Message "Failed to update mapping for '$AppName': $($_.Exception.Message)" -Source "WinGetMappings"
    }
}

function Find-WinGetPackageId {
    param(
        [string]$AppName,
        [string]$Publisher
    )

    $mappings = Get-WinGetMappings

    if (-not $mappings -or -not $mappings.mappings) {
        Write-LogWarning -Message "No WinGet mappings loaded" -Source "WinGetMappings"
        return $null
    }

    # Clean the app name for better matching
    $cleanName = $AppName -replace '\s*(Enterprise|Professional|Updated|\(x64\)|\(x86\)|64-bit|32-bit|Client|App|Application|Desktop|Suite|Software)\s*', '' -replace '\s+', ' '
    $cleanName = $cleanName.Trim()

    foreach ($mapping in $mappings.mappings) {
        # Check if app name matches any of the common names (exact match first)
        foreach ($commonName in $mapping.commonNames) {
            # Exact match (case-insensitive)
            if ($AppName.ToLower() -eq $commonName.ToLower() -or $cleanName.ToLower() -eq $commonName.ToLower()) {
                Write-LogInfo -Message "Found exact mapping: '$AppName' -> $($mapping.packageId)" -Source "WinGetMappings"
                return $mapping.packageId
            }
        }

        # Partial match with publisher verification
        foreach ($commonName in $mapping.commonNames) {
            $appLower = $AppName.ToLower()
            $commonLower = $commonName.ToLower()

            if ($appLower.Contains($commonLower) -or $commonLower.Contains($appLower)) {
                # If publisher is available, verify it matches
                if ($Publisher -and $mapping.publisher) {
                    $pubLower = $Publisher.ToLower()
                    $mapPubLower = $mapping.publisher.ToLower()

                    if ($pubLower -eq $mapPubLower -or $pubLower.Contains($mapPubLower) -or $mapPubLower.Contains($pubLower)) {
                        Write-LogInfo -Message "Found partial mapping with publisher: '$AppName' ($Publisher) -> $($mapping.packageId)" -Source "WinGetMappings"
                        return $mapping.packageId
                    }
                }
                # If no publisher info, accept the match
                elseif (-not $Publisher -or -not $mapping.publisher) {
                    Write-LogInfo -Message "Found partial mapping: '$AppName' -> $($mapping.packageId)" -Source "WinGetMappings"
                    return $mapping.packageId
                }
            }
        }
    }

    Write-LogInfo -Message "No mapping found for: '$AppName' (Publisher: $Publisher)" -Source "WinGetMappings"
    return $null
}

function Get-WinGetPackageInfo {
    param(
        [string]$PackageId
    )

    try {
        Write-LogInfo -Message "Fetching package info for: $PackageId" -Source "WinGet"

        # Use local winget command to show package info
        $output = & winget show --id $PackageId --exact --accept-source-agreements 2>&1

        if ($LASTEXITCODE -eq 0 -and $output) {
            # Parse the output to extract version
            $versionLine = $output | Where-Object { $_ -match '^\s*Version:\s*(.+)$' } | Select-Object -First 1

            if ($versionLine -match '^\s*Version:\s*(.+)$') {
                $version = $Matches[1].Trim()
                Write-LogInfo -Message "Got version $version for $PackageId" -Source "WinGet"

                return @{
                    PackageId = $PackageId
                    Version = $version
                    Name = $PackageId
                }
            }
        }

        Write-LogWarning -Message "Could not get version info for $PackageId from winget" -Source "WinGet"
    }
    catch {
        Write-LogError -Message "Failed to get WinGet package info for '$PackageId': $($_.Exception.Message)" -Source "WinGet"
    }

    return $null
}

function Search-WinGetRepository {
    param(
        [string]$AppName,
        [string]$Publisher,
        [string]$CurrentVersion
    )

    try {
        # Clean the app name - remove common suffixes and words
        $cleanName = $AppName -replace '\s*(Enterprise|Professional|Updated|\(x64\)|\(x86\)|64-bit|32-bit|Client|App|Application|Player|Desktop|Suite|Software)\s*', '' -replace '\s+', ' '
        $cleanName = $cleanName.Trim()

        # Try searching with cleaned name
        $searchTerm = if ($cleanName) { $cleanName } else { $AppName }

        Write-LogInfo -Message "Searching WinGet for: '$searchTerm' (Publisher: $Publisher)" -Source "WinGetSearch"

        # Use local winget search command
        $output = & winget search $searchTerm --accept-source-agreements 2>&1

        if ($LASTEXITCODE -eq 0 -and $output) {
            # Parse winget search output (format: Name  Id  Version  Source)
            $packages = @()
            $inResults = $false

            foreach ($line in $output) {
                # Skip until we hit the separator line
                if ($line -match '^-+\s+-+') {
                    $inResults = $true
                    continue
                }

                if ($inResults -and $line -match '\S') {
                    # Parse line: Name   Id   Version   Source
                    # Split by multiple spaces (2 or more)
                    $parts = $line -split '\s{2,}' | Where-Object { $_ -ne '' }

                    if ($parts.Count -ge 3) {
                        $pkgName = $parts[0].Trim()
                        $pkgId = $parts[1].Trim()
                        $pkgVersion = $parts[2].Trim()

                        $packages += @{
                            Name = $pkgName
                            Id = $pkgId
                            Version = $pkgVersion
                        }
                    }
                }
            }

            # Try to find best match
            foreach ($pkg in $packages) {
                # Exact name match
                if ($pkg.Name -eq $AppName -or $pkg.Name -eq $cleanName) {
                    Write-LogInfo -Message "Found exact match: $($pkg.Id)" -Source "WinGetSearch"
                    return @{
                        Match = "[Available] - $($pkg.Id)"
                        PackageId = $pkg.Id
                        Confidence = "High"
                        LatestVersion = $pkg.Version
                    }
                }

                # Name similarity match
                $similarity = Get-StringSimilarity -String1 $cleanName -String2 $pkg.Name
                if ($similarity -gt 80) {
                    Write-LogInfo -Message "Found similar match: $($pkg.Id) (similarity: $similarity)" -Source "WinGetSearch"
                    return @{
                        Match = "[Available] - $($pkg.Id)"
                        PackageId = $pkg.Id
                        Confidence = "Medium"
                        LatestVersion = $pkg.Version
                    }
                }
            }

            # If we found packages but no good match, return the first one as possible
            if ($packages.Count -gt 0) {
                $firstPkg = $packages[0]
                return @{
                    Match = "[Possible] - $($firstPkg.Id)"
                    PackageId = $firstPkg.Id
                    Confidence = "Low"
                    LatestVersion = $firstPkg.Version
                }
            }
        }

        return @{ Match = "Not Found"; PackageId = $null; Confidence = "None"; LatestVersion = $null }
    }
    catch {
        Write-LogError -Message "WinGet search failed for '$AppName': $($_.Exception.Message)" -Source "WinGetSearch"
        return @{ Match = "Unknown"; PackageId = $null; Confidence = "None"; LatestVersion = $null }
    }
}

function Find-StoreAlternative {
    param(
        [string]$DisplayName,
        [string]$Publisher,
        [string]$CurrentVersion,
        [array]$WinGetApps
    )

    # First check in-tenant WinGet apps (fast)
    $cleanName = $DisplayName -replace '\s*(Enterprise|Professional|Updated|\(x64\)|\(x86\)|64-bit|32-bit)\s*', ''

    # Try exact match in tenant first
    $exactMatch = $WinGetApps | Where-Object { $_.displayName -eq $DisplayName }
    if ($exactMatch) {
        $pkgId = if ($exactMatch.packageIdentifier) { " - $($exactMatch.packageIdentifier)" } else { "" }
        return @{
            Match = "[In Tenant]$pkgId"
            PackageId = $exactMatch.packageIdentifier
            Confidence = "High"
            LatestVersion = $null
        }
    }

    # Try publisher + name match in tenant
    if ($Publisher) {
        $publisherMatches = $WinGetApps | Where-Object {
            $_.publisher -and $_.publisher -eq $Publisher
        }

        foreach ($match in $publisherMatches) {
            $similarity = Get-StringSimilarity -String1 $cleanName -String2 $match.displayName
            if ($similarity -gt 70) {
                $pkgId = if ($match.packageIdentifier) { " - $($match.packageIdentifier)" } else { "" }
                return @{
                    Match = "[In Tenant]$pkgId"
                    PackageId = $match.packageIdentifier
                    Confidence = "High"
                    LatestVersion = $null
                }
            }
        }
    }

    # Not found in tenant - check local WinGet mappings database
    $mappedPackageId = Find-WinGetPackageId -AppName $DisplayName -Publisher $Publisher
    if ($mappedPackageId) {
        # Check if packageId needs to be discovered
        if ($mappedPackageId -eq "DISCOVER") {
            Write-LogInfo -Message "Package ID not yet discovered for '$DisplayName', searching winget..." -Source "WinGetMappings"
            # Search winget to discover the actual package ID
            $searchResult = Search-WinGetRepository -AppName $DisplayName -Publisher $Publisher -CurrentVersion $CurrentVersion

            if ($searchResult.PackageId -and $searchResult.PackageId -ne $null) {
                # Update the mapping file with discovered package ID
                Update-MappingPackageId -AppName $DisplayName -PackageId $searchResult.PackageId
                return $searchResult
            }

            return $searchResult
        }
        else {
            # Found in local mappings with known packageId - get package info directly
            $pkgInfo = Get-WinGetPackageInfo -PackageId $mappedPackageId
            if ($pkgInfo) {
                return @{
                    Match = "[Available] - $mappedPackageId"
                    PackageId = $mappedPackageId
                    Confidence = "High"
                    LatestVersion = $pkgInfo.Version
                }
            }
        }
    }

    # Not found in local mappings - search WinGet repository
    return Search-WinGetRepository -AppName $DisplayName -Publisher $Publisher -CurrentVersion $CurrentVersion
}

function Load-Applications {
    # Hide empty state
    if ($controls['AppsEmptyState']) {
        $controls['AppsEmptyState'].Visibility = 'Collapsed'
    }
    if ($controls['AppsDataGrid']) {
        $controls['AppsDataGrid'].ItemsSource = $null
        $controls['AppsDataGrid'].Visibility = 'Visible'
    }

    # Check if authenticated
    $authState = Get-AuthenticationState
    if (-not $authState.IsAuthenticated) {
        [System.Windows.MessageBox]::Show("Please sign in to view applications.", "Authentication Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Fetch applications using Microsoft Graph (runs synchronously to avoid runspace issues)
    try {
        Write-LogInfo -Message "Fetching applications from Graph API..." -Source "Applications"

        # Fetch ALL applications
        $allApps = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceAppManagement/mobileApps" -OutputType PSObject

        Write-LogInfo -Message "Found $($allApps.value.Count) total apps" -Source "Applications"

        $appsList = [System.Collections.ArrayList]::new()

        foreach ($app in $allApps.value) {
            # Determine app type from @odata.type
            $appType = if ($app.'@odata.type') {
                $app.'@odata.type' -replace '#microsoft.graph.', '' -replace 'Application', ''
            } else {
                'Unknown'
            }

            # Get version information
            $currentVersion = if ($app.displayVersion) { $app.displayVersion } else { "Unknown" }

            $appsList.Add([PSCustomObject]@{
                id = $app.id
                displayName = $app.displayName
                publisher = $app.publisher
                version = $currentVersion
                appType = $appType
                storeAlternative = ""  # Will be populated by Check-WinGetVersions
                upgradeAvailable = ""  # Will be populated by Check-WinGetVersions
            }) | Out-Null
        }

        # Store apps list in script scope for later WinGet checking
        $script:LoadedApps = $appsList

        Write-LogInfo -Message "Loaded $($appsList.Count) applications" -Source "Applications"

        # Update UI
        if ($controls['AppsDataGrid']) {
            $controls['AppsDataGrid'].ItemsSource = $appsList
        }
        # Enable Check Versions button
        if ($controls['CheckVersionsButton']) {
            $controls['CheckVersionsButton'].IsEnabled = $true
        }
    }
    catch {
        Write-LogError -Message "Failed to load applications: $($_.Exception.Message)" -Source "Applications"
        [System.Windows.MessageBox]::Show("Failed to load applications:`n$($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Check-WinGetVersions {
    if (-not $script:LoadedApps -or $script:LoadedApps.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please load applications first.", "Check Versions", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Show progress card
    if ($controls['AppsProgressCard']) {
        $controls['AppsProgressCard'].Visibility = 'Visible'
    }
    if ($controls['AppsProgressBar']) {
        $controls['AppsProgressBar'].Value = 0
    }
    if ($controls['AppsProgressText']) {
        $controls['AppsProgressText'].Text = "Preparing to check versions..."
    }

    # Force UI update
    $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    # Disable the button during processing
    if ($controls['CheckVersionsButton']) {
        $controls['CheckVersionsButton'].IsEnabled = $false
    }

    # Force UI update
    $Window.Dispatcher.Invoke([Action]{}, "Render")

    try {
        Write-LogInfo -Message "Starting WinGet version check for $($script:LoadedApps.Count) apps..." -Source "Applications"

        # Get WinGet apps from the loaded list
        $wingetApps = $script:LoadedApps | Where-Object { $_.appType -eq 'winGetApp' }

        $checkedCount = 0
        $totalCount = $script:LoadedApps.Count

        foreach ($app in $script:LoadedApps) {
            $checkedCount++

            # Calculate progress percentage
            $progressPercent = [math]::Round(($checkedCount / $totalCount) * 100)

            # Update progress bar and text
            if ($controls['AppsProgressBar']) {
                $controls['AppsProgressBar'].Value = $progressPercent
            }
            if ($controls['AppsProgressText']) {
                $controls['AppsProgressText'].Text = "Checking $checkedCount of $totalCount apps: $($app.displayName)"
            }

            # Force UI to update every 5 apps to show progress
            if ($checkedCount % 5 -eq 0) {
                $Window.Dispatcher.Invoke([Action]{}, "Render")
            }

            # Check for Store alternative (only for Win32 apps)
            if ($app.appType -eq 'win32LobApp') {
                $match = Find-StoreAlternative -DisplayName $app.displayName -Publisher $app.publisher -CurrentVersion $app.version -WinGetApps $wingetApps
                $app.storeAlternative = $match.Match

                # Check if upgrade is available
                if ($match.LatestVersion) {
                    $app.upgradeAvailable = Compare-AppVersion -CurrentVersion $app.version -LatestVersion $match.LatestVersion
                }
            }
            elseif ($app.appType -eq 'winGetApp') {
                $app.storeAlternative = "[Store App]"
                $app.upgradeAvailable = "Managed by Store"
            }
            else {
                $app.storeAlternative = "N/A"
            }

            # Refresh DataGrid every 10 apps to show partial results
            if ($checkedCount % 10 -eq 0) {
                if ($controls['AppsDataGrid']) {
                    $controls['AppsDataGrid'].Items.Refresh()
                }
            }
        }

        Write-LogInfo -Message "Completed WinGet version check" -Source "Applications"

        # Final refresh of the DataGrid
        if ($controls['AppsDataGrid']) {
            $controls['AppsDataGrid'].Items.Refresh()
        }

        # Hide progress card
        if ($controls['AppsProgressCard']) {
            $controls['AppsProgressCard'].Visibility = 'Collapsed'
        }

        [System.Windows.MessageBox]::Show("Completed checking versions for $totalCount applications.", "Version Check Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-LogError -Message "Failed to check versions: $($_.Exception.Message)" -Source "Applications"

        # Hide progress card
        if ($controls['AppsProgressCard']) {
            $controls['AppsProgressCard'].Visibility = 'Collapsed'
        }

        [System.Windows.MessageBox]::Show("Failed to check versions:`n$($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    finally {
        # Re-enable the button
        if ($controls['CheckVersionsButton']) {
            $controls['CheckVersionsButton'].IsEnabled = $true
        }
    }
}

function Export-Applications {
    # Get the current data from the DataGrid
    if (-not $controls['AppsDataGrid']) { return }

    $apps = $controls['AppsDataGrid'].ItemsSource
    if (-not $apps -or $apps.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No applications to export. Please load applications first.", "Export Applications", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Show SaveFileDialog
    $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $saveDialog.DefaultExt = ".csv"
    $saveDialog.FileName = "IntuneApplications_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $saveDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

    if ($saveDialog.ShowDialog()) {
        try {
            $filePath = $saveDialog.FileName
            $extension = [System.IO.Path]::GetExtension($filePath)

            if ($extension -eq '.json') {
                # Export as JSON
                $apps | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
            }
            else {
                # Export as CSV
                $apps | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
            }

            Write-LogInfo -Message "Exported $($apps.Count) applications to $filePath" -Source "Applications"
            [System.Windows.MessageBox]::Show("Successfully exported $($apps.Count) applications to:`n$filePath", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
        catch {
            Write-LogError -Message "Failed to export applications: $($_.Exception.Message)" -Source "Applications"
            [System.Windows.MessageBox]::Show("Failed to export applications:`n$($_.Exception.Message)", "Export Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
}
#endregion

#region Configuration Functions
# Script-scope variables to store fetched configuration data
$script:ConfigProfiles = $null
$script:EndpointSecurityPolicies = $null
$script:AppProtectionPolicies = $null

function Get-PolicyAssignments {
    param(
        [string]$PolicyId,
        [string]$PolicyType
    )

    try {
        $assignmentUri = switch ($PolicyType) {
            'SettingsCatalog' { "beta/deviceManagement/configurationPolicies/$PolicyId/assignments" }
            'ConfigurationProfile' { "beta/deviceManagement/deviceConfigurations/$PolicyId/assignments" }
            'AdminTemplate' { "beta/deviceManagement/groupPolicyConfigurations/$PolicyId/assignments" }
            'Intent' { "beta/deviceManagement/intents/$PolicyId/assignments" }
            'AppProtection' { "beta/deviceAppManagement/managedAppPolicies/$PolicyId/assignments" }
            'ConditionalAccess' {
                # Conditional Access has different structure - get the policy details
                $policy = Invoke-MgGraphRequest -Method GET -Uri "beta/identity/conditionalAccess/policies/$PolicyId" -OutputType PSObject
                if ($policy.conditions.users.includeGroups) {
                    return ($policy.conditions.users.includeGroups -join ', ')
                }
                elseif ($policy.conditions.users.includeUsers) {
                    if ($policy.conditions.users.includeUsers -contains 'All') {
                        return 'All Users'
                    }
                    return ($policy.conditions.users.includeUsers -join ', ')
                }
                return 'No assignments'
            }
        }

        if ($PolicyType -eq 'ConditionalAccess') {
            return $assignmentUri  # Already processed above
        }

        $assignments = Invoke-MgGraphRequest -Method GET -Uri $assignmentUri -OutputType PSObject

        if (-not $assignments.value -or $assignments.value.Count -eq 0) {
            return 'Not assigned'
        }

        # Extract group names or targets
        $targets = @()
        foreach ($assignment in $assignments.value) {
            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $targets += 'All Users'
            }
            elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $targets += 'All Devices'
            }
            elseif ($assignment.target.groupId) {
                # Try to get group display name
                try {
                    $group = Invoke-MgGraphRequest -Method GET -Uri "beta/groups/$($assignment.target.groupId)?`$select=displayName" -OutputType PSObject
                    $targets += $group.displayName
                }
                catch {
                    $targets += $assignment.target.groupId
                }
            }
        }

        if ($targets.Count -eq 0) {
            return 'Not assigned'
        }

        return ($targets -join ', ')
    }
    catch {
        Write-LogWarning -Message "Failed to get assignments for policy $PolicyId`: $($_.Exception.Message)" -Source "Configurations"
        return 'Error fetching assignments'
    }
}

function Clear-AdvancedSearchCache {
    $cacheFolder = Join-Path $env:TEMP "IntuneAdmin\PolicyCache"
    if (Test-Path $cacheFolder) {
        Write-LogInfo -Message "Clearing Advanced Search cache..." -Source "Configurations"
        try {
            Remove-Item -Path $cacheFolder -Recurse -Force -ErrorAction Stop
            Write-LogInfo -Message "Advanced Search cache cleared" -Source "Configurations"
        }
        catch {
            Write-LogWarning -Message "Failed to clear Advanced Search cache: $($_.Exception.Message)" -Source "Configurations"
        }
    }
    # Clear in-memory index
    $script:PolicySearchIndex = $null
}

function Fetch-ConfigurationProfiles {
    $authState = Get-AuthenticationState
    if (-not $authState.IsAuthenticated) {
        [System.Windows.MessageBox]::Show("Please sign in to fetch configuration profiles.", "Not Authenticated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Clear search cache when fetching new data
    Clear-AdvancedSearchCache

    # Show loading
    if ($controls['ConfigProfilesLoadingText']) {
        $controls['ConfigProfilesLoadingText'].Visibility = 'Visible'
        $controls['ConfigProfilesLoadingText'].Text = "Fetching configuration profiles..."
    }

    # Disable button during processing
    if ($controls['FetchConfigProfilesButton']) {
        $controls['FetchConfigProfilesButton'].IsEnabled = $false
    }

    # Force UI update
    $Window.Dispatcher.Invoke([Action]{}, "Render")

    try {
        Write-LogInfo -Message "Fetching configuration profiles..." -Source "Configurations"

        # Helper function to get all pages from Graph API
        function Get-AllGraphPages {
            param([string]$Uri)
            $allResults = @()
            $nextLink = $Uri

            while ($nextLink) {
                $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject
                if ($response.value) {
                    $allResults += $response.value
                }
                $nextLink = $response.'@odata.nextLink'
            }

            return $allResults
        }

        # Fetch Settings Catalog (with Settings expanded) - with pagination
        Write-LogInfo -Message "Fetching Settings Catalog policies..." -Source "Configurations"
        $settingsCatalogPolicies = Get-AllGraphPages -Uri "beta/deviceManagement/configurationPolicies?`$expand=Settings"

        # Fetch Device Configurations (exclude update policies) - with pagination
        Write-LogInfo -Message "Fetching Device Configuration policies..." -Source "Configurations"
        $filter = "not isof('microsoft.graph.windowsUpdateForBusinessConfiguration') and not isof('microsoft.graph.iosUpdateConfiguration')"
        $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filter)
        $configProfiles = Get-AllGraphPages -Uri "beta/deviceManagement/deviceConfigurations?`$filter=$encodedFilter"

        # Fetch Administrative Templates (Group Policy Configurations) - with pagination
        Write-LogInfo -Message "Fetching Administrative Templates..." -Source "Configurations"
        $adminTemplates = Get-AllGraphPages -Uri "beta/deviceManagement/groupPolicyConfigurations"

        # Combine all profiles and tag with source
        $allProfiles = @()
        if ($settingsCatalogPolicies) {
            foreach ($policy in $settingsCatalogPolicies) {
                $policy | Add-Member -NotePropertyName 'policySource' -NotePropertyValue 'SettingsCatalog' -Force
                $allProfiles += $policy
            }
        }
        if ($configProfiles) {
            foreach ($policy in $configProfiles) {
                $policy | Add-Member -NotePropertyName 'policySource' -NotePropertyValue 'DeviceConfiguration' -Force
                $allProfiles += $policy
            }
        }
        if ($adminTemplates) {
            foreach ($policy in $adminTemplates) {
                $policy | Add-Member -NotePropertyName 'policySource' -NotePropertyValue 'AdminTemplate' -Force
                $policy | Add-Member -NotePropertyName '@odata.type' -NotePropertyValue '#microsoft.graph.groupPolicyConfiguration' -Force
                $allProfiles += $policy
            }
        }

        # Fetch assignments for each profile
        Write-LogInfo -Message "Fetching assignments for $($allProfiles.Count) profiles..." -Source "Configurations"
        $profilesWithAssignments = @()
        $processedCount = 0

        foreach ($profile in $allProfiles) {
            $processedCount++
            if ($processedCount % 10 -eq 0) {
                if ($controls['ConfigProfilesLoadingText']) {
                    $controls['ConfigProfilesLoadingText'].Text = "Processing assignments: $processedCount of $($allProfiles.Count)"
                }
                $Window.Dispatcher.Invoke([Action]{}, "Render")
            }

            # Use policySource to determine the correct PolicyType for assignment fetching
            $policyType = if ($profile.policySource -eq 'SettingsCatalog') { 'SettingsCatalog' }
                         elseif ($profile.policySource -eq 'AdminTemplate') { 'AdminTemplate' }
                         else { 'ConfigurationProfile' }

            $assignments = Get-PolicyAssignments -PolicyId $profile.id -PolicyType $policyType
            $profile | Add-Member -NotePropertyName 'assignmentInfo' -NotePropertyValue $assignments -Force
            $profilesWithAssignments += $profile
        }

        # Store all profiles with assignments
        $script:ConfigProfiles = $profilesWithAssignments

        # Categorize by source and odata.type
        $settingsCatalog = @($profilesWithAssignments | Where-Object { $_.policySource -eq 'SettingsCatalog' })
        $deviceRestrictions = @($profilesWithAssignments | Where-Object { $_.policySource -eq 'DeviceConfiguration' -and $_.'@odata.type' -eq '#microsoft.graph.windows10GeneralConfiguration' })
        $adminTemplates = @($profilesWithAssignments | Where-Object { $_.policySource -eq 'AdminTemplate' })

        # Update counts
        if ($controls['SettingsCatalogCount']) {
            $controls['SettingsCatalogCount'].Text = "$($settingsCatalog.Count) policies"
        }
        if ($controls['DeviceRestrictionsCount']) {
            $controls['DeviceRestrictionsCount'].Text = "$($deviceRestrictions.Count) policies"
        }
        if ($controls['AdminTemplatesCount']) {
            $controls['AdminTemplatesCount'].Text = "$($adminTemplates.Count) policies"
        }

        Write-LogInfo -Message "Fetched $($profilesWithAssignments.Count) configuration profiles with assignments" -Source "Configurations"
        $controls['StatusMessageText'].Text = "Loaded $($profilesWithAssignments.Count) configuration profiles"
    }
    catch {
        Write-LogError -Message "Failed to fetch configuration profiles: $($_.Exception.Message)" -Source "Configurations"
        [System.Windows.MessageBox]::Show(
            "Failed to fetch configuration profiles:`n$($_.Exception.Message)",
            "Fetch Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
    finally {
        # Hide loading and re-enable button
        if ($controls['ConfigProfilesLoadingText']) {
            $controls['ConfigProfilesLoadingText'].Visibility = 'Collapsed'
        }
        if ($controls['FetchConfigProfilesButton']) {
            $controls['FetchConfigProfilesButton'].IsEnabled = $true
        }
    }
}

function Fetch-EndpointSecurity {
    $authState = Get-AuthenticationState
    if (-not $authState.IsAuthenticated) {
        [System.Windows.MessageBox]::Show("Please sign in to fetch endpoint security policies.", "Not Authenticated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Clear search cache when fetching new data
    Clear-AdvancedSearchCache

    # Show loading
    if ($controls['EndpointSecLoadingText']) {
        $controls['EndpointSecLoadingText'].Visibility = 'Visible'
        $controls['EndpointSecLoadingText'].Text = "Fetching endpoint security policies..."
    }

    # Disable button during processing
    if ($controls['FetchEndpointSecButton']) {
        $controls['FetchEndpointSecButton'].IsEnabled = $false
    }

    # Force UI update
    $Window.Dispatcher.Invoke([Action]{}, "Render")

    try {
        Write-LogInfo -Message "Fetching endpoint security policies..." -Source "Configurations"

        # Helper function to get all pages from Graph API (defined locally for this function)
        function Get-AllGraphPages {
            param([string]$Uri)
            $allResults = @()
            $nextLink = $Uri

            while ($nextLink) {
                $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject
                if ($response.value) {
                    $allResults += $response.value
                }
                $nextLink = $response.'@odata.nextLink'
            }

            return $allResults
        }

        # Fetch Endpoint Security Policies (Intents) - with pagination
        Write-LogInfo -Message "Fetching intents..." -Source "Configurations"
        $allIntents = Get-AllGraphPages -Uri "beta/deviceManagement/intents"

        # Fetch templates to get displayName for categorization
        Write-LogInfo -Message "Fetching endpoint security templates..." -Source "Configurations"
        $allTemplates = Get-AllGraphPages -Uri "beta/deviceManagement/templates"

        # Create a hashtable for quick template lookup
        $templateLookup = @{}
        foreach ($template in $allTemplates) {
            $templateLookup[$template.id] = $template
        }

        # Fetch assignments for intents and add template display names
        Write-LogInfo -Message "Fetching assignments for $($allIntents.Count) intents..." -Source "Configurations"
        $intentsWithAssignments = @()
        $processedCount = 0

        foreach ($intent in $allIntents) {
            $processedCount++
            if ($processedCount % 10 -eq 0) {
                if ($controls['EndpointSecLoadingText']) {
                    $controls['EndpointSecLoadingText'].Text = "Processing intent assignments: $processedCount of $($allIntents.Count)"
                }
                $Window.Dispatcher.Invoke([Action]{}, "Render")
            }

            # Add template display name from template lookup
            if ($intent.templateId -and $templateLookup[$intent.templateId]) {
                $intent | Add-Member -NotePropertyName 'templateDisplayName' -NotePropertyValue $templateLookup[$intent.templateId].displayName -Force
            }

            $assignments = Get-PolicyAssignments -PolicyId $intent.id -PolicyType 'Intent'
            $intent | Add-Member -NotePropertyName 'assignmentInfo' -NotePropertyValue $assignments -Force
            $intentsWithAssignments += $intent
        }

        # Store all policies with assignments
        $script:EndpointSecurityPolicies = @{
            Intents = $intentsWithAssignments
        }

        # Debug: Log unique templateDisplayName values to understand categorization
        $uniqueTemplates = $intentsWithAssignments | Where-Object { $_.templateDisplayName } | Select-Object -ExpandProperty templateDisplayName -Unique | Sort-Object
        Write-LogInfo -Message "Found unique template types: $($uniqueTemplates -join ', ')" -Source "Configurations"

        # Categorize intents by templateDisplayName
        $firewall = @($intentsWithAssignments | Where-Object {
            $_.templateDisplayName -match 'Firewall'
        })
        $edr = @($intentsWithAssignments | Where-Object {
            $_.templateDisplayName -match 'Endpoint.*[Dd]etection|Defender.*Endpoint|EDR'
        })
        $asr = @($intentsWithAssignments | Where-Object {
            $_.templateDisplayName -match '[Aa]ttack.*[Ss]urface|ASR'
        })
        $accountProtection = @($intentsWithAssignments | Where-Object {
            $_.templateDisplayName -match '[Aa]ccount.*[Pp]rotection|Windows Hello|Credential Guard'
        })

        # Update counts
        if ($controls['FirewallCount']) {
            $controls['FirewallCount'].Text = "$($firewall.Count) policies"
        }
        if ($controls['EDRCount']) {
            $controls['EDRCount'].Text = "$($edr.Count) policies"
        }
        if ($controls['ASRCount']) {
            $controls['ASRCount'].Text = "$($asr.Count) policies"
        }
        if ($controls['AccountProtectionCount']) {
            $controls['AccountProtectionCount'].Text = "$($accountProtection.Count) policies"
        }

        Write-LogInfo -Message "Fetched $($intentsWithAssignments.Count) endpoint security intents with assignments" -Source "Configurations"
        $controls['StatusMessageText'].Text = "Loaded $($intentsWithAssignments.Count) endpoint security policies"
    }
    catch {
        Write-LogError -Message "Failed to fetch endpoint security: $($_.Exception.Message)" -Source "Configurations"
        [System.Windows.MessageBox]::Show(
            "Failed to fetch endpoint security policies:`n$($_.Exception.Message)",
            "Fetch Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
    finally {
        # Hide loading and re-enable button
        if ($controls['EndpointSecLoadingText']) {
            $controls['EndpointSecLoadingText'].Visibility = 'Collapsed'
        }
        if ($controls['FetchEndpointSecButton']) {
            $controls['FetchEndpointSecButton'].IsEnabled = $true
        }
    }
}

function Fetch-AppProtection {
    $authState = Get-AuthenticationState
    if (-not $authState.IsAuthenticated) {
        [System.Windows.MessageBox]::Show("Please sign in to fetch app protection policies.", "Not Authenticated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Clear search cache when fetching new data
    Clear-AdvancedSearchCache

    # Show loading
    if ($controls['AppProtectionLoadingText']) {
        $controls['AppProtectionLoadingText'].Visibility = 'Visible'
        $controls['AppProtectionLoadingText'].Text = "Fetching app protection policies..."
    }

    # Disable button during processing
    if ($controls['FetchAppProtectionButton']) {
        $controls['FetchAppProtectionButton'].IsEnabled = $false
    }

    # Force UI update
    $Window.Dispatcher.Invoke([Action]{}, "Render")

    try {
        Write-LogInfo -Message "Fetching app protection policies..." -Source "Configurations"

        # Fetch App Protection Policies
        $appProtectionPolicies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceAppManagement/managedAppPolicies" -OutputType PSObject

        # Fetch assignments for each policy
        Write-LogInfo -Message "Fetching assignments for $($appProtectionPolicies.value.Count) app protection policies..." -Source "Configurations"
        $policiesWithAssignments = @()
        $processedCount = 0

        foreach ($policy in $appProtectionPolicies.value) {
            $processedCount++
            if ($processedCount % 10 -eq 0) {
                if ($controls['AppProtectionLoadingText']) {
                    $controls['AppProtectionLoadingText'].Text = "Processing assignments: $processedCount of $($appProtectionPolicies.value.Count)"
                }
                $Window.Dispatcher.Invoke([Action]{}, "Render")
            }

            $assignments = Get-PolicyAssignments -PolicyId $policy.id -PolicyType 'AppProtection'
            $policy | Add-Member -NotePropertyName 'assignmentInfo' -NotePropertyValue $assignments -Force
            $policiesWithAssignments += $policy
        }

        # Store all policies with assignments
        $script:AppProtectionPolicies = $policiesWithAssignments

        # Categorize by platform
        $androidPolicies = @($policiesWithAssignments | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.androidManagedAppProtection' })
        $iOSPolicies = @($policiesWithAssignments | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.iosManagedAppProtection' })

        # Update counts
        if ($controls['AndroidAppProtectionCount']) {
            $controls['AndroidAppProtectionCount'].Text = "$($androidPolicies.Count) policies"
        }
        if ($controls['iOSAppProtectionCount']) {
            $controls['iOSAppProtectionCount'].Text = "$($iOSPolicies.Count) policies"
        }

        Write-LogInfo -Message "Fetched $($policiesWithAssignments.Count) app protection policies with assignments" -Source "Configurations"
        $controls['StatusMessageText'].Text = "Loaded $($policiesWithAssignments.Count) app protection policies"
    }
    catch {
        Write-LogError -Message "Failed to fetch app protection: $($_.Exception.Message)" -Source "Configurations"
        [System.Windows.MessageBox]::Show(
            "Failed to fetch app protection policies:`n$($_.Exception.Message)",
            "Fetch Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
    finally {
        # Hide loading and re-enable button
        if ($controls['AppProtectionLoadingText']) {
            $controls['AppProtectionLoadingText'].Visibility = 'Collapsed'
        }
        if ($controls['FetchAppProtectionButton']) {
            $controls['FetchAppProtectionButton'].IsEnabled = $true
        }
    }
}

function Fetch-AllConfigurations {
    $authState = Get-AuthenticationState
    if (-not $authState.IsAuthenticated) {
        [System.Windows.MessageBox]::Show("Please sign in to fetch all configurations.", "Not Authenticated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Disable the Fetch All button during processing
    if ($controls['FetchAllConfigurationsButton']) {
        $controls['FetchAllConfigurationsButton'].IsEnabled = $false
    }

    try {
        Write-LogInfo -Message "Fetching all configuration data..." -Source "Configurations"
        $controls['StatusMessageText'].Text = "Fetching all configurations..."

        # Clear Advanced Search cache so it rebuilds with fresh data
        Clear-AdvancedSearchCache

        # Fetch Configuration Profiles
        Fetch-ConfigurationProfiles

        # Fetch Endpoint Security
        Fetch-EndpointSecurity

        # Fetch App Protection
        Fetch-AppProtection

        Write-LogInfo -Message "Completed fetching all configuration data" -Source "Configurations"
        $controls['StatusMessageText'].Text = "All configurations loaded successfully"
    }
    catch {
        Write-LogError -Message "Failed to fetch all configurations: $($_.Exception.Message)" -Source "Configurations"
        [System.Windows.MessageBox]::Show(
            "Failed to fetch all configurations:`n$($_.Exception.Message)",
            "Fetch Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
    finally {
        # Re-enable the Fetch All button
        if ($controls['FetchAllConfigurationsButton']) {
            $controls['FetchAllConfigurationsButton'].IsEnabled = $true
        }
    }
}

function Invoke-GraphRequestWithRetry {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [int]$MaxRetries = 5
    )

    $retryCount = 0
    $success = $false
    $result = $null

    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            $result = Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType PSObject
            $success = $true
        }
        catch {
            $retryCount++

            # Check if it's a 429 (Too Many Requests) error
            if ($_.Exception.Response.StatusCode.value__ -eq 429 -and $retryCount -lt $MaxRetries) {
                $waitTime = 5
                Write-LogWarning -Message "429 Too Many Requests. Waiting $waitTime seconds before retry $retryCount of $MaxRetries..." -Source "GraphAPI"
                Start-Sleep -Seconds $waitTime
            }
            else {
                # Not a 429 or max retries reached, throw the error
                throw
            }
        }
    }

    return $result
}

function Export-AllPoliciesToJSON {
    param([string]$ExportPath)

    try {
        # Create export directory
        if (-not (Test-Path $ExportPath)) {
            New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        }

        $allPolicies = @()
        if ($script:ConfigProfiles) { $allPolicies += $script:ConfigProfiles }
        if ($script:EndpointSecurityPolicies) {
            if ($script:EndpointSecurityPolicies.Intents) { $allPolicies += $script:EndpointSecurityPolicies.Intents }
            if ($script:EndpointSecurityPolicies.ConditionalAccess) { $allPolicies += $script:EndpointSecurityPolicies.ConditionalAccess }
        }
        if ($script:AppProtectionPolicies) { $allPolicies += $script:AppProtectionPolicies }

        $exportCount = 0
        foreach ($policy in $allPolicies) {
            $exportCount++

            # Build full policy data including settings
            $policyData = @{
                Policy = $policy
                Settings = @()
            }

            # Fetch settings based on policy type
            try {
                if ($policy.policySource -eq 'SettingsCatalog') {
                    $settings = Invoke-GraphRequestWithRetry -Uri "beta/deviceManagement/configurationPolicies/$($policy.id)/settings"
                    if ($settings.value) {
                        $policyData.Settings = $settings.value
                    }
                    Start-Sleep -Milliseconds 200  # Small delay to avoid rate limiting
                }
            }
            catch {
                Write-LogWarning -Message "Could not fetch settings for $($policy.displayName): $($_.Exception.Message)" -Source "PolicyExport"
            }

            # Save to JSON file
            $fileName = "$($policy.id).json"
            $filePath = Join-Path $ExportPath $fileName
            $policyData | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding UTF8
        }

        Write-LogInfo -Message "Exported $exportCount policies to $ExportPath" -Source "PolicyExport"
        return $exportCount
    }
    catch {
        Write-LogError -Message "Failed to export policies: $($_.Exception.Message)" -Source "PolicyExport"
        throw
    }
}

function Get-PolicySettingsFromJSON {
    param(
        [object]$Policy,
        [string]$ExportPath
    )

    $settingsDetails = @()

    if (-not $Policy -or -not $Policy.id) {
        Write-LogWarning -Message "Invalid policy object passed to Get-PolicySettingsFromJSON" -Source "AdvancedSearch"
        return $settingsDetails
    }

    try {
        # Check if JSON file exists
        $jsonFile = Join-Path $ExportPath "$($Policy.id).json"

        if (Test-Path $jsonFile) {
            try {
                $policyData = Get-Content -Path $jsonFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                Write-LogWarning -Message "Failed to read/parse JSON file for policy $($Policy.displayName): $($_.Exception.Message)" -Source "AdvancedSearch"
                return $settingsDetails
            }

            # Parse settings from JSON
            if ($policyData.Settings) {
                foreach ($setting in $policyData.Settings) {
                    try {
                        if ($setting.settingInstance) {
                            $settingName = $setting.settingInstance.settingDefinitionId -replace '.*_', ''
                            $settingValue = ""

                            # Extract value based on setting type
                            if ($setting.settingInstance.simpleSettingValue) {
                                $settingValue = $setting.settingInstance.simpleSettingValue.value
                            }
                            elseif ($setting.settingInstance.choiceSettingValue) {
                                $settingValue = $setting.settingInstance.choiceSettingValue.value -replace '.*_', ''
                            }
                            elseif ($setting.settingInstance.groupSettingCollectionValue) {
                                $settingValue = "Collection: $($setting.settingInstance.groupSettingCollectionValue.Count) items"
                            }

                            $settingsDetails += @{
                                Name = $settingName
                                Value = if ($settingValue) { $settingValue.ToString() } else { "" }
                                FullPath = $setting.settingInstance.settingDefinitionId
                            }
                        }
                    }
                    catch {
                        Write-LogWarning -Message "Failed to parse setting in policy $($Policy.displayName): $($_.Exception.Message)" -Source "AdvancedSearch"
                        # Continue with next setting
                    }
                }
            }
        }
        else {
            Write-LogWarning -Message "JSON file not found for policy $($Policy.displayName): $jsonFile" -Source "AdvancedSearch"
        }

        # Fallback: Parse policy properties for Device Configuration
        if ($settingsDetails.Count -eq 0 -and $Policy.'@odata.type' -ne '#microsoft.graph.groupPolicyConfiguration') {
            $excludeProps = @('id', '@odata.type', '@odata.context', 'createdDateTime', 'lastModifiedDateTime',
                            'version', 'displayName', 'description', 'assignmentInfo', 'policySource', 'assignments')

            foreach ($prop in $Policy.PSObject.Properties) {
                try {
                    if ($prop.Name -notin $excludeProps -and $null -ne $prop.Value -and $prop.Value -ne '') {
                        $settingsDetails += @{
                            Name = $prop.Name
                            Value = $prop.Value.ToString()
                            FullPath = $prop.Name
                        }
                    }
                }
                catch {
                    # Skip properties that can't be converted to string
                }
            }
        }
    }
    catch {
        Write-LogError -Message "Unexpected error reading settings from JSON for policy $($Policy.displayName): $($_.Exception.Message)" -Source "AdvancedSearch"
    }

    return $settingsDetails
}

function Show-AdvancedSearch {
    try {
        $authState = Get-AuthenticationState
        if (-not $authState.IsAuthenticated) {
            [System.Windows.MessageBox]::Show("Please sign in first.", "Not Authenticated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Check if policies are loaded
        if (-not $script:ConfigProfiles -and -not $script:EndpointSecurityPolicies -and -not $script:AppProtectionPolicies) {
            $result = [System.Windows.MessageBox]::Show(
                "No policies loaded. Would you like to fetch all configurations now?`n`nThis may take a few minutes.",
                "Fetch Policies",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )

            if ($result -eq 'Yes') {
                Fetch-AllConfigurations
            }
            else {
                return
            }
        }

        Write-LogInfo -Message "Loading Advanced Search dialog..." -Source "AdvancedSearch"

        # Load the Advanced Search dialog XAML
        $dialogXaml = [System.IO.File]::ReadAllText("$PSScriptRoot\Resources\AdvancedSearchDialog.xaml")
        $searchWindow = [Windows.Markup.XamlReader]::Parse($dialogXaml)

        Write-LogInfo -Message "Advanced Search dialog loaded successfully" -Source "AdvancedSearch"

        # Get controls
        Write-LogInfo -Message "Loading dialog controls..." -Source "AdvancedSearch"
        $searchBox = $searchWindow.FindName("SearchBox")
        $searchButton = $searchWindow.FindName("SearchButton")
        $searchPlaceholder = $searchWindow.FindName("SearchPlaceholder")
        $searchStatus = $searchWindow.FindName("SearchStatus")
        $emptyState = $searchWindow.FindName("EmptyState")
        $resultsDataGrid = $searchWindow.FindName("ResultsDataGrid")
        $closeButton = $searchWindow.FindName("CloseButton")
        $searchSubtitle = $searchWindow.FindName("SearchSubtitle")

        # Verify critical controls loaded
        if (-not $searchBox -or -not $searchButton -or -not $searchStatus -or -not $emptyState -or -not $resultsDataGrid) {
            throw "Failed to load one or more critical controls from XAML"
        }

        Write-LogInfo -Message "All dialog controls loaded successfully" -Source "AdvancedSearch"
    }
    catch {
        Write-LogError -Message "Failed to initialize Advanced Search: $($_.Exception.Message)" -Source "AdvancedSearch"
        [System.Windows.MessageBox]::Show(
            "Failed to open Advanced Search:`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
        return
    }

    # No indexing needed - we'll search JSON files directly when user searches
    $searchStatus.Visibility = 'Collapsed'

    # Search function - simple and direct
    $performSearch = {
        param([string]$SearchTerm)

        try {
            Write-LogInfo -Message "Search initiated with term: $SearchTerm" -Source "AdvancedSearch"

            if ([string]::IsNullOrWhiteSpace($SearchTerm)) {
                $emptyState.Visibility = 'Visible'
                $resultsDataGrid.Visibility = 'Collapsed'
                $searchSubtitle.Text = "Search through all policy settings and configurations"
                return
            }

            # Disable search button and show loading state
            $searchButton.IsEnabled = $false
            $searchButton.Content = "Searching..."
            $searchStatus.Visibility = 'Visible'
            $searchStatus.Text = "Preparing to search..."

            # Force UI update so button greys out immediately
            $searchWindow.Dispatcher.Invoke([Action]{}, "Render")

            # Get cache folder
            $cacheFolder = Join-Path $env:TEMP "IntuneAdmin\PolicyCache"

            # Check if cache exists
            if (-not (Test-Path $cacheFolder)) {
                Write-LogWarning -Message "Cache folder not found. Exporting policies first..." -Source "AdvancedSearch"
                $searchStatus.Text = "Exporting policies to cache... This may take a moment."

                $exportCount = Export-AllPoliciesToJSON -ExportPath $cacheFolder
                Write-LogInfo -Message "Exported $exportCount policies" -Source "AdvancedSearch"
            }

            # Get all JSON files
            $jsonFiles = Get-ChildItem -Path $cacheFolder -Filter "*.json" -File
            Write-LogInfo -Message "Searching through $($jsonFiles.Count) policy files for '$SearchTerm'..." -Source "AdvancedSearch"

            $searchStatus.Text = "Searching through $($jsonFiles.Count) policies for '$SearchTerm'..."

            $results = @()
            $processedCount = 0

            foreach ($file in $jsonFiles) {
                try {
                    $processedCount++

                    # Read JSON file as raw text for searching
                    $jsonContent = Get-Content -Path $file.FullName -Raw

                    # Search for the term (case-insensitive)
                    if ($jsonContent -match [regex]::Escape($SearchTerm)) {
                        # Found a match! Parse JSON to get policy details
                        $policyData = $jsonContent | ConvertFrom-Json

                        $policyName = if ($policyData.Policy.displayName) { $policyData.Policy.displayName } else { "Unknown Policy" }
                        $policyType = if ($policyData.Policy.'@odata.type') {
                            $policyData.Policy.'@odata.type' -replace '#microsoft.graph.', ''
                        } else {
                            "Unknown Type"
                        }

                        # Skip policies with Unknown Type (CA policies and others)
                        if ($policyType -eq "Unknown Type") {
                            Write-LogInfo -Message "Skipping policy with unknown type: $policyName" -Source "AdvancedSearch"
                            continue
                        }

                        # Determine where the match was found
                        $matchLocation = "In settings"
                        if ($policyData.Policy.displayName -match $SearchTerm) {
                            $matchLocation = "Policy Name"
                        }
                        elseif ($policyData.Policy.description -match $SearchTerm) {
                            $matchLocation = "Description"
                        }

                        $results += [PSCustomObject]@{
                            PolicyName = $policyName
                            PolicyType = $policyType
                            MatchCount = $matchLocation
                            MatchDetails = "Contains '$SearchTerm'"
                        }

                        Write-LogInfo -Message "Match found in: $policyName" -Source "AdvancedSearch"
                    }
                }
                catch {
                    Write-LogWarning -Message "Error searching file $($file.Name): $($_.Exception.Message)" -Source "AdvancedSearch"
                }
            }

            Write-LogInfo -Message "Search completed. Found $($results.Count) matching policies out of $processedCount files." -Source "AdvancedSearch"

        # Display results
        Write-LogInfo -Message "Preparing to display $($results.Count) results..." -Source "AdvancedSearch"

        try {
            if ($results.Count -eq 0) {
                Write-LogInfo -Message "No results found, showing empty state" -Source "AdvancedSearch"
                $emptyState.Visibility = 'Visible'
                $resultsDataGrid.Visibility = 'Collapsed'
                $searchSubtitle.Text = "No matches found for '$SearchTerm'"
                $searchStatus.Visibility = 'Collapsed'
            }
            else {
                Write-LogInfo -Message "Displaying $($results.Count) results in DataGrid..." -Source "AdvancedSearch"

                $emptyState.Visibility = 'Collapsed'
                $resultsDataGrid.Visibility = 'Visible'

                Write-LogInfo -Message "Setting DataGrid ItemsSource with $($results.Count) items..." -Source "AdvancedSearch"
                $resultsDataGrid.ItemsSource = $results

                $searchSubtitle.Text = "Found $($results.Count) policies with matching settings"
                $searchStatus.Visibility = 'Collapsed'

                Write-LogInfo -Message "Results display completed successfully" -Source "AdvancedSearch"
            }

            Write-LogInfo -Message "Search completed successfully. Found $($results.Count) matching policies." -Source "AdvancedSearch"

            # Re-enable search button
            $searchButton.IsEnabled = $true
            $searchButton.Content = "Search"
        }
        catch {
            Write-LogError -Message "Failed to display results: $($_.Exception.Message)" -Source "AdvancedSearch"

            # Re-enable search button even on error
            $searchButton.IsEnabled = $true
            $searchButton.Content = "Search"

            throw
        }
        }
        catch {
            Write-LogError -Message "Search failed: $($_.Exception.Message)" -Source "AdvancedSearch"
            Write-LogError -Message "Stack trace: $($_.ScriptStackTrace)" -Source "AdvancedSearch"

            $searchStatus.Visibility = 'Visible'
            $searchStatus.Text = "Search failed. Please check the logs."

            # Re-enable search button
            $searchButton.IsEnabled = $true
            $searchButton.Content = "Search"

            [System.Windows.MessageBox]::Show(
                "An error occurred during search:`n`n$($_.Exception.Message)`n`nPlease check the logs for details.",
                "Search Error",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error
            )
        }
    }

    # Wire up search box events
    $searchBox.Add_TextChanged({
        if ($searchBox.Text.Length -eq 0) {
            $searchPlaceholder.Visibility = 'Visible'
        }
        else {
            $searchPlaceholder.Visibility = 'Collapsed'
        }
    })

    $searchBox.Add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq 'Return') {
            & $performSearch -SearchTerm $searchBox.Text
        }
    })

    # Search button click
    $searchButton.Add_Click({
        & $performSearch -SearchTerm $searchBox.Text
    })

    # Double-click on DataGrid row to open JSON file
    $resultsDataGrid.Add_MouseDoubleClick({
        param($sender, $e)

        if ($resultsDataGrid.SelectedItem) {
            $selectedPolicy = $resultsDataGrid.SelectedItem
            $policyName = $selectedPolicy.PolicyName

            Write-LogInfo -Message "User double-clicked policy: $policyName" -Source "AdvancedSearch"

            # Find the JSON file for this policy
            $cacheFolder = Join-Path $env:TEMP "IntuneAdmin\PolicyCache"
            $jsonFiles = Get-ChildItem -Path $cacheFolder -Filter "*.json" -File

            foreach ($file in $jsonFiles) {
                try {
                    $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
                    if ($content.Policy.displayName -eq $policyName) {
                        Write-LogInfo -Message "Opening JSON file: $($file.FullName)" -Source "AdvancedSearch"
                        Start-Process $file.FullName
                        break
                    }
                }
                catch {
                    Write-LogWarning -Message "Error checking file $($file.Name): $($_.Exception.Message)" -Source "AdvancedSearch"
                }
            }
        }
    })

    # Close button
    $closeButton.Add_Click({
        Write-LogInfo -Message "Close button clicked" -Source "AdvancedSearch"
        $searchWindow.Close()
    })

    # Add unhandled exception handler for the window
    $searchWindow.Add_Loaded({
        Write-LogInfo -Message "Search window loaded and displayed" -Source "AdvancedSearch"
    })

    $searchWindow.Add_Closing({
        param($sender, $e)
        Write-LogInfo -Message "Search window closing" -Source "AdvancedSearch"
    })

    # Set window owner and show
    try {
        Write-LogInfo -Message "Setting window owner and preparing to show dialog" -Source "AdvancedSearch"
        $searchWindow.Owner = $Window

        Write-LogInfo -Message "Showing Advanced Search dialog..." -Source "AdvancedSearch"
        $dialogResult = $searchWindow.ShowDialog()
        Write-LogInfo -Message "Advanced Search dialog closed with result: $dialogResult" -Source "AdvancedSearch"
    }
    catch {
        Write-LogError -Message "Error showing Advanced Search dialog: $($_.Exception.Message)" -Source "AdvancedSearch"
        [System.Windows.MessageBox]::Show(
            "Failed to display search dialog:`n$($_.Exception.Message)",
            "Dialog Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
}

function Show-ConfigurationDetails {
    param(
        [string]$PolicyType
    )

    Write-LogInfo -Message "Showing details for: $PolicyType" -Source "Configurations"

    # Filter policies based on type
    $policies = @()

    switch ($PolicyType) {
        "Settings Catalog" {
            if (-not $script:ConfigProfiles) {
                [System.Windows.MessageBox]::Show("Please fetch configuration profiles first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:ConfigProfiles | Where-Object { $_.policySource -eq 'SettingsCatalog' })
        }
        "Device Restrictions" {
            if (-not $script:ConfigProfiles) {
                [System.Windows.MessageBox]::Show("Please fetch configuration profiles first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:ConfigProfiles | Where-Object { $_.policySource -eq 'DeviceConfiguration' -and $_.'@odata.type' -eq '#microsoft.graph.windows10GeneralConfiguration' })
        }
        "Administrative Templates" {
            if (-not $script:ConfigProfiles) {
                [System.Windows.MessageBox]::Show("Please fetch configuration profiles first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:ConfigProfiles | Where-Object { $_.policySource -eq 'AdminTemplate' })
        }
        "Firewall" {
            if (-not $script:EndpointSecurityPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch endpoint security policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:EndpointSecurityPolicies.Intents | Where-Object { $_.displayName -like '*Firewall*' -or $_.templateDisplayName -like '*Firewall*' })
        }
        "EDR" {
            if (-not $script:EndpointSecurityPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch endpoint security policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:EndpointSecurityPolicies.Intents | Where-Object { $_.displayName -like '*EDR*' -or $_.displayName -like '*Endpoint Detection*' -or $_.templateDisplayName -like '*Endpoint Detection*' })
        }
        "Attack Surface Reduction" {
            if (-not $script:EndpointSecurityPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch endpoint security policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:EndpointSecurityPolicies.Intents | Where-Object { $_.displayName -like '*ASR*' -or $_.displayName -like '*Attack Surface*' -or $_.templateDisplayName -like '*Attack Surface*' })
        }
        "Account Protection" {
            if (-not $script:EndpointSecurityPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch endpoint security policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:EndpointSecurityPolicies.Intents | Where-Object { $_.displayName -like '*Account Protection*' -or $_.templateDisplayName -like '*Account Protection*' })
        }
        "Conditional Access" {
            if (-not $script:EndpointSecurityPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch endpoint security policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:EndpointSecurityPolicies.ConditionalAccess)
        }
        "Android App Protection" {
            if (-not $script:AppProtectionPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch app protection policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:AppProtectionPolicies | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.androidManagedAppProtection' })
        }
        "iOS/iPadOS App Protection" {
            if (-not $script:AppProtectionPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch app protection policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:AppProtectionPolicies | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.iosManagedAppProtection' })
        }
    }

    if ($policies.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No $PolicyType policies found.", $PolicyType, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Load the modern policy details dialog
    try {
        $dialogXamlPath = Join-Path -Path $ResourcesPath -ChildPath 'PolicyDetailsDialog.xaml'
        if (-not (Test-Path -Path $dialogXamlPath)) {
            throw "Dialog XAML not found: $dialogXamlPath"
        }

        $dialogXaml = Get-Content -Path $dialogXamlPath -Raw
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($dialogXaml))
        $dialog = [System.Windows.Markup.XamlReader]::Load($reader)
        $reader.Close()

        # Get dialog controls
        $dialogControls = @{}
        @('DialogTitle', 'DialogSubtitle', 'SearchBox', 'SearchPlaceholder', 'PoliciesDataGrid', 'ExportButton', 'CloseButton') | ForEach-Object {
            $ctrl = $dialog.FindName($_)
            if ($ctrl) { $dialogControls[$_] = $ctrl }
        }

        # Set dialog properties
        $dialog.Owner = $Window
        $dialogControls['DialogTitle'].Text = $PolicyType
        $dialogControls['DialogSubtitle'].Text = "$($policies.Count) policies"

        # Prepare data for DataGrid
        $policyData = @($policies | ForEach-Object {
            [PSCustomObject]@{
                displayName = if ($_.displayName) { $_.displayName } elseif ($_.name) { $_.name } else { "Unnamed Policy" }
                description = if ($_.description) { $_.description } else { "No description" }
                assignments = if ($_.assignmentInfo) { $_.assignmentInfo } else { "No assignment data" }
                policyType = $_.'@odata.type' -replace '#microsoft.graph.', ''
                id = $_.id
            }
        })

        # Store full data for filtering
        $script:AllPolicyData = $policyData
        $dialogControls['PoliciesDataGrid'].ItemsSource = $policyData

        # Search box functionality
        $dialogControls['SearchBox'].Add_TextChanged({
            $searchText = $dialogControls['SearchBox'].Text.ToLower()

            if ([string]::IsNullOrWhiteSpace($searchText)) {
                $dialogControls['PoliciesDataGrid'].ItemsSource = $script:AllPolicyData
                $dialogControls['SearchPlaceholder'].Visibility = 'Visible'
            }
            else {
                $dialogControls['SearchPlaceholder'].Visibility = 'Collapsed'
                $filtered = $script:AllPolicyData | Where-Object {
                    $_.displayName.ToLower().Contains($searchText) -or
                    $_.description.ToLower().Contains($searchText) -or
                    $_.policyType.ToLower().Contains($searchText) -or
                    $_.id.ToLower().Contains($searchText)
                }
                $dialogControls['PoliciesDataGrid'].ItemsSource = $filtered
            }
        })

        # Search box focus handling for placeholder
        $dialogControls['SearchBox'].Add_GotFocus({
            if ([string]::IsNullOrWhiteSpace($dialogControls['SearchBox'].Text)) {
                $dialogControls['SearchPlaceholder'].Visibility = 'Collapsed'
            }
        })

        $dialogControls['SearchBox'].Add_LostFocus({
            if ([string]::IsNullOrWhiteSpace($dialogControls['SearchBox'].Text)) {
                $dialogControls['SearchPlaceholder'].Visibility = 'Visible'
            }
        })

        # Export button
        $dialogControls['ExportButton'].Add_Click({
            $exportData = $dialogControls['PoliciesDataGrid'].ItemsSource
            if (-not $exportData -or $exportData.Count -eq 0) {
                [System.Windows.MessageBox]::Show("No data to export.", "Export", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }

            $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
            $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
            $saveDialog.DefaultExt = ".csv"
            $saveDialog.FileName = "${PolicyType}_Policies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $saveDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

            if ($saveDialog.ShowDialog()) {
                try {
                    $exportData | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
                    [System.Windows.MessageBox]::Show("Exported $($exportData.Count) policies to:`n$($saveDialog.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                }
                catch {
                    [System.Windows.MessageBox]::Show("Failed to export:`n$($_.Exception.Message)", "Export Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                }
            }
        })

        # Close button
        $dialogControls['CloseButton'].Add_Click({
            $dialog.Close()
        })

        # Show dialog
        $dialog.ShowDialog() | Out-Null
    }
    catch {
        Write-LogError -Message "Failed to show policy details dialog: $($_.Exception.Message)" -Source "Configurations"
        [System.Windows.MessageBox]::Show(
            "Failed to show policy details:`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
}

function Show-BenchmarkDialog {
    param([string]$Category)

    Write-LogInfo -Message "Showing benchmark dialog for: $Category" -Source "Configurations"

    [System.Windows.MessageBox]::Show(
        "Benchmark functionality for $Category will be available in a future update.`n`nThis will compare your policies against industry standards (CIS, NIST).",
        "Benchmark - $Category",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information
    )
}

function Export-ConfigurationSection {
    param([string]$Section)

    Write-LogInfo -Message "Exporting $Section section..." -Source "Configurations"

    # Get policies based on section
    $policies = @()
    $sectionName = ""

    switch ($Section) {
        'ConfigurationProfiles' {
            if (-not $script:ConfigProfiles) {
                [System.Windows.MessageBox]::Show("Please fetch configuration profiles first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = $script:ConfigProfiles
            $sectionName = "ConfigurationProfiles"
        }
        'EndpointSecurity' {
            if (-not $script:EndpointSecurityPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch endpoint security policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = @($script:EndpointSecurityPolicies.Intents) + @($script:EndpointSecurityPolicies.ConditionalAccess)
            $sectionName = "EndpointSecurity"
        }
        'AppProtection' {
            if (-not $script:AppProtectionPolicies) {
                [System.Windows.MessageBox]::Show("Please fetch app protection policies first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
            $policies = $script:AppProtectionPolicies
            $sectionName = "AppProtection"
        }
    }

    if ($policies.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No policies found in $Section.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Prepare export data
    $exportData = $policies | ForEach-Object {
        [PSCustomObject]@{
            Name = if ($_.displayName) { $_.displayName } else { "Unnamed Policy" }
            Description = if ($_.description) { $_.description } else { "No description" }
            Assignments = if ($_.assignmentInfo) { $_.assignmentInfo } else { "No assignment data" }
            Type = $_.'@odata.type' -replace '#microsoft.graph.', ''
            ID = $_.id
            CreatedDateTime = $_.createdDateTime
            LastModifiedDateTime = $_.lastModifiedDateTime
        }
    }

    # Show save dialog
    $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveDialog.DefaultExt = ".csv"
    $saveDialog.FileName = "${sectionName}_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $saveDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

    if ($saveDialog.ShowDialog()) {
        try {
            $exportData | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            Write-LogInfo -Message "Exported $($exportData.Count) policies to $($saveDialog.FileName)" -Source "Configurations"
            [System.Windows.MessageBox]::Show(
                "Successfully exported $($exportData.Count) policies to:`n$($saveDialog.FileName)",
                "Export Complete",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            )
        }
        catch {
            Write-LogError -Message "Failed to export: $($_.Exception.Message)" -Source "Configurations"
            [System.Windows.MessageBox]::Show(
                "Failed to export:`n$($_.Exception.Message)",
                "Export Failed",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error
            )
        }
    }
}
#endregion

#region Permission Display Functions
function Update-PermissionsDisplay {
    $permGrid = $controls['PermissionsGrid']
    if (-not $permGrid) { return }

    $permGrid.Children.Clear()

    $authState = Get-AuthenticationState
    if (-not $authState.IsAuthenticated) {
        $textBlock = [System.Windows.Controls.TextBlock]::new()
        $textBlock.Text = "Please authenticate to view permissions."
        $textBlock.Foreground = $Window.Resources['TextSecondaryBrush']
        $textBlock.SetValue([System.Windows.Controls.Grid]::ColumnSpanProperty, 3)
        $permGrid.Children.Add($textBlock)
        return
    }

    $categories = Get-CategoryAccessSummary

    $col = 0
    foreach ($category in $categories) {
        $stackPanel = [System.Windows.Controls.StackPanel]::new()
        $stackPanel.Margin = [System.Windows.Thickness]::new(0, 0, 20, 16)
        $stackPanel.SetValue([System.Windows.Controls.Grid]::ColumnProperty, $col)

        # Category header
        $header = [System.Windows.Controls.StackPanel]::new()
        $header.Orientation = 'Horizontal'
        $header.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)

        $indicator = [System.Windows.Shapes.Ellipse]::new()
        $indicator.Width = 10
        $indicator.Height = 10
        $indicator.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
        $indicator.Fill = switch ($category.AccessLevel) {
            'Full' { $Window.Resources['SuccessBrush'] }
            'Partial' { $Window.Resources['WarningBrush'] }
            'None' { $Window.Resources['ErrorBrush'] }
        }
        $header.Children.Add($indicator)

        $titleText = [System.Windows.Controls.TextBlock]::new()
        $titleText.Text = $category.DisplayName
        $titleText.FontWeight = 'SemiBold'
        $titleText.Foreground = $Window.Resources['TextPrimaryBrush']
        $header.Children.Add($titleText)

        $stackPanel.Children.Add($header)

        # Access level text
        $accessText = [System.Windows.Controls.TextBlock]::new()
        $accessText.Text = "$($category.AccessibleCount) of $($category.TotalCount) features"
        $accessText.FontSize = 12
        $accessText.Foreground = $Window.Resources['TextSecondaryBrush']
        $stackPanel.Children.Add($accessText)

        $permGrid.Children.Add($stackPanel)

        $col++
        if ($col -ge 3) { $col = 0 }
    }
}
#endregion

#region Authentication Functions
function Start-Authentication {
    # Update UI to show signing in state
    if ($controls['HeaderSignInButton']) { $controls['HeaderSignInButton'].Visibility = 'Collapsed' }
    if ($controls['SigningInPanel']) { $controls['SigningInPanel'].Visibility = 'Visible' }
    if ($controls['WelcomeSignInButton']) { $controls['WelcomeSignInButton'].IsEnabled = $false }

    Write-LogInfo -Message "Starting authentication..." -Source 'Authentication'

    # Check if MSAL library is available
    $msalAvailable = $false
    try {
        # Try to load from Az.Accounts first
        $azModule = Get-Module -Name Az.Accounts -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        if ($azModule) {
            $moduleDir = Split-Path -Parent $azModule.Path

            # Check multiple possible locations for MSAL DLL
            $possiblePaths = @(
                'PreloadAssemblies\Microsoft.Identity.Client.dll',
                'lib\netstandard2.0\Microsoft.Identity.Client.dll',
                'Dependencies\Microsoft.Identity.Client.dll'
            )

            foreach ($relativePath in $possiblePaths) {
                $msalPath = Join-Path -Path $moduleDir -ChildPath $relativePath
                if (Test-Path -Path $msalPath) {
                    $msalAvailable = $true
                    break
                }
            }
        }

        # Try MSAL.PS if Az.Accounts not found
        if (-not $msalAvailable) {
            $msalModule = Get-Module -Name MSAL.PS -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
            if ($msalModule) {
                $msalAvailable = $true
            }
        }
    }
    catch {
        $msalAvailable = $false
    }

    # Show error if MSAL not found
    if (-not $msalAvailable) {
        if ($controls['HeaderSignInButton']) { $controls['HeaderSignInButton'].Visibility = 'Visible' }
        if ($controls['SigningInPanel']) { $controls['SigningInPanel'].Visibility = 'Collapsed' }
        if ($controls['WelcomeSignInButton']) { $controls['WelcomeSignInButton'].IsEnabled = $true }

        $result = [System.Windows.MessageBox]::Show(
            "The Microsoft Authentication Library (MSAL) is required for sign-in.`n`nWould you like to install it now?`n`nThis will run:`nInstall-Module Az.Accounts -Scope CurrentUser -Force",
            "Authentication Library Required",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning
        )

        if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
            # Install Az.Accounts module
            try {
                if ($controls['StatusMessageText']) {
                    $controls['StatusMessageText'].Text = "Installing Az.Accounts module..."
                }

                $installJob = Start-Job -ScriptBlock {
                    Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber
                }

                # Wait for installation with timeout
                $installJob | Wait-Job -Timeout 120 | Out-Null

                if ($installJob.State -eq 'Completed') {
                    $result = [System.Windows.MessageBox]::Show(
                        "Az.Accounts module installed successfully!`n`nThe application needs to restart to use the new module.`n`nRestart now?",
                        "Installation Complete - Restart Required",
                        [System.Windows.MessageBoxButton]::YesNo,
                        [System.Windows.MessageBoxImage]::Information
                    )

                    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
                        # Restart the application
                        $scriptPath = $PSCommandPath
                        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" -WindowStyle Hidden
                        $Window.Close()
                    }
                    else {
                        if ($controls['StatusMessageText']) {
                            $controls['StatusMessageText'].Text = "Please restart the application to use Az.Accounts module"
                        }
                    }
                }
                else {
                    [System.Windows.MessageBox]::Show(
                        "Installation timed out or failed.`n`nPlease run manually:`nInstall-Module Az.Accounts -Scope CurrentUser -Force",
                        "Installation Failed",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error
                    )
                }
                Remove-Job -Job $installJob -Force
            }
            catch {
                [System.Windows.MessageBox]::Show(
                    "Failed to install Az.Accounts module.`n`nError: $($_.Exception.Message)`n`nPlease install manually:`nInstall-Module Az.Accounts -Scope CurrentUser -Force",
                    "Installation Error",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error
                )
            }
        }
        else {
            if ($controls['StatusMessageText']) {
                $controls['StatusMessageText'].Text = "Authentication requires Az.Accounts module"
            }
        }

        Write-LogWarning -Message "MSAL library not found. Authentication aborted." -Source 'Authentication'
        return
    }

    # Run authentication directly (MSAL handles async browser interaction)
    Write-LogInfo -Message "Calling Connect-IntuneAdmin -Interactive" -Source "Authentication"
    $success = Connect-IntuneAdmin -Interactive
    Write-LogInfo -Message "Connect-IntuneAdmin returned: $success" -Source "Authentication"

    if ($success) {
        Write-LogInfo -Message "Authentication succeeded, updating UI" -Source "Authentication"
        $authState = Get-AuthenticationState

        # Hide signing in panel
        if ($controls['SigningInPanel']) { $controls['SigningInPanel'].Visibility = 'Collapsed' }

        # Show user profile section
        if ($controls['UserProfileSection']) { $controls['UserProfileSection'].Visibility = 'Visible' }

        # Update user info in header
        $displayName = $authState.DisplayName
        if ($displayName) {
            if ($controls['HeaderUserName']) { $controls['HeaderUserName'].Text = $displayName }
            $initials = ($displayName -split ' ' | ForEach-Object { $_[0] }) -join ''
            if ($controls['HeaderUserInitials']) {
                $controls['HeaderUserInitials'].Text = $initials.Substring(0, [Math]::Min(2, $initials.Length)).ToUpper()
            }
        }
        if ($controls['HeaderUserEmail']) {
            $controls['HeaderUserEmail'].Text = if ($authState.UserPrincipalName) { $authState.UserPrincipalName } else { $authState.TenantId }
        }

        # Update connection status
        if ($controls['ConnectionStatusText']) { $controls['ConnectionStatusText'].Text = "Connected" }
        if ($controls['ConnectionIndicator']) { $controls['ConnectionIndicator'].Fill = $Window.Resources['SuccessBrush'] }

        # Hide welcome view and show dashboard
        if ($controls['WelcomeView']) { $controls['WelcomeView'].Visibility = 'Collapsed' }
        if ($controls['DashboardView']) { $controls['DashboardView'].Visibility = 'Visible' }

        # Enable navigation buttons and hide lock icons based on permissions
        foreach ($viewName in $script:NavButtons.Keys) {
            $navInfo = $script:NavButtons[$viewName]
            $button = $navInfo.Button
            $lockIcon = $navInfo.Lock

            if ($button -and $viewName -ne 'Dashboard') {
                $button.IsEnabled = $true
                if ($lockIcon) { $lockIcon.Visibility = 'Collapsed' }
            }
        }

        # Enable search box
        if ($controls['SearchBox']) { $controls['SearchBox'].IsEnabled = $true }

        # Re-enable welcome sign in button (in case they sign out later)
        if ($controls['WelcomeSignInButton']) { $controls['WelcomeSignInButton'].IsEnabled = $true }

        Write-LogInfo -Message "UI update completed successfully" -Source "Authentication"
    }
    else {
        Write-LogWarning -Message "Authentication failed - Connect-IntuneAdmin returned false" -Source "Authentication"

        # Show error and restore sign in button
        if ($controls['SigningInPanel']) { $controls['SigningInPanel'].Visibility = 'Collapsed' }
        if ($controls['HeaderSignInButton']) { $controls['HeaderSignInButton'].Visibility = 'Visible' }
        if ($controls['WelcomeSignInButton']) { $controls['WelcomeSignInButton'].IsEnabled = $true }
        if ($controls['StatusMessageText']) { $controls['StatusMessageText'].Text = "Authentication failed. Please try again." }
    }
}

function Start-TokenRefresh {
    Write-LogInfo -Message "Force refreshing authentication token (clearing cache)..." -Source 'Authentication'

    try {
        # Clear the token cache to force a fresh login with updated permissions (important for PIM)
        Disconnect-IntuneAdmin -ClearCache
        Write-LogInfo -Message "Token cache cleared, initiating fresh authentication" -Source 'Authentication'

        # Force interactive login to get fresh token with current PIM roles
        $success = Connect-IntuneAdmin -Interactive
        if ($success) {
            $controls['StatusMessageText'].Text = "Token refreshed successfully with updated permissions"
            Write-LogInfo -Message "Token refreshed with updated permissions" -Source 'Authentication'

            # Update permissions display to show new permissions
            Update-PermissionsDisplay
        }
        else {
            $controls['StatusMessageText'].Text = "Token refresh failed"
            Write-LogWarning -Message "Token refresh failed" -Source 'Authentication'
        }
    }
    catch {
        $controls['StatusMessageText'].Text = "Token refresh error: $($_.Exception.Message)"
        Write-LogError -Message "Token refresh error: $_" -Source 'Authentication'
    }
}

function Start-SignOut {
    try {
        Disconnect-IntuneAdmin -ClearCache
        Write-LogInfo -Message "User signed out and token cache cleared" -Source 'Authentication'

        # Close dropdown if open
        if ($controls['UserDropdownPopup']) { $controls['UserDropdownPopup'].IsOpen = $false }

        # Hide user profile section and show sign in button
        if ($controls['UserProfileSection']) { $controls['UserProfileSection'].Visibility = 'Collapsed' }
        if ($controls['HeaderSignInButton']) { $controls['HeaderSignInButton'].Visibility = 'Visible' }

        # Reset user info
        if ($controls['HeaderUserName']) { $controls['HeaderUserName'].Text = "User Name" }
        if ($controls['HeaderUserEmail']) { $controls['HeaderUserEmail'].Text = "user@tenant.onmicrosoft.com" }
        if ($controls['HeaderUserInitials']) { $controls['HeaderUserInitials'].Text = "U" }

        # Update connection status
        if ($controls['ConnectionStatusText']) { $controls['ConnectionStatusText'].Text = "Not signed in" }
        if ($controls['ConnectionIndicator']) { $controls['ConnectionIndicator'].Fill = $Window.Resources['TextDisabledBrush'] }

        # Show welcome view and hide dashboard
        if ($controls['DashboardView']) { $controls['DashboardView'].Visibility = 'Collapsed' }
        if ($controls['PlaceholderView']) { $controls['PlaceholderView'].Visibility = 'Collapsed' }
        if ($controls['SettingsView']) { $controls['SettingsView'].Visibility = 'Collapsed' }
        if ($controls['WelcomeView']) { $controls['WelcomeView'].Visibility = 'Visible' }

        # Disable navigation buttons and show lock icons
        Update-NavigationState -IsAuthenticated $false

        # Clear status message
        if ($controls['StatusMessageText']) { $controls['StatusMessageText'].Text = "" }
    }
    catch {
        Write-LogError -Message "Sign out error: $_" -Source 'Authentication'
    }
}
#endregion

#region Device Ownership Functions

function Get-GroupDeviceOwnershipAnalysis {
    <#
    .SYNOPSIS
        Analyzes device ownership for members of a specified Entra ID group.
    .PARAMETER GroupId
        The GUID of the Entra ID user group to analyze.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    try {
        Write-LogInfo -Message "Starting Device Ownership Analysis for group: $GroupId" -Source 'DeviceOwnership'

        # Initialize result collections
        $usersNoDevices = [System.Collections.ArrayList]::new()
        $usersMultipleDevices = [System.Collections.ArrayList]::new()
        $usersSingleDevice = [System.Collections.ArrayList]::new()
        $totalDeviceCount = 0
        $processedCount = 0
        $errorCount = 0

        # Get all group members with pagination
        Write-LogInfo -Message "Fetching group members..." -Source 'DeviceOwnership'
        $allMembers = [System.Collections.ArrayList]::new()
        $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,userPrincipalName,displayName,mail"

        while ($uri) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
            if ($response.value) {
                $users = $response.value | Where-Object {
                    $_.'@odata.type' -eq '#microsoft.graph.user' -or $null -ne $_.userPrincipalName
                }
                foreach ($user in $users) {
                    [void]$allMembers.Add($user)
                }
            }
            $uri = $response.'@odata.nextLink'
        }

        if (-not $allMembers -or $allMembers.Count -eq 0) {
            Write-LogInfo -Message "No user members found in group" -Source 'DeviceOwnership'
            return @{
                Success = $true
                Message = "No user members found in group"
                UsersWithNoDevices = @()
                UsersWithMultipleDevices = @()
                UsersWithSingleDevice = @()
                Summary = @{
                    TotalUsers = 0
                    TotalDevices = 0
                    UsersWithNoDevices = 0
                    UsersWithMultipleDevices = 0
                    UsersWithSingleDevice = 0
                }
            }
        }

        Write-LogInfo -Message "Found $($allMembers.Count) user members, fetching all Intune devices..." -Source 'DeviceOwnership'

        # Get ALL managed devices from Intune (this is how the original script does it)
        $allDevices = [System.Collections.ArrayList]::new()
        $deviceUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,operatingSystem,model,userId"

        while ($deviceUri) {
            $devResponse = Invoke-MgGraphRequest -Method GET -Uri $deviceUri -OutputType PSObject
            if ($devResponse.value) {
                foreach ($device in $devResponse.value) {
                    [void]$allDevices.Add($device)
                }
            }
            $deviceUri = $devResponse.'@odata.nextLink'
        }

        Write-LogInfo -Message "Retrieved $($allDevices.Count) total devices from Intune" -Source 'DeviceOwnership'

        # Build user ID to devices mapping
        $userDeviceMap = @{}
        $devicesWithoutUserId = 0
        foreach ($device in $allDevices) {
            if ($device.userId) {
                if (-not $userDeviceMap.ContainsKey($device.userId)) {
                    $userDeviceMap[$device.userId] = [System.Collections.ArrayList]::new()
                }
                [void]$userDeviceMap[$device.userId].Add($device)
            } else {
                $devicesWithoutUserId++
            }
        }

        Write-LogInfo -Message "Built device map with $($userDeviceMap.Count) unique users, $devicesWithoutUserId devices without userId" -Source 'DeviceOwnership'

        # Debug: Show first few user IDs in the map
        $mapKeys = @($userDeviceMap.Keys | Select-Object -First 3)
        Write-LogInfo -Message "DEBUG: First 3 device map keys: $($mapKeys -join ', ')" -Source 'DeviceOwnership'

        Write-LogInfo -Message "Analyzing device ownership for $($allMembers.Count) users..." -Source 'DeviceOwnership'

        # Process each user
        foreach ($user in $allMembers) {
            $processedCount++

            try {
                # Get device count DIRECTLY from hashtable to avoid PowerShell unwrapping
                if ($userDeviceMap.ContainsKey($user.id)) {
                    # Access the ArrayList directly and get its Count
                    $deviceList = $userDeviceMap[$user.id]
                    $deviceCount = $deviceList.Count
                    # Force to array to prevent unwrapping when accessing items
                    $userDevices = [array]$deviceList
                } else {
                    $deviceCount = 0
                    $userDevices = @()
                }

                $totalDeviceCount += $deviceCount

                $userInfo = @{
                    UserPrincipalName = $user.userPrincipalName
                    DisplayName = $user.displayName
                    UserId = $user.id
                    Email = $user.mail
                }

                # Debug log for first 3 users to see what's happening
                if ($processedCount -le 3) {
                    $foundInMap = $userDeviceMap.ContainsKey($user.id)
                    Write-LogInfo -Message "DEBUG: User $($user.userPrincipalName), ID: $($user.id), Found in map: $foundInMap, DeviceCount: $deviceCount" -Source 'DeviceOwnership'
                }

                # Special debug for Wilco Versteeg
                if ($user.userPrincipalName -like '*wilco.versteeg*') {
                    $foundInMap = $userDeviceMap.ContainsKey($user.id)
                    Write-LogInfo -Message "DEBUG WILCO: User ID: $($user.id), Found in device map: $foundInMap, DeviceCount: $deviceCount" -Source 'DeviceOwnership'
                    Write-LogInfo -Message "DEBUG WILCO: userDevices type: $($userDevices.GetType().Name), Count property: $($userDevices.Count)" -Source 'DeviceOwnership'

                    if ($foundInMap) {
                        $rawList = $userDeviceMap[$user.id]
                        Write-LogInfo -Message "DEBUG WILCO: Raw ArrayList from map - Type: $($rawList.GetType().Name), Count: $($rawList.Count)" -Source 'DeviceOwnership'
                        if ($rawList.Count -gt 0) {
                            Write-LogInfo -Message "DEBUG WILCO: First device in list: $($rawList[0].deviceName)" -Source 'DeviceOwnership'
                        }
                    }

                    # Search all devices for this user
                    $wilcoAllDevices = $allDevices | Where-Object { $_.userId -eq $user.id }
                    Write-LogInfo -Message "DEBUG WILCO: Direct device search found: $($wilcoAllDevices.Count) devices" -Source 'DeviceOwnership'
                    if ($wilcoAllDevices.Count -gt 0) {
                        Write-LogInfo -Message "DEBUG WILCO: Device names: $($wilcoAllDevices.deviceName -join ', ')" -Source 'DeviceOwnership'
                    }
                }

                if ($deviceCount -eq 0) {
                    [void]$usersNoDevices.Add($userInfo)
                }
                elseif ($deviceCount -eq 1) {
                    $userInfo['DeviceCount'] = 1
                    # Add null checks for device properties
                    if ($userDevices[0] -and $userDevices[0].deviceName) {
                        $userInfo['DeviceName'] = $userDevices[0].deviceName
                    } else {
                        $userInfo['DeviceName'] = 'Unknown'
                    }
                    if ($userDevices[0] -and $userDevices[0].operatingSystem) {
                        $userInfo['DeviceOS'] = $userDevices[0].operatingSystem
                    } else {
                        $userInfo['DeviceOS'] = 'Unknown'
                    }
                    [void]$usersSingleDevice.Add($userInfo)
                }
                else {
                    $deviceNames = ($userDevices | Where-Object { $_ -and $_.deviceName } | ForEach-Object { $_.deviceName }) -join '; '
                    $userInfo['DeviceCount'] = $deviceCount
                    $userInfo['DeviceNames'] = if ($deviceNames) { $deviceNames } else { 'Unknown devices' }
                    $userInfo['Devices'] = @($userDevices)
                    [void]$usersMultipleDevices.Add($userInfo)
                }
            }
            catch {
                $errorCount++
                Write-LogError -Message "Error processing user $($user.userPrincipalName): $($_.Exception.Message)" -Source 'DeviceOwnership'
            }

            if ($processedCount % 10 -eq 0) {
                Write-LogInfo -Message "Progress: $processedCount/$($allMembers.Count) users processed" -Source 'DeviceOwnership'
            }
        }

        $summary = @{
            TotalUsers = $allMembers.Count
            TotalDevices = $totalDeviceCount
            UsersWithNoDevices = $usersNoDevices.Count
            UsersWithMultipleDevices = $usersMultipleDevices.Count
            UsersWithSingleDevice = $usersSingleDevice.Count
        }

        Write-LogInfo -Message "Analysis complete. Total users: $($summary.TotalUsers), No devices: $($summary.UsersWithNoDevices), Single device: $($summary.UsersWithSingleDevice), Multiple devices: $($summary.UsersWithMultipleDevices)" -Source 'DeviceOwnership'

        return @{
            Success = $true
            Message = "Device ownership analysis completed successfully"
            GroupId = $GroupId
            UsersWithNoDevices = @($usersNoDevices)
            UsersWithMultipleDevices = @($usersMultipleDevices)
            UsersWithSingleDevice = @($usersSingleDevice)
            Summary = $summary
        }
    }
    catch {
        Write-LogError -Message "Device ownership analysis failed: $($_.Exception.Message)" -Source 'DeviceOwnership'
        return @{
            Success = $false
            Message = $_.Exception.Message
            GroupId = $GroupId
            UsersWithNoDevices = @()
            UsersWithMultipleDevices = @()
            UsersWithSingleDevice = @()
            Summary = $null
        }
    }
}

#endregion

#region Event Handlers
# Header sign-in button click
if ($controls['HeaderSignInButton']) {
    $controls['HeaderSignInButton'].Add_Click({
        Start-Authentication
    })
}

# Welcome view sign-in button click
if ($controls['WelcomeSignInButton']) {
    $controls['WelcomeSignInButton'].Add_Click({
        Start-Authentication
    })
}

# User profile button click (toggle dropdown)
if ($controls['UserProfileButton']) {
    $controls['UserProfileButton'].Add_Click({
        if ($controls['UserDropdownPopup']) {
            $controls['UserDropdownPopup'].IsOpen = -not $controls['UserDropdownPopup'].IsOpen
        }
    })
}

# Dropdown menu: Refresh Token
if ($controls['MenuRefreshToken']) {
    $controls['MenuRefreshToken'].Add_Click({
        if ($controls['UserDropdownPopup']) { $controls['UserDropdownPopup'].IsOpen = $false }
        Start-TokenRefresh
    })
}

# Dropdown menu: Settings
if ($controls['MenuSettings']) {
    $controls['MenuSettings'].Add_Click({
        if ($controls['UserDropdownPopup']) { $controls['UserDropdownPopup'].IsOpen = $false }
        Show-View -ViewName 'Settings'
    })
}

# Dropdown menu: Sign Out
if ($controls['MenuSignOut']) {
    $controls['MenuSignOut'].Add_Click({
        $result = [System.Windows.MessageBox]::Show(
            "Are you sure you want to sign out?",
            "Sign Out",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Question
        )
        if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
            Start-SignOut
        }
    })
}

# Navigation button clicks
if ($controls['NavDashboard']) {
    $controls['NavDashboard'].Add_Click({
        Show-View -ViewName 'Dashboard'
        Update-SelectedNavButton -ViewName 'Dashboard'
    })
}

if ($controls['NavApps']) {
    $controls['NavApps'].Add_Click({
        Show-View -ViewName 'Applications'
        Update-SelectedNavButton -ViewName 'Applications'
    })
}

if ($controls['NavConfiguration']) {
    $controls['NavConfiguration'].Add_Click({
        Show-View -ViewName 'Configuration'
        Update-SelectedNavButton -ViewName 'Configuration'
    })
}

if ($controls['NavAssignments']) {
    $controls['NavAssignments'].Add_Click({
        Show-View -ViewName 'Assignments'
        Update-SelectedNavButton -ViewName 'Assignments'
    })
}

if ($controls['NavDeviceOwnership']) {
    $controls['NavDeviceOwnership'].Add_Click({
        Show-View -ViewName 'Device Ownership'
        Update-SelectedNavButton -ViewName 'Device Ownership'
    })
}

if ($controls['NavRemediation']) {
    $controls['NavRemediation'].Add_Click({
        Show-View -ViewName 'Remediation'
        Update-SelectedNavButton -ViewName 'Remediation'
    })
}

if ($controls['NavBulkOps']) {
    $controls['NavBulkOps'].Add_Click({
        Show-View -ViewName 'BulkOps'
        Update-SelectedNavButton -ViewName 'BulkOps'
    })
}

#region Backup Functions
function Start-IntuneBackup {
    param(
        [string]$BackupPath,
        [bool]$IncludeAssignments,
        [bool]$ExcludeBuiltIn,
        [string]$ApiVersion,
        [hashtable]$SelectedCategories
    )

    $startTime = Get-Date

    # Create backup folder with timestamp
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $backupFolder = Join-Path -Path $BackupPath -ChildPath $timestamp

    try {
        New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
        Write-LogInfo -Message "Created backup folder: $backupFolder" -Source 'Backup'
    }
    catch {
        $controls['BackupProgressCard'].Visibility = 'Collapsed'
        $controls['BackupResultsCard'].Visibility = 'Visible'
        $controls['BackupResultIcon'].Text = [char]0xE711
        $controls['BackupResultIcon'].Foreground = $window.FindResource('ErrorBrush')
        $controls['BackupResultTitle'].Text = 'Backup Failed'
        $controls['BackupResultMessage'].Text = "Failed to create backup folder:`n$($_.Exception.Message)"
        $controls['BackupStatsGrid'].Visibility = 'Collapsed'

        # Re-enable controls
        $controls['StartBackupButton'].IsEnabled = $true
        $controls['BrowseBackupPathButton'].IsEnabled = $true
        $controls['IncludeAssignmentsCheckBox'].IsEnabled = $true
        $controls['ExcludeBuiltInCheckBox'].IsEnabled = $true
        $controls['ApiVersionV1RadioButton'].IsEnabled = $true
        $controls['ApiVersionBetaRadioButton'].IsEnabled = $true
        return
    }

    # Define backup operations
    $baseUri = "https://graph.microsoft.com/$ApiVersion"
    $operations = @(
        @{ Name = 'Device Compliance Policies'; Uri = "$baseUri/deviceManagement/deviceCompliancePolicies"; Folder = 'Device Compliance Policies'; Category = 'Compliance' }
        @{ Name = 'Device Configurations'; Uri = "$baseUri/deviceManagement/deviceConfigurations"; Folder = 'Device Configurations'; Category = 'Configurations' }
        @{ Name = 'Settings Catalog'; Uri = "$baseUri/deviceManagement/configurationPolicies"; Folder = 'Settings Catalog'; Category = 'SettingsCatalog' }
        @{ Name = 'Device Management Scripts'; Uri = "$baseUri/deviceManagement/deviceManagementScripts"; Folder = 'Device Management Scripts'; Category = 'Scripts' }
        @{ Name = 'Proactive Remediations'; Uri = "$baseUri/deviceManagement/deviceHealthScripts"; Folder = 'Proactive Remediations'; Category = 'Remediations' }
        @{ Name = 'Applications'; Uri = "$baseUri/deviceAppManagement/mobileApps"; Folder = 'Applications'; Category = 'Applications' }
        @{ Name = 'Autopilot Profiles'; Uri = "$baseUri/deviceManagement/windowsAutopilotDeploymentProfiles"; Folder = 'Autopilot Profiles'; Category = 'Autopilot' }
        @{ Name = 'Endpoint Security'; Uri = "$baseUri/deviceManagement/intents"; Folder = 'Endpoint Security'; Category = 'EndpointSecurity' }
        @{ Name = 'Administrative Templates'; Uri = "$baseUri/deviceManagement/groupPolicyConfigurations"; Folder = 'Administrative Templates'; Category = 'AdminTemplates' }
    )

    # Filter operations based on selected categories
    if ($SelectedCategories) {
        $operations = $operations | Where-Object {
            $category = $_.Category
            $SelectedCategories[$category] -eq $true
        }
    }

    $totalItems = 0
    $totalFiles = 0
    $currentOp = 0

    foreach ($op in $operations) {
        $currentOp++
        $controls['BackupStatusText'].Text = "Backing up $($op.Name)..."
        $controls['BackupCurrentItemText'].Text = "Operation $currentOp of $($operations.Count)"

        try {
            # Create folder for this resource type
            $opFolder = Join-Path -Path $backupFolder -ChildPath $op.Folder
            New-Item -Path $opFolder -ItemType Directory -Force | Out-Null

            # Fetch all items with pagination
            $allItems = @()
            $uri = $op.Uri

            while ($uri) {
                try {
                    $response = Invoke-GraphRequest -Uri $uri -Method GET

                    if ($response.value) {
                        $allItems += $response.value
                    }

                    # Handle pagination
                    $uri = $response.'@odata.nextLink'
                }
                catch {
                    Write-LogError -Message "Failed to fetch $($op.Name): $($_.Exception.Message)" -Source 'Backup'
                    $uri = $null
                }
            }

            # Save items to JSON files
            if ($allItems.Count -gt 0) {
                $filteredItems = if ($ExcludeBuiltIn -and $op.Name -eq 'Proactive Remediations') {
                    # Only filter built-in items for Proactive Remediations
                    $allItems | Where-Object {
                        $_.publisher -ne 'Microsoft'
                    }
                } else {
                    $allItems
                }

                # Create Script Content subfolder if needed
                if ($op.Name -in @('Device Management Scripts', 'Proactive Remediations')) {
                    $scriptContentFolder = Join-Path -Path $opFolder -ChildPath 'Script Content'
                    New-Item -Path $scriptContentFolder -ItemType Directory -Force | Out-Null
                }

                foreach ($item in $filteredItems) {
                    $itemName = $item.displayName -replace '[\\/:*?"<>|]', '_'
                    $itemId = $item.id
                    $fileName = "${itemName}.json"
                    $filePath = Join-Path -Path $opFolder -ChildPath $fileName

                    # Get full details for scripts (includes script content)
                    if ($op.Name -in @('Device Management Scripts', 'Proactive Remediations')) {
                        try {
                            $detailUri = "$($op.Uri)/$itemId"
                            $item = Invoke-GraphRequest -Uri $detailUri -Method GET
                        }
                        catch {
                            Write-LogError -Message "Failed to get script details for $($item.displayName): $($_.Exception.Message)" -Source 'Backup'
                        }
                    }

                    # Include assignments if requested
                    if ($IncludeAssignments -and $itemId) {
                        try {
                            $assignUri = "$($op.Uri)/$itemId/assignments"
                            $assignments = Invoke-GraphRequest -Uri $assignUri -Method GET -ErrorAction SilentlyContinue
                            $item | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments.value -Force
                        }
                        catch {
                            # Assignments not available for this resource type
                        }
                    }

                    # Save JSON metadata
                    $item | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
                    $totalFiles++

                    # Extract script content for Device Management Scripts
                    if ($op.Name -eq 'Device Management Scripts' -and $item.scriptContent) {
                        try {
                            $scriptContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($item.scriptContent))
                            $scriptFilePath = Join-Path -Path $scriptContentFolder -ChildPath "${itemName}.ps1"
                            $scriptContent | Out-File -FilePath $scriptFilePath -Encoding UTF8
                            $totalFiles++
                        }
                        catch {
                            Write-LogError -Message "Failed to extract script content for $($item.displayName): $($_.Exception.Message)" -Source 'Backup'
                        }
                    }

                    # Extract detection and remediation scripts for Proactive Remediations
                    if ($op.Name -eq 'Proactive Remediations') {
                        if ($item.detectionScriptContent) {
                            try {
                                $detectionContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($item.detectionScriptContent))
                                $detectionFilePath = Join-Path -Path $scriptContentFolder -ChildPath "${itemName}_detection.ps1"
                                $detectionContent | Out-File -FilePath $detectionFilePath -Encoding UTF8
                                $totalFiles++
                            }
                            catch {
                                Write-LogError -Message "Failed to extract detection script for $($item.displayName): $($_.Exception.Message)" -Source 'Backup'
                            }
                        }

                        if ($item.remediationScriptContent) {
                            try {
                                $remediationContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($item.remediationScriptContent))
                                $remediationFilePath = Join-Path -Path $scriptContentFolder -ChildPath "${itemName}_remediation.ps1"
                                $remediationContent | Out-File -FilePath $remediationFilePath -Encoding UTF8
                                $totalFiles++
                            }
                            catch {
                                Write-LogError -Message "Failed to extract remediation script for $($item.displayName): $($_.Exception.Message)" -Source 'Backup'
                            }
                        }
                    }
                }

                $totalItems += $filteredItems.Count
                Write-LogInfo -Message "Backed up $($filteredItems.Count) $($op.Name)" -Source 'Backup'
            }
        }
        catch {
            Write-LogError -Message "Error backing up $($op.Name): $($_.Exception.Message)" -Source 'Backup'
        }
    }

    # Create summary file
    $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    $summary = [PSCustomObject]@{
        BackupDate = $timestamp
        Duration = "$duration seconds"
        TotalItems = $totalItems
        TotalFiles = $totalFiles
        ApiVersion = $ApiVersion
        IncludeAssignments = $IncludeAssignments
        ExcludeBuiltIn = $ExcludeBuiltIn
        Operations = $operations | ForEach-Object { $_.Name }
    }

    $summaryPath = Join-Path -Path $backupFolder -ChildPath 'BackupSummary.json'
    $summary | ConvertTo-Json | Out-File -FilePath $summaryPath -Encoding UTF8

    # Update UI with results
    $controls['BackupProgressCard'].Visibility = 'Collapsed'
    $controls['BackupResultsCard'].Visibility = 'Visible'
    $controls['BackupResultIcon'].Text = [char]0xE73E
    $controls['BackupResultIcon'].Foreground = $window.FindResource('SuccessBrush')
    $controls['BackupResultTitle'].Text = 'Backup Complete'
    $controls['BackupResultMessage'].Text = "Your Intune configuration has been successfully backed up to:`n$backupFolder"

    $controls['BackupStatsGrid'].Visibility = 'Visible'
    $controls['BackupItemsCount'].Text = $totalItems.ToString()
    $controls['BackupFilesCount'].Text = $totalFiles.ToString()
    $controls['BackupDuration'].Text = "${duration}s"

    $controls['OpenBackupFolderButton'].Visibility = 'Visible'
    $controls['OpenBackupFolderButton'].Tag = $backupFolder

    # Re-enable controls
    $controls['StartBackupButton'].IsEnabled = $true
    $controls['BrowseBackupPathButton'].IsEnabled = $true
    $controls['IncludeAssignmentsCheckBox'].IsEnabled = $true
    $controls['ExcludeBuiltInCheckBox'].IsEnabled = $true
    $controls['ApiVersionV1RadioButton'].IsEnabled = $true
    $controls['ApiVersionBetaRadioButton'].IsEnabled = $true

    Write-LogInfo -Message "Backup completed: $totalItems items, $totalFiles files, ${duration}s" -Source 'Backup'
}
#endregion

if ($controls['NavBackup']) {
    $controls['NavBackup'].Add_Click({
        Show-View -ViewName 'Backup'
        Update-SelectedNavButton -ViewName 'Backup'
    })
}

# Backup view event handlers
if ($controls['BrowseBackupPathButton']) {
    $controls['BrowseBackupPathButton'].Add_Click({
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select backup destination folder"
        $folderBrowser.ShowNewFolderButton = $true

        if ($folderBrowser.ShowDialog() -eq 'OK') {
            $controls['BackupPathTextBox'].Text = $folderBrowser.SelectedPath
            # Enable the Start Backup button
            $controls['StartBackupButton'].IsEnabled = $true
        }
    })
}

# Select All checkbox handler
if ($controls['BackupSelectAllCheckBox']) {
    $controls['BackupSelectAllCheckBox'].Add_Checked({
        $controls['BackupComplianceCheckBox'].IsChecked = $true
        $controls['BackupConfigurationsCheckBox'].IsChecked = $true
        $controls['BackupSettingsCatalogCheckBox'].IsChecked = $true
        $controls['BackupScriptsCheckBox'].IsChecked = $true
        $controls['BackupRemediationsCheckBox'].IsChecked = $true
        $controls['BackupApplicationsCheckBox'].IsChecked = $true
        $controls['BackupAutopilotCheckBox'].IsChecked = $true
        $controls['BackupEndpointSecurityCheckBox'].IsChecked = $true
        $controls['BackupAdminTemplatesCheckBox'].IsChecked = $true
    })

    $controls['BackupSelectAllCheckBox'].Add_Unchecked({
        $controls['BackupComplianceCheckBox'].IsChecked = $false
        $controls['BackupConfigurationsCheckBox'].IsChecked = $false
        $controls['BackupSettingsCatalogCheckBox'].IsChecked = $false
        $controls['BackupScriptsCheckBox'].IsChecked = $false
        $controls['BackupRemediationsCheckBox'].IsChecked = $false
        $controls['BackupApplicationsCheckBox'].IsChecked = $false
        $controls['BackupAutopilotCheckBox'].IsChecked = $false
        $controls['BackupEndpointSecurityCheckBox'].IsChecked = $false
        $controls['BackupAdminTemplatesCheckBox'].IsChecked = $false
    })
}

if ($controls['StartBackupButton']) {
    $controls['StartBackupButton'].Add_Click({
        # Get backup parameters
        $backupPath = $controls['BackupPathTextBox'].Text
        $includeAssignments = $controls['IncludeAssignmentsCheckBox'].IsChecked
        $excludeBuiltIn = $controls['ExcludeBuiltInCheckBox'].IsChecked
        $apiVersion = if ($controls['ApiVersionBetaRadioButton'].IsChecked) { 'Beta' } else { 'v1.0' }

        # Get selected backup categories
        $selectedCategories = @{
            Compliance       = $controls['BackupComplianceCheckBox'].IsChecked
            Configurations   = $controls['BackupConfigurationsCheckBox'].IsChecked
            SettingsCatalog  = $controls['BackupSettingsCatalogCheckBox'].IsChecked
            Scripts          = $controls['BackupScriptsCheckBox'].IsChecked
            Remediations     = $controls['BackupRemediationsCheckBox'].IsChecked
            Applications     = $controls['BackupApplicationsCheckBox'].IsChecked
            Autopilot        = $controls['BackupAutopilotCheckBox'].IsChecked
            EndpointSecurity = $controls['BackupEndpointSecurityCheckBox'].IsChecked
            AdminTemplates   = $controls['BackupAdminTemplatesCheckBox'].IsChecked
        }

        # Validate at least one category is selected
        $hasSelection = $false
        foreach ($value in $selectedCategories.Values) {
            if ($value -eq $true) {
                $hasSelection = $true
                break
            }
        }

        if (-not $hasSelection) {
            [System.Windows.MessageBox]::Show(
                "Please select at least one category to backup.",
                "No Categories Selected",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning
            )
            return
        }

        # Validate path
        if ([string]::IsNullOrWhiteSpace($backupPath) -or $backupPath -eq 'Select a folder...') {
            [System.Windows.MessageBox]::Show(
                "Please select a backup destination folder.",
                "Backup Path Required",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning
            )
            return
        }

        # Verify authentication
        $authState = Get-AuthenticationState
        if (-not $authState.IsAuthenticated) {
            [System.Windows.MessageBox]::Show(
                "You must be signed in to perform a backup.",
                "Authentication Required",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning
            )
            return
        }

        # Disable controls during backup
        $controls['StartBackupButton'].IsEnabled = $false
        $controls['BrowseBackupPathButton'].IsEnabled = $false
        $controls['IncludeAssignmentsCheckBox'].IsEnabled = $false
        $controls['ExcludeBuiltInCheckBox'].IsEnabled = $false
        $controls['ApiVersionV1RadioButton'].IsEnabled = $false
        $controls['ApiVersionBetaRadioButton'].IsEnabled = $false

        # Show loading indicator
        $controls['BackupLoadingText'].Visibility = 'Visible'
        $controls['StartBackupButton'].Opacity = 0.5

        # Force UI to update before starting backup
        $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

        # Start backup
        Start-IntuneBackup -BackupPath $backupPath -IncludeAssignments $includeAssignments -ExcludeBuiltIn $excludeBuiltIn -ApiVersion $apiVersion -SelectedCategories $selectedCategories

        # Hide loading indicator and restore button
        $controls['BackupLoadingText'].Visibility = 'Collapsed'
        $controls['StartBackupButton'].Opacity = 1.0
    })
}

if ($controls['OpenBackupFolderButton']) {
    $controls['OpenBackupFolderButton'].Add_Click({
        $backupFolder = $controls['OpenBackupFolderButton'].Tag
        if ($backupFolder -and (Test-Path -Path $backupFolder)) {
            Start-Process explorer.exe -ArgumentList $backupFolder
        }
    })
}

if ($controls['NewBackupButton']) {
    $controls['NewBackupButton'].Add_Click({
        # Reset the view for a new backup
        $controls['BackupProgressCard'].Visibility = 'Collapsed'
        $controls['BackupResultsCard'].Visibility = 'Collapsed'
        $controls['BackupPathTextBox'].Text = 'Select a folder...'
        $controls['StartBackupButton'].IsEnabled = $false
        $controls['OpenBackupFolderButton'].Visibility = 'Collapsed'
        $controls['BackupStatsGrid'].Visibility = 'Collapsed'
    })
}

if ($controls['NavScripts']) {
    $controls['NavScripts'].Add_Click({
        Show-View -ViewName 'Scripts'
        Update-SelectedNavButton -ViewName 'Scripts'
    })
}

if ($controls['NavReports']) {
    $controls['NavReports'].Add_Click({
        Show-View -ViewName 'Reports'
        Update-SelectedNavButton -ViewName 'Reports'
    })
}

# Settings toggles
if ($controls['DarkModeToggle']) {
    $controls['DarkModeToggle'].Add_Checked({
        Set-Configuration -Section 'Theme' -Key 'Mode' -Value 'Dark' -Save
        Update-Theme -IsDark $true
    })

    $controls['DarkModeToggle'].Add_Unchecked({
        Set-Configuration -Section 'Theme' -Key 'Mode' -Value 'Light' -Save
        Update-Theme -IsDark $false
    })
}

if ($controls['ViewLogsButton']) {
    $controls['ViewLogsButton'].Add_Click({
        $logPath = Get-LogFilePath
        if (Test-Path -Path $logPath) {
            Start-Process notepad.exe -ArgumentList $logPath
        }
        else {
            [System.Windows.MessageBox]::Show(
                "No log file found at: $logPath",
                "Log File",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            )
        }
    })
}

# Add handler for hyperlinks (GitHub link in About section)
$Window.AddHandler(
    [System.Windows.Documents.Hyperlink]::RequestNavigateEvent,
    [System.Windows.RoutedEventHandler]{
        param($sender, $e)
        Start-Process $e.Uri.AbsoluteUri
        $e.Handled = $true
    }
)

if ($controls['BrowseExportPath']) {
    $controls['BrowseExportPath'].Add_Click({
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select export folder"
        $folderBrowser.SelectedPath = Get-Configuration -Section 'Data' -Key 'ExportPath'

        if ($folderBrowser.ShowDialog() -eq 'OK') {
            $controls['ExportPathTextBox'].Text = $folderBrowser.SelectedPath
            Set-Configuration -Section 'Data' -Key 'ExportPath' -Value $folderBrowser.SelectedPath -Save
        }
    })
}

# Quick action clicks
if ($controls['QuickActionRefresh']) {
    $controls['QuickActionRefresh'].Add_Click({
        Update-DashboardData
        $controls['LastRefreshText'].Text = "Last updated: $(Get-Date -Format 'HH:mm:ss')"
    })
}

# Refresh permissions button
if ($controls['RefreshPermissionsButton']) {
    $controls['RefreshPermissionsButton'].Add_Click({
        Update-PermissionsDisplay
    })
}

# Load applications button
if ($controls['LoadAppsButton']) {
    $controls['LoadAppsButton'].Add_Click({
        Load-Applications
    })
}

# Check versions button
if ($controls['CheckVersionsButton']) {
    $controls['CheckVersionsButton'].Add_Click({
        Check-WinGetVersions
    })
}

# Export applications button
if ($controls['ExportAppsButton']) {
    $controls['ExportAppsButton'].Add_Click({
        Export-Applications
    })
}

# Configuration buttons - Export buttons
if ($controls['ExportConfigProfilesButton']) {
    $controls['ExportConfigProfilesButton'].Add_Click({
        Export-ConfigurationSection -Section 'ConfigurationProfiles'
    })
}

if ($controls['ExportEndpointSecButton']) {
    $controls['ExportEndpointSecButton'].Add_Click({
        Export-ConfigurationSection -Section 'EndpointSecurity'
    })
}

if ($controls['ExportAppProtectionButton']) {
    $controls['ExportAppProtectionButton'].Add_Click({
        Export-ConfigurationSection -Section 'AppProtection'
    })
}

# Configuration buttons - Advanced Search button
if ($controls['AdvancedSearchButton']) {
    $controls['AdvancedSearchButton'].Add_Click({
        Show-AdvancedSearch
    })
}

# Configuration buttons - Fetch All button
if ($controls['FetchAllConfigurationsButton']) {
    $controls['FetchAllConfigurationsButton'].Add_Click({
        Fetch-AllConfigurations
    })
}

# Configuration buttons - Fetch buttons
if ($controls['FetchConfigProfilesButton']) {
    $controls['FetchConfigProfilesButton'].Add_Click({
        Fetch-ConfigurationProfiles
    })
}

if ($controls['FetchEndpointSecButton']) {
    $controls['FetchEndpointSecButton'].Add_Click({
        Fetch-EndpointSecurity
    })
}

if ($controls['FetchAppProtectionButton']) {
    $controls['FetchAppProtectionButton'].Add_Click({
        Fetch-AppProtection
    })
}

# Configuration buttons - Benchmark buttons
if ($controls['BenchmarkConfigProfilesButton']) {
    $controls['BenchmarkConfigProfilesButton'].Add_Click({
        Show-BenchmarkDialog -Category "Configuration Profiles"
    })
}

if ($controls['BenchmarkEndpointSecButton']) {
    $controls['BenchmarkEndpointSecButton'].Add_Click({
        Show-BenchmarkDialog -Category "Endpoint Security"
    })
}

if ($controls['BenchmarkAppProtectionButton']) {
    $controls['BenchmarkAppProtectionButton'].Add_Click({
        Show-BenchmarkDialog -Category "App Protection"
    })
}

# Configuration Profiles buttons
if ($controls['SettingsCatalogButton']) {
    $controls['SettingsCatalogButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Settings Catalog"
    })
}

if ($controls['DeviceRestrictionsButton']) {
    $controls['DeviceRestrictionsButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Device Restrictions"
    })
}

if ($controls['AdminTemplatesButton']) {
    $controls['AdminTemplatesButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Administrative Templates"
    })
}

# Endpoint Security buttons
if ($controls['FirewallButton']) {
    $controls['FirewallButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Firewall"
    })
}

if ($controls['EDRButton']) {
    $controls['EDRButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "EDR"
    })
}

if ($controls['ASRButton']) {
    $controls['ASRButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Attack Surface Reduction"
    })
}

if ($controls['AccountProtectionButton']) {
    $controls['AccountProtectionButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Account Protection"
    })
}

if ($controls['ConditionalAccessButton']) {
    $controls['ConditionalAccessButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Conditional Access"
    })
}

# App Protection buttons
if ($controls['AndroidAppProtectionButton']) {
    $controls['AndroidAppProtectionButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "Android App Protection"
    })
}

if ($controls['iOSAppProtectionButton']) {
    $controls['iOSAppProtectionButton'].Add_Click({
        Show-ConfigurationDetails -PolicyType "iOS/iPadOS App Protection"
    })
}

#region Assignments Tab Event Handlers

# Placeholder text handling for Device Group search box
if ($controls['DeviceGroupSearchBox']) {
    $controls['DeviceGroupSearchBox'].Add_GotFocus({
        if ($this.Text -match "^Enter (group display name|device name)") {
            $this.Text = ""
            $this.Foreground = $Window.FindResource('TextPrimaryBrush')
        }
    })
    $controls['DeviceGroupSearchBox'].Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($this.Text)) {
            $placeholderText = if ($controls['DeviceGroupRadio'].IsChecked) {
                "Enter group display name..."
            } else {
                "Enter device name..."
            }
            $this.Text = $placeholderText
            $this.Foreground = $Window.FindResource('TextTertiaryBrush')
        }
    })
}

# Placeholder text handling for User Group search box
if ($controls['UserGroupSearchBox']) {
    $controls['UserGroupSearchBox'].Add_GotFocus({
        if ($this.Text -match "^Enter (group display name|user UPN)") {
            $this.Text = ""
            $this.Foreground = $Window.FindResource('TextPrimaryBrush')
        }
    })
    $controls['UserGroupSearchBox'].Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($this.Text)) {
            $placeholderText = if ($controls['UserGroupRadio'].IsChecked) {
                "Enter group display name..."
            } else {
                "Enter user UPN (email)..."
            }
            $this.Text = $placeholderText
            $this.Foreground = $Window.FindResource('TextTertiaryBrush')
        }
    })
}

# Device Search Type RadioButton handlers
if ($controls['DeviceGroupRadio'] -and $controls['SingleDeviceRadio']) {
    $deviceRadioHandler = {
        $searchBox = $controls['DeviceGroupSearchBox']
        if ($searchBox) {
            # Update placeholder text based on selection
            if ($controls['DeviceGroupRadio'].IsChecked) {
                if ($searchBox.Text -match "^Enter (group display name|device name)") {
                    $searchBox.Text = "Enter group display name..."
                }
            } else {
                if ($searchBox.Text -match "^Enter (group display name|device name)") {
                    $searchBox.Text = "Enter device name..."
                }
            }
            # Reset fetch button and clear tag
            $controls['FetchDeviceGroupAssignmentsButton'].IsEnabled = $false
            $searchBox.Tag = $null
        }
    }
    $controls['DeviceGroupRadio'].Add_Checked($deviceRadioHandler)
    $controls['SingleDeviceRadio'].Add_Checked($deviceRadioHandler)
}

# User Search Type RadioButton handlers
if ($controls['UserGroupRadio'] -and $controls['SingleUserRadio']) {
    $userRadioHandler = {
        $searchBox = $controls['UserGroupSearchBox']
        if ($searchBox) {
            # Update placeholder text based on selection
            if ($controls['UserGroupRadio'].IsChecked) {
                if ($searchBox.Text -match "^Enter (group display name|user UPN)") {
                    $searchBox.Text = "Enter group display name..."
                }
            } else {
                if ($searchBox.Text -match "^Enter (group display name|user UPN)") {
                    $searchBox.Text = "Enter user UPN (email)..."
                }
            }
            # Reset fetch button and clear tag
            $controls['FetchUserGroupAssignmentsButton'].IsEnabled = $false
            $searchBox.Tag = $null
        }
    }
    $controls['UserGroupRadio'].Add_Checked($userRadioHandler)
    $controls['SingleUserRadio'].Add_Checked($userRadioHandler)
}

# Device Search Button (handles both groups and individual devices)
if ($controls['SearchDeviceGroupsButton']) {
    $controls['SearchDeviceGroupsButton'].Add_Click({
        $searchText = $controls['DeviceGroupSearchBox'].Text
        $isDeviceGroup = $controls['DeviceGroupRadio'].IsChecked

        if ([string]::IsNullOrWhiteSpace($searchText) -or $searchText -match "^Enter (group display name|device name)") {
            $message = if ($isDeviceGroup) { "Please enter a device group name to search." } else { "Please enter a device name to search." }
            [System.Windows.MessageBox]::Show($message, "Input Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            if ($isDeviceGroup) {
                # Search for device group
                Write-LogInfo -Message "Searching for device group: $searchText" -Source 'Assignments'
                $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$searchText'"
                $response = Invoke-GraphRequest -Uri $uri -Method GET

                if ($response.value -and $response.value.Count -gt 0) {
                    $group = $response.value[0]
                    $controls['DeviceGroupSearchBox'].Text = "$($group.displayName) (ID: $($group.id))"
                    $controls['DeviceGroupSearchBox'].Tag = @{ Type = 'Group'; Id = $group.id; Name = $group.displayName }
                    $controls['FetchDeviceGroupAssignmentsButton'].IsEnabled = $true
                    Write-LogInfo -Message "Found device group: $($group.displayName)" -Source 'Assignments'
                }
                else {
                    [System.Windows.MessageBox]::Show("No device group found with name: $searchText", "Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                    $controls['FetchDeviceGroupAssignmentsButton'].IsEnabled = $false
                }
            }
            else {
                # Search for individual device
                Write-LogInfo -Message "Searching for device: $searchText" -Source 'Assignments'
                $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$searchText'"
                $response = Invoke-GraphRequest -Uri $uri -Method GET

                if ($response.value -and $response.value.Count -gt 0) {
                    $device = $response.value[0]
                    $controls['DeviceGroupSearchBox'].Text = "$($device.displayName) (ID: $($device.id))"
                    $controls['DeviceGroupSearchBox'].Tag = @{ Type = 'Device'; Id = $device.id; Name = $device.displayName }
                    $controls['FetchDeviceGroupAssignmentsButton'].IsEnabled = $true
                    Write-LogInfo -Message "Found device: $($device.displayName)" -Source 'Assignments'
                }
                else {
                    [System.Windows.MessageBox]::Show("No device found with name: $searchText", "Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                    $controls['FetchDeviceGroupAssignmentsButton'].IsEnabled = $false
                }
            }
        }
        catch {
            Write-LogError -Message "Error searching: $_" -Source 'Assignments'
            [System.Windows.MessageBox]::Show("Error searching: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })
}

# Fetch Device Assignments Button (handles both groups and individual devices)
if ($controls['FetchDeviceGroupAssignmentsButton']) {
    $controls['FetchDeviceGroupAssignmentsButton'].Add_Click({
        $tagData = $controls['DeviceGroupSearchBox'].Tag
        $displayName = $controls['DeviceGroupSearchBox'].Text

        if (-not $tagData) {
            [System.Windows.MessageBox]::Show("Please search first.", "Search Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            $assignments = @()
            $resultKey = ""
            $entityName = ""

            if ($tagData.Type -eq 'Group') {
                # Fetch assignments for device group
                Write-LogInfo -Message "Fetching assignments for device group ID: $($tagData.Id)" -Source 'Assignments'
                $assignments = Get-GroupAssignments -GroupId $tagData.Id
                $resultKey = "DeviceGroup_$($tagData.Id)"
                $entityName = $tagData.Name
            }
            else {
                # Fetch assignments for individual device
                Write-LogInfo -Message "Fetching assignments for device: $($tagData.Name)" -Source 'Assignments'
                $result = Get-DeviceAssignments -DeviceName $tagData.Name
                if ($result.Found) {
                    $assignments = $result.Assignments
                    $entityName = "$($result.DeviceName) (via $($result.GroupCount) groups)"
                }
                else {
                    [System.Windows.MessageBox]::Show("Device not found: $($tagData.Name)", "Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                    return
                }
                $resultKey = "Device_$($tagData.Id)"
            }

            # Store assignments in results hashtable
            if (-not $script:AssignmentResults) {
                $script:AssignmentResults = @{}
            }
            $script:AssignmentResults[$resultKey] = @{
                GroupName = $entityName
                Assignments = $assignments
            }

            # Create result card programmatically (avoids XAML parsing issues)
            $resultBorder = New-Object System.Windows.Controls.Border
            $resultBorder.Background = [System.Windows.Media.Brushes]::White
            $resultBorder.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(224, 224, 224))
            $resultBorder.BorderThickness = 1
            $resultBorder.CornerRadius = 8
            $resultBorder.Padding = 16
            $resultBorder.Margin = New-Object System.Windows.Thickness(0, 0, 0, 12)

            $grid = New-Object System.Windows.Controls.Grid
            $col1 = New-Object System.Windows.Controls.ColumnDefinition
            $col1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            $col2 = New-Object System.Windows.Controls.ColumnDefinition
            $col2.Width = [System.Windows.GridLength]::Auto
            $grid.ColumnDefinitions.Add($col1)
            $grid.ColumnDefinitions.Add($col2)

            $row1 = New-Object System.Windows.Controls.RowDefinition
            $row1.Height = [System.Windows.GridLength]::Auto
            $row2 = New-Object System.Windows.Controls.RowDefinition
            $row2.Height = [System.Windows.GridLength]::Auto
            $grid.RowDefinitions.Add($row1)
            $grid.RowDefinitions.Add($row2)

            $stackPanel = New-Object System.Windows.Controls.StackPanel
            [System.Windows.Controls.Grid]::SetRow($stackPanel, 0)
            [System.Windows.Controls.Grid]::SetColumn($stackPanel, 0)

            $nameText = New-Object System.Windows.Controls.TextBlock
            $nameText.Text = $entityName
            $nameText.FontSize = 14
            $nameText.FontWeight = 'SemiBold'

            $countText = New-Object System.Windows.Controls.TextBlock
            $countText.Text = "Found $($assignments.Count) policy/app assignments"
            $countText.FontSize = 12
            $countText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(102, 102, 102))
            $countText.Margin = New-Object System.Windows.Thickness(0, 4, 0, 8)

            $stackPanel.Children.Add($nameText)
            $stackPanel.Children.Add($countText)

            # Remove button (X in top-right)
            $removeButton = New-Object System.Windows.Controls.Button
            $removeButton.Content = "X"
            $removeButton.Width = 28
            $removeButton.Height = 28
            $removeButton.FontSize = 14
            $removeButton.FontWeight = 'Bold'
            $removeButton.HorizontalAlignment = 'Right'
            $removeButton.VerticalAlignment = 'Top'
            $removeButton.Background = [System.Windows.Media.Brushes]::Transparent
            $removeButton.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(220, 53, 69))
            $removeButton.BorderThickness = 0
            $removeButton.Cursor = 'Hand'
            $removeButton.Tag = $resultBorder
            $removeButton.ToolTip = "Remove this result"
            [System.Windows.Controls.Grid]::SetRow($removeButton, 0)
            [System.Windows.Controls.Grid]::SetColumn($removeButton, 1)

            $removeButton.Add_Click({
                $borderToRemove = $this.Tag
                $parentPanel = $borderToRemove.Parent
                if ($parentPanel) {
                    $parentPanel.Children.Remove($borderToRemove)
                }
            })

            $viewButton = New-Object System.Windows.Controls.Button
            $viewButton.Content = "View Details"
            $viewButton.Padding = New-Object System.Windows.Thickness(12, 6, 12, 6)
            $viewButton.HorizontalAlignment = 'Left'
            $viewButton.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(0, 120, 212))
            $viewButton.Foreground = [System.Windows.Media.Brushes]::White
            $viewButton.BorderThickness = 0
            $viewButton.Cursor = 'Hand'
            $viewButton.Tag = $resultKey
            [System.Windows.Controls.Grid]::SetRow($viewButton, 1)
            [System.Windows.Controls.Grid]::SetColumn($viewButton, 0)

            $viewButton.Add_Click({
                $key = $this.Tag
                if ($script:AssignmentResults.ContainsKey($key)) {
                    $data = $script:AssignmentResults[$key]
                    Show-AssignmentResults -GroupName $data.GroupName -Assignments $data.Assignments
                }
            })

            $grid.Children.Add($stackPanel)
            $grid.Children.Add($removeButton)
            $grid.Children.Add($viewButton)
            $resultBorder.Child = $grid

            # Add card to results panel
            $controls['DeviceGroupResultsPanel'].Children.Add($resultBorder)

            Write-LogInfo -Message "Added result card for $entityName ($($assignments.Count) assignments)" -Source 'Assignments'
        }
        catch {
            Write-LogError -Message "Error fetching assignments: $_" -Source 'Assignments'
            [System.Windows.MessageBox]::Show("Error fetching assignments: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })
}

# User Search Button (handles both groups and individual users)
if ($controls['SearchUserGroupsButton']) {
    $controls['SearchUserGroupsButton'].Add_Click({
        $searchText = $controls['UserGroupSearchBox'].Text
        $isUserGroup = $controls['UserGroupRadio'].IsChecked

        if ([string]::IsNullOrWhiteSpace($searchText) -or $searchText -match "^Enter (group display name|user UPN)") {
            $message = if ($isUserGroup) { "Please enter a user group name to search." } else { "Please enter a user UPN to search." }
            [System.Windows.MessageBox]::Show($message, "Input Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            if ($isUserGroup) {
                # Search for user group
                Write-LogInfo -Message "Searching for user group: $searchText" -Source 'Assignments'
                $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$searchText'"
                $response = Invoke-GraphRequest -Uri $uri -Method GET

                if ($response.value -and $response.value.Count -gt 0) {
                    $group = $response.value[0]
                    $controls['UserGroupSearchBox'].Text = "$($group.displayName) (ID: $($group.id))"
                    $controls['UserGroupSearchBox'].Tag = @{ Type = 'Group'; Id = $group.id; Name = $group.displayName }
                    $controls['FetchUserGroupAssignmentsButton'].IsEnabled = $true
                    Write-LogInfo -Message "Found user group: $($group.displayName)" -Source 'Assignments'
                }
                else {
                    [System.Windows.MessageBox]::Show("No user group found with name: $searchText", "Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                    $controls['FetchUserGroupAssignmentsButton'].IsEnabled = $false
                }
            }
            else {
                # Search for individual user by UPN
                Write-LogInfo -Message "Searching for user: $searchText" -Source 'Assignments'
                $uri = "https://graph.microsoft.com/v1.0/users/$searchText"
                try {
                    $user = Invoke-GraphRequest -Uri $uri -Method GET
                    $controls['UserGroupSearchBox'].Text = "$($user.displayName) ($($user.userPrincipalName))"
                    $controls['UserGroupSearchBox'].Tag = @{ Type = 'User'; Id = $user.id; UPN = $user.userPrincipalName; Name = $user.displayName }
                    $controls['FetchUserGroupAssignmentsButton'].IsEnabled = $true
                    Write-LogInfo -Message "Found user: $($user.displayName)" -Source 'Assignments'
                }
                catch {
                    [System.Windows.MessageBox]::Show("No user found with UPN: $searchText", "Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                    $controls['FetchUserGroupAssignmentsButton'].IsEnabled = $false
                }
            }
        }
        catch {
            Write-LogError -Message "Error searching: $_" -Source 'Assignments'
            [System.Windows.MessageBox]::Show("Error searching: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })
}

# Fetch User Assignments Button (handles both groups and individual users)
if ($controls['FetchUserGroupAssignmentsButton']) {
    $controls['FetchUserGroupAssignmentsButton'].Add_Click({
        $tagData = $controls['UserGroupSearchBox'].Tag
        $displayName = $controls['UserGroupSearchBox'].Text

        if (-not $tagData) {
            [System.Windows.MessageBox]::Show("Please search first.", "Search Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            $assignments = @()
            $resultKey = ""
            $entityName = ""

            if ($tagData.Type -eq 'Group') {
                # Fetch assignments for user group
                Write-LogInfo -Message "Fetching assignments for user group ID: $($tagData.Id)" -Source 'Assignments'
                $assignments = Get-GroupAssignments -GroupId $tagData.Id
                $resultKey = "UserGroup_$($tagData.Id)"
                $entityName = $tagData.Name
            }
            else {
                # Fetch assignments for individual user
                Write-LogInfo -Message "Fetching assignments for user: $($tagData.UPN)" -Source 'Assignments'
                $result = Get-UserAssignments -UserPrincipalName $tagData.UPN
                if ($result.Found) {
                    $assignments = $result.Assignments
                    $entityName = "$($result.DisplayName) (via $($result.GroupCount) groups)"
                }
                else {
                    [System.Windows.MessageBox]::Show("User not found: $($tagData.UPN)", "Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                    return
                }
                $resultKey = "User_$($tagData.Id)"
            }

            # Store assignments in results hashtable
            if (-not $script:AssignmentResults) {
                $script:AssignmentResults = @{}
            }
            $script:AssignmentResults[$resultKey] = @{
                GroupName = $entityName
                Assignments = $assignments
            }

            # Create result card programmatically (avoids XAML parsing issues)
            $resultBorder = New-Object System.Windows.Controls.Border
            $resultBorder.Background = [System.Windows.Media.Brushes]::White
            $resultBorder.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(224, 224, 224))
            $resultBorder.BorderThickness = 1
            $resultBorder.CornerRadius = 8
            $resultBorder.Padding = 16
            $resultBorder.Margin = New-Object System.Windows.Thickness(0, 0, 0, 12)

            $grid = New-Object System.Windows.Controls.Grid
            $col1 = New-Object System.Windows.Controls.ColumnDefinition
            $col1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            $col2 = New-Object System.Windows.Controls.ColumnDefinition
            $col2.Width = [System.Windows.GridLength]::Auto
            $grid.ColumnDefinitions.Add($col1)
            $grid.ColumnDefinitions.Add($col2)

            $row1 = New-Object System.Windows.Controls.RowDefinition
            $row1.Height = [System.Windows.GridLength]::Auto
            $row2 = New-Object System.Windows.Controls.RowDefinition
            $row2.Height = [System.Windows.GridLength]::Auto
            $grid.RowDefinitions.Add($row1)
            $grid.RowDefinitions.Add($row2)

            $stackPanel = New-Object System.Windows.Controls.StackPanel
            [System.Windows.Controls.Grid]::SetRow($stackPanel, 0)
            [System.Windows.Controls.Grid]::SetColumn($stackPanel, 0)

            $nameText = New-Object System.Windows.Controls.TextBlock
            $nameText.Text = $entityName
            $nameText.FontSize = 14
            $nameText.FontWeight = 'SemiBold'

            $countText = New-Object System.Windows.Controls.TextBlock
            $countText.Text = "Found $($assignments.Count) policy/app assignments"
            $countText.FontSize = 12
            $countText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(102, 102, 102))
            $countText.Margin = New-Object System.Windows.Thickness(0, 4, 0, 8)

            $stackPanel.Children.Add($nameText)
            $stackPanel.Children.Add($countText)

            # Remove button (X in top-right)
            $removeButton = New-Object System.Windows.Controls.Button
            $removeButton.Content = "X"
            $removeButton.Width = 28
            $removeButton.Height = 28
            $removeButton.FontSize = 14
            $removeButton.FontWeight = 'Bold'
            $removeButton.HorizontalAlignment = 'Right'
            $removeButton.VerticalAlignment = 'Top'
            $removeButton.Background = [System.Windows.Media.Brushes]::Transparent
            $removeButton.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(220, 53, 69))
            $removeButton.BorderThickness = 0
            $removeButton.Cursor = 'Hand'
            $removeButton.Tag = $resultBorder
            $removeButton.ToolTip = "Remove this result"
            [System.Windows.Controls.Grid]::SetRow($removeButton, 0)
            [System.Windows.Controls.Grid]::SetColumn($removeButton, 1)

            $removeButton.Add_Click({
                $borderToRemove = $this.Tag
                $parentPanel = $borderToRemove.Parent
                if ($parentPanel) {
                    $parentPanel.Children.Remove($borderToRemove)
                }
            })

            $viewButton = New-Object System.Windows.Controls.Button
            $viewButton.Content = "View Details"
            $viewButton.Padding = New-Object System.Windows.Thickness(12, 6, 12, 6)
            $viewButton.HorizontalAlignment = 'Left'
            $viewButton.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(0, 120, 212))
            $viewButton.Foreground = [System.Windows.Media.Brushes]::White
            $viewButton.BorderThickness = 0
            $viewButton.Cursor = 'Hand'
            $viewButton.Tag = $resultKey
            [System.Windows.Controls.Grid]::SetRow($viewButton, 1)
            [System.Windows.Controls.Grid]::SetColumn($viewButton, 0)

            $viewButton.Add_Click({
                $key = $this.Tag
                if ($script:AssignmentResults.ContainsKey($key)) {
                    $data = $script:AssignmentResults[$key]
                    Show-AssignmentResults -GroupName $data.GroupName -Assignments $data.Assignments
                }
            })

            $grid.Children.Add($stackPanel)
            $grid.Children.Add($removeButton)
            $grid.Children.Add($viewButton)
            $resultBorder.Child = $grid

            # Add card to results panel
            $controls['UserGroupResultsPanel'].Children.Add($resultBorder)

            Write-LogInfo -Message "Added result card for $entityName ($($assignments.Count) assignments)" -Source 'Assignments'
        }
        catch {
            Write-LogError -Message "Error fetching assignments: $_" -Source 'Assignments'
            [System.Windows.MessageBox]::Show("Error fetching assignments: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })
}

# Find Orphaned Assignments Button
if ($controls['FindOrphanedButton']) {
    $controls['FindOrphanedButton'].Add_Click({
        try {
            Write-LogInfo -Message "Scanning for orphaned assignments..." -Source 'Assignments'
            $controls['OrphanedLoadingText'].Visibility = 'Visible'
            $controls['FindOrphanedButton'].IsEnabled = $false

            # Force UI to update before the long-running operation
            $Window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)

            $orphanedResults = Find-OrphanedAssignments

            $controls['NoAssignmentsCount'].Text = "$($orphanedResults.NoAssignments.Count) items"
            $controls['EmptyGroupsCount'].Text = "$($orphanedResults.EmptyGroups.Count) items"
            $controls['TotalOrphanedCount'].Text = "$($orphanedResults.TotalOrphaned) items"

            # Show/hide View Details buttons based on results
            if ($orphanedResults.NoAssignments.Count -gt 0) {
                $controls['ViewNoAssignmentsButton'].Visibility = 'Visible'
            } else {
                $controls['ViewNoAssignmentsButton'].Visibility = 'Collapsed'
            }

            if ($orphanedResults.EmptyGroups.Count -gt 0) {
                $controls['ViewEmptyGroupsButton'].Visibility = 'Visible'
            } else {
                $controls['ViewEmptyGroupsButton'].Visibility = 'Collapsed'
            }

            if ($orphanedResults.TotalOrphaned -gt 0) {
                $controls['ViewAllOrphanedButton'].Visibility = 'Visible'
                $controls['ExportOrphanedButton'].IsEnabled = $true
                $script:OrphanedData = $orphanedResults
                Show-ModernNotification -Title "Scan Complete" -Message "Found $($orphanedResults.TotalOrphaned) orphaned assignments. Click 'View Details' on the cards to see results." -Icon "Success"
            }
            else {
                $controls['ViewAllOrphanedButton'].Visibility = 'Collapsed'
                $controls['ExportOrphanedButton'].IsEnabled = $false
                Show-ModernNotification -Title "Scan Complete" -Message "No orphaned assignments found. All policies are properly assigned!" -Icon "Info"
            }

            $controls['OrphanedLoadingText'].Visibility = 'Collapsed'
            $controls['FindOrphanedButton'].IsEnabled = $true

            Write-LogInfo -Message "Orphaned scan complete. Total: $($orphanedResults.TotalOrphaned)" -Source 'Assignments'
        }
        catch {
            $controls['OrphanedLoadingText'].Visibility = 'Collapsed'
            $controls['FindOrphanedButton'].IsEnabled = $true
            Write-LogError -Message "Error finding orphaned assignments: $_" -Source 'Assignments'
            [System.Windows.MessageBox]::Show("Error scanning for orphaned assignments: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })
}

# Export Orphaned Results Button
if ($controls['ExportOrphanedButton']) {
    $controls['ExportOrphanedButton'].Add_Click({
        if (-not $script:OrphanedData) {
            [System.Windows.MessageBox]::Show("No orphaned data to export. Please run 'Find Orphaned' first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
            $saveDialog.Filter = "CSV files (*.csv)|*.csv|JSON files (*.json)|*.json|All files (*.*)|*.*"
            $saveDialog.DefaultExt = ".csv"
            $saveDialog.FileName = "OrphanedAssignments_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

            if ($saveDialog.ShowDialog()) {
                $exportPath = $saveDialog.FileName
                $extension = [System.IO.Path]::GetExtension($exportPath)

                if ($extension -eq '.json') {
                    $script:OrphanedData | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Encoding UTF8
                }
                else {
                    # Export as CSV
                    $csvData = @()
                    foreach ($item in $script:OrphanedData.NoAssignments) {
                        $csvData += [PSCustomObject]@{
                            Category = 'No Assignments'
                            Type     = $item.Type
                            Name     = $item.Name
                            ID       = $item.Id
                        }
                    }
                    foreach ($item in $script:OrphanedData.EmptyGroups) {
                        $csvData += [PSCustomObject]@{
                            Category = 'Empty Groups'
                            Type     = $item.Type
                            Name     = $item.Name
                            ID       = $item.Id
                            GroupID  = $item.GroupId
                            GroupName = $item.GroupName
                        }
                    }
                    $csvData | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
                }

                [System.Windows.MessageBox]::Show("Orphaned assignments exported successfully to:`n$exportPath", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                Write-LogInfo -Message "Exported orphaned assignments to: $exportPath" -Source 'Assignments'
            }
        }
        catch {
            Write-LogError -Message "Error exporting orphaned assignments: $_" -Source 'Assignments'
            [System.Windows.MessageBox]::Show("Error exporting results: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })
}

# View No Assignments Button
if ($controls['ViewNoAssignmentsButton']) {
    $controls['ViewNoAssignmentsButton'].Add_Click({
        if ($script:OrphanedData -and $script:OrphanedData.NoAssignments) {
            Show-AssignmentResults -GroupName "Policies with No Assignments" -Assignments $script:OrphanedData.NoAssignments
        }
    })
}

# View Empty Groups Button
if ($controls['ViewEmptyGroupsButton']) {
    $controls['ViewEmptyGroupsButton'].Add_Click({
        if ($script:OrphanedData -and $script:OrphanedData.EmptyGroups) {
            Show-AssignmentResults -GroupName "Policies Assigned to Empty Groups" -Assignments $script:OrphanedData.EmptyGroups
        }
    })
}

# View All Orphaned Button
if ($controls['ViewAllOrphanedButton']) {
    $controls['ViewAllOrphanedButton'].Add_Click({
        if ($script:OrphanedData) {
            $allOrphaned = @()
            $allOrphaned += $script:OrphanedData.NoAssignments
            $allOrphaned += $script:OrphanedData.EmptyGroups
            Show-AssignmentResults -GroupName "All Orphaned Assignments" -Assignments $allOrphaned
        }
    })
}

#endregion

#region Device Ownership Event Handlers

# Placeholder text handling for Ownership Group search box
if ($controls['OwnershipGroupSearchBox']) {
    $controls['OwnershipGroupSearchBox'].Add_GotFocus({
        if ($this.Text -eq "Enter group display name...") {
            $this.Text = ""
            $this.Foreground = $Window.FindResource('TextPrimaryBrush')
        }
    })
    $controls['OwnershipGroupSearchBox'].Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($this.Text)) {
            $this.Text = "Enter group display name..."
            $this.Foreground = $Window.FindResource('TextTertiaryBrush')
        }
    })
}

# Search Ownership Group Button
if ($controls['SearchOwnershipGroupButton']) {
    $controls['SearchOwnershipGroupButton'].Add_Click({
        $searchText = $controls['OwnershipGroupSearchBox'].Text

        if ([string]::IsNullOrWhiteSpace($searchText) -or $searchText -eq "Enter group display name...") {
            [System.Windows.MessageBox]::Show("Please enter a group name to search.", "Input Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            Write-LogInfo -Message "Searching for group: $searchText" -Source 'DeviceOwnership'
            $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$searchText'"
            $response = Invoke-GraphRequest -Uri $uri -Method GET

            if ($response.value -and $response.value.Count -gt 0) {
                $group = $response.value[0]
                $controls['OwnershipGroupSearchBox'].Text = "$($group.displayName) (ID: $($group.id))"
                $controls['OwnershipGroupSearchBox'].Tag = @{ Id = $group.id; Name = $group.displayName }
                $controls['AnalyzeOwnershipButton'].IsEnabled = $true
                Write-LogInfo -Message "Found group: $($group.displayName)" -Source 'DeviceOwnership'
            }
            else {
                [System.Windows.MessageBox]::Show("No group found with name: $searchText", "Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                $controls['AnalyzeOwnershipButton'].IsEnabled = $false
            }
        }
        catch {
            Write-LogError -Message "Failed to search for group: $($_.Exception.Message)" -Source 'DeviceOwnership'
            [System.Windows.MessageBox]::Show("Failed to search for group. Please check the logs.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            $controls['AnalyzeOwnershipButton'].IsEnabled = $false
        }
    })
}

# Analyze Ownership Button
if ($controls['AnalyzeOwnershipButton']) {
    $controls['AnalyzeOwnershipButton'].Add_Click({
        $groupInfo = $controls['OwnershipGroupSearchBox'].Tag

        if (-not $groupInfo -or -not $groupInfo.Id) {
            [System.Windows.MessageBox]::Show("Please search for a group first.", "Group Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            # Show loading indicator
            $controls['OwnershipLoadingText'].Visibility = 'Visible'
            $controls['OwnershipSummaryCards'].Visibility = 'Collapsed'
            $controls['ExportOwnershipButton'].Visibility = 'Collapsed'
            $controls['AnalyzeOwnershipButton'].IsEnabled = $false

            Write-LogInfo -Message "Starting device ownership analysis for group: $($groupInfo.Name)" -Source 'DeviceOwnership'

            # Run analysis
            $result = Get-GroupDeviceOwnershipAnalysis -GroupId $groupInfo.Id

            if ($result.Success) {
                # Update summary cards
                $controls['NoDevicesCount'].Text = "$($result.Summary.UsersWithNoDevices) users"
                $controls['MultipleDevicesCount'].Text = "$($result.Summary.UsersWithMultipleDevices) users"

                # Check if SingleDeviceCount control exists (for backward compatibility)
                if ($controls.ContainsKey('SingleDeviceCount') -and $controls['SingleDeviceCount']) {
                    $controls['SingleDeviceCount'].Text = "$($result.Summary.UsersWithSingleDevice) users"
                } else {
                    Write-LogWarning -Message "SingleDeviceCount control not found. Please restart the application to load updated UI." -Source 'DeviceOwnership'
                }

                # Store results for export and detail views
                $script:CurrentOwnershipResults = $result

                # Show summary cards and export button
                $controls['OwnershipSummaryCards'].Visibility = 'Visible'
                $controls['ExportOwnershipButton'].Visibility = 'Visible'

                Write-LogInfo -Message "Device ownership analysis completed successfully" -Source 'DeviceOwnership'
            }
            else {
                [System.Windows.MessageBox]::Show("Analysis failed: $($result.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
        catch {
            Write-LogError -Message "Failed to analyze device ownership: $($_.Exception.Message)" -Source 'DeviceOwnership'
            [System.Windows.MessageBox]::Show("Failed to analyze device ownership. Please check the logs.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
        finally {
            $controls['OwnershipLoadingText'].Visibility = 'Collapsed'
            $controls['AnalyzeOwnershipButton'].IsEnabled = $true
        }
    })
}

# View No Devices Button
if ($controls['ViewNoDevicesButton']) {
    $controls['ViewNoDevicesButton'].Add_Click({
        if (-not $script:CurrentOwnershipResults) { return }

        $users = $script:CurrentOwnershipResults.UsersWithNoDevices
        if ($users.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No users found without devices.", "No Results", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }

        # Clear previous results
        $controls['OwnershipResultsPanel'].Children.Clear()

        # Create header
        $header = New-Object System.Windows.Controls.TextBlock
        $header.Text = "Users with No Devices ($($users.Count))"
        $header.FontSize = $Window.Resources['FontSizeLarge']
        $header.FontWeight = 'SemiBold'
        $header.Foreground = $Window.Resources['TextPrimaryBrush']
        $header.Margin = "0,0,0,20"
        $controls['OwnershipResultsPanel'].Children.Add($header)

        # Create results card
        $card = New-Object System.Windows.Controls.Border
        $card.Style = $Window.Resources['CardStyle']
        $card.Padding = "20"

        $stackPanel = New-Object System.Windows.Controls.StackPanel

        foreach ($user in $users) {
            $userCard = New-Object System.Windows.Controls.Border
            $userCard.Background = $Window.Resources['BackgroundBrush']
            $userCard.BorderBrush = $Window.Resources['BorderBrush']
            $userCard.BorderThickness = "1"
            $userCard.CornerRadius = "6"
            $userCard.Padding = "12,8"
            $userCard.Margin = "0,0,0,8"

            $userStack = New-Object System.Windows.Controls.StackPanel

            $nameText = New-Object System.Windows.Controls.TextBlock
            $nameText.Text = $user.DisplayName
            $nameText.FontWeight = 'SemiBold'
            $nameText.FontSize = $Window.Resources['FontSizeNormal']
            $nameText.Foreground = $Window.Resources['TextPrimaryBrush']
            $userStack.Children.Add($nameText)

            $upnText = New-Object System.Windows.Controls.TextBlock
            $upnText.Text = $user.UserPrincipalName
            $upnText.FontSize = $Window.Resources['FontSizeSmall']
            $upnText.Foreground = $Window.Resources['TextSecondaryBrush']
            $upnText.Margin = "0,2,0,0"
            $userStack.Children.Add($upnText)

            $userCard.Child = $userStack
            $stackPanel.Children.Add($userCard)
        }

        $card.Child = $stackPanel
        $controls['OwnershipResultsPanel'].Children.Add($card)
        $controls['OwnershipResultsPanel'].Visibility = 'Visible'
    })
}

# View Single Device Button
if ($controls['ViewSingleDeviceButton']) {
    $controls['ViewSingleDeviceButton'].Add_Click({
        if (-not $script:CurrentOwnershipResults) { return }

        $users = $script:CurrentOwnershipResults.UsersWithSingleDevice
        if ($users.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No users found with a single device.", "No Results", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }

        # Clear previous results
        $controls['OwnershipResultsPanel'].Children.Clear()

        # Create header
        $header = New-Object System.Windows.Controls.TextBlock
        $header.Text = "Users with Single Device ($($users.Count))"
        $header.FontSize = $Window.Resources['FontSizeLarge']
        $header.FontWeight = 'SemiBold'
        $header.Foreground = $Window.Resources['TextPrimaryBrush']
        $header.Margin = "0,0,0,20"
        $controls['OwnershipResultsPanel'].Children.Add($header)

        # Create results card
        $card = New-Object System.Windows.Controls.Border
        $card.Style = $Window.Resources['CardStyle']
        $card.Padding = "20"

        $stackPanel = New-Object System.Windows.Controls.StackPanel

        foreach ($user in $users) {
            $userCard = New-Object System.Windows.Controls.Border
            $userCard.Background = $Window.Resources['BackgroundBrush']
            $userCard.BorderBrush = $Window.Resources['SuccessBrush']
            $userCard.BorderThickness = "2"
            $userCard.CornerRadius = "6"
            $userCard.Padding = "12,8"
            $userCard.Margin = "0,0,0,12"

            $userStack = New-Object System.Windows.Controls.StackPanel

            $nameText = New-Object System.Windows.Controls.TextBlock
            $nameText.Text = $user.DisplayName
            $nameText.FontWeight = 'SemiBold'
            $nameText.FontSize = $Window.Resources['FontSizeNormal']
            $nameText.Foreground = $Window.Resources['TextPrimaryBrush']
            $userStack.Children.Add($nameText)

            $upnText = New-Object System.Windows.Controls.TextBlock
            $upnText.Text = $user.UserPrincipalName
            $upnText.FontSize = $Window.Resources['FontSizeSmall']
            $upnText.Foreground = $Window.Resources['TextSecondaryBrush']
            $upnText.Margin = "0,2,0,0"
            $userStack.Children.Add($upnText)

            $deviceText = New-Object System.Windows.Controls.TextBlock
            $deviceText.Text = "$($user.DeviceName) ($($user.DeviceOS))"
            $deviceText.FontSize = $Window.Resources['FontSizeSmall']
            $deviceText.Foreground = $Window.Resources['TextTertiaryBrush']
            $deviceText.Margin = "0,4,0,0"
            $userStack.Children.Add($deviceText)

            $userCard.Child = $userStack
            $stackPanel.Children.Add($userCard)
        }

        $card.Child = $stackPanel
        $controls['OwnershipResultsPanel'].Children.Add($card)
        $controls['OwnershipResultsPanel'].Visibility = 'Visible'
    })
}

# View Multiple Devices Button
if ($controls['ViewMultipleDevicesButton']) {
    $controls['ViewMultipleDevicesButton'].Add_Click({
        if (-not $script:CurrentOwnershipResults) { return }

        $users = $script:CurrentOwnershipResults.UsersWithMultipleDevices
        if ($users.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No users found with multiple devices.", "No Results", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }

        # Clear previous results
        $controls['OwnershipResultsPanel'].Children.Clear()

        # Create header
        $header = New-Object System.Windows.Controls.TextBlock
        $header.Text = "Users with Multiple Devices ($($users.Count))"
        $header.FontSize = $Window.Resources['FontSizeLarge']
        $header.FontWeight = 'SemiBold'
        $header.Foreground = $Window.Resources['TextPrimaryBrush']
        $header.Margin = "0,0,0,20"
        $controls['OwnershipResultsPanel'].Children.Add($header)

        # Create results card
        $card = New-Object System.Windows.Controls.Border
        $card.Style = $Window.Resources['CardStyle']
        $card.Padding = "20"

        $stackPanel = New-Object System.Windows.Controls.StackPanel

        foreach ($user in $users) {
            $userCard = New-Object System.Windows.Controls.Border
            $userCard.Background = $Window.Resources['BackgroundBrush']
            $userCard.BorderBrush = $Window.Resources['InfoBrush']
            $userCard.BorderThickness = "2"
            $userCard.CornerRadius = "6"
            $userCard.Padding = "12,8"
            $userCard.Margin = "0,0,0,12"

            $userStack = New-Object System.Windows.Controls.StackPanel

            $nameText = New-Object System.Windows.Controls.TextBlock
            $nameText.Text = $user.DisplayName
            $nameText.FontWeight = 'SemiBold'
            $nameText.FontSize = $Window.Resources['FontSizeNormal']
            $nameText.Foreground = $Window.Resources['TextPrimaryBrush']
            $userStack.Children.Add($nameText)

            $upnText = New-Object System.Windows.Controls.TextBlock
            $upnText.Text = $user.UserPrincipalName
            $upnText.FontSize = $Window.Resources['FontSizeSmall']
            $upnText.Foreground = $Window.Resources['TextSecondaryBrush']
            $upnText.Margin = "0,2,0,0"
            $userStack.Children.Add($upnText)

            $deviceCountText = New-Object System.Windows.Controls.TextBlock
            $deviceCountText.Text = "$($user.DeviceCount) devices"
            $deviceCountText.FontSize = $Window.Resources['FontSizeSmall']
            $deviceCountText.Foreground = $Window.Resources['InfoBrush']
            $deviceCountText.FontWeight = 'SemiBold'
            $deviceCountText.Margin = "0,4,0,4"
            $userStack.Children.Add($deviceCountText)

            $devicesText = New-Object System.Windows.Controls.TextBlock
            $devicesText.Text = $user.DeviceNames
            $devicesText.FontSize = $Window.Resources['FontSizeSmall']
            $devicesText.Foreground = $Window.Resources['TextTertiaryBrush']
            $devicesText.TextWrapping = 'Wrap'
            $userStack.Children.Add($devicesText)

            $userCard.Child = $userStack
            $stackPanel.Children.Add($userCard)
        }

        $card.Child = $stackPanel
        $controls['OwnershipResultsPanel'].Children.Add($card)
        $controls['OwnershipResultsPanel'].Visibility = 'Visible'
    })
}

# Export Ownership Button
if ($controls['ExportOwnershipButton']) {
    $controls['ExportOwnershipButton'].Add_Click({
        if (-not $script:CurrentOwnershipResults) {
            [System.Windows.MessageBox]::Show("No results to export. Please run an analysis first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        try {
            $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
            $saveDialog.Filter = "CSV files (*.csv)|*.csv"
            $saveDialog.FileName = "DeviceOwnership_$($script:CurrentOwnershipResults.GroupId)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

            if ($saveDialog.ShowDialog()) {
                $exportData = [System.Collections.ArrayList]::new()

                # Export users with no devices
                foreach ($user in $script:CurrentOwnershipResults.UsersWithNoDevices) {
                    [void]$exportData.Add([PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        Email = $user.Email
                        DeviceCount = 0
                        Category = 'No Devices'
                        DeviceNames = ''
                    })
                }

                # Export users with single device
                foreach ($user in $script:CurrentOwnershipResults.UsersWithSingleDevice) {
                    [void]$exportData.Add([PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        Email = $user.Email
                        DeviceCount = 1
                        Category = 'Single Device'
                        DeviceNames = $user.DeviceName
                    })
                }

                # Export users with multiple devices
                foreach ($user in $script:CurrentOwnershipResults.UsersWithMultipleDevices) {
                    [void]$exportData.Add([PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        Email = $user.Email
                        DeviceCount = $user.DeviceCount
                        Category = 'Multiple Devices'
                        DeviceNames = $user.DeviceNames
                    })
                }

                $exportData | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
                Write-LogInfo -Message "Exported device ownership results to: $($saveDialog.FileName)" -Source 'DeviceOwnership'
                [System.Windows.MessageBox]::Show("Results exported successfully to:`n$($saveDialog.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
        catch {
            Write-LogError -Message "Failed to export results: $($_.Exception.Message)" -Source 'DeviceOwnership'
            [System.Windows.MessageBox]::Show("Failed to export results. Please check the logs.", "Export Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })
}

#endregion

#region Remediation Scripts Handlers
# Load remediation scripts from JSON
$script:RemediationScripts = @()
$script:CurrentCategory = "All"
$script:RemediationScriptsSourcePath = Join-Path $PSScriptRoot "Resources\RemediationScripts"
$script:RemediationScriptsSourcePath2 = Join-Path $PSScriptRoot "Resources\RemediationScripts"

function Show-ScriptViewer {
    param(
        [string]$ScriptName,
        [string]$ScriptFileName
    )

    try {
        # Find the script file - search both source directories
        $scriptPath = Get-ChildItem -Path $script:RemediationScriptsSourcePath -Filter $ScriptFileName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if (-not $scriptPath) {
            $scriptPath = Get-ChildItem -Path $script:RemediationScriptsSourcePath2 -Filter $ScriptFileName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if (-not $scriptPath) {
            Show-ModernNotification -Title "Script Not Found" -Message "Could not find script file: $ScriptFileName" -Icon "Warning"
            return
        }

        # Read script content
        $scriptContent = Get-Content -Path $scriptPath.FullName -Raw -ErrorAction Stop

        # Create viewer window with VS Code dark theme
        $viewerWindow = New-Object System.Windows.Window
        $viewerWindow.Title = $ScriptName
        $viewerWindow.Width = 1100
        $viewerWindow.Height = 800
        $viewerWindow.WindowStartupLocation = 'CenterOwner'
        $viewerWindow.Owner = $Window
        $viewerWindow.ResizeMode = 'CanResize'

        # VS Code dark background
        $viewerWindow.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(30, 30, 30))

        # Main grid
        $mainGrid = New-Object System.Windows.Controls.Grid
        $row1 = New-Object System.Windows.Controls.RowDefinition
        $row1.Height = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
        $row2 = New-Object System.Windows.Controls.RowDefinition
        $row2.Height = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Auto)
        [void]$mainGrid.RowDefinitions.Add($row1)
        [void]$mainGrid.RowDefinitions.Add($row2)

        # Border for the textbox area
        $border = New-Object System.Windows.Controls.Border
        $border.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(60, 60, 60))
        $border.BorderThickness = "1"
        $border.Margin = "20,20,20,0"
        $border.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(30, 30, 30))

        # Script content TextBox with VS Code colors
        $textBox = New-Object System.Windows.Controls.TextBox
        $textBox.Text = $scriptContent
        $textBox.IsReadOnly = $true
        $textBox.FontFamily = "Consolas,Courier New,monospace"
        $textBox.FontSize = 14
        $textBox.TextWrapping = "NoWrap"
        $textBox.AcceptsReturn = $true
        $textBox.VerticalScrollBarVisibility = "Auto"
        $textBox.HorizontalScrollBarVisibility = "Auto"

        # VS Code dark theme colors
        $textBox.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(30, 30, 30))
        $textBox.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(212, 212, 212))
        $textBox.CaretBrush = [System.Windows.Media.Brushes]::White
        $textBox.SelectionBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(38, 79, 120))

        $textBox.BorderThickness = "0"
        $textBox.Padding = "16"

        $border.Child = $textBox
        [System.Windows.Controls.Grid]::SetRow($border, 0)
        [void]$mainGrid.Children.Add($border)

        # Button panel
        $buttonPanel = New-Object System.Windows.Controls.StackPanel
        $buttonPanel.Orientation = "Horizontal"
        $buttonPanel.HorizontalAlignment = "Right"
        $buttonPanel.Margin = "20"

        # Copy button
        $copyBtn = New-Object System.Windows.Controls.Button
        $copyBtn.Content = "Copy to Clipboard"
        $copyBtn.Padding = "16,10"
        $copyBtn.Margin = "0,0,12,0"
        $copyBtn.FontSize = 13
        $copyBtn.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(0, 120, 212))
        $copyBtn.Foreground = [System.Windows.Media.Brushes]::White
        $copyBtn.BorderThickness = "0"
        $copyBtn.Cursor = [System.Windows.Input.Cursors]::Hand
        $copyBtn.Add_Click({
            try {
                # Use PowerShell's Set-Clipboard cmdlet instead of WPF Clipboard
                $textBox.Text | Set-Clipboard
                Show-ModernNotification -Title "Copied" -Message "Script content copied to clipboard" -Icon "Success"
            }
            catch {
                Write-LogError -Message "Failed to copy to clipboard: $_" -Source 'RemediationScripts'
                Show-ModernNotification -Title "Copy Failed" -Message "Failed to copy to clipboard: $_" -Icon "Error"
            }
        })
        [void]$buttonPanel.Children.Add($copyBtn)

        # Close button
        $closeBtn = New-Object System.Windows.Controls.Button
        $closeBtn.Content = "Close"
        $closeBtn.Padding = "16,10"
        $closeBtn.FontSize = 13
        $closeBtn.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(60, 60, 60))
        $closeBtn.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(212, 212, 212))
        $closeBtn.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(80, 80, 80))
        $closeBtn.BorderThickness = "1"
        $closeBtn.Cursor = [System.Windows.Input.Cursors]::Hand
        $closeBtn.Add_Click({
            $viewerWindow.Close()
        })
        [void]$buttonPanel.Children.Add($closeBtn)

        [System.Windows.Controls.Grid]::SetRow($buttonPanel, 1)
        [void]$mainGrid.Children.Add($buttonPanel)

        $viewerWindow.Content = $mainGrid

        # Show dialog
        [void]$viewerWindow.ShowDialog()
    }
    catch {
        Write-LogError -Message "Failed to show script viewer: $_" -Source 'RemediationScripts'
        Show-ModernNotification -Title "Error" -Message "Failed to load script: $_" -Icon "Error"
    }
}

function Load-RemediationScripts {
    try {
        $jsonPath = Join-Path $PSScriptRoot "Resources\RemediationScripts.json"
        if (Test-Path $jsonPath) {
            $script:RemediationScripts = Get-Content $jsonPath -Raw | ConvertFrom-Json
            Write-LogInfo -Message "Loaded $($script:RemediationScripts.Count) remediation scripts" -Source 'RemediationScripts'
            return $true
        } else {
            Write-LogError -Message "RemediationScripts.json not found at $jsonPath" -Source 'RemediationScripts'
            return $false
        }
    } catch {
        Write-LogError -Message "Failed to load remediation scripts: $_" -Source 'RemediationScripts'
        return $false
    }
}

function Show-RemediationScripts {
    param(
        [string]$SearchText = "",
        [string]$Category = "All"
    )

    try {
        if ($script:RemediationScripts.Count -eq 0) {
            if (-not (Load-RemediationScripts)) {
                return
            }
        }

    # Filter scripts - force array to handle single result case
    $filteredScripts = @($script:RemediationScripts | Where-Object {
        $matchesSearch = $true
        $matchesCategory = $true

        # Search filter
        if (-not [string]::IsNullOrWhiteSpace($SearchText) -and $SearchText -notmatch "^Search by") {
            $searchLower = $SearchText.Trim().ToLower()
            $matchesSearch = $false

            # Check Name
            if ($_.Name -and $_.Name.ToLower().Contains($searchLower)) {
                $matchesSearch = $true
            }
            # Check Category
            elseif ($_.Category -and $_.Category.ToLower().Contains($searchLower)) {
                $matchesSearch = $true
            }
            # Check Description
            elseif ($_.Description -and $_.Description.ToLower().Contains($searchLower)) {
                $matchesSearch = $true
            }
            # Check Tags
            elseif ($_.Tags) {
                $tagsString = ($_.Tags | ForEach-Object { $_.ToString() }) -join " "
                if ($tagsString.ToLower().Contains($searchLower)) {
                    $matchesSearch = $true
                }
            }
        }

        # Category filter
        if ($Category -ne "All") {
            $matchesCategory = $_.Category -eq $Category
        }

        return ($matchesSearch -and $matchesCategory)
    })

    # Clear existing cards
    $controls['RemediationScriptsContainer'].Children.Clear()

    if ($filteredScripts.Count -eq 0) {
        $controls['RemediationNoResults'].Visibility = 'Visible'
        $controls['RemediationResultsSummary'].Visibility = 'Collapsed'
    } else {
        $controls['RemediationNoResults'].Visibility = 'Collapsed'
        $controls['RemediationResultsSummary'].Visibility = 'Visible'
        $controls['RemediationResultsCount'].Text = "Showing $($filteredScripts.Count) script$(if($filteredScripts.Count -ne 1){'s'})"

        # Create two-column grid
        $currentRow = 0
        for ($i = 0; $i -lt $filteredScripts.Count; $i += 2) {
            # Create row grid
            $rowGrid = New-Object System.Windows.Controls.Grid
            $rowGrid.Margin = "0,0,0,16"

            # Define columns
            $col1 = New-Object System.Windows.Controls.ColumnDefinition
            $col1.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
            $col2 = New-Object System.Windows.Controls.ColumnDefinition
            $col2.Width = New-Object System.Windows.GridLength(16)
            $col3 = New-Object System.Windows.Controls.ColumnDefinition
            $col3.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
            [void]$rowGrid.ColumnDefinitions.Add($col1)
            [void]$rowGrid.ColumnDefinitions.Add($col2)
            [void]$rowGrid.ColumnDefinitions.Add($col3)

            # Add first card
                $card1 = Create-ScriptCard -Script $filteredScripts[$i]
                if ($card1) {
                    [System.Windows.Controls.Grid]::SetColumn($card1, 0)
                    [void]$rowGrid.Children.Add($card1)
                }

                # Add second card if exists
                if ($i + 1 -lt $filteredScripts.Count) {
                    $card2 = Create-ScriptCard -Script $filteredScripts[$i + 1]
                    if ($card2) {
                        [System.Windows.Controls.Grid]::SetColumn($card2, 2)
                        [void]$rowGrid.Children.Add($card2)
                    }
                }

                [void]$controls['RemediationScriptsContainer'].Children.Add($rowGrid)
            }
        }
    }
    catch {
        Write-LogError -Message "Failed to show remediation scripts: $_" -Source 'RemediationScripts'
        $controls['RemediationNoResults'].Visibility = 'Visible'
        $controls['RemediationResultsSummary'].Visibility = 'Collapsed'
    }
}

function Create-ScriptCard {
    param($Script)

    try {
        # Load CardStyle
        $cardBorder = New-Object System.Windows.Controls.Border
        $cardStyle = $Window.TryFindResource("CardStyle")
        if ($cardStyle) {
            $cardBorder.Style = $cardStyle
        }
        $cardBorder.Padding = "20"

        $cardStack = New-Object System.Windows.Controls.StackPanel

        # Header
        $headerStack = New-Object System.Windows.Controls.StackPanel
        $headerStack.Margin = "0,0,0,12"

        $nameText = New-Object System.Windows.Controls.TextBlock
        $nameText.Text = $Script.Name
        $nameText.SetResourceReference([System.Windows.Controls.TextBlock]::FontSizeProperty, "FontSizeLarge")
        $nameText.FontWeight = "SemiBold"
        $nameText.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "TextPrimaryBrush")
        $nameText.TextWrapping = "Wrap"
        [void]$headerStack.Children.Add($nameText)

        $categoryText = New-Object System.Windows.Controls.TextBlock
        $categoryText.Text = $Script.Category
        $categoryText.SetResourceReference([System.Windows.Controls.TextBlock]::FontSizeProperty, "FontSizeSmall")
        $categoryText.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "AccentBrush")
        $categoryText.Margin = "0,4,0,0"
        [void]$headerStack.Children.Add($categoryText)

        [void]$cardStack.Children.Add($headerStack)

        # Description
        $descText = New-Object System.Windows.Controls.TextBlock
        $descText.Text = $Script.Description
        $descText.SetResourceReference([System.Windows.Controls.TextBlock]::FontSizeProperty, "FontSizeNormal")
        $descText.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "TextSecondaryBrush")
        $descText.TextWrapping = "Wrap"
        $descText.Margin = "0,0,0,12"
        [void]$cardStack.Children.Add($descText)

        # Tags
        $tagsText = New-Object System.Windows.Controls.TextBlock
        $tagsText.SetResourceReference([System.Windows.Controls.TextBlock]::FontSizeProperty, "FontSizeSmall")
        $tagsText.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "TextTertiaryBrush")
        $tagsText.Margin = "0,0,0,12"
        $tagsRun1 = New-Object System.Windows.Documents.Run
        $tagsRun1.Text = "Tags: "
        $tagsRun2 = New-Object System.Windows.Documents.Run
        $tagsRun2.Text = ($Script.Tags -join ", ")
        [void]$tagsText.Inlines.Add($tagsRun1)
        [void]$tagsText.Inlines.Add($tagsRun2)
        [void]$cardStack.Children.Add($tagsText)

        # Buttons
        $buttonGrid = New-Object System.Windows.Controls.Grid
        $buttonCol1 = New-Object System.Windows.Controls.ColumnDefinition
        $buttonCol1.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
        $buttonCol2 = New-Object System.Windows.Controls.ColumnDefinition
        $buttonCol2.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Auto)
        [void]$buttonGrid.ColumnDefinitions.Add($buttonCol1)
        [void]$buttonGrid.ColumnDefinitions.Add($buttonCol2)

        $buttonStack = New-Object System.Windows.Controls.StackPanel
        $buttonStack.Orientation = "Horizontal"

    # View Detection Button
        $viewDetectionBtn = New-Object System.Windows.Controls.Button
        $viewDetectionBtn.Content = "View Detection"
        $secondaryStyle = $Window.TryFindResource("SecondaryButtonStyle")
        if ($secondaryStyle) {
            $viewDetectionBtn.Style = $secondaryStyle
        }
        $viewDetectionBtn.Padding = "10,6"
        $viewDetectionBtn.SetResourceReference([System.Windows.Controls.Button]::FontSizeProperty, "FontSizeSmall")
        $viewDetectionBtn.Tag = @{
            Name = "$($Script.Name) - Detection"
            FileName = $Script.DetectionScript
        }
        $viewDetectionBtn.Margin = "0,0,8,0"
        $viewDetectionBtn.Add_Click({
            param($sender, $e)
            $scriptInfo = $sender.Tag
            Show-ScriptViewer -ScriptName $scriptInfo.Name -ScriptFileName $scriptInfo.FileName
        })
        [void]$buttonStack.Children.Add($viewDetectionBtn)

        # View Remediation Button (if exists)
        if ($Script.RemediationScript) {
            $viewRemediationBtn = New-Object System.Windows.Controls.Button
            $viewRemediationBtn.Content = "View Remediation"
            if ($secondaryStyle) {
                $viewRemediationBtn.Style = $secondaryStyle
            }
            $viewRemediationBtn.Padding = "10,6"
            $viewRemediationBtn.SetResourceReference([System.Windows.Controls.Button]::FontSizeProperty, "FontSizeSmall")
            $viewRemediationBtn.Tag = @{
                Name = "$($Script.Name) - Remediation"
                FileName = $Script.RemediationScript
            }
            $viewRemediationBtn.Add_Click({
                param($sender, $e)
                $scriptInfo = $sender.Tag
                Show-ScriptViewer -ScriptName $scriptInfo.Name -ScriptFileName $scriptInfo.FileName
            })
            [void]$buttonStack.Children.Add($viewRemediationBtn)
        }

        [System.Windows.Controls.Grid]::SetColumn($buttonStack, 0)
        [void]$buttonGrid.Children.Add($buttonStack)

        # Source Button
        $sourceBtn = New-Object System.Windows.Controls.Button
        $sourceBtn.Content = "Source"
        $modernStyle = $Window.TryFindResource("ModernButtonStyle")
        if ($modernStyle) {
            $sourceBtn.Style = $modernStyle
        }
        $sourceBtn.Padding = "16,6"
        $sourceBtn.SetResourceReference([System.Windows.Controls.Button]::FontSizeProperty, "FontSizeSmall")
        $sourceBtn.Tag = $Script.Source
        $sourceBtn.Add_Click({
            param($sender, $e)
            Start-Process $sender.Tag
        })
        [System.Windows.Controls.Grid]::SetColumn($sourceBtn, 1)
        [void]$buttonGrid.Children.Add($sourceBtn)

        [void]$cardStack.Children.Add($buttonGrid)
        $cardBorder.Child = $cardStack

        return $cardBorder
    }
    catch {
        Write-LogError -Message "Failed to create script card for '$($Script.Name)': $_" -Source 'RemediationScripts'
        return $null
    }
}

# Search box handler
if ($controls['RemediationSearchBox']) {
    # Placeholder text behavior
    $controls['RemediationSearchBox'].Add_GotFocus({
        if ($this.Text -match "^Search by") {
            $this.Text = ""
            $this.SetResourceReference([System.Windows.Controls.TextBox]::ForegroundProperty, "TextPrimaryBrush")
        }
    })

    $controls['RemediationSearchBox'].Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($this.Text)) {
            $this.Text = "Search by name, category, or tag..."
            $this.SetResourceReference([System.Windows.Controls.TextBox]::ForegroundProperty, "TextTertiaryBrush")
        }
    })

    $controls['RemediationSearchBox'].Add_TextChanged({
        Show-RemediationScripts -SearchText $this.Text -Category $script:CurrentCategory
    })
}

# Category filter buttons
$categoryButtons = @(
    'CategoryAll', 'CategorySecurity', 'CategoryMaintenance', 'CategoryApplicationManagement',
    'CategorySystemConfiguration', 'CategoryNetwork', 'CategoryUserExperience', 'CategoryTroubleshooting'
)

foreach ($btnName in $categoryButtons) {
    if ($controls[$btnName]) {
        $controls[$btnName].Add_Click({
            param($sender, $e)
            try {
                $script:CurrentCategory = $sender.Tag
                Show-RemediationScripts -SearchText $controls['RemediationSearchBox'].Text -Category $script:CurrentCategory

                # Update button styles (highlight selected)
                $modernStyle = $Window.TryFindResource("ModernButtonStyle")
                $secondaryStyle = $Window.TryFindResource("SecondaryButtonStyle")

                foreach ($btn in $categoryButtons) {
                    if ($controls[$btn]) {
                        if ($controls[$btn].Tag -eq $script:CurrentCategory) {
                            if ($modernStyle) {
                                $controls[$btn].Style = $modernStyle
                            }
                        } else {
                            if ($secondaryStyle) {
                                $controls[$btn].Style = $secondaryStyle
                            }
                        }
                    }
                }
            }
            catch {
                Write-LogError -Message "Failed to filter by category: $_" -Source 'RemediationScripts'
            }
        })
    }
}

#endregion

# Window loaded event
$Window.Add_Loaded({
    # Apply saved theme
    $themeMode = Get-Configuration -Section 'Theme' -Key 'Mode'
    $isDark = $themeMode -eq 'Dark'
    if ($controls['DarkModeToggle']) { $controls['DarkModeToggle'].IsChecked = $isDark }
    Update-Theme -IsDark $isDark

    # Load saved settings
    if ($controls['AnimationsToggle']) {
        $controls['AnimationsToggle'].IsChecked = Get-Configuration -Section 'Theme' -Key 'EnableAnimations'
    }
    if ($controls['CachingToggle']) {
        $controls['CachingToggle'].IsChecked = Get-Configuration -Section 'Data' -Key 'CacheEnabled'
    }

    $exportPath = Get-Configuration -Section 'Data' -Key 'ExportPath'
    if ($exportPath -and $controls['ExportPathTextBox']) {
        $controls['ExportPathTextBox'].Text = $exportPath
    }

    # Initialize navigation state (unauthenticated)
    Update-NavigationState -IsAuthenticated $false

    # Start clock update timer
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    $timer.Add_Tick({
        if ($controls['CurrentTimeText']) {
            $controls['CurrentTimeText'].Text = Get-Date -Format 'HH:mm:ss'
        }
    })
    $timer.Start()

    Write-LogInfo -Message "Application window loaded" -Source 'Launcher'
})

# Window closing event
$Window.Add_Closing({
    Write-LogInfo -Message "Application closing..." -Source 'Launcher'

    # Save window state
    if ($Window.WindowState -eq 'Normal') {
        Set-Configuration -Section 'UI' -Key 'WindowWidth' -Value $Window.Width
        Set-Configuration -Section 'UI' -Key 'WindowHeight' -Value $Window.Height
    }
    Set-Configuration -Section 'UI' -Key 'WindowState' -Value $Window.WindowState.ToString()
    Save-Configuration

    # Disconnect if authenticated
    $authState = Get-AuthenticationState
    if ($authState.IsAuthenticated) {
        Disconnect-IntuneAdmin
    }

    Write-LogInfo -Message "Application closed" -Source 'Launcher'
})
#endregion

#region Application Start
# Apply saved window dimensions
$savedWidth = Get-Configuration -Section 'UI' -Key 'WindowWidth'
$savedHeight = Get-Configuration -Section 'UI' -Key 'WindowHeight'
$savedState = Get-Configuration -Section 'UI' -Key 'WindowState'

if ($savedWidth -gt 0) { $Window.Width = $savedWidth }
if ($savedHeight -gt 0) { $Window.Height = $savedHeight }
if ($savedState -and $savedState -ne 'Minimized') {
    $Window.WindowState = $savedState
}

# Show the window
Write-LogInfo -Message "Showing main window..." -Source 'Launcher'
$Window.ShowDialog() | Out-Null
#endregion
