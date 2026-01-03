<#
.SYNOPSIS
    Configuration management module for InSight.

.DESCRIPTION
    Handles application settings, user preferences, theme configuration,
    and persistent storage of user settings.

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Version: 1.0.0
#>

#Requires -Version 5.1

# Default configuration
$script:DefaultConfig = @{
    # Application Settings
    Application = @{
        Name           = 'InSight'
        Version        = '1.0.0'
        Author         = 'Kosta Wadenfalk'
        ConfigVersion  = 1
    }

    # Theme Settings
    Theme = @{
        Mode              = 'Light'  # Light, Dark, System
        AccentColor       = '#0078D4'  # Microsoft Blue
        FontFamily        = 'Segoe UI'
        FontSize          = 12
        EnableAnimations  = $true
        EnableShadows     = $true
    }

    # Authentication Settings
    Authentication = @{
        TenantId                  = $null
        PreferredAuthMethod       = 'Interactive'  # Interactive, ServicePrincipal
        RememberTenant            = $true
        TokenRefreshBufferMinutes = 5
    }

    # UI Settings
    UI = @{
        WindowWidth          = 1400
        WindowHeight         = 900
        WindowState          = 'Normal'
        NavigationPaneWidth  = 280
        ShowStatusBar        = $true
        ShowQuickActions     = $true
        DefaultView          = 'Dashboard'
        GridPageSize         = 50
    }

    # Data Settings
    Data = @{
        CacheEnabled         = $true
        CacheDurationMinutes = 5
        ExportPath           = [Environment]::GetFolderPath('Desktop')
        DefaultExportFormat  = 'CSV'  # CSV, JSON
    }

    # Logging Settings
    Logging = @{
        Level             = 'Information'
        EnableFileLogging = $true
        LogDirectory      = 'C:\Logs\IntuneAdmin'
        RetentionDays     = 30
    }

    # Feature Toggles
    Features = @{
        EnableDeviceActions    = $true
        EnableBulkOperations   = $false
        EnableAdvancedFilters  = $true
        ShowExperimentalItems  = $false
    }
}

# Runtime configuration (merged default + user settings)
$script:CurrentConfig = $null
$script:UserConfigPath = $null

function Initialize-Configuration {
    <#
    .SYNOPSIS
        Initializes the configuration system.

    .DESCRIPTION
        Loads user configuration from file or creates defaults.
        Merges user settings with default configuration.

    .PARAMETER ConfigPath
        Path to user configuration file. Defaults to user's AppData.

    .EXAMPLE
        Initialize-Configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    # Set config path
    if ([string]::IsNullOrEmpty($ConfigPath)) {
        $appDataPath = [Environment]::GetFolderPath('LocalApplicationData')
        $script:UserConfigPath = Join-Path -Path $appDataPath -ChildPath 'IntuneAdmin\config.json'
    }
    else {
        $script:UserConfigPath = $ConfigPath
    }

    # Deep clone default config
    $script:CurrentConfig = ConvertTo-HashtableDeep -InputObject $script:DefaultConfig

    # Load and merge user config if exists
    if (Test-Path -Path $script:UserConfigPath) {
        try {
            $userConfig = Get-Content -Path $script:UserConfigPath -Raw | ConvertFrom-Json
            $userConfigHash = ConvertTo-HashtableDeep -InputObject $userConfig
            Merge-Configuration -UserConfig $userConfigHash
            Write-Verbose "Loaded user configuration from: $script:UserConfigPath"
        }
        catch {
            Write-Warning "Failed to load user configuration: $_. Using defaults."
        }
    }
    else {
        Write-Verbose "No user configuration found. Using defaults."
    }
}

function ConvertTo-HashtableDeep {
    <#
    .SYNOPSIS
        Recursively converts PSCustomObject to hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [hashtable]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-HashtableDeep -InputObject $InputObject[$key]
        }
        return $result
    }
    elseif ($InputObject -is [PSCustomObject]) {
        $result = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $result[$prop.Name] = ConvertTo-HashtableDeep -InputObject $prop.Value
        }
        return $result
    }
    elseif ($InputObject -is [array]) {
        return @($InputObject | ForEach-Object { ConvertTo-HashtableDeep -InputObject $_ })
    }
    else {
        return $InputObject
    }
}

function Merge-Configuration {
    <#
    .SYNOPSIS
        Merges user configuration with current configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$UserConfig
    )

    foreach ($section in $UserConfig.Keys) {
        if ($script:CurrentConfig.ContainsKey($section)) {
            if ($UserConfig[$section] -is [hashtable] -and $script:CurrentConfig[$section] -is [hashtable]) {
                foreach ($key in $UserConfig[$section].Keys) {
                    $script:CurrentConfig[$section][$key] = $UserConfig[$section][$key]
                }
            }
            else {
                $script:CurrentConfig[$section] = $UserConfig[$section]
            }
        }
    }
}

function Get-Configuration {
    <#
    .SYNOPSIS
        Gets configuration value(s).

    .DESCRIPTION
        Retrieves configuration values by section or specific key.

    .PARAMETER Section
        Configuration section name (Theme, UI, Authentication, etc.).

    .PARAMETER Key
        Specific key within the section.

    .OUTPUTS
        Configuration value, section hashtable, or full configuration.

    .EXAMPLE
        Get-Configuration -Section 'Theme' -Key 'Mode'
        Returns: 'Light'

    .EXAMPLE
        Get-Configuration -Section 'UI'
        Returns: Hashtable of all UI settings
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Application', 'Theme', 'Authentication', 'UI', 'Data', 'Logging', 'Features')]
        [string]$Section,

        [Parameter()]
        [string]$Key
    )

    # Auto-initialize if needed
    if ($null -eq $script:CurrentConfig) {
        Initialize-Configuration
    }

    if ([string]::IsNullOrEmpty($Section)) {
        return $script:CurrentConfig.Clone()
    }

    if (-not $script:CurrentConfig.ContainsKey($Section)) {
        return $null
    }

    if ([string]::IsNullOrEmpty($Key)) {
        return $script:CurrentConfig[$Section].Clone()
    }

    if ($script:CurrentConfig[$Section].ContainsKey($Key)) {
        return $script:CurrentConfig[$Section][$Key]
    }

    return $null
}

function Set-Configuration {
    <#
    .SYNOPSIS
        Sets a configuration value.

    .DESCRIPTION
        Updates a configuration value and optionally saves to disk.

    .PARAMETER Section
        Configuration section name.

    .PARAMETER Key
        Key within the section.

    .PARAMETER Value
        New value to set.

    .PARAMETER Save
        Immediately save to disk after setting.

    .EXAMPLE
        Set-Configuration -Section 'Theme' -Key 'Mode' -Value 'Dark' -Save
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Application', 'Theme', 'Authentication', 'UI', 'Data', 'Logging', 'Features')]
        [string]$Section,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter()]
        [switch]$Save
    )

    # Auto-initialize if needed
    if ($null -eq $script:CurrentConfig) {
        Initialize-Configuration
    }

    if (-not $script:CurrentConfig.ContainsKey($Section)) {
        throw "Invalid configuration section: $Section"
    }

    $script:CurrentConfig[$Section][$Key] = $Value
    Write-Verbose "Set configuration: $Section.$Key = $Value"

    if ($Save) {
        Save-Configuration
    }
}

function Save-Configuration {
    <#
    .SYNOPSIS
        Saves current configuration to disk.

    .DESCRIPTION
        Persists the current configuration to the user's config file.

    .EXAMPLE
        Save-Configuration
    #>
    [CmdletBinding()]
    param()

    if ($null -eq $script:CurrentConfig) {
        Write-Warning "No configuration to save."
        return
    }

    try {
        # Ensure directory exists
        $configDir = [System.IO.Path]::GetDirectoryName($script:UserConfigPath)
        if (-not (Test-Path -Path $configDir)) {
            New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        }

        # Save as JSON
        $script:CurrentConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $script:UserConfigPath -Encoding UTF8
        Write-Verbose "Configuration saved to: $script:UserConfigPath"
    }
    catch {
        Write-Error "Failed to save configuration: $_"
    }
}

function Reset-Configuration {
    <#
    .SYNOPSIS
        Resets configuration to defaults.

    .DESCRIPTION
        Clears user configuration and restores default settings.

    .PARAMETER Section
        Reset only a specific section. If not specified, resets all.

    .PARAMETER Save
        Save the reset configuration to disk.

    .EXAMPLE
        Reset-Configuration -Section 'Theme' -Save
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Application', 'Theme', 'Authentication', 'UI', 'Data', 'Logging', 'Features')]
        [string]$Section,

        [Parameter()]
        [switch]$Save
    )

    if ([string]::IsNullOrEmpty($Section)) {
        $script:CurrentConfig = ConvertTo-HashtableDeep -InputObject $script:DefaultConfig
        Write-Verbose "Reset all configuration to defaults"
    }
    else {
        if ($script:DefaultConfig.ContainsKey($Section)) {
            $script:CurrentConfig[$Section] = ConvertTo-HashtableDeep -InputObject $script:DefaultConfig[$Section]
            Write-Verbose "Reset $Section configuration to defaults"
        }
    }

    if ($Save) {
        Save-Configuration
    }
}

function Get-ThemeColors {
    <#
    .SYNOPSIS
        Returns the complete color palette for the current theme.

    .DESCRIPTION
        Provides all colors needed for UI rendering based on the
        current theme mode (Light/Dark).

    .OUTPUTS
        Hashtable of color values.

    .EXAMPLE
        $colors = Get-ThemeColors
        $backgroundColor = $colors.Background
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $themeMode = Get-Configuration -Section 'Theme' -Key 'Mode'
    $accentColor = Get-Configuration -Section 'Theme' -Key 'AccentColor'

    # Determine actual mode if "System" is selected
    if ($themeMode -eq 'System') {
        try {
            $regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
            $useLightTheme = Get-ItemPropertyValue -Path $regPath -Name 'AppsUseLightTheme' -ErrorAction SilentlyContinue
            $themeMode = if ($useLightTheme -eq 1) { 'Light' } else { 'Dark' }
        }
        catch {
            $themeMode = 'Light'  # Default to light if can't detect
        }
    }

    if ($themeMode -eq 'Dark') {
        return @{
            # Backgrounds
            Background           = '#1E1E1E'
            BackgroundSecondary  = '#252526'
            BackgroundTertiary   = '#2D2D30'
            Surface              = '#333337'
            SurfaceHover         = '#3E3E42'
            SurfaceSelected      = '#094771'

            # Text
            TextPrimary          = '#FFFFFF'
            TextSecondary        = '#CCCCCC'
            TextTertiary         = '#9D9D9D'
            TextDisabled         = '#6D6D6D'
            TextOnAccent         = '#FFFFFF'

            # Borders
            Border               = '#3F3F46'
            BorderLight          = '#4D4D53'
            BorderFocus          = $accentColor

            # Accent
            Accent               = $accentColor
            AccentLight          = '#1A89CC'
            AccentDark           = '#005A9E'
            AccentHover          = '#1A89CC'

            # Status
            Success              = '#107C10'
            Warning              = '#CA5010'
            Error                = '#D32F2F'
            Info                 = '#0078D4'

            # Special
            Shadow               = '#000000'
            Overlay              = 'rgba(0,0,0,0.5)'
            Divider              = '#3F3F46'
            ScrollBar            = '#4D4D53'
            ScrollBarHover       = '#6D6D6D'

            # Navigation
            NavBackground        = '#252526'
            NavItemHover         = '#2D2D30'
            NavItemSelected      = '#094771'
            NavItemText          = '#CCCCCC'
            NavItemTextSelected  = '#FFFFFF'

            # Cards
            CardBackground       = '#2D2D30'
            CardBorder           = '#3F3F46'
            CardShadow           = '0 2px 4px rgba(0,0,0,0.3)'
        }
    }
    else {
        # Light theme
        return @{
            # Backgrounds
            Background           = '#F3F3F3'
            BackgroundSecondary  = '#FFFFFF'
            BackgroundTertiary   = '#FAFAFA'
            Surface              = '#FFFFFF'
            SurfaceHover         = '#F5F5F5'
            SurfaceSelected      = '#E5F3FF'

            # Text
            TextPrimary          = '#1A1A1A'
            TextSecondary        = '#605E5C'
            TextTertiary         = '#8A8886'
            TextDisabled         = '#A19F9D'
            TextOnAccent         = '#FFFFFF'

            # Borders
            Border               = '#E1E1E1'
            BorderLight          = '#EDEBE9'
            BorderFocus          = $accentColor

            # Accent
            Accent               = $accentColor
            AccentLight          = '#50A0E0'
            AccentDark           = '#005A9E'
            AccentHover          = '#106EBE'

            # Status
            Success              = '#107C10'
            Warning              = '#CA5010'
            Error                = '#D32F2F'
            Info                 = '#0078D4'

            # Special
            Shadow               = 'rgba(0,0,0,0.1)'
            Overlay              = 'rgba(0,0,0,0.3)'
            Divider              = '#EDEBE9'
            ScrollBar            = '#C8C8C8'
            ScrollBarHover       = '#A0A0A0'

            # Navigation
            NavBackground        = '#F3F3F3'
            NavItemHover         = '#E5E5E5'
            NavItemSelected      = '#E5F3FF'
            NavItemText          = '#605E5C'
            NavItemTextSelected  = $accentColor

            # Cards
            CardBackground       = '#FFFFFF'
            CardBorder           = '#E1E1E1'
            CardShadow           = '0 2px 4px rgba(0,0,0,0.08)'
        }
    }
}

function Export-Configuration {
    <#
    .SYNOPSIS
        Exports configuration to a file.

    .PARAMETER Path
        Export file path.

    .EXAMPLE
        Export-Configuration -Path 'C:\Backup\intune-admin-config.json'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($null -eq $script:CurrentConfig) {
        Initialize-Configuration
    }

    try {
        $script:CurrentConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
        Write-Verbose "Configuration exported to: $Path"
    }
    catch {
        Write-Error "Failed to export configuration: $_"
    }
}

function Import-Configuration {
    <#
    .SYNOPSIS
        Imports configuration from a file.

    .PARAMETER Path
        Import file path.

    .PARAMETER Save
        Save imported configuration as user config.

    .EXAMPLE
        Import-Configuration -Path 'C:\Backup\intune-admin-config.json' -Save
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [switch]$Save
    )

    if (-not (Test-Path -Path $Path)) {
        throw "Configuration file not found: $Path"
    }

    try {
        $importedConfig = Get-Content -Path $Path -Raw | ConvertFrom-Json
        $importedHash = ConvertTo-HashtableDeep -InputObject $importedConfig

        # Validate version compatibility
        if ($importedHash.Application.ConfigVersion -gt $script:DefaultConfig.Application.ConfigVersion) {
            Write-Warning "Imported configuration version is newer than supported. Some settings may not apply."
        }

        # Reset to defaults and merge
        $script:CurrentConfig = ConvertTo-HashtableDeep -InputObject $script:DefaultConfig
        Merge-Configuration -UserConfig $importedHash

        Write-Verbose "Configuration imported from: $Path"

        if ($Save) {
            Save-Configuration
        }
    }
    catch {
        throw "Failed to import configuration: $_"
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-Configuration',
    'Get-Configuration',
    'Set-Configuration',
    'Save-Configuration',
    'Reset-Configuration',
    'Get-ThemeColors',
    'Export-Configuration',
    'Import-Configuration'
)
