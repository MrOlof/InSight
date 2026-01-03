<#
.SYNOPSIS
    Centralized MSAL authentication module for InSight.

.DESCRIPTION
    Provides Microsoft Graph API authentication using MSAL (Microsoft.Identity.Client)
    with token management, caching, permission enumeration, and session state tracking.

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Requires: Microsoft.Identity.Client.dll (from MSAL.PS, Az.Accounts, or direct download)
    Version: 2.0.0
#>

#Requires -Version 5.1

# Module-scoped variables for session state
$script:AuthenticationState = @{
    IsAuthenticated    = $false
    AccessToken        = $null
    TokenExpiration    = $null
    UserPrincipalName  = $null
    DisplayName        = $null
    TenantId           = $null
    Scopes             = @()
    Permissions        = @()
    AuthMethod         = $null  # 'Interactive' or 'ServicePrincipal'
    LastRefresh        = $null
    SessionStartTime   = $null  # Track when session started for timeout enforcement
}

# MSAL Application configuration
$script:MSALConfig = @{
    # Default Azure AD app for Intune Management (Microsoft Intune PowerShell)
    ClientId     = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    RedirectUri  = 'http://localhost'
    Authority    = 'https://login.microsoftonline.com/common'
    Scopes       = @(
        'https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All',
        'https://graph.microsoft.com/DeviceManagementApps.Read.All',
        'https://graph.microsoft.com/DeviceManagementConfiguration.Read.All',
        'https://graph.microsoft.com/User.Read.All',
        'https://graph.microsoft.com/Directory.Read.All',
        'https://graph.microsoft.com/Group.Read.All',
        'https://graph.microsoft.com/offline_access',
        'https://graph.microsoft.com/openid',
        'https://graph.microsoft.com/profile'
    )
}

# Token cache path
$script:TokenCachePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'IntuneAdmin\msalcache.bin'

# MSAL application instance
$script:MSALApp = $null
$script:MSALToken = $null

# Permission definitions for Intune administration
$script:IntunePermissions = @{
    # Device Management
    'DeviceManagementManagedDevices.Read.All' = @{
        DisplayName = 'Read Managed Devices'
        Description = 'View all Intune managed devices'
        Category    = 'Devices'
        Required    = $false
    }
    'DeviceManagementManagedDevices.ReadWrite.All' = @{
        DisplayName = 'Manage Devices'
        Description = 'Perform actions on managed devices (sync, retire, wipe)'
        Category    = 'Devices'
        Required    = $false
    }
    'DeviceManagementManagedDevices.PrivilegedOperations.All' = @{
        DisplayName = 'Privileged Device Operations'
        Description = 'Perform privileged operations like remote wipe'
        Category    = 'Devices'
        Required    = $false
    }

    # Application Management
    'DeviceManagementApps.Read.All' = @{
        DisplayName = 'Read Applications'
        Description = 'View Intune applications and assignments'
        Category    = 'Applications'
        Required    = $false
    }
    'DeviceManagementApps.ReadWrite.All' = @{
        DisplayName = 'Manage Applications'
        Description = 'Create and modify Intune applications'
        Category    = 'Applications'
        Required    = $false
    }

    # Configuration Policies
    'DeviceManagementConfiguration.Read.All' = @{
        DisplayName = 'Read Configuration Policies'
        Description = 'View device configuration policies'
        Category    = 'Configuration'
        Required    = $false
    }
    'DeviceManagementConfiguration.ReadWrite.All' = @{
        DisplayName = 'Manage Configuration Policies'
        Description = 'Create and modify configuration policies'
        Category    = 'Configuration'
        Required    = $false
    }

    # Compliance Policies
    'DeviceManagementRBAC.Read.All' = @{
        DisplayName = 'Read RBAC Settings'
        Description = 'View role-based access control settings'
        Category    = 'RBAC'
        Required    = $false
    }

    # User Operations
    'User.Read.All' = @{
        DisplayName = 'Read Users'
        Description = 'View user information'
        Category    = 'Users'
        Required    = $false
    }
    'User.ReadWrite.All' = @{
        DisplayName = 'Manage Users'
        Description = 'Modify user information'
        Category    = 'Users'
        Required    = $false
    }

    # Directory Operations
    'Directory.Read.All' = @{
        DisplayName = 'Read Directory'
        Description = 'Read directory data'
        Category    = 'Directory'
        Required    = $false
    }

    # Group Operations
    'Group.Read.All' = @{
        DisplayName = 'Read Groups'
        Description = 'View group information'
        Category    = 'Groups'
        Required    = $false
    }
    'GroupMember.Read.All' = @{
        DisplayName = 'Read Group Members'
        Description = 'View group membership'
        Category    = 'Groups'
        Required    = $false
    }
}

function Initialize-MSALLibrary {
    <#
    .SYNOPSIS
        Loads the MSAL library (Microsoft.Identity.Client.dll).

    .DESCRIPTION
        Searches for and loads the MSAL DLL from various sources:
        1. MSAL.PS module
        2. Az.Accounts module
        3. Local Bin folder

    .OUTPUTS
        Boolean indicating if MSAL was loaded successfully.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # Check if already loaded
    if ('Microsoft.Identity.Client.PublicClientApplication' -as [type]) {
        Write-Verbose "MSAL library already loaded."
        return $true
    }

    $msalPath = $null

    # Try MSAL.PS module
    $msalModule = Get-Module -Name MSAL.PS -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    if ($msalModule) {
        $moduleDir = Split-Path -Parent $msalModule.Path
        $msalFolder = Get-ChildItem -Path $moduleDir -Filter 'Microsoft.Identity.Client*' -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($msalFolder) {
            $testPath = Join-Path -Path $msalFolder.FullName -ChildPath 'net45\Microsoft.Identity.Client.dll'
            if (Test-Path -Path $testPath) {
                $msalPath = $testPath
            }
        }
    }

    # Try Az.Accounts module
    if (-not $msalPath) {
        $azModule = Get-Module -Name Az.Accounts -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        if ($azModule) {
            $moduleDir = Split-Path -Parent $azModule.Path

            # Check multiple possible locations (path structure changed in newer versions)
            $possiblePaths = @(
                'PreloadAssemblies\Microsoft.Identity.Client.dll',
                'lib\netstandard2.0\Microsoft.Identity.Client.dll',
                'Dependencies\Microsoft.Identity.Client.dll'
            )

            foreach ($relativePath in $possiblePaths) {
                $testPath = Join-Path -Path $moduleDir -ChildPath $relativePath
                if (Test-Path -Path $testPath) {
                    $msalPath = $testPath
                    break
                }
            }
        }
    }

    # Try local Bin folder
    if (-not $msalPath) {
        $scriptRoot = Split-Path -Parent $PSScriptRoot
        $testPath = Join-Path -Path $scriptRoot -ChildPath 'Bin\Microsoft.Identity.Client.dll'
        if (Test-Path -Path $testPath) {
            $msalPath = $testPath
        }
    }

    if (-not $msalPath) {
        Write-Warning "Microsoft.Identity.Client.dll not found. Please install MSAL.PS or Az.Accounts module."
        Write-Warning "Run: Install-Module MSAL.PS -Scope CurrentUser"
        return $false
    }

    try {
        # Load the assembly
        [System.Reflection.Assembly]::LoadFrom($msalPath) | Out-Null
        Write-Verbose "Loaded MSAL from: $msalPath"
        return $true
    }
    catch {
        Write-Error "Failed to load MSAL library: $_"
        return $false
    }
}

function Get-MSALPublicClientApplication {
    <#
    .SYNOPSIS
        Gets or creates the MSAL public client application.

    .OUTPUTS
        Microsoft.Identity.Client.IPublicClientApplication instance.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantId
    )

    if ($script:MSALApp) {
        return $script:MSALApp
    }

    if (-not (Initialize-MSALLibrary)) {
        throw "MSAL library not available"
    }

    try {
        $authority = if ($TenantId) {
            "https://login.microsoftonline.com/$TenantId"
        } else {
            $script:MSALConfig.Authority
        }

        $appBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($script:MSALConfig.ClientId)
        [void]$appBuilder.WithAuthority($authority)
        [void]$appBuilder.WithRedirectUri($script:MSALConfig.RedirectUri)
        [void]$appBuilder.WithClientName('IntuneAdminTool')
        [void]$appBuilder.WithClientVersion('2.0.0')

        $script:MSALApp = $appBuilder.Build()

        # Enable token cache serialization
        Initialize-TokenCache

        return $script:MSALApp
    }
    catch {
        Write-Error "Failed to create MSAL application: $_"
        throw
    }
}

function Initialize-TokenCache {
    <#
    .SYNOPSIS
        Initializes the token cache with encryption.

    .DESCRIPTION
        Sets up the MSAL token cache to persist tokens to disk with DPAPI encryption.
        This allows silent token acquisition on subsequent runs.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:MSALApp) {
        return
    }

    try {
        # Ensure cache directory exists
        $cacheDir = Split-Path -Parent $script:TokenCachePath
        if (-not (Test-Path -Path $cacheDir)) {
            New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null
        }

        # Register cache callbacks
        $script:MSALApp.UserTokenCache.SetBeforeAccess({
            param($args)
            if (Test-Path -Path $script:TokenCachePath) {
                try {
                    $encryptedData = [System.IO.File]::ReadAllBytes($script:TokenCachePath)
                    $decryptedData = [System.Security.Cryptography.ProtectedData]::Unprotect(
                        $encryptedData,
                        $null,
                        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                    )
                    $args.TokenCache.DeserializeMsalV3($decryptedData)
                }
                catch {
                    Write-Verbose "Failed to read token cache: $_"
                }
            }
        })

        $script:MSALApp.UserTokenCache.SetAfterAccess({
            param($args)
            if ($args.HasStateChanged) {
                try {
                    $data = $args.TokenCache.SerializeMsalV3()
                    $encryptedData = [System.Security.Cryptography.ProtectedData]::Protect(
                        $data,
                        $null,
                        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                    )
                    [System.IO.File]::WriteAllBytes($script:TokenCachePath, $encryptedData)
                }
                catch {
                    Write-Verbose "Failed to write token cache: $_"
                }
            }
        })

        Write-Verbose "Token cache initialized: $script:TokenCachePath"
    }
    catch {
        Write-Warning "Failed to initialize token cache: $_"
    }
}

function Get-AuthenticationState {
    <#
    .SYNOPSIS
        Returns the current authentication state.

    .DESCRIPTION
        Provides access to the current authentication session including
        token status, user information, and available permissions.

    .OUTPUTS
        Hashtable containing authentication state information.

    .EXAMPLE
        $state = Get-AuthenticationState
        if ($state.IsAuthenticated) { Write-Host "Logged in as $($state.DisplayName)" }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return $script:AuthenticationState.Clone()
}

function Test-TokenExpiration {
    <#
    .SYNOPSIS
        Checks if the current token is expired or near expiration.

    .DESCRIPTION
        Returns true if the token needs to be refreshed (expired or within buffer minutes of expiration).

    .OUTPUTS
        Boolean indicating if token refresh is needed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [int]$BufferMinutes = 5
    )

    if (-not $script:AuthenticationState.IsAuthenticated) {
        return $true
    }

    if ($null -eq $script:AuthenticationState.TokenExpiration) {
        return $true
    }

    $expirationWithBuffer = $script:AuthenticationState.TokenExpiration.AddMinutes(-$BufferMinutes)
    return (Get-Date) -ge $expirationWithBuffer
}

function Test-SessionDuration {
    <#
    .SYNOPSIS
        Checks if the session has exceeded the maximum allowed duration.

    .DESCRIPTION
        Returns true if the session should be terminated based on MaxSessionDurationHours setting.
        Only applies if EnforceSessionTimeout is enabled in configuration.

    .OUTPUTS
        Boolean indicating if session has exceeded maximum duration.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not $script:AuthenticationState.IsAuthenticated) {
        return $false
    }

    if ($null -eq $script:AuthenticationState.SessionStartTime) {
        return $false
    }

    # Get configuration settings
    try {
        $config = Get-Configuration -Section 'Authentication'
        $enforceTimeout = $config.EnforceSessionTimeout
        $maxHours = $config.MaxSessionDurationHours

        if (-not $enforceTimeout -or $null -eq $maxHours) {
            return $false
        }

        $sessionAge = (Get-Date) - $script:AuthenticationState.SessionStartTime
        $maxDuration = [TimeSpan]::FromHours($maxHours)

        if ($sessionAge -ge $maxDuration) {
            Write-Log "Session exceeded maximum duration of $maxHours hours (started: $($script:AuthenticationState.SessionStartTime))" -Level 'Warning'
            return $true
        }

        return $false
    }
    catch {
        Write-Verbose "Failed to check session duration: $_"
        return $false
    }
}

function Connect-IntuneAdmin {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Graph for Intune administration.

    .DESCRIPTION
        Performs interactive or silent authentication to Microsoft Graph API using Connect-MgGraph.
        Stores the token and enumerates available permissions for the session.
        Supports token caching for seamless re-authentication.

    .PARAMETER Interactive
        Force interactive authentication (browser-based login).

    .PARAMETER TenantId
        The Azure AD tenant ID for authentication.

    .PARAMETER Silent
        Attempt silent authentication first (uses cached token).

    .PARAMETER Scopes
        Additional scopes to request during authentication.

    .EXAMPLE
        Connect-IntuneAdmin -Interactive
        Performs interactive browser-based authentication.

    .EXAMPLE
        Connect-IntuneAdmin -Silent
        Attempts to acquire token silently from cache.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    [OutputType([bool])]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [switch]$Silent,

        [Parameter()]
        [string[]]$Scopes
    )

    # Try using Microsoft.Graph.Authentication module instead of raw MSAL
    if (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable) {
        Write-Log "Connect-IntuneAdmin: Using Microsoft.Graph.Authentication module" -Level "Information"

        try {
            # If forcing interactive (not silent), disconnect first to ensure fresh auth with current PIM roles
            if ($Interactive -and -not $Silent) {
                $existingContext = Get-MgContext -ErrorAction SilentlyContinue
                if ($existingContext) {
                    Write-Log "Connect-IntuneAdmin: Existing context found, disconnecting to force fresh authentication" -Level "Information"
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                }
            }

            # Use configured scopes if not specified
            if (-not $Scopes -or $Scopes.Count -eq 0) {
                $Scopes = $script:MSALConfig.Scopes
            }

            $connectParams = @{
                Scopes = $Scopes
                NoWelcome = $true
            }

            if ($TenantId) {
                $connectParams['TenantId'] = $TenantId
            }

            Write-Log "Connect-IntuneAdmin: Calling Connect-MgGraph with scopes: $($Scopes -join ', ')" -Level "Information"
            Connect-MgGraph @connectParams -ErrorAction Stop

            # Get the access token from the current context
            $context = Get-MgContext
            if ($context) {
                Write-Log "Connect-IntuneAdmin: Successfully connected to tenant: $($context.TenantId)" -Level "Information"

                # Store authentication state
                $script:AuthenticationState.IsAuthenticated = $true
                $script:AuthenticationState.TenantId = $context.TenantId
                $script:AuthenticationState.Scopes = $context.Scopes
                $script:AuthenticationState.AuthMethod = 'Interactive'
                $script:AuthenticationState.LastRefresh = Get-Date
                $script:AuthenticationState.UserPrincipalName = $context.Account
                $script:AuthenticationState.DisplayName = $context.Account

                # Set session start time only on initial login (not on token refresh)
                if ($null -eq $script:AuthenticationState.SessionStartTime) {
                    $script:AuthenticationState.SessionStartTime = Get-Date
                    Write-Log "Connect-IntuneAdmin: Session started at $($script:AuthenticationState.SessionStartTime)" -Level "Information"
                }

                # Get access token - use reflection to call internal method
                try {
                    $authProvider = (Get-MgContext).AuthType
                    if ($authProvider -eq 'Delegated') {
                        # For delegated auth, we can get the token from the HTTP client
                        $graphClient = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.GraphClient
                        if ($graphClient) {
                            $authContext = $graphClient.HttpProvider.AuthenticationProvider
                            # Get token silently
                            $tokenRequest = $authContext.GetType().GetMethod('GetAccessTokenSilentAsync', [System.Reflection.BindingFlags]'NonPublic,Instance')
                            if ($tokenRequest) {
                                $tokenTask = $tokenRequest.Invoke($authContext, @($null))
                                $script:AuthenticationState.AccessToken = $tokenTask.Result
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Connect-IntuneAdmin: Could not retrieve access token from Microsoft.Graph context - $($_.Exception.Message)" -Level "Warning"
                }

                # Enumerate permissions
                $script:AuthenticationState.Permissions = Get-EffectivePermissions

                Write-Log "Connect-IntuneAdmin: Authentication successful" -Level "Information"
                return $true
            }
            else {
                Write-Log "Connect-IntuneAdmin: No context returned after Connect-MgGraph" -Level "Error"
                return $false
            }
        }
        catch {
            Write-Log "Connect-IntuneAdmin: Microsoft.Graph.Authentication failed - $($_.Exception.Message)" -Level "Error"
            Reset-AuthenticationState
            return $false
        }
    }

    # Fall back to MSAL if Microsoft.Graph.Authentication not available

    try {
        Write-Log "Connect-IntuneAdmin: Starting MSAL authentication process..." -Level "Information"
        Write-Verbose "Starting MSAL authentication process..."

        # Get or create MSAL app
        Write-Log "Connect-IntuneAdmin: Getting MSAL public client application" -Level "Information"
        $app = Get-MSALPublicClientApplication -TenantId $TenantId
        Write-Log "Connect-IntuneAdmin: MSAL app created successfully" -Level "Information"

        # Use configured scopes if not specified
        if (-not $Scopes -or $Scopes.Count -eq 0) {
            $Scopes = $script:MSALConfig.Scopes
        }
        Write-Log "Connect-IntuneAdmin: Using scopes: $($Scopes -join ', ')" -Level "Information"

        $authResult = $null
        $account = $null

        # Try to get cached accounts
        Write-Log "Connect-IntuneAdmin: Checking for cached accounts" -Level "Information"
        $accounts = $app.GetAccountsAsync().GetAwaiter().GetResult()
        if ($accounts -and $accounts.Count -gt 0) {
            $account = $accounts | Select-Object -First 1
            Write-Log "Connect-IntuneAdmin: Found cached account: $($account.Username)" -Level "Information"
        }
        else {
            Write-Log "Connect-IntuneAdmin: No cached accounts found" -Level "Information"
        }

        # Try silent authentication first if requested or if we have a cached account
        if (($Silent -or $account) -and -not $Interactive) {
            if ($account) {
                Write-Log "Connect-IntuneAdmin: Attempting silent token acquisition..." -Level "Information"
                Write-Verbose "Attempting silent token acquisition..."
                try {
                    $silentRequest = $app.AcquireTokenSilent($Scopes, $account)
                    $authResult = $silentRequest.ExecuteAsync().GetAwaiter().GetResult()
                    Write-Log "Connect-IntuneAdmin: Silent authentication successful" -Level "Information"
                    Write-Verbose "Silent authentication successful"
                }
                catch [Microsoft.Identity.Client.MsalUiRequiredException] {
                    Write-Log "Connect-IntuneAdmin: Silent authentication failed - UI required" -Level "Information"
                    Write-Verbose "Silent authentication failed, UI required"
                    $authResult = $null
                }
                catch {
                    Write-Log "Connect-IntuneAdmin: Silent authentication failed - $_" -Level "Warning"
                    Write-Verbose "Silent authentication failed: $_"
                    $authResult = $null
                }
            }
        }

        # Fall back to interactive if silent failed or was not requested
        if (-not $authResult) {
            Write-Log "Connect-IntuneAdmin: Performing interactive authentication (opening browser)..." -Level "Information"
            Write-Verbose "Performing interactive authentication..."
            $interactiveRequest = $app.AcquireTokenInteractive($Scopes)

            if ($account) {
                [void]$interactiveRequest.WithAccount($account)
                Write-Log "Connect-IntuneAdmin: Using cached account for interactive auth" -Level "Information"
            }

            # Use system browser
            [void]$interactiveRequest.WithUseEmbeddedWebView($false)

            Write-Log "Connect-IntuneAdmin: Calling ExecuteAsync() - waiting for user to complete browser authentication..." -Level "Information"

            # Use the same approach as IntuneManagement - process UI events while waiting
            Add-Type -AssemblyName System.Windows.Forms
            $tokenSource = New-Object System.Threading.CancellationTokenSource
            $taskAuthResult = $interactiveRequest.ExecuteAsync($tokenSource.Token)

            try {
                while (-not $taskAuthResult.IsCompleted) {
                    [System.Windows.Forms.Application]::DoEvents()
                    Start-Sleep -Milliseconds 100
                }
            }
            finally {
                if (-not $taskAuthResult.IsCompleted) {
                    $tokenSource.Cancel()
                }
                $tokenSource.Dispose()
            }

            if ($taskAuthResult.IsFaulted) {
                $exception = if ($taskAuthResult.Exception.InnerException) { $taskAuthResult.Exception.InnerException } else { $taskAuthResult.Exception }
                Write-Log "Connect-IntuneAdmin: Task faulted - $($exception.Message)" -Level "Error"
                throw $exception
            }

            $authResult = $taskAuthResult.Result
            Write-Log "Connect-IntuneAdmin: ExecuteAsync() completed successfully, authResult is $($null -ne $authResult)" -Level "Information"
        }

        if ($null -eq $authResult) {
            Write-Log "Connect-IntuneAdmin: Authentication failed - no result returned from MSAL" -Level "Error"
            throw "Authentication failed - no result returned"
        }

        # Store token and update state
        Write-Log "Connect-IntuneAdmin: Storing authentication result and updating state" -Level "Information"
        $script:MSALToken = $authResult

        $script:AuthenticationState.IsAuthenticated = $true
        $script:AuthenticationState.AccessToken = $authResult.AccessToken
        $script:AuthenticationState.TokenExpiration = $authResult.ExpiresOn.LocalDateTime
        $script:AuthenticationState.UserPrincipalName = $authResult.Account.Username
        $script:AuthenticationState.TenantId = $authResult.TenantId
        $script:AuthenticationState.Scopes = $authResult.Scopes
        $script:AuthenticationState.AuthMethod = 'Interactive'
        $script:AuthenticationState.LastRefresh = Get-Date

        # Set session start time only on initial login (not on token refresh)
        if ($null -eq $script:AuthenticationState.SessionStartTime) {
            $script:AuthenticationState.SessionStartTime = Get-Date
            Write-Log "Connect-IntuneAdmin: Session started at $($script:AuthenticationState.SessionStartTime)" -Level "Information"
        }

        Write-Log "Connect-IntuneAdmin: Token stored, expires at $($script:AuthenticationState.TokenExpiration)" -Level "Information"

        # Get display name from token claims or username
        $script:AuthenticationState.DisplayName = $authResult.Account.Username
        if ($authResult.ClaimsPrincipal) {
            $nameClaim = $authResult.ClaimsPrincipal.Claims | Where-Object { $_.Type -eq 'name' } | Select-Object -First 1
            if ($nameClaim) {
                $script:AuthenticationState.DisplayName = $nameClaim.Value
            }
        }

        Write-Log "Connect-IntuneAdmin: Display name set to: $($script:AuthenticationState.DisplayName)" -Level "Information"

        # Enumerate permissions from scopes
        Write-Log "Connect-IntuneAdmin: Enumerating effective permissions..." -Level "Information"
        $script:AuthenticationState.Permissions = Get-EffectivePermissions

        Write-Log "Connect-IntuneAdmin: Authentication successful for: $($script:AuthenticationState.DisplayName)" -Level "Information"
        Write-Verbose "Authentication successful for: $($script:AuthenticationState.DisplayName)"
        Write-Verbose "Token expires: $($script:AuthenticationState.TokenExpiration)"
        Write-Verbose "Available scopes: $($script:AuthenticationState.Scopes -join ', ')"

        Write-Log "Connect-IntuneAdmin: Returning TRUE" -Level "Information"
        return $true
    }
    catch {
        $errorDetails = $_.Exception.Message
        $errorStack = $_.ScriptStackTrace
        Write-Log "Connect-IntuneAdmin: EXCEPTION CAUGHT - $errorDetails" -Level "Error"
        Write-Log "Connect-IntuneAdmin: Stack trace - $errorStack" -Level "Error"
        Write-Error "Authentication failed: $_"
        Reset-AuthenticationState
        Write-Log "Connect-IntuneAdmin: Returning FALSE due to exception" -Level "Error"
        return $false
    }
}

function Disconnect-IntuneAdmin {
    <#
    .SYNOPSIS
        Disconnects from Microsoft Graph and clears the session.

    .DESCRIPTION
        Signs out from Microsoft Graph and resets all authentication state.
        Optionally clears the token cache.

    .PARAMETER ClearCache
        Also clear the persisted token cache.

    .EXAMPLE
        Disconnect-IntuneAdmin
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$ClearCache
    )

    try {
        # Disconnect from Microsoft.Graph if module is available
        if (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable) {
            try {
                # Force disconnect to clear the session completely
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose "Disconnected from Microsoft Graph"

                # Clear Microsoft.Graph token cache directories to force fresh auth
                $graphCachePaths = @(
                    (Join-Path $env:USERPROFILE '.graph'),
                    (Join-Path $env:LOCALAPPDATA '.IdentityService'),
                    (Join-Path $env:TEMP 'GraphTokenCache')
                )

                foreach ($cachePath in $graphCachePaths) {
                    if (Test-Path -Path $cachePath) {
                        try {
                            Remove-Item -Path $cachePath -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Verbose "Cleared Microsoft.Graph cache: $cachePath"
                        }
                        catch {
                            Write-Verbose "Could not clear cache: $cachePath - $_"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Disconnect-MgGraph warning: $_"
            }
        }

        if ($script:MSALApp -and $script:MSALToken) {
            # Remove account from cache
            $accounts = $script:MSALApp.GetAccountsAsync().GetAwaiter().GetResult()
            foreach ($account in $accounts) {
                $script:MSALApp.RemoveAsync($account).GetAwaiter().GetResult() | Out-Null
            }
        }

        if ($ClearCache -and (Test-Path -Path $script:TokenCachePath)) {
            Remove-Item -Path $script:TokenCachePath -Force -ErrorAction SilentlyContinue
            Write-Verbose "Token cache cleared"
        }
    }
    catch {
        Write-Verbose "Disconnect warning: $_"
    }
    finally {
        Reset-AuthenticationState
        $script:MSALApp = $null
        $script:MSALToken = $null
        Write-Verbose "Session disconnected and state cleared."
    }
}

function Reset-AuthenticationState {
    <#
    .SYNOPSIS
        Resets the authentication state to default values.
    #>
    [CmdletBinding()]
    param()

    $script:AuthenticationState.IsAuthenticated = $false
    $script:AuthenticationState.AccessToken = $null
    $script:AuthenticationState.TokenExpiration = $null
    $script:AuthenticationState.UserPrincipalName = $null
    $script:AuthenticationState.DisplayName = $null
    $script:AuthenticationState.TenantId = $null
    $script:AuthenticationState.Scopes = @()
    $script:AuthenticationState.Permissions = @()
    $script:AuthenticationState.AuthMethod = $null
    $script:AuthenticationState.LastRefresh = $null
    $script:AuthenticationState.SessionStartTime = $null
}

function Get-AccessToken {
    <#
    .SYNOPSIS
        Gets the current access token, refreshing if necessary.

    .DESCRIPTION
        Returns the current access token for Graph API calls.
        Automatically refreshes the token if expired or near expiration.
        Enforces maximum session duration if configured.

    .OUTPUTS
        String containing the access token.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not $script:AuthenticationState.IsAuthenticated) {
        throw "Not authenticated. Please run Connect-IntuneAdmin first."
    }

    # Check if session has exceeded maximum duration
    if (Test-SessionDuration) {
        Write-LogWarning -Message "Session exceeded maximum duration. Forcing re-authentication." -Source 'AuthenticationManager'

        # Get configuration to check if cache should be cleared
        try {
            $config = Get-Configuration -Section 'Authentication'
            $clearCache = $config.ClearCacheOnTimeout
        }
        catch {
            $clearCache = $true
        }

        # Disconnect and clear cache if configured
        if ($clearCache) {
            Disconnect-IntuneAdmin -ClearCache
        }
        else {
            Disconnect-IntuneAdmin
        }

        throw "Session expired after maximum duration. Please sign in again."
    }

    # Check if token needs refresh
    if (Test-TokenExpiration) {
        Write-Verbose "Token expired or near expiration, refreshing..."
        $refreshed = Connect-IntuneAdmin -Silent
        if (-not $refreshed) {
            throw "Failed to refresh token. Please re-authenticate."
        }
    }

    return $script:AuthenticationState.AccessToken
}

function Get-EffectivePermissions {
    <#
    .SYNOPSIS
        Determines effective permissions based on current scopes.

    .DESCRIPTION
        Analyzes the current authentication scopes and returns a list of
        effective permissions with their metadata.

    .OUTPUTS
        Array of permission objects with details about each granted permission.
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $effectivePermissions = @()
    $currentScopes = $script:AuthenticationState.Scopes

    foreach ($scope in $currentScopes) {
        # Remove any prefix like 'https://graph.microsoft.com/'
        $cleanScope = $scope -replace '^https://graph\.microsoft\.com/', ''
        $cleanScope = $cleanScope -replace '^\.default$', ''

        if ([string]::IsNullOrWhiteSpace($cleanScope)) {
            continue
        }

        $permissionInfo = $script:IntunePermissions[$cleanScope]

        $permission = [PSCustomObject]@{
            Scope       = $cleanScope
            DisplayName = if ($permissionInfo) { $permissionInfo.DisplayName } else { $cleanScope }
            Description = if ($permissionInfo) { $permissionInfo.Description } else { 'Custom permission' }
            Category    = if ($permissionInfo) { $permissionInfo.Category } else { 'Other' }
            IsGranted   = $true
        }

        $effectivePermissions += $permission
    }

    return $effectivePermissions
}

function Test-IntunePermission {
    <#
    .SYNOPSIS
        Tests if the current session has a specific permission.

    .DESCRIPTION
        Checks if the authenticated user/service principal has the specified
        Graph API permission in their current session.

    .PARAMETER Permission
        The permission scope to check (e.g., 'DeviceManagementManagedDevices.Read.All').

    .PARAMETER Any
        If specified with multiple permissions, returns true if ANY permission is granted.

    .PARAMETER All
        If specified with multiple permissions, returns true only if ALL permissions are granted.

    .OUTPUTS
        Boolean indicating if the permission is available.

    .EXAMPLE
        if (Test-IntunePermission -Permission 'DeviceManagementManagedDevices.ReadWrite.All') {
            # Can perform device actions
        }
    #>
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]]$Permission,

        [Parameter(ParameterSetName = 'Any')]
        [switch]$Any,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All
    )

    if (-not $script:AuthenticationState.IsAuthenticated) {
        Write-Verbose "Not authenticated - permission check returns false"
        return $false
    }

    $currentScopes = $script:AuthenticationState.Scopes | ForEach-Object {
        $_ -replace '^https://graph\.microsoft\.com/', ''
    }

    $results = foreach ($perm in $Permission) {
        $hasPermission = $currentScopes -contains $perm

        # Check for ReadWrite implying Read
        if (-not $hasPermission -and $perm -like '*.Read.*') {
            $rwPermission = $perm -replace '\.Read\.', '.ReadWrite.'
            $hasPermission = $currentScopes -contains $rwPermission
        }

        $hasPermission
    }

    if ($Any) {
        return ($results -contains $true)
    }
    elseif ($All -or $Permission.Count -gt 1) {
        return ($results -notcontains $false)
    }
    else {
        return $results[0]
    }
}

function Get-IntunePermissionCategories {
    <#
    .SYNOPSIS
        Returns permission categories with their status.

    .DESCRIPTION
        Groups permissions by category and indicates which are available
        in the current session. Useful for UI permission display.

    .OUTPUTS
        Hashtable of categories with permission status.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $categories = @{}

    foreach ($key in $script:IntunePermissions.Keys) {
        $perm = $script:IntunePermissions[$key]
        $category = $perm.Category

        if (-not $categories.ContainsKey($category)) {
            $categories[$category] = @{
                Permissions   = @()
                HasAnyAccess  = $false
                HasFullAccess = $true
            }
        }

        $isGranted = Test-IntunePermission -Permission $key

        $categories[$category].Permissions += [PSCustomObject]@{
            Scope       = $key
            DisplayName = $perm.DisplayName
            Description = $perm.Description
            IsGranted   = $isGranted
        }

        if ($isGranted) {
            $categories[$category].HasAnyAccess = $true
        }
        else {
            $categories[$category].HasFullAccess = $false
        }
    }

    return $categories
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Wrapper for Graph API requests with automatic token management.

    .DESCRIPTION
        Executes a Microsoft Graph API request using the current session.
        Automatically refreshes token if needed and provides consistent error handling.

    .PARAMETER Uri
        The Graph API endpoint URI.

    .PARAMETER Method
        The HTTP method (GET, POST, PATCH, DELETE).

    .PARAMETER Body
        The request body for POST/PATCH requests.

    .PARAMETER RequiredPermission
        Permission required for this operation. Will check before executing.

    .OUTPUTS
        The Graph API response object.

    .EXAMPLE
        $devices = Invoke-GraphRequest -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' -Method GET
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE', 'PUT')]
        [string]$Method = 'GET',

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [string]$RequiredPermission
    )

    if (-not $script:AuthenticationState.IsAuthenticated) {
        throw "Not authenticated. Please run Connect-IntuneAdmin first."
    }

    if ($RequiredPermission -and -not (Test-IntunePermission -Permission $RequiredPermission)) {
        throw "Missing required permission: $RequiredPermission"
    }

    # Get fresh token
    $token = Get-AccessToken

    $headers = @{
        'Authorization' = "Bearer $token"
        'Content-Type'  = 'application/json'
    }

    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $headers
        ErrorAction = 'Stop'
    }

    if ($Body) {
        if ($Body -is [string]) {
            $params['Body'] = $Body
        }
        else {
            $params['Body'] = $Body | ConvertTo-Json -Depth 10
        }
    }

    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $errorMessage = $_.Exception.Message

        # Parse Graph API error if available
        if ($_.ErrorDetails.Message) {
            try {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                $errorMessage = $errorDetails.error.message
            }
            catch {
                # Use original error message
            }
        }

        throw "Graph API request failed: $errorMessage"
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-AuthenticationState',
    'Test-TokenExpiration',
    'Test-SessionDuration',
    'Connect-IntuneAdmin',
    'Disconnect-IntuneAdmin',
    'Get-AccessToken',
    'Test-IntunePermission',
    'Get-EffectivePermissions',
    'Get-IntunePermissionCategories',
    'Invoke-GraphRequest'
)
