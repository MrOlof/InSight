<#
.SYNOPSIS
    Script management module for InSight.

.DESCRIPTION
    Handles registration, discovery, and execution of custom scripts.

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Version: 1.0.0
#>

#Requires -Version 5.1

# Registered scripts collection
$script:RegisteredScripts = @{}

function Register-IntuneScript {
    <#
    .SYNOPSIS
        Registers a script with the InSight.

    .DESCRIPTION
        Adds a script to the tool's registry for integration with the GUI.
        Registered scripts appear in the Scripts section and can be
        executed through the interface.

    .PARAMETER ScriptPath
        Full path to the PowerShell script file.

    .PARAMETER Name
        Display name for the script.

    .PARAMETER Description
        Brief description of what the script does.

    .PARAMETER Category
        Category for grouping in the GUI.

    .PARAMETER RequiredPermissions
        Array of Graph API permissions required by the script.

    .PARAMETER Icon
        Icon character from Segoe MDL2 Assets font.

    .PARAMETER Parameters
        Hashtable defining script parameters for GUI input fields.

    .EXAMPLE
        Register-IntuneScript -ScriptPath 'C:\Scripts\Get-DeviceInfo.ps1' `
            -Name 'Get Device Info' `
            -Description 'Retrieves detailed device information' `
            -Category 'Devices' `
            -RequiredPermissions @('DeviceManagementManagedDevices.Read.All')
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [string]$Description = '',

        [Parameter()]
        [ValidateSet('Devices', 'Applications', 'Configuration', 'Compliance', 'Users', 'Groups', 'Reports', 'Custom')]
        [string]$Category = 'Custom',

        [Parameter()]
        [string[]]$RequiredPermissions = @(),

        [Parameter()]
        [char]$Icon = [char]0xE756,

        [Parameter()]
        [hashtable]$Parameters = @{}
    )

    $scriptId = [guid]::NewGuid().ToString('N').Substring(0, 8)

    $script:RegisteredScripts[$scriptId] = @{
        Id                  = $scriptId
        Name                = $Name
        Description         = $Description
        ScriptPath          = $ScriptPath
        Category            = $Category
        RequiredPermissions = $RequiredPermissions
        Icon                = $Icon
        Parameters          = $Parameters
        RegisteredAt        = Get-Date
        Enabled             = $true
    }

    Write-Verbose "Registered script: $Name (ID: $scriptId)"

    # Register as a feature for permission checking
    if (Get-Command -Name 'Register-CustomFeature' -ErrorAction SilentlyContinue) {
        Register-CustomFeature `
            -FeatureId "Script.$scriptId" `
            -DisplayName $Name `
            -Description $Description `
            -RequiredPermissions $RequiredPermissions `
            -Category 'Scripts' `
            -Icon ([string]$Icon) `
            -MenuPath "Scripts/$Category"
    }

    return $scriptId
}

function Unregister-IntuneScript {
    <#
    .SYNOPSIS
        Removes a script from the registry.

    .PARAMETER ScriptId
        The ID of the script to remove.

    .EXAMPLE
        Unregister-IntuneScript -ScriptId 'abc12345'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptId
    )

    if ($script:RegisteredScripts.ContainsKey($ScriptId)) {
        $script:RegisteredScripts.Remove($ScriptId)
        Write-Verbose "Unregistered script: $ScriptId"
    }
    else {
        Write-Warning "Script not found: $ScriptId"
    }
}

function Get-RegisteredScripts {
    <#
    .SYNOPSIS
        Returns all registered scripts.

    .PARAMETER Category
        Filter by category.

    .PARAMETER IncludeDisabled
        Include disabled scripts in results.

    .OUTPUTS
        Array of registered script objects.

    .EXAMPLE
        Get-RegisteredScripts -Category 'Devices'
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter()]
        [string]$Category,

        [Parameter()]
        [switch]$IncludeDisabled
    )

    $scripts = $script:RegisteredScripts.Values

    if (-not $IncludeDisabled) {
        $scripts = $scripts | Where-Object { $_.Enabled }
    }

    if ($Category) {
        $scripts = $scripts | Where-Object { $_.Category -eq $Category }
    }

    # Add permission status to each script
    $results = foreach ($s in $scripts) {
        $hasPermission = $true
        $missingPerms = @()

        foreach ($perm in $s.RequiredPermissions) {
            if (-not (Test-IntunePermission -Permission $perm)) {
                $hasPermission = $false
                $missingPerms += $perm
            }
        }

        [PSCustomObject]@{
            Id                  = $s.Id
            Name                = $s.Name
            Description         = $s.Description
            ScriptPath          = $s.ScriptPath
            Category            = $s.Category
            Icon                = $s.Icon
            RequiredPermissions = $s.RequiredPermissions
            HasPermission       = $hasPermission
            MissingPermissions  = $missingPerms
            Enabled             = $s.Enabled
            RegisteredAt        = $s.RegisteredAt
            Parameters          = $s.Parameters
        }
    }

    return $results | Sort-Object Category, Name
}

function Invoke-IntuneScript {
    <#
    .SYNOPSIS
        Executes a registered script.

    .DESCRIPTION
        Runs a script with the provided parameters, handling permission
        checks and error management.

    .PARAMETER ScriptId
        The ID of the script to execute.

    .PARAMETER Parameters
        Hashtable of parameters to pass to the script.

    .PARAMETER AsJob
        Run the script as a background job.

    .OUTPUTS
        Script execution result object.

    .EXAMPLE
        Invoke-IntuneScript -ScriptId 'abc12345' -Parameters @{ DeviceId = '123' }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptId,

        [Parameter()]
        [hashtable]$Parameters = @{},

        [Parameter()]
        [switch]$AsJob
    )

    # Validate script exists
    if (-not $script:RegisteredScripts.ContainsKey($ScriptId)) {
        throw "Script not found: $ScriptId"
    }

    $scriptInfo = $script:RegisteredScripts[$ScriptId]

    # Check permissions
    foreach ($perm in $scriptInfo.RequiredPermissions) {
        if (-not (Test-IntunePermission -Permission $perm)) {
            throw "Missing required permission: $perm"
        }
    }

    # Validate script file exists
    if (-not (Test-Path -Path $scriptInfo.ScriptPath)) {
        throw "Script file not found: $($scriptInfo.ScriptPath)"
    }

    Write-LogInfo -Message "Executing script: $($scriptInfo.Name)" -Source 'ScriptManager' -Data @{
        ScriptId   = $ScriptId
        Parameters = $Parameters
    }

    try {
        if ($AsJob) {
            # Run as background job
            $job = Start-Job -ScriptBlock {
                param($ScriptPath, $Params)
                & $ScriptPath @Params
            } -ArgumentList $scriptInfo.ScriptPath, $Parameters

            return [PSCustomObject]@{
                Success  = $true
                JobId    = $job.Id
                JobState = $job.State
                Message  = "Script started as job $($job.Id)"
            }
        }
        else {
            # Run synchronously
            $result = & $scriptInfo.ScriptPath @Parameters

            Write-LogInfo -Message "Script completed: $($scriptInfo.Name)" -Source 'ScriptManager'

            return [PSCustomObject]@{
                Success = $true
                Result  = $result
                Message = "Script executed successfully"
            }
        }
    }
    catch {
        Write-LogError -Message "Script execution failed: $($scriptInfo.Name)" -Source 'ScriptManager' -Exception $_.Exception

        return [PSCustomObject]@{
            Success = $false
            Result  = $null
            Message = $_.Exception.Message
            Error   = $_
        }
    }
}

function Find-ScriptsInFolder {
    <#
    .SYNOPSIS
        Discovers and optionally registers scripts from a folder.

    .DESCRIPTION
        Scans a folder for PowerShell scripts that contain the
        $script:ScriptInfo metadata block and registers them.

    .PARAMETER Path
        Folder path to scan.

    .PARAMETER Register
        Automatically register discovered scripts.

    .PARAMETER Recurse
        Include subdirectories in the search.

    .OUTPUTS
        Array of discovered script information.

    .EXAMPLE
        Find-ScriptsInFolder -Path 'C:\IntuneAdmin\Scripts' -Register
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$Path,

        [Parameter()]
        [switch]$Register,

        [Parameter()]
        [switch]$Recurse
    )

    $searchParams = @{
        Path   = $Path
        Filter = '*.ps1'
    }

    if ($Recurse) {
        $searchParams['Recurse'] = $true
    }

    $scripts = Get-ChildItem @searchParams

    $discovered = foreach ($script in $scripts) {
        # Skip template file
        if ($script.Name -eq 'ScriptTemplate.ps1') {
            continue
        }

        try {
            $content = Get-Content -Path $script.FullName -Raw

            # Check for ScriptInfo block
            if ($content -match '\$script:ScriptInfo\s*=\s*@\{') {
                # Try to extract metadata by executing in isolated scope
                $scriptBlock = [scriptblock]::Create($content)

                # Look for common patterns in the content
                $nameMatch = [regex]::Match($content, "Name\s*=\s*['""]([^'""]+)['""]")
                $descMatch = [regex]::Match($content, "Description\s*=\s*['""]([^'""]+)['""]")
                $catMatch = [regex]::Match($content, "Category\s*=\s*['""]([^'""]+)['""]")

                $scriptInfo = @{
                    ScriptPath  = $script.FullName
                    FileName    = $script.Name
                    Name        = if ($nameMatch.Success) { $nameMatch.Groups[1].Value } else { $script.BaseName }
                    Description = if ($descMatch.Success) { $descMatch.Groups[1].Value } else { '' }
                    Category    = if ($catMatch.Success) { $catMatch.Groups[1].Value } else { 'Custom' }
                    HasMetadata = $true
                }

                if ($Register) {
                    $id = Register-IntuneScript `
                        -ScriptPath $script.FullName `
                        -Name $scriptInfo.Name `
                        -Description $scriptInfo.Description `
                        -Category $scriptInfo.Category

                    $scriptInfo['RegisteredId'] = $id
                }

                [PSCustomObject]$scriptInfo
            }
        }
        catch {
            Write-LogWarning -Message "Failed to process script: $($script.Name)" -Source 'ScriptManager'
        }
    }

    return $discovered
}

function Enable-IntuneScript {
    <#
    .SYNOPSIS
        Enables a disabled script.

    .PARAMETER ScriptId
        The ID of the script to enable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptId
    )

    if ($script:RegisteredScripts.ContainsKey($ScriptId)) {
        $script:RegisteredScripts[$ScriptId].Enabled = $true
        Write-Verbose "Enabled script: $ScriptId"
    }
}

function Disable-IntuneScript {
    <#
    .SYNOPSIS
        Disables a script without removing it.

    .PARAMETER ScriptId
        The ID of the script to disable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptId
    )

    if ($script:RegisteredScripts.ContainsKey($ScriptId)) {
        $script:RegisteredScripts[$ScriptId].Enabled = $false
        Write-Verbose "Disabled script: $ScriptId"
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Register-IntuneScript',
    'Unregister-IntuneScript',
    'Get-RegisteredScripts',
    'Invoke-IntuneScript',
    'Find-ScriptsInFolder',
    'Enable-IntuneScript',
    'Disable-IntuneScript'
)
