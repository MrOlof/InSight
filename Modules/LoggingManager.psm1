<#
.SYNOPSIS
    Centralized logging module for InSight.

.DESCRIPTION
    Provides logging with file output, log rotation, and structured logging.

.NOTES
    Author: Kosta Wadenfalk
    GitHub: https://github.com/MrOlof
    Version: 1.0.0
#>

#Requires -Version 5.1

# Module-scoped logging configuration
$script:LogConfig = @{
    LogDirectory     = "C:\Logs\IntuneAdmin"
    LogFileName      = "IntuneAdmin"
    MaxLogSizeMB     = 10
    MaxLogFiles      = 5
    LogLevel         = 'Information'  # Debug, Information, Warning, Error
    EnableConsole    = $true
    EnableFile       = $true
    DateFormat       = 'yyyy-MM-dd HH:mm:ss.fff'
    SessionId        = [guid]::NewGuid().ToString('N').Substring(0, 8)
    Initialized      = $false
}

# Log level enumeration
$script:LogLevels = @{
    'Debug'       = 0
    'Information' = 1
    'Warning'     = 2
    'Error'       = 3
}

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging system.

    .DESCRIPTION
        Sets up the logging directory, creates initial log file,
        and configures logging parameters.

    .PARAMETER LogDirectory
        Directory for log files. Defaults to C:\Logs\IntuneAdmin.

    .PARAMETER LogLevel
        Minimum log level to record. Debug, Information, Warning, or Error.

    .PARAMETER EnableConsole
        Enable console output for log messages.

    .PARAMETER EnableFile
        Enable file output for log messages.

    .EXAMPLE
        Initialize-Logging -LogLevel 'Debug' -EnableConsole $true
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$LogDirectory = "C:\Logs\IntuneAdmin",

        [Parameter()]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string]$LogLevel = 'Information',

        [Parameter()]
        [bool]$EnableConsole = $true,

        [Parameter()]
        [bool]$EnableFile = $true
    )

    $script:LogConfig.LogDirectory = $LogDirectory
    $script:LogConfig.LogLevel = $LogLevel
    $script:LogConfig.EnableConsole = $EnableConsole
    $script:LogConfig.EnableFile = $EnableFile
    $script:LogConfig.SessionId = [guid]::NewGuid().ToString('N').Substring(0, 8)

    # Create log directory if needed
    if ($EnableFile -and -not (Test-Path -Path $LogDirectory)) {
        try {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogDirectory"
        }
        catch {
            Write-Warning "Failed to create log directory: $_"
            $script:LogConfig.EnableFile = $false
        }
    }

    $script:LogConfig.Initialized = $true

    # Write initial log entry
    Write-Log -Message "Logging initialized. Session ID: $($script:LogConfig.SessionId)" -Level 'Information' -Source 'LoggingManager'
}

function Get-LogFilePath {
    <#
    .SYNOPSIS
        Returns the current log file path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $date = Get-Date -Format 'yyyyMMdd'
    $fileName = "$($script:LogConfig.LogFileName)_$date.log"
    return Join-Path -Path $script:LogConfig.LogDirectory -ChildPath $fileName
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log entry.

    .DESCRIPTION
        Writes a structured log entry to file and/or console based on
        the current logging configuration.

    .PARAMETER Message
        The log message text.

    .PARAMETER Level
        Log level: Debug, Information, Warning, or Error.

    .PARAMETER Source
        Source component/module name.

    .PARAMETER Exception
        Exception object for error logging.

    .PARAMETER Data
        Additional data hashtable to include in log.

    .EXAMPLE
        Write-Log -Message "Device sync started" -Level 'Information' -Source 'DeviceManager'

    .EXAMPLE
        Write-Log -Message "API call failed" -Level 'Error' -Source 'GraphAPI' -Exception $_.Exception
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string]$Level = 'Information',

        [Parameter()]
        [string]$Source = 'Application',

        [Parameter()]
        [System.Exception]$Exception,

        [Parameter()]
        [hashtable]$Data
    )

    # Auto-initialize if needed
    if (-not $script:LogConfig.Initialized) {
        Initialize-Logging
    }

    # Check log level threshold
    $currentLevelValue = $script:LogLevels[$script:LogConfig.LogLevel]
    $messageLevelValue = $script:LogLevels[$Level]

    if ($messageLevelValue -lt $currentLevelValue) {
        return
    }

    # Build log entry
    $timestamp = Get-Date -Format $script:LogConfig.DateFormat
    $sessionId = $script:LogConfig.SessionId

    $logEntry = @{
        Timestamp = $timestamp
        SessionId = $sessionId
        Level     = $Level
        Source    = $Source
        Message   = $Message
    }

    if ($Exception) {
        $logEntry.Exception = @{
            Type       = $Exception.GetType().FullName
            Message    = $Exception.Message
            StackTrace = $Exception.StackTrace
        }
    }

    if ($Data) {
        $logEntry.Data = $Data
    }

    # Format for file/console
    $formattedMessage = "[$timestamp] [$sessionId] [$Level] [$Source] $Message"

    if ($Exception) {
        $formattedMessage += " | Exception: $($Exception.Message)"
    }

    # Write to console
    if ($script:LogConfig.EnableConsole) {
        $color = switch ($Level) {
            'Debug'       { 'Gray' }
            'Information' { 'White' }
            'Warning'     { 'Yellow' }
            'Error'       { 'Red' }
        }
        Write-Host $formattedMessage -ForegroundColor $color
    }

    # Write to file
    if ($script:LogConfig.EnableFile) {
        try {
            $logFilePath = Get-LogFilePath

            # Check for log rotation
            if (Test-Path -Path $logFilePath) {
                $fileSize = (Get-Item -Path $logFilePath).Length / 1MB
                if ($fileSize -ge $script:LogConfig.MaxLogSizeMB) {
                    Invoke-LogRotation
                }
            }

            # Append to log file
            $formattedMessage | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        }
        catch {
            if ($script:LogConfig.EnableConsole) {
                Write-Warning "Failed to write to log file: $_"
            }
        }
    }
}

function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Performs log file rotation.

    .DESCRIPTION
        Renames current log file with timestamp and removes old log files
        beyond the maximum retention count.
    #>
    [CmdletBinding()]
    param()

    $logFilePath = Get-LogFilePath

    if (-not (Test-Path -Path $logFilePath)) {
        return
    }

    try {
        # Rename current log with timestamp
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($logFilePath)
        $extension = [System.IO.Path]::GetExtension($logFilePath)
        $directory = [System.IO.Path]::GetDirectoryName($logFilePath)

        $archiveName = "${baseName}_$timestamp$extension"
        $archivePath = Join-Path -Path $directory -ChildPath $archiveName

        Rename-Item -Path $logFilePath -NewName $archiveName -Force

        # Remove old log files
        $logFiles = Get-ChildItem -Path $directory -Filter "$($script:LogConfig.LogFileName)*.log" |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip $script:LogConfig.MaxLogFiles

        foreach ($oldFile in $logFiles) {
            Remove-Item -Path $oldFile.FullName -Force
        }
    }
    catch {
        Write-Warning "Log rotation failed: $_"
    }
}

function Write-LogDebug {
    <#
    .SYNOPSIS
        Writes a debug-level log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [string]$Source = 'Application',

        [Parameter()]
        [hashtable]$Data
    )

    Write-Log -Message $Message -Level 'Debug' -Source $Source -Data $Data
}

function Write-LogInfo {
    <#
    .SYNOPSIS
        Writes an information-level log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [string]$Source = 'Application',

        [Parameter()]
        [hashtable]$Data
    )

    Write-Log -Message $Message -Level 'Information' -Source $Source -Data $Data
}

function Write-LogWarning {
    <#
    .SYNOPSIS
        Writes a warning-level log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [string]$Source = 'Application',

        [Parameter()]
        [hashtable]$Data
    )

    Write-Log -Message $Message -Level 'Warning' -Source $Source -Data $Data
}

function Write-LogError {
    <#
    .SYNOPSIS
        Writes an error-level log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [string]$Source = 'Application',

        [Parameter()]
        [System.Exception]$Exception,

        [Parameter()]
        [hashtable]$Data
    )

    Write-Log -Message $Message -Level 'Error' -Source $Source -Exception $Exception -Data $Data
}

function Get-LogEntries {
    <#
    .SYNOPSIS
        Retrieves log entries from the current log file.

    .DESCRIPTION
        Reads and parses log entries from the current day's log file.
        Supports filtering by level and count limiting.

    .PARAMETER Level
        Filter by log level.

    .PARAMETER Last
        Return only the last N entries.

    .PARAMETER Source
        Filter by source component.

    .OUTPUTS
        Array of log entry strings.

    .EXAMPLE
        Get-LogEntries -Level 'Error' -Last 10
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string]$Level,

        [Parameter()]
        [int]$Last = 100,

        [Parameter()]
        [string]$Source
    )

    $logFilePath = Get-LogFilePath

    if (-not (Test-Path -Path $logFilePath)) {
        return @()
    }

    $entries = Get-Content -Path $logFilePath -Tail $Last

    if ($Level) {
        $entries = $entries | Where-Object { $_ -match "\[$Level\]" }
    }

    if ($Source) {
        $entries = $entries | Where-Object { $_ -match "\[$Source\]" }
    }

    return $entries
}

function Clear-OldLogs {
    <#
    .SYNOPSIS
        Removes log files older than specified days.

    .PARAMETER DaysToKeep
        Number of days of logs to retain.

    .EXAMPLE
        Clear-OldLogs -DaysToKeep 30
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$DaysToKeep = 30
    )

    $cutoffDate = (Get-Date).AddDays(-$DaysToKeep)
    $logFiles = Get-ChildItem -Path $script:LogConfig.LogDirectory -Filter "*.log" |
        Where-Object { $_.LastWriteTime -lt $cutoffDate }

    $count = 0
    foreach ($file in $logFiles) {
        try {
            Remove-Item -Path $file.FullName -Force
            $count++
        }
        catch {
            Write-LogWarning -Message "Failed to remove old log file: $($file.Name)" -Source 'LoggingManager'
        }
    }

    if ($count -gt 0) {
        Write-LogInfo -Message "Removed $count old log files" -Source 'LoggingManager'
    }
}

function Get-LogConfiguration {
    <#
    .SYNOPSIS
        Returns the current logging configuration.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return $script:LogConfig.Clone()
}

function Set-LogLevel {
    <#
    .SYNOPSIS
        Changes the current log level.

    .PARAMETER Level
        New log level threshold.

    .EXAMPLE
        Set-LogLevel -Level 'Debug'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string]$Level
    )

    $script:LogConfig.LogLevel = $Level
    Write-LogInfo -Message "Log level changed to: $Level" -Source 'LoggingManager'
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-Logging',
    'Write-Log',
    'Write-LogDebug',
    'Write-LogInfo',
    'Write-LogWarning',
    'Write-LogError',
    'Get-LogEntries',
    'Get-LogFilePath',
    'Clear-OldLogs',
    'Get-LogConfiguration',
    'Set-LogLevel'
)
