<#
Version: 2.0 (SAFE VERSION - Modified)
Author:
- Joey Verlinden (joeyverlinden.com)
- Andrew Taylor (andrewstaylor.com)
- Florian Slazmann (scloud.work)
- Jannik Reinhard (jannikreinhard.com)
Modified: Added safety features to prevent data loss
Script: Clear-DownloadFolder (Safe Version)
Description: Clears Downloads folders for all users - ONLY files older than 90 days
Safety Features:
- Age filter: Only deletes files older than 90 days
- Preserves recent downloads
- Logs deleted files for audit trail
- Excludes important file types (.exe, .msi)
Hint: This is a community script. There is no guarantee for this. Please check thoroughly before running.
Version 1.0: Init
Version 2.0: Added age filtering and safety checks
Run as: System
Context: 64 Bit
#>

# Configuration
$DaysToKeep = 90  # Only delete files older than this many days
$DateLimit = (Get-Date).AddDays(-$DaysToKeep)
$ExcludeExtensions = @('.exe', '.msi', '.zip')  # Preserve installers and archives

# Log file for audit trail
$LogPath = "$env:ProgramData\IntuneRemediations\Logs"
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = "$LogPath\Clear-DownloadFolder_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

Write-Log "=== Downloads Cleanup Started ==="
Write-Log "Delete files older than: $DateLimit"

$DeletedCount = 0
$PreservedCount = 0
$TotalSizeFreed = 0

# Process each user's Downloads folder
Get-ChildItem "C:\Users\*\Downloads" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $UserDownloads = $_.FullName
    $UserName = $_.Parent.Name

    Write-Log "Processing: $UserName"

    # Get files older than the age limit
    Get-ChildItem $UserDownloads -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $File = $_

        # Check if file is old enough
        if ($File.LastWriteTime -lt $DateLimit) {

            # Check if file type should be preserved
            if ($ExcludeExtensions -contains $File.Extension) {
                Write-Log "  Preserved: $($File.Name) (excluded extension)"
                $PreservedCount++
            }
            else {
                try {
                    $FileSize = $File.Length
                    Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                    Write-Log "  Deleted: $($File.Name) (Age: $([math]::Round((New-TimeSpan -Start $File.LastWriteTime -End (Get-Date)).TotalDays)) days, Size: $([math]::Round($FileSize/1MB, 2)) MB)"
                    $DeletedCount++
                    $TotalSizeFreed += $FileSize
                }
                catch {
                    Write-Log "  ERROR: Could not delete $($File.Name) - $($_.Exception.Message)"
                }
            }
        }
        else {
            $PreservedCount++
        }
    }
}

Write-Log "=== Summary ==="
Write-Log "Files deleted: $DeletedCount"
Write-Log "Files preserved: $PreservedCount"
Write-Log "Space freed: $([math]::Round($TotalSizeFreed/1GB, 2)) GB"
Write-Log "=== Cleanup Completed ==="

exit 0
