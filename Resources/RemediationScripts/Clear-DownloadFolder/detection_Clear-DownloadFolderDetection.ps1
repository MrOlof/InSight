<#
Version: 2.0 (SAFE VERSION - Modified)
Author:
- Joey Verlinden (joeyverlinden.com)
- Andrew Taylor (andrewstaylor.com)
- Florian Slazmann (scloud.work)
- Jannik Reinhard (jannikreinhard.com)
Modified: Added intelligent detection logic
Script: Clear-DownloadFolder Detection (Safe Version)
Description: Checks if there are files older than 90 days in Downloads folders
Exit 0 = Compliant (no old files to clean)
Exit 1 = Not compliant (old files found, trigger cleanup)
Version 1.0: Init
Version 2.0: Added age-based detection
Run as: System
Context: 64 Bit
#>

# Configuration - Must match remediation script settings
$DaysToKeep = 90
$DateLimit = (Get-Date).AddDays(-$DaysToKeep)
$ExcludeExtensions = @('.exe', '.msi', '.zip')

$OldFilesFound = $false
$OldFileCount = 0

# Check each user's Downloads folder
Get-ChildItem "C:\Users\*\Downloads" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $UserDownloads = $_.FullName

    # Check for files older than the age limit
    Get-ChildItem $UserDownloads -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $File = $_

        # Check if file is old enough and not excluded
        if (($File.LastWriteTime -lt $DateLimit) -and ($ExcludeExtensions -notcontains $File.Extension)) {
            $OldFilesFound = $true
            $OldFileCount++
        }
    }
}

if ($OldFilesFound) {
    Write-Host "Found $OldFileCount files older than $DaysToKeep days - cleanup needed"
    exit 1  # Trigger remediation
}
else {
    Write-Host "No files older than $DaysToKeep days found - no cleanup needed"
    exit 0  # Compliant
}