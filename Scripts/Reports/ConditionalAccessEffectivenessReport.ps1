<#PSScriptInfo

.VERSION 1.0.0

.GUID 3f8b4c2a-9d1e-4f5a-8c3b-7e2d4a1f6b9c

.AUTHOR Kosta Wadenfalk

.COPYRIGHT © 2026 Kosta Wadenfalk. All rights reserved.

.TAGS
    Microsoft Entra
    Conditional Access
    Microsoft Graph
    Security

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES
    Microsoft.Graph.Authentication

.RELEASENOTES
    v1.0 - 2026-01-11 - Conditional Access effectiveness reporting

#>

<#
.SYNOPSIS
    Generates a comprehensive Conditional Access policy effectiveness report

.DESCRIPTION
    This script analyzes Conditional Access policies and their effectiveness at blocking sign-ins.
    It provides insights into:
    - Sign-in attempts blocked by each policy
    - Policies that never block anything (dead policies)
    - Users frequently triggering blocks
    - Geographic patterns of blocks
    - Report-only vs Enabled policy comparison

    NOTE: This report focuses on EFFECTIVENESS (blocks/failures) and only analyzes failed sign-ins
    for performance. Successful sign-ins are not included as they're not relevant for effectiveness analysis.

.PARAMETER outpath
    Specifies the output path for the HTML report file.

.PARAMETER days
    Number of days to analyze sign-in logs (default: 30, max: 30)

.PARAMETER maxSignIns
    Maximum number of sign-in records to analyze (default: 0 = unlimited).
    Use this to limit processing time for large tenants. Recommended: 10000-20000 for quick reports.

.PARAMETER openBrowser
    If specified, opens the generated report in the default browser.

.EXAMPLE
    .\ConditionalAccessEffectivenessReport.ps1 -outpath "C:\Reports" -days 30 -openBrowser

.EXAMPLE
    .\ConditionalAccessEffectivenessReport.ps1 -outpath "C:\Reports" -days 7

.EXAMPLE
    .\ConditionalAccessEffectivenessReport.ps1 -outpath "C:\Reports" -days 7 -maxSignIns 10000
    Limit analysis to first 10,000 sign-ins for faster processing

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$outpath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 30)]
    [int]$days = 30,

    [Parameter(Mandatory = $false)]
    [int]$maxSignIns = 0,

    [Parameter(Mandatory = $false)]
    [switch]$openBrowser = $false
)

# Check Microsoft Graph connection
$state = Get-MgContext

# Define required permissions
$requiredPerms = @("Policy.Read.All", "AuditLog.Read.All", "Directory.Read.All")

# Check if we're connected and have all required permissions
$hasAllPerms = $false
if ($state) {
    $missingPerms = @()
    foreach ($perm in $requiredPerms) {
        if ($state.Scopes -notcontains $perm) {
            $missingPerms += $perm
        }
    }
    if ($missingPerms.Count -eq 0) {
        $hasAllPerms = $true
        Write-Output "Connected to Microsoft Graph with all required permissions"
    }
    else {
        Write-Output "Missing required permissions: $($missingPerms -join ', ')"
        Write-Output "Reconnecting with all required permissions..."
    }
}
else {
    Write-Output "Not connected to Microsoft Graph. Connecting now..."
}

# Connect if we need to
if (-not $hasAllPerms) {
    try {
        Connect-MgGraph -Scopes $requiredPerms -ErrorAction Stop -NoWelcome
        Write-Output "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit
    }
}

# Get organization name
$organisationName = (Invoke-MgGraphRequest -Uri "v1.0/organization" -OutputType PSObject | Select-Object -ExpandProperty value).DisplayName

Write-Output "Fetching Conditional Access policies..."
# Get all CA policies (enabled and report-only)
$allPolicies = Invoke-MgGraphRequest -Uri "v1.0/identity/conditionalAccess/policies" -OutputType PSObject | Select-Object -ExpandProperty value

# Filter for enabled and report-only policies
$activePolicies = $allPolicies | Where-Object { $_.state -in @('enabled', 'enabledForReportingButNotEnforced') }

Write-Output "Found $($activePolicies.Count) active policies (enabled or report-only)"

# Calculate date range for sign-in logs
$startDate = (Get-Date).AddDays(-$days).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Output "Fetching sign-in logs for the last $days days..."
Write-Output "Filtering for failures, blocks, and interruptions only (much faster)..."

# Fetch sign-in logs - only get failures and interruptions for effectiveness analysis
# We don't need successful sign-ins for this report
$signIns = @()
# Filter for sign-ins that failed or were interrupted (status.errorCode ne 0 means there was an issue)
$uri = "v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startDate and status/errorCode ne 0&`$top=999"

do {
    try {
        $response = Invoke-MgGraphRequest -Uri $uri -OutputType PSObject
        $signIns += $response.value
        $uri = $response.'@odata.nextLink'
        Write-Output "Fetched $($signIns.Count) sign-in records so far..."
    }
    catch {
        Write-Warning "Error fetching sign-ins: $_"
        break
    }
} while ($uri)

Write-Output "Total sign-in records fetched: $($signIns.Count)"

# Limit sign-ins if requested
if ($maxSignIns -gt 0 -and $signIns.Count -gt $maxSignIns) {
    Write-Output "Limiting analysis to first $maxSignIns sign-ins (set -maxSignIns 0 to process all)"
    $signIns = $signIns | Select-Object -First $maxSignIns
}

# Analyze policy impact
Write-Output "Analyzing policy impact data for $($signIns.Count) sign-ins..."
Write-Output "This may take a minute..."

$policyStats = @{}
$userBlockStats = @{}
$locationBlockStats = @{}

# Initialize policy stats with hashtables for O(1) lookups
foreach ($policy in $activePolicies) {
    $policyStats[$policy.id] = @{
        PolicyName = $policy.displayName
        PolicyId = $policy.id
        State = $policy.state
        Failure = 0
        Interrupted = 0
        TotalBlocks = 0
        UniqueUsersHash = @{}
        UniqueLocationsHash = @{}
        UniqueAppsHash = @{}
        BlockedUsersHash = @{}
        BlockedLocationsHash = @{}
    }
}

# Process each sign-in with progress tracking
$processedCount = 0
$totalSignIns = $signIns.Count
$progressInterval = [Math]::Max(1, [Math]::Floor($totalSignIns / 20))

foreach ($signIn in $signIns) {
    $processedCount++

    # Show progress every 5%
    if ($processedCount % $progressInterval -eq 0 -or $processedCount -eq $totalSignIns) {
        $percentComplete = [Math]::Round(($processedCount / $totalSignIns) * 100)
        Write-Output "  Progress: $percentComplete% ($processedCount / $totalSignIns records)"
    }

    if ($signIn.appliedConditionalAccessPolicies) {
        foreach ($appliedPolicy in $signIn.appliedConditionalAccessPolicies) {
            # Only track policies we're reporting on
            if ($policyStats.ContainsKey($appliedPolicy.id)) {
                $stat = $policyStats[$appliedPolicy.id]

                # Track unique users, locations, apps using hashtables for fast lookups
                if ($signIn.userPrincipalName) {
                    $stat.UniqueUsersHash[$signIn.userPrincipalName] = $true
                }

                if ($signIn.location.city) {
                    $location = "$($signIn.location.city), $($signIn.location.countryOrRegion)"
                    $stat.UniqueLocationsHash[$location] = $true
                }

                if ($signIn.appDisplayName) {
                    $stat.UniqueAppsHash[$signIn.appDisplayName] = $true
                }

                # Track results (only failures and interruptions since we filtered for errorCode ne 0)
                switch ($appliedPolicy.result) {
                    'failure' {
                        $stat.Failure++
                        $stat.TotalBlocks++

                        # Track blocked users
                        if ($signIn.userPrincipalName) {
                            if (-not $userBlockStats.ContainsKey($signIn.userPrincipalName)) {
                                $userBlockStats[$signIn.userPrincipalName] = @{
                                    TotalBlocks = 0
                                    Policies = @{}
                                }
                            }
                            $userBlockStats[$signIn.userPrincipalName].TotalBlocks++
                            if (-not $userBlockStats[$signIn.userPrincipalName].Policies.ContainsKey($stat.PolicyName)) {
                                $userBlockStats[$signIn.userPrincipalName].Policies[$stat.PolicyName] = 0
                            }
                            $userBlockStats[$signIn.userPrincipalName].Policies[$stat.PolicyName]++
                            $stat.BlockedUsersHash[$signIn.userPrincipalName] = $true
                        }

                        # Track blocked locations
                        if ($signIn.location.city) {
                            $location = "$($signIn.location.city), $($signIn.location.countryOrRegion)"
                            if (-not $locationBlockStats.ContainsKey($location)) {
                                $locationBlockStats[$location] = @{
                                    TotalBlocks = 0
                                    Country = $signIn.location.countryOrRegion
                                    City = $signIn.location.city
                                }
                            }
                            $locationBlockStats[$location].TotalBlocks++
                            $stat.BlockedLocationsHash[$location] = $true
                        }
                    }
                    'interrupted' { $stat.Interrupted++ }
                }
            }
        }
    }
}

Write-Output "Analysis complete! Converting results..."

# Convert hashtables to counts for the report
foreach ($policyId in $policyStats.Keys) {
    $stat = $policyStats[$policyId]
    $stat.UniqueUsersCount = $stat.UniqueUsersHash.Count
    $stat.UniqueLocationsCount = $stat.UniqueLocationsHash.Count
    $stat.UniqueAppsCount = $stat.UniqueAppsHash.Count
    $stat.BlockedUsersCount = $stat.BlockedUsersHash.Count
    $stat.BlockedLocationsCount = $stat.BlockedLocationsHash.Count
}

# Calculate summary statistics
$totalPolicies = $activePolicies.Count
$enabledPolicies = ($activePolicies | Where-Object { $_.state -eq 'enabled' }).Count
$reportOnlyPolicies = ($activePolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
$deadPolicies = ($policyStats.Values | Where-Object { $_.TotalBlocks -eq 0 }).Count
$blockingPolicies = ($policyStats.Values | Where-Object { $_.TotalBlocks -gt 0 }).Count

# Calculate total blocks safely
$totalBlocks = 0
if ($policyStats.Count -gt 0) {
    $totalBlocks = ($policyStats.Values | ForEach-Object { $_.TotalBlocks } | Measure-Object -Sum).Sum
    if (-not $totalBlocks) { $totalBlocks = 0 }
}

# Get top blocked users
$topBlockedUsers = @()
if ($userBlockStats.Count -gt 0) {
    $topBlockedUsers = $userBlockStats.GetEnumerator() | Sort-Object { $_.Value.TotalBlocks } -Descending | Select-Object -First 10
}

# Get top blocked locations
$topBlockedLocations = @()
if ($locationBlockStats.Count -gt 0) {
    $topBlockedLocations = $locationBlockStats.GetEnumerator() | Sort-Object { $_.Value.TotalBlocks } -Descending | Select-Object -First 10
}

Write-Output "Analysis complete. Generating HTML report..."

# Generate HTML Report
Function Generate-CAEffectivenessReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$PolicyStatistics,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    # Create HTML header
    $html = [System.Text.StringBuilder]::new()

    [void]$html.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conditional Access Effectiveness Report - $organisationName</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }

        .header-container {
            background: linear-gradient(135deg, #c0392b 0%, #e74c3c 50%, #e67e22 100%);
            color: white;
            padding: 25px 40px;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .header-content {
            max-width: 1550px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            font-size: 28px;
            font-weight: 600;
            margin: 0;
            letter-spacing: -0.5px;
        }

        .header-subtitle {
            font-size: 14px;
            font-weight: 400;
            margin-top: 8px;
            opacity: 0.9;
        }

        .report-info {
            text-align: right;
            font-size: 14px;
        }

        .report-date {
            font-weight: 500;
            margin-top: 5px;
        }

        .content-container {
            max-width: 1550px;
            margin: 0 auto;
            padding: 0 20px 40px;
        }

        .summary-stats {
            display: flex;
            flex-wrap: wrap;
            margin-bottom: 30px;
            gap: 20px;
        }

        .stat-card {
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            flex: 1;
            min-width: 200px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 6px 25px rgba(231, 76, 60, 0.15);
        }

        .stat-title {
            font-size: 14px;
            color: #666;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #c0392b;
        }

        .stat-percentage {
            font-size: 14px;
            color: #666;
        }

        .search-container {
            margin-bottom: 20px;
        }

        #searchBox {
            padding: 10px;
            width: 300px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }

        .filter-container {
            display: flex;
            margin-bottom: 20px;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filter-button {
            padding: 8px 15px;
            background-color: #eee;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }

        .filter-button:hover {
            border-color: #e74c3c;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(231, 76, 60, 0.15);
        }

        .filter-button.active {
            background-color: #c0392b;
            color: white;
            border-color: #c0392b;
        }

        .table-container {
            width: 100%;
            overflow-x: auto;
            margin-bottom: 30px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            position: relative;
            background-color: white;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: auto;
        }

        thead {
            background: linear-gradient(135deg, #c0392b, #e74c3c);
            position: sticky;
            top: 0;
            z-index: 10;
        }

        th {
            padding: 16px 12px;
            font-weight: 700;
            text-align: left;
            color: white;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            cursor: pointer;
            user-select: none;
            border-right: 1px solid rgba(255,255,255,0.1);
            position: relative;
        }

        th::after {
            content: ' ⇅';
            opacity: 0.3;
            font-size: 12px;
            margin-left: 4px;
        }

        th[data-sort-order="asc"]::after {
            content: ' ↑';
            opacity: 1;
        }

        th[data-sort-order="desc"]::after {
            content: ' ↓';
            opacity: 1;
        }

        td {
            padding: 14px 12px;
            border-bottom: 1px solid #ecf0f1;
            text-align: left;
            color: #2c3e50;
            font-size: 13px;
        }

        tr:nth-child(even) {
            background-color: #f8f9fa;
        }

        tbody tr:hover {
            background-color: #fff5f5;
        }

        .policy-name {
            font-weight: 600;
            color: #34495e;
        }

        .state-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .state-enabled {
            background-color: #27ae60;
            color: white;
        }

        .state-report {
            background-color: #f39c12;
            color: white;
        }

        .number {
            text-align: right;
            font-weight: 600;
        }

        .dead-policy {
            opacity: 0.5;
        }

        .high-blocks {
            background-color: #fff5f5;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
        }

        .button-group {
            margin-left: auto;
            display: flex;
            gap: 10px;
        }

        .export-csv-button, .expand-icon {
            padding: 8px 15px;
            background-color: #eee;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .export-csv-button:hover, .expand-icon:hover {
            background: #e74c3c;
            color: white;
            border-color: #e74c3c;
        }

        .export-csv-button svg, .expand-icon svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
        }

        /* User and Location tables */
        .insights-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        @media (max-width: 1200px) {
            .insights-container {
                grid-template-columns: 1fr;
            }
        }

        .insight-card {
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        .insight-title {
            font-size: 18px;
            font-weight: 600;
            color: #c0392b;
            margin-bottom: 15px;
        }

        .insight-table {
            width: 100%;
            border-collapse: collapse;
        }

        .insight-table th {
            background: #f8f9fa;
            color: #2c3e50;
            padding: 10px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
        }

        .insight-table td {
            padding: 10px;
            border-bottom: 1px solid #ecf0f1;
            font-size: 13px;
        }

        .insight-table tr:hover {
            background-color: #fff5f5;
        }
    </style>
</head>
<body>
    <div class="header-container">
        <div class="header-content">
            <div>
                <h1>Conditional Access Effectiveness Report</h1>
                <div class="header-subtitle">Analyzing blocks and failures over the last $days days</div>
            </div>
            <div class="report-info">
                <div class="report-date">Generated: $(Get-Date -Format "MMMM d, yyyy HH:mm")</div>
                <div class="tenant">$organisationName</div>
            </div>
        </div>
    </div>

    <div class="content-container">
        <div class="summary-stats">
            <div class="stat-card">
                <div class="stat-title">Total Active Policies</div>
                <div class="stat-value">$totalPolicies</div>
                <div class="stat-percentage">Enabled + Report-Only</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Enabled Policies</div>
                <div class="stat-value">$enabledPolicies</div>
                <div class="stat-percentage">$([math]::Round(($enabledPolicies / $totalPolicies) * 100, 1))% of total</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Report-Only Policies</div>
                <div class="stat-value">$reportOnlyPolicies</div>
                <div class="stat-percentage">$([math]::Round(($reportOnlyPolicies / $totalPolicies) * 100, 1))% of total</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Total Blocks</div>
                <div class="stat-value">$totalBlocks</div>
                <div class="stat-percentage">Sign-ins blocked by CA</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Active Blocking Policies</div>
                <div class="stat-value">$blockingPolicies</div>
                <div class="stat-percentage">$([math]::Round(($blockingPolicies / $totalPolicies) * 100, 1))% effectiveness</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Dead Policies</div>
                <div class="stat-value">$deadPolicies</div>
                <div class="stat-percentage">Never blocked or applied</div>
            </div>
        </div>

        <!-- Top Blocked Users and Locations -->
        <div class="insights-container">
            <div class="insight-card">
                <div class="insight-title">Top 10 Most Blocked Users</div>
                <table class="insight-table">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th style="text-align: right;">Total Blocks</th>
                        </tr>
                    </thead>
                    <tbody>
"@)

    # Add top blocked users
    foreach ($user in $topBlockedUsers) {
        [void]$html.AppendLine(@"
                        <tr>
                            <td>$($user.Key)</td>
                            <td class="number">$($user.Value.TotalBlocks)</td>
                        </tr>
"@)
    }

    [void]$html.AppendLine(@"
                    </tbody>
                </table>
            </div>

            <div class="insight-card">
                <div class="insight-title">Top 10 Blocked Locations</div>
                <table class="insight-table">
                    <thead>
                        <tr>
                            <th>Location</th>
                            <th style="text-align: right;">Total Blocks</th>
                        </tr>
                    </thead>
                    <tbody>
"@)

    # Add top blocked locations
    foreach ($location in $topBlockedLocations) {
        [void]$html.AppendLine(@"
                        <tr>
                            <td>$($location.Key)</td>
                            <td class="number">$($location.Value.TotalBlocks)</td>
                        </tr>
"@)
    }

    [void]$html.AppendLine(@"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="search-container">
            <input type="text" id="searchBox" placeholder="Search for a policy..." onkeyup="searchTable()">
        </div>

        <div class="filter-container">
            <button class="filter-button active" onclick="filterTable('all')">All Policies</button>
            <button class="filter-button" onclick="filterTable('enabled')">Enabled Only</button>
            <button class="filter-button" onclick="filterTable('report')">Report-Only</button>
            <button class="filter-button" onclick="filterTable('blocking')">Blocking Policies</button>
            <button class="filter-button" onclick="filterTable('dead')">Dead Policies</button>
            <div class="button-group">
                <button class="export-csv-button" onclick="exportTableToCSV()" title="Export table to CSV file">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Export CSV
                </button>
            </div>
        </div>

        <div class="table-container">
            <table id="policyTable">
                <thead>
                    <tr>
                        <th>Policy Name</th>
                        <th>State</th>
                        <th style="text-align: right;">Total Blocks</th>
                        <th style="text-align: right;">Interrupted</th>
                        <th style="text-align: right;">Unique Users Affected</th>
                        <th style="text-align: right;">Users Blocked</th>
                        <th style="text-align: right;">Apps Affected</th>
                        <th style="text-align: right;">Locations Affected</th>
                    </tr>
                </thead>
                <tbody>
"@)

    # Add policy rows
    foreach ($policy in $PolicyStatistics.Values | Sort-Object -Property TotalBlocks -Descending) {
        $stateClass = if ($policy.State -eq 'enabled') { 'state-enabled' } else { 'state-report' }
        $stateText = if ($policy.State -eq 'enabled') { 'Enabled' } else { 'Report-Only' }

        $rowClass = ""
        if ($policy.TotalBlocks -eq 0) {
            $rowClass = "dead-policy"
        }
        elseif ($policy.TotalBlocks -gt 100) {
            $rowClass = "high-blocks"
        }

        $dataAttrs = ""
        if ($policy.State -eq 'enabled') { $dataAttrs += "data-enabled='true' " }
        if ($policy.State -eq 'enabledForReportingButNotEnforced') { $dataAttrs += "data-report='true' " }
        if ($policy.TotalBlocks -gt 0) { $dataAttrs += "data-blocking='true' " }
        if ($policy.TotalBlocks -eq 0) { $dataAttrs += "data-dead='true' " }

        [void]$html.AppendLine(@"
                    <tr class="$rowClass" $dataAttrs>
                        <td class="policy-name">$([System.Web.HttpUtility]::HtmlEncode($policy.PolicyName))</td>
                        <td><span class="state-badge $stateClass">$stateText</span></td>
                        <td class="number">$($policy.TotalBlocks)</td>
                        <td class="number">$($policy.Interrupted)</td>
                        <td class="number">$($policy.UniqueUsersCount)</td>
                        <td class="number">$($policy.BlockedUsersCount)</td>
                        <td class="number">$($policy.UniqueAppsCount)</td>
                        <td class="number">$($policy.UniqueLocationsCount)</td>
                    </tr>
"@)
    }

    [void]$html.AppendLine(@"
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Conditional Access Effectiveness Report | Generated via Microsoft Graph API | $organisationName</p>
            <p>Analysis period: Last $days days | Failed/blocked sign-ins analyzed: $($signIns.Count)</p>
            <p>Note: This report focuses on effectiveness and only analyzes failed sign-ins (blocks, interruptions). Successful sign-ins are excluded for performance.</p>
        </div>
    </div>

    <script>
        function searchTable() {
            const input = document.getElementById('searchBox');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('policyTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const firstCol = rows[i].getElementsByTagName('td')[0];
                if (firstCol) {
                    const txtValue = firstCol.textContent || firstCol.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        rows[i].style.display = '';
                    } else {
                        rows[i].style.display = 'none';
                    }
                }
            }
        }

        function filterTable(filterType) {
            const buttons = document.querySelectorAll('.filter-button');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const table = document.getElementById('policyTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];

                if (filterType === 'all') {
                    row.style.display = '';
                } else if (filterType === 'enabled' && row.hasAttribute('data-enabled')) {
                    row.style.display = '';
                } else if (filterType === 'report' && row.hasAttribute('data-report')) {
                    row.style.display = '';
                } else if (filterType === 'blocking' && row.hasAttribute('data-blocking')) {
                    row.style.display = '';
                } else if (filterType === 'dead' && row.hasAttribute('data-dead')) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            }
        }

        // Add click event listeners to table headers for sorting
        document.addEventListener('DOMContentLoaded', function() {
            const headers = document.querySelectorAll('#policyTable thead th');
            headers.forEach((header, index) => {
                header.addEventListener('click', () => sortTable(index));
            });
        });

        function sortTable(columnIndex) {
            const table = document.getElementById('policyTable');
            if (!table) return;

            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr')).filter(row => row.style.display !== 'none');
            const headers = table.querySelectorAll('thead th');
            const header = headers[columnIndex];

            // Clear sort indicators from all other headers
            headers.forEach((h, idx) => {
                if (idx !== columnIndex) {
                    delete h.dataset.sortOrder;
                }
            });

            let ascending = header.dataset.sortOrder !== 'asc';
            header.dataset.sortOrder = ascending ? 'asc' : 'desc';

            rows.sort((a, b) => {
                const aValue = a.cells[columnIndex]?.textContent.trim() || '';
                const bValue = b.cells[columnIndex]?.textContent.trim() || '';

                const aNum = parseFloat(aValue.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bValue.replace(/[^0-9.-]/g, ''));

                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return ascending ? aNum - bNum : bNum - aNum;
                }

                return ascending ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
            });

            rows.forEach(row => tbody.appendChild(row));
        }

        function exportTableToCSV() {
            let csvContent = [];

            const table = document.getElementById('policyTable');
            const headerRow = table.querySelector('thead tr');
            const headerCells = headerRow.querySelectorAll('th');

            let headerCsvRow = [];
            for (let i = 0; i < headerCells.length; i++) {
                let cellText = headerCells[i].textContent.trim();
                cellText = cellText.replace(/"/g, '""');
                headerCsvRow.push('"' + cellText + '"');
            }
            csvContent.push(headerCsvRow.join(','));

            const dataRows = table.querySelectorAll('tbody tr');
            for (let i = 0; i < dataRows.length; i++) {
                if (dataRows[i].style.display === 'none') continue;

                let csvRow = [];
                const cells = dataRows[i].querySelectorAll('td');

                for (let j = 0; j < cells.length; j++) {
                    let cellText = cells[j].textContent.trim();
                    cellText = cellText.replace(/"/g, '""');
                    csvRow.push('"' + cellText + '"');
                }

                csvContent.push(csvRow.join(','));
            }

            const csvString = csvContent.join('\r\n');
            const today = new Date();
            const date = today.toISOString().split('T')[0];

            const downloadLink = document.createElement('a');
            const BOM = '\uFEFF';
            const encodedUri = 'data:text/csv;charset=utf-8,' + encodeURIComponent(BOM + csvString);

            downloadLink.setAttribute('href', encodedUri);
            downloadLink.setAttribute('download', 'CA_Effectiveness_Report_' + date + '.csv');
            document.body.appendChild(downloadLink);

            downloadLink.click();
            document.body.removeChild(downloadLink);
        }
    </script>
</body>
</html>
"@)

    # Generate the path
    $finalPath = Join-Path -Path $OutputPath -ChildPath "ConditionalAccess_Effectiveness_Report.html"

    # Output HTML report
    $html.ToString() | Out-File -FilePath $finalPath -Encoding UTF8
    Write-Output "HTML report generated at $finalPath"

    # Open the report in the default browser
    if ($openBrowser) {
        Start-Process $finalPath
    }

    return $finalPath
}

# Generate the report
$reportPath = Generate-CAEffectivenessReport -PolicyStatistics $policyStats -OutputPath $outpath

Write-Output "`nReport generation complete!"
Write-Output "Report saved to: $reportPath"
Write-Output "`nSummary:"
Write-Output "  Total Policies Analyzed: $totalPolicies"
Write-Output "  Total Blocks: $totalBlocks"
Write-Output "  Dead Policies (never blocked): $deadPolicies"
Write-Output "  Failed Sign-ins Analyzed: $($signIns.Count)"
Write-Output "`nNote: Only failed/blocked sign-ins were fetched for performance (successful sign-ins excluded)"
