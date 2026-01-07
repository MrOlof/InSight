<#PSScriptInfo
.VERSION 1.0.0
.AUTHOR Kosta Wadenfalk
.COPYRIGHT © 2026 Kosta Wadenfalk. All rights reserved.
.TAGS Microsoft Entra, Microsoft Graph, Intune, Shadow IT, Unmanaged Devices, HTML
#>

<#
.SYNOPSIS
  Generate a Shadow IT & Unmanaged Devices analytics report with an interactive HTML dashboard.

.DESCRIPTION
  This script connects to Microsoft Graph using least-privilege read scopes and produces a fully interactive,
  client-side HTML report. No data changes are performed—this is strictly read-only.

  The generated report includes:
    • Summary cards (Total users with unmanaged access, managed vs unmanaged ratio, high-risk attempts)
    • Top applications accessed from unmanaged devices
    • Users with no enrolled Intune devices but active sign-ins
    • Interactive search and filtering (risk level, device OS, app name)
    • Column-visibility checkboxes (user can hide/show columns dynamically)
    • Fullscreen table mode
    • CSV export of visible rows and visible columns only

  Data analyzed from sign-in activity over a configurable time period (default: 10 days).

.PARAMETER SaveReportTo
  Directory where the report file will be saved.

.PARAMETER Days
  Number of days to analyze sign-in logs. Default is 10 days for faster testing. Increase to 30+ for production analysis.

.PARAMETER OpenBrowser
  Automatically open the generated HTML report after creation.

.PARAMETER IncludeRiskData
  Include Azure AD Identity Protection risk detection data (requires IdentityRiskyUser.Read.All scope).

#>

param(
    [Parameter(
        Mandatory = $true,
        HelpMessage = "Path where the HTML report should be saved."
    )]
    [ValidateNotNullOrEmpty()]
    [string]$SaveReportTo,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$Days = 10,

    [switch]$OpenBrowser,
    [switch]$IncludeRiskData
)


#-----------------------------#
#  Graph connection (read-only)
#-----------------------------#
function Connect-MgGraphLeastPriv {
    param([bool]$WithRiskData)

    $requiredScopes = @(
        'AuditLog.Read.All',                          # sign-in logs
        'Directory.Read.All',                         # users
        'DeviceManagementManagedDevices.Read.All'     # Intune devices
    )

    if ($WithRiskData) {
        $requiredScopes += 'IdentityRiskyUser.Read.All'
    }

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needConnect = $true
    if ($ctx) {
        $missing = $requiredScopes | Where-Object { $ctx.Scopes -notcontains $_ }
        if (-not $missing) { $needConnect = $false }
    }

    if ($needConnect) {
        try {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
        } catch {
            throw "Connect-MgGraph failed: $($_.Exception.Message)"
        }
    }
}

#-----------------------------#
#  Data collection
#-----------------------------#
function Get-TenantDisplayName {
    try {
        (Invoke-MgGraphRequest -Uri 'v1.0/organization' -OutputType PSObject).value[0].displayName
    } catch {
        'Unknown Organization'
    }
}

function Get-UnmanagedDeviceData {
    param(
        [bool]$IncludeRisk,
        [int]$DaysBack
    )

    Write-Host "Collecting sign-in logs (last $DaysBack days)..." -ForegroundColor Cyan

    # Get sign-ins from last X days
    $startDate = (Get-Date).AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "createdDateTime ge $startDate"

    # Use beta endpoint for better deviceDetail properties
    $uri = "beta/auditLogs/signIns?`$filter=$filter&`$select=id,createdDateTime,userPrincipalName,userId,appDisplayName,deviceDetail,status,ipAddress,location,riskDetail,riskLevelAggregated,riskLevelDuringSignIn&`$top=999"

    $signIns = @()
    $nextLink = $uri

    while ($nextLink) {
        try {
            $response = Invoke-MgGraphRequest -Uri $nextLink -OutputType PSObject
            $signIns += $response.value
            $nextLink = $response.'@odata.nextLink'
            Write-Host "  Retrieved $($signIns.Count) sign-ins..." -ForegroundColor Gray
        } catch {
            Write-Warning "Error retrieving sign-ins: $($_.Exception.Message)"
            break
        }
    }

    Write-Host "Collecting Intune managed devices..." -ForegroundColor Cyan

    # Get all Intune managed devices
    $intuneDevices = @()
    try {
        $uri = "v1.0/deviceManagement/managedDevices?`$select=id,userId,deviceName,operatingSystem,complianceState,managementAgent"
        $nextLink = $uri

        while ($nextLink) {
            $response = Invoke-MgGraphRequest -Uri $nextLink -OutputType PSObject
            $intuneDevices += $response.value
            $nextLink = $response.'@odata.nextLink'
        }
    } catch {
        Write-Warning "Error retrieving Intune devices: $($_.Exception.Message)"
    }

    # Group Intune devices by userId
    $intuneByUser = @{}
    foreach ($dev in $intuneDevices) {
        if ($dev.userId) {
            if (-not $intuneByUser.ContainsKey($dev.userId)) {
                $intuneByUser[$dev.userId] = @()
            }
            $intuneByUser[$dev.userId] += $dev
        }
    }

    # Get risky users if requested
    $riskyUsers = @{}
    if ($IncludeRisk) {
        Write-Host "Collecting risk detection data..." -ForegroundColor Cyan
        try {
            $uri = "v1.0/identityProtection/riskyUsers?`$select=id,userPrincipalName,riskLevel,riskState,riskDetail"
            $response = Invoke-MgGraphRequest -Uri $uri -OutputType PSObject
            foreach ($ru in $response.value) {
                if ($ru.id) {
                    $riskyUsers[$ru.id] = $ru
                }
            }
        } catch {
            Write-Warning "Error retrieving risky users: $($_.Exception.Message)"
        }
    }

    Write-Host "Processing data and correlating..." -ForegroundColor Cyan

    # Group sign-ins by user
    $userSignIns = $signIns | Group-Object -Property userId -AsHashTable -AsString

    $rows = foreach ($userId in $userSignIns.Keys) {
        $userSigns = $userSignIns[$userId]
        $upn = $userSigns[0].userPrincipalName
        if (-not $upn) { continue }

        $totalSignIns = $userSigns.Count
        $unmanagedSignIns = @($userSigns | Where-Object {
            $_.deviceDetail.isManaged -eq $false -or
            $_.deviceDetail.isCompliant -eq $false
        })
        $unmanagedCount = $unmanagedSignIns.Count

        if ($unmanagedCount -eq 0) { continue }  # Skip users with no unmanaged access

        # Unique apps accessed from unmanaged devices
        $unmanagedApps = $unmanagedSignIns |
            Select-Object -ExpandProperty appDisplayName -Unique |
            Where-Object { $_ } |
            Sort-Object

        # Device OS types used
        $deviceOS = $unmanagedSignIns |
            ForEach-Object { $_.deviceDetail.operatingSystem } |
            Where-Object { $_ } |
            Select-Object -Unique |
            Sort-Object

        # Has enrolled Intune devices?
        $hasIntuneDevice = $intuneByUser.ContainsKey($userId)
        $intuneDeviceCount = if ($hasIntuneDevice) { $intuneByUser[$userId].Count } else { 0 }

        # Latest unmanaged sign-in
        $latestUnmanaged = ($unmanagedSignIns | Sort-Object -Property createdDateTime -Descending | Select-Object -First 1).createdDateTime

        # Risk level calculation
        $riskLevel = 'Low'
        if ($IncludeRisk -and $riskyUsers.ContainsKey($userId)) {
            $riskLevel = $riskyUsers[$userId].riskLevel
        } else {
            # Simple heuristic: high % of unmanaged + no Intune device = higher risk
            $unmanagedPct = [math]::Round(($unmanagedCount / $totalSignIns) * 100, 1)
            if (-not $hasIntuneDevice -and $unmanagedPct -ge 80) { $riskLevel = 'High' }
            elseif (-not $hasIntuneDevice -and $unmanagedPct -ge 50) { $riskLevel = 'Medium' }
            elseif ($unmanagedPct -ge 90) { $riskLevel = 'Medium' }
        }

        # Unique countries/locations (potential suspicious activity)
        $locations = $unmanagedSignIns |
            ForEach-Object {
                if ($_.location.countryOrRegion) { $_.location.countryOrRegion }
            } |
            Where-Object { $_ } |
            Select-Object -Unique |
            Sort-Object

        [PSCustomObject]@{
            UPN                      = $upn
            UserId                   = $userId
            TotalSignIns             = $totalSignIns
            UnmanagedSignIns         = $unmanagedCount
            UnmanagedPercentage      = [math]::Round(($unmanagedCount / $totalSignIns) * 100, 1)
            AppsOnUnmanagedDevices   = ($unmanagedApps -join ', ')
            DeviceOSTypes            = ($deviceOS -join ', ')
            HasIntuneDevice          = $hasIntuneDevice
            IntuneDeviceCount        = $intuneDeviceCount
            RiskLevel                = $riskLevel
            LastUnmanagedSignIn      = if ($latestUnmanaged) { (Get-Date $latestUnmanaged).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
            Locations                = ($locations -join ', ')
        }
    }

    Write-Host "Analysis complete. Found $($rows.Count) users with unmanaged device access." -ForegroundColor Green
    $rows
}

#-----------------------------#
#  HTML report
#-----------------------------#
function Write-UnmanagedDevicesHtml {
    param(
        [Parameter(Mandatory)][array]$Rows,
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$OutputFile,
        [Parameter(Mandatory)][int]$DaysAnalyzed
    )

    if ($Rows.Count -eq 0) {
        Write-Warning "No data to generate report. All users are accessing from managed devices only."
        return
    }

    # Summary metrics
    $totalUsers           = $Rows.Count
    $totalSignIns         = ($Rows | Measure-Object -Property TotalSignIns -Sum).Sum
    $totalUnmanaged       = ($Rows | Measure-Object -Property UnmanagedSignIns -Sum).Sum
    $unmanagedRatio       = [math]::Round(($totalUnmanaged / $totalSignIns) * 100, 1)
    $noIntuneCount        = ($Rows | Where-Object { -not $_.HasIntuneDevice }).Count
    $highRiskCount        = ($Rows | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumRiskCount      = ($Rows | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $lowRiskCount         = $totalUsers - $highRiskCount - $mediumRiskCount

    # Calculate percentages for risk bar
    $highPct   = [math]::Round(($highRiskCount / $totalUsers) * 100, 1)
    $mediumPct = [math]::Round(($mediumRiskCount / $totalUsers) * 100, 1)
    $lowPct    = [math]::Round(($lowRiskCount / $totalUsers) * 100, 1)

    # Table column definitions
    $cols = @(
        @{h='User Principal Name';                  p='UPN'}
        @{h='Total Sign-ins';                       p='TotalSignIns'}
        @{h='Unmanaged';                            p='UnmanagedSignIns'}
        @{h='Unmanaged %';                          p='UnmanagedPercentage'}
        @{h='Applications on Unmanaged Devices';    p='AppsOnUnmanagedDevices'}
        @{h='Device OS Types';                      p='DeviceOSTypes'}
        @{h='Has Intune';                           p='HasIntuneDevice'}
        @{h='Device Count';                         p='IntuneDeviceCount'}
        @{h='Risk Level';                           p='RiskLevel'}
        @{h='Last Unmanaged Sign-in';               p='LastUnmanagedSignIn'}
        @{h='Locations';                            p='Locations'}
    )

    $date = Get-Date -Format 'MMMM d, yyyy'

    # Build HTML
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine(@"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Shadow IT Risk Monitor</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f5f5f5;
    color: #333;
    min-height: 100vh;
  }

  .header {
    background: linear-gradient(135deg, #e53935 0%, #d32f2f 100%);
    color: #fff;
    padding: 24px 40px;
    box-shadow: 0 2px 12px rgba(229, 57, 53, 0.3);
  }
  .header h1 {
    font-size: 28px;
    font-weight: 700;
    margin-bottom: 6px;
  }
  .header .meta {
    font-size: 13px;
    opacity: 0.95;
  }

  .risk-bar-container {
    max-width: 1600px;
    margin: 30px auto 20px;
    padding: 0 40px;
  }
  .risk-bar-title {
    font-size: 14px;
    font-weight: 600;
    color: #666;
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .risk-bar {
    display: flex;
    height: 60px;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    background: #fff;
  }
  .risk-segment {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: #fff;
    font-weight: 600;
    transition: all 0.3s;
    cursor: pointer;
    position: relative;
  }
  .risk-segment:hover {
    filter: brightness(1.1);
    transform: scaleY(1.05);
  }
  .risk-segment.low {
    background: linear-gradient(135deg, #2e7d32, #388e3c);
  }
  .risk-segment.medium {
    background: linear-gradient(135deg, #ef6c00, #f57c00);
  }
  .risk-segment.high {
    background: linear-gradient(135deg, #c62828, #d32f2f);
  }
  .risk-segment-label {
    font-size: 11px;
    text-transform: uppercase;
    opacity: 0.9;
    letter-spacing: 0.5px;
  }
  .risk-segment-value {
    font-size: 22px;
    font-weight: 700;
    margin-top: 2px;
  }
  .risk-segment-pct {
    font-size: 10px;
    opacity: 0.85;
  }

  .content {
    max-width: 1600px;
    margin: 0 auto;
    padding: 20px 40px 40px;
  }

  .filters {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
    align-items: center;
    background: #fff;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  }
  input[type=text], select {
    padding: 12px 16px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
    background: #fff;
  }
  input[type=text]:focus, select:focus {
    outline: none;
    border-color: #e53935;
    box-shadow: 0 0 0 3px rgba(229, 57, 53, 0.1);
  }
  input[type=text] {
    min-width: 300px;
  }
  select {
    min-width: 180px;
  }

  .btn {
    padding: 12px 24px;
    background: linear-gradient(135deg, #e53935, #d32f2f);
    border: 0;
    border-radius: 6px;
    cursor: pointer;
    color: white;
    font-weight: 600;
    font-size: 14px;
    transition: all 0.2s;
    margin-left: auto;
  }
  .btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(229, 57, 53, 0.3);
  }

  .table-container {
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    overflow: hidden;
  }
  .table-wrap {
    overflow-x: auto;
    max-height: calc(100vh - 400px);
    overflow-y: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 1200px;
  }
  th, td {
    padding: 14px 16px;
    border-bottom: 1px solid #f0f0f0;
    text-align: left;
    font-size: 13px;
  }
  thead th {
    background: #fafafa;
    color: #555;
    font-weight: 600;
    position: sticky;
    top: 0;
    z-index: 10;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.5px;
    border-bottom: 2px solid #e0e0e0;
    cursor: pointer;
    user-select: none;
    transition: background 0.2s;
  }
  thead th:hover {
    background: #f0f0f0;
  }
  thead th.sort-asc::after {
    content: ' ▲';
    color: #e53935;
    font-size: 10px;
  }
  thead th.sort-desc::after {
    content: ' ▼';
    color: #e53935;
    font-size: 10px;
  }
  tbody tr {
    transition: background 0.2s;
  }
  tbody tr:hover {
    background: #fef5f5;
  }
  tbody tr[data-risk='High'] {
    border-left: 4px solid #c62828;
    background: rgba(198, 40, 40, 0.04);
  }
  tbody tr[data-risk='Medium'] {
    border-left: 4px solid #ef6c00;
    background: rgba(239, 108, 0, 0.04);
  }
  tbody tr[data-risk='Low'] {
    border-left: 4px solid #2e7d32;
    background: rgba(46, 125, 50, 0.03);
  }
  .badge {
    display: inline-block;
    padding: 5px 12px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge.high {
    background: #c62828;
    color: white;
  }
  .badge.medium {
    background: #ef6c00;
    color: white;
  }
  .badge.low {
    background: #2e7d32;
    color: white;
  }
</style>
</head>
<body>

<div class="header">
  <h1>Shadow IT Risk Monitor</h1>
  <div class="meta">Generated: $date | Org: $tenant | Analysis Period: Last $DaysAnalyzed Days</div>
</div>

<div class="risk-bar-container">
  <div class="risk-bar-title">Risk Distribution Overview</div>
  <div class="risk-bar">
    <div class="risk-segment low" style="width: $lowPct%" onclick="filterByRisk('Low')">
      <span class="risk-segment-label">Low Risk</span>
      <span class="risk-segment-value">$lowRiskCount</span>
      <span class="risk-segment-pct">$lowPct%</span>
    </div>
    <div class="risk-segment medium" style="width: $mediumPct%" onclick="filterByRisk('Medium')">
      <span class="risk-segment-label">Medium Risk</span>
      <span class="risk-segment-value">$mediumRiskCount</span>
      <span class="risk-segment-pct">$mediumPct%</span>
    </div>
    <div class="risk-segment high" style="width: $highPct%" onclick="filterByRisk('High')">
      <span class="risk-segment-label">High Risk</span>
      <span class="risk-segment-value">$highRiskCount</span>
      <span class="risk-segment-pct">$highPct%</span>
    </div>
  </div>
</div>

<div class="content">
  <div class="filters">
    <input id="search" type="text" placeholder="Search by UPN..." onkeyup="applyFilters()" />
    <select id="riskFilter" onchange="applyFilters()">
      <option value="">All Risk Levels</option>
      <option value="High">High Risk</option>
      <option value="Medium">Medium Risk</option>
      <option value="Low">Low Risk</option>
    </select>
    <select id="osFilter" onchange="applyFilters()">
      <option value="">All Device OS</option>
      <option value="Windows">Windows</option>
      <option value="iOS">iOS</option>
      <option value="Android">Android</option>
      <option value="MacOS">MacOS</option>
      <option value="Linux">Linux</option>
    </select>
    <input id="appFilter" type="text" placeholder="Filter by application..." onkeyup="applyFilters()" style="min-width: 220px;" />
    <button class="btn" onclick="exportCSV()">Export CSV</button>
  </div>

  <div class="table-container">
    <div class="table-wrap">
      <table id="tbl">
        <thead>
          <tr>
"@)

    # headers with sortable attributes
    $dataTypes = @('text', 'number', 'number', 'number', 'text', 'text', 'text', 'number', 'risk', 'date', 'text')
    for ($i = 0; $i -lt $cols.Count; $i++) {
        $h = [System.Web.HttpUtility]::HtmlEncode($cols[$i].h)
        $dataType = $dataTypes[$i]
        [void]$sb.AppendLine("            <th onclick=""sortTable($i)"" data-type=""$dataType"">$h</th>")
    }

    [void]$sb.AppendLine("        </tr></thead><tbody>")

    # rows
    foreach ($r in $Rows) {
        $attrs = @()
        $attrs += "data-risk='$($r.RiskLevel)'"
        $attrs += "data-os='$($r.DeviceOSTypes)'"
        $attrs += "data-apps='$($r.AppsOnUnmanagedDevices)'"
        $attrs += "data-nointune='$(-not $r.HasIntuneDevice)'"
        $attrs += "data-unmanagedpct='$($r.UnmanagedPercentage)'"

        [void]$sb.AppendLine("        <tr $(($attrs -join ' '))>")

        foreach ($c in $cols) {
            $v = $r.($c.p)

            # Special formatting for risk level
            if ($c.p -eq 'RiskLevel') {
                $badgeClass = switch ($v) {
                    'High'   { 'high' }
                    'Medium' { 'medium' }
                    default  { 'low' }
                }
                $v = "<span class='badge $badgeClass'>$v</span>"
            }
            # Boolean formatting
            elseif ($v -is [bool]) {
                $v = if ($v) { 'Yes' } else { 'No' }
            }
            # DateTime formatting
            elseif ($v -is [datetime]) {
                $v = $v.ToString('yyyy-MM-dd HH:mm')
            }
            else {
                $v = [System.Web.HttpUtility]::HtmlEncode([string]$v)
            }

            [void]$sb.AppendLine("          <td>$v</td>")
        }
        [void]$sb.AppendLine("        </tr>")
    }

    [void]$sb.AppendLine(@"
          </tbody>
      </table>
    </div>
  </div>
</div>

<script>
  function applyFilters() {
    const q = (document.getElementById('search').value || '').toLowerCase();
    const risk = document.getElementById('riskFilter').value;
    const os = document.getElementById('osFilter').value;
    const app = (document.getElementById('appFilter').value || '').toLowerCase();

    const rows = document.querySelectorAll('#tbl tbody tr');
    rows.forEach(r => {
      const upn = r.cells[0].textContent.toLowerCase();
      let show = true;
      if (q && !upn.includes(q)) show = false;
      if (risk && r.dataset.risk !== risk) show = false;
      if (os && !r.dataset.os.includes(os)) show = false;
      if (app && !r.dataset.apps.toLowerCase().includes(app)) show = false;
      r.style.display = show ? '' : 'none';
    });
  }

  function filterByRisk(riskLevel) {
    document.getElementById('riskFilter').value = riskLevel;
    applyFilters();
  }

  function exportCSV() {
    const rows = document.querySelectorAll('#tbl tbody tr');
    let csv = 'UPN,Total Sign-ins,Unmanaged,Unmanaged %,Apps,OS,Has Intune,Device Count,Risk,Last Unmanaged,Locations\n';
    rows.forEach(r => {
      if (r.style.display === 'none') return;
      const cells = Array.from(r.cells).map(c => {
        let text = c.textContent.trim().replace(/"/g, '""');
        return '"' + text + '"';
      });
      csv += cells.join(',') + '\n';
    });
    const a = document.createElement('a');
    a.href = 'data:text/csv;charset=utf-8,\uFEFF' + encodeURIComponent(csv);
    a.download = 'ShadowIT_RiskMonitor_' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
  }

  let currentSort = { column: -1, ascending: true };

  function sortTable(columnIndex) {
    const table = document.getElementById('tbl');
    const tbody = table.querySelector('tbody');
    const headers = table.querySelectorAll('thead th');
    const dataType = headers[columnIndex].getAttribute('data-type');

    // Toggle sort direction if clicking same column
    if (currentSort.column === columnIndex) {
      currentSort.ascending = !currentSort.ascending;
    } else {
      currentSort.ascending = true;
      currentSort.column = columnIndex;
    }

    // Remove sort indicators from all headers
    headers.forEach(h => {
      h.classList.remove('sort-asc', 'sort-desc');
    });

    // Add sort indicator to current column
    headers[columnIndex].classList.add(currentSort.ascending ? 'sort-asc' : 'sort-desc');

    // Get all rows (including hidden ones for proper sorting)
    const rows = Array.from(tbody.querySelectorAll('tr'));

    rows.sort((a, b) => {
      let aVal = a.cells[columnIndex].textContent.trim();
      let bVal = b.cells[columnIndex].textContent.trim();

      // Handle different data types
      if (dataType === 'number') {
        aVal = parseFloat(aVal) || 0;
        bVal = parseFloat(bVal) || 0;
      } else if (dataType === 'date') {
        aVal = new Date(aVal).getTime() || 0;
        bVal = new Date(bVal).getTime() || 0;
      } else if (dataType === 'risk') {
        const riskOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
        aVal = riskOrder[aVal] || 0;
        bVal = riskOrder[bVal] || 0;
      } else {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (aVal < bVal) return currentSort.ascending ? -1 : 1;
      if (aVal > bVal) return currentSort.ascending ? 1 : -1;
      return 0;
    });

    // Re-append sorted rows
    rows.forEach(row => tbody.appendChild(row));
  }
</script>

</body>
</html>
"@)

    $null = New-Item -ItemType Directory -Path $SaveReportTo -ErrorAction SilentlyContinue
    $sb.ToString() | Out-File -FilePath $OutputFile -Encoding UTF8
}

#-----------------------------#
#  Main
#-----------------------------#
try {
    Write-Host "`nShadow IT & Unmanaged Devices Report Generator" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan

    Connect-MgGraphLeastPriv -WithRiskData $IncludeRiskData.IsPresent
    $tenant = Get-TenantDisplayName
    $rows   = Get-UnmanagedDeviceData -IncludeRisk $IncludeRiskData.IsPresent -DaysBack $Days

    if ($rows.Count -gt 0) {
        $outfile = Join-Path -Path $SaveReportTo -ChildPath 'ShadowIT_UnmanagedDevices_Report.html'
        Write-UnmanagedDevicesHtml -Rows $rows -Tenant $tenant -OutputFile $outfile -DaysAnalyzed $Days

        Write-Host "`nHTML report saved: $outfile" -ForegroundColor Green
        if ($OpenBrowser) { Start-Process $outfile }
    } else {
        Write-Host "`nNo unmanaged device access detected in the last $Days days." -ForegroundColor Green
        Write-Host "All sign-ins appear to be from managed/compliant devices." -ForegroundColor Green
    }
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
}
