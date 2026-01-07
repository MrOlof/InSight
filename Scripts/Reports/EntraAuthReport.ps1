<#PSScriptInfo

.VERSION 1.0.0

.GUID bbda77a3-7d1c-415e-9c28-7c934971599c

.AUTHOR Kosta Wadenfalk

.Credit: https://ourcloudnetwork.com/create-a-free-interactive-entra-authentication-methods-report/
.Original creator: Daniel Bradley - Thanks for this excellent script

.TAGS
    Microsoft Entra
    Microsoft Graph

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES
    Microsoft.Graph.Authentication

.RELEASENOTES
    v1.0 - 2026-01-11 - Initial release

#>

<#
.SYNOPSIS
    Generates a comprehensive Microsoft Entra authentication methods report.

.DESCRIPTION
    Analyzes authentication methods registered by users including MFA status,
    passwordless capabilities, and privileged account security.

.PARAMETER outpath
    Output directory for the HTML report.

.PARAMETER limit
    Maximum userRegistrationDetails records to fetch (default: 20000).

.PARAMETER skipGuest
    Exclude guest users from the report.

.PARAMETER skipDetailedPhoneInfo
    Skip detailed mobile authentication method queries.

.PARAMETER openBrowser
    Open the generated report in default browser.

.EXAMPLE
    .\EntraAuthReport.ps1 -outpath "C:\Reports"

#>

param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$outpath,

    [Parameter(Mandatory = $false)]
    [int]$limit = 20000,

    [Parameter(Mandatory = $false)]
    [switch]$skipGuest = $false,

    [Parameter(Mandatory = $false)]
    [switch]$skipDetailedPhoneInfo = $false,

    [Parameter(Mandatory = $false)]
    [switch]$openBrowser = $false
)

$state = Get-MgContext

$requiredPerms = @("Policy.Read.All", "Organization.Read.All", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All", "RoleAssignmentSchedule.Read.Directory", "RoleEligibilitySchedule.Read.Directory")

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
        Write-output "Connected to Microsoft Graph with all required permissions"
    }
    else {
        Write-output "Missing required permissions: $($missingPerms -join ', ')"
        Write-output "Reconnecting with all required permissions..."
    }
}
else {
    Write-output "Not connected to Microsoft Graph. Connecting now..."
}

if (-not $hasAllPerms) {
    try {
        Connect-MgGraph -Scopes $requiredPerms -ErrorAction Stop -NoWelcome
        Write-output "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit
    }
}

$items = @("AAD_PREMIUM_P2", "AAD_PREMIUM", "AAD_BASIC")
$Skus = Invoke-MgGraphRequest -Uri "Beta/subscribedSkus" -OutputType PSObject | Select -Expand Value
foreach ($item in $items) {
    $Search = $skus | ? { $_.ServicePlans.servicePlanName -contains "$item" }
    if ($Search) {
        $licenseplan = $item
        break
    }
    ElseIf ((!$Search) -and ($item -eq "AAD_BASIC")) {
        $licenseplan = $item
        break
    }
}

$organisationName = (Invoke-MgGraphRequest -Uri "v1.0/organization" -OutputType PSObject | Select -Expand value).DisplayName

Function Get-AuthenticationMethods {
    $policies = Invoke-MgGraphRequest -Uri "beta/policies/authenticationmethodspolicy" -OutputType PSObject | Select -Expand authenticationMethodConfigurations
    $policiesReport = [System.Collections.Generic.List[Object]]::new()
    forEach ($policy in $policies) {
        $obj = [PSCustomObject][ordered]@{
            "Type"        = if ($policy.displayName) { "Custom" }else { "Built-in" }
            "DisplayName" = if ($policy.displayName) { $policy.displayName }else { $policy.id }
            "State"       = $policy.state
            "Aliases"     = ($policy.includeTargets.id -join [environment]::NewLine)
        }
        $policiesReport.Add($obj)
    }
    return $policiesReport
}

Function Get-UserRegistrationDetails {
    $userRegistrations = Invoke-MgGraphRequest -Uri "Beta/reports/authenticationMethods/userRegistrationDetails?`$top=$limit&`$orderby=userPrincipalName" -OutputType PSObject | Select -Expand Value

    if ($skipGuest) {
        $userRegistrations = $userRegistrations | Where-Object { $_.userType -ne "guest" }
    }

    $usersWithMobileMethods = $userRegistrations | Where-Object { $_.methodsRegistered -contains "mobilePhone" } | Select-Object id, userPrincipalName, methodsRegistered

    Foreach ($user in $usersWithMobileMethods) {
        $methodsFromReport = ($userRegistrations | Where-Object { $_.userPrincipalName -eq $user.userPrincipalName }).methodsRegistered
        $methodsToReplace = @()
        $methodsToReplace += $methodsFromReport | Where-Object { $_ -ne "mobilePhone" }
        $methodsToReplace += "Voice Call"

        if (-not $skipDetailedPhoneInfo) {
            $Methods = Invoke-MgGraphRequest -uri "/beta/users/$($user.id)/authentication/methods" -OutputType PSObject | WHere { $_."@odata.type" -eq '#microsoft.graph.phoneAuthenticationMethod'}
            if ($Methods.smsSignInState -eq "ready") {
                $methodsToReplace += "SMS"
            }
        }

        ($userRegistrations | Where-Object { $_.userPrincipalName -eq $user.userPrincipalName }).methodsRegistered = $methodsToReplace
    }

    return $userRegistrations
}

Function Get-PrivilegedUserRegistrationDetails {
    [CmdletBinding()]
    param (
        [Parameter()]
        $userRegistrations
    )
    If ($licenseplan -eq "AAD_PREMIUM_P2") {
        $EligiblePIMRoles = Invoke-MgGraphRequest -Uri "beta/roleManagement/directory/roleEligibilitySchedules?`$expand=*" -OutputType PSObject | Select -Expand Value
        $AssignedPIMRoles = Invoke-MgGraphRequest -Uri "beta/roleManagement/directory/roleAssignmentSchedules?`$expand=*" -OutputType PSObject | Select -Expand Value
        $DirectoryRoles = $EligiblePIMRoles + $AssignedPIMRoles
        $DirectoryRoleUsers = $DirectoryRoles | Where { $_.Principal.'@odata.type' -eq "#microsoft.graph.user" }
        $RoleMembers = $DirectoryRoleUsers.Principal.userPrincipalName | Select-Object -Unique
    }
    else {
        $DirectoryRoles = Invoke-MgGraphRequest -Uri "/beta/directoryRoles?" -OutputType PSObject | Select -Expand Value
        $RoleMembers = $DirectoryRoles | ForEach-Object { Invoke-MgGraphRequest -uri "/beta/directoryRoles/$($_.id)/members" -OutputType PSObject | Select -Expand Value } | where { $_.'@odata.type' -eq "#microsoft.graph.user" } | Select-Object -expand userPrincipalName -Unique
    }
    $PrivilegedUserRegistrationDetails = $userRegistrationsReport | where { $RoleMembers -contains $_.userPrincipalName }
    Return $PrivilegedUserRegistrationDetails
}

$AllMethods = @(
    [pscustomobject]@{type='microsoftAuthenticatorPasswordless';Name='Microsoft Authenticator Passwordless';Strength='Strong'}
    [pscustomobject]@{type='fido2SecurityKey';AltName='Fido2';Name='Fido2 Security Key';Strength='Strong'}
    [pscustomobject]@{type='passKeyDeviceBound';AltName='Fido2';Name='Device Bound Passkey';Strength='Strong'}
    [pscustomobject]@{type='passKeyDeviceBoundAuthenticator';AltName='Fido2';Name='Microsoft Authenticator Passkey';Strength='Strong'}
    [pscustomobject]@{type='passKeyDeviceBoundWindowsHello';AltName='Fido2';Name='Windows Hello Passkey';Strength='Strong'}
    [pscustomobject]@{type='microsoftAuthenticatorPush';AltName='MicrosoftAuthenticator';Name='Microsoft Authenticator App';Strength='Strong'}
    [pscustomobject]@{type='softwareOneTimePasscode';AltName='SoftwareOath';Name='Software OTP';Strength='Strong'}
    [pscustomobject]@{type='hardwareOneTimePasscode';AltName='HardwareOath';Name='Hardware OTP';Strength='Strong'}
    [pscustomobject]@{type='windowsHelloForBusiness';AltName='windowsHelloForBusiness';Name='Windows Hello for Business';Strength='Strong'}
    [pscustomobject]@{type='temporaryAccessPass';AltName='TemporaryAccessPass';Name='Temporary Access Pass';Strength='Strong'}
    [pscustomobject]@{type='macOsSecureEnclaveKey';Name='MacOS Secure Enclave Key';Strength='Strong'}
    [pscustomobject]@{type='SMS';AltName='SMS';Name='SMS';Strength='Weak'}
    [pscustomobject]@{type='Voice Call';AltName='voice';Name='Voice Call';Strength='Weak'}
    [pscustomobject]@{type='email';AltName='Email';Name='Email';Strength='Weak'}
    [pscustomobject]@{type='alternateMobilePhone';AltName='Voice';Name='Alternative Mobile Phone';Strength='Weak'}
    [pscustomobject]@{type='securityQuestion';AltName='Security Questions';Name='Security Questions';Strength='Weak'}
)
$strongMethodTypes = $AllMethods | Where-Object { $_.Strength -eq 'Strong' } | Select-Object -ExpandProperty type
$weakMethodTypes = $AllMethods | Where-Object { $_.Strength -eq 'Weak' }

Write-output "Fetching users registration details..."
$userRegistrationsReport = Get-UserRegistrationDetails

Write-output "Fetching authentication methods..."
$authenticationMethods = Get-AuthenticationMethods

$disabledAuthenticationMethods = $authenticationMethods | where { $_.State -eq "Disabled" }
$enabledAuthenticationMethods = $authenticationMethods | where { $_.State -eq "Enabled" }

$MethodsDisabledByPolicy = $AllMethods | Where { $_.AltName -in $disabledAuthenticationMethods.DisplayName }
$MethodsEnabledByPolicy = $AllMethods | Where { $_.AltName -in $enabledAuthenticationMethods.DisplayName }

$enabledWeakAuthenticationMethods = $MethodsEnabledByPolicy | where { $_.Strength -eq "Weak" }

$totalUsersCount = $userRegistrationsReport.Count

Write-output "Analyzing MFA info..."
$totalMFACapableUsers = $userRegistrationsReport | where { $_.isMfaCapable -eq $true }
$totalMFACapableUsersCount = $totalMFACapableUsers.Count

$MfaCapablePercentage = 0
if ($totalUsersCount -gt 0) {
    $MfaCapablePercentage = [math]::Round(($totalMFACapableUsersCount / $totalUsersCount) * 100, 2)
}

Write-output "Analyzing passwordless info..."
$totalPasswordlessUsers = $userRegistrationsReport | where { $_.isPasswordlessCapable -eq $true }
$totalPasswordlessUsersCount = $totalPasswordlessUsers.Count

$passwordlessCapablePercentage = 0
if ($totalUsersCount -gt 0) {
    $passwordlessCapablePercentage = [math]::Round(($totalPasswordlessUsersCount / $totalUsersCount) * 100, 2)
}

Write-output "Analyzing users who have registered strong authentication methods..."
$usersWithStrongMethods = $userRegistrationsReport | Where-Object {
    $user = $_
    if ($user.methodsRegistered) {
        foreach ($method in $user.methodsRegistered) {
            if ($strongMethodTypes -contains $method) {
                return $true
            }
        }
    }
    return $false
}

$totalStrongAuthUsersCount = $usersWithStrongMethods.Count
$strongAuthPercentage = 0
if ($totalUsersCount -gt 0) {
    $strongAuthPercentage = [math]::Round(($totalStrongAuthUsersCount / $totalUsersCount) * 100, 2)
}

Write-output "Analyzing users who have ONLY weak authentication methods registered..."
$usersWithWeakMethods = $userRegistrationsReport | Where-Object {
    $user = $_
    if ($user.methodsRegistered) {
        foreach ($method in $user.methodsRegistered) {
            if ($weakMethodTypes.type -contains $method) {
                return $true
            }
        }
    }
    return $false
}

Write-output "Analyzing users with both strong AND weak methods..."
$usersWithBothMethodTypes = $usersWithStrongMethods | Where-Object {
    $user = $_
    $usersWithWeakMethods.userPrincipalName -contains $user.userPrincipalName
}

$totalBothMethodTypesCount = $usersWithBothMethodTypes.Count
$bothMethodsPercentage = 0
if ($totalUsersCount -gt 0) {
    $bothMethodsPercentage = [math]::Round(($totalBothMethodTypesCount / $totalUsersCount) * 100, 2)
}

Write-output "Analyzing privileged users not using phish resistant methods..."
$PrivilegedUsersRegistrationDetails = Get-PrivilegedUserRegistrationDetails -userRegistrations $userRegistrationsReport
$PrivilegedUsersNotUsingPhishResistantMethods = $PrivilegedUsersRegistrationDetails | where { $_.methodsRegistered -notcontains "fido2SecurityKey" -and $_.methodsRegistered -notcontains "passKeyDeviceBound" -and $_.methodsRegistered -notcontains "passKeyDeviceBoundAuthenticator" }

$PrivilegedUsersNotUsingPhishResistantMethodsCount = $PrivilegedUsersNotUsingPhishResistantMethods.Count

Write-output "Generating HTML report..."
Function Generate-EntraAuthReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserRegistrations,

        [Parameter(Mandatory = $true)]
        [array]$MethodTypes,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\GitHub\Private\Reports\EntraAuthenticationReport.html"
    )

    $html = [System.Text.StringBuilder]::new()

    [void]$html.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Entra Authentication Methods Report</title>
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
            max-width: 1200px;
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
            margin-top: 0px;
            margin-bottom: 10px;
            opacity: 0.9;
        }
        .author-info {
            margin-top: 12px;
            border-top: 1px solid rgba(255, 255, 255, 0.3);
            padding-top: 10px;
            display: flex;
            align-items: center;
            font-size: 13px;
        }
        .author-label {
            opacity: 0.8;
            margin-right: 6px;
        }
        .author-links {
            display: flex;
            align-items: center;
        }
        .author-link {
            color: white;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.5);
            padding: 4px 10px;
            border-radius: 4px;
            margin-right: 10px;
            transition: all 0.2s ease;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .author-link:hover {
            background-color: rgba(255, 255, 255, 0.2);
            border-color: rgba(255, 255, 255, 0.7);
        }
        .author-link svg {
            margin-right: 5px;
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
        .progress-container {
            width: 100%;
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            box-sizing: border-box;
        }
        .progress-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #333;
        }
        .progress-bar-container {
            height: 30px;
            width: 100%;
            background-color: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
            border-radius: 15px;
            transition: width 1s ease-in-out;
        }
        .progress-text {
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
        }
        .progress-info {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 14px;
            color: #666;
        }
        .progress-legend {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            margin-top: 15px;
            gap: 20px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            font-size: 13px;
        }
        .legend-color {
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border-radius: 2px;
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
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: none;
            margin-bottom: 0;
            table-layout: fixed;
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

        th.diagonal-header::after {
            content: '';
        }

        th.diagonal-header {
            text-align: center;
            min-width: 90px;
            padding: 12px 8px;
        }

        th.diagonal-header > div {
            font-size: 10px;
            padding: 0;
            white-space: normal;
            word-break: break-word;
            line-height: 1.3;
        }

        th.strong-method {
            background: linear-gradient(135deg, #27ae60, #229954);
        }

        th.weak-method {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
        }
        td {
            padding: 10px 15px;
            border-bottom: 1px solid #eee;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            text-align: center;
        }
        td:first-child {
            text-align: left;
        }
        tr:last-child td {
            border-bottom: none;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tbody tr:hover {
            background-color: #fff5f5;
        }
        .table-container {
            width: 100%;
            overflow-x: auto;
            margin-bottom: 30px;
            margin-left: 0;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            position: relative;
        }

        .expand-icon {
            padding: 8px 15px;
            background-color: #eee;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-left: auto;
        }

        .expand-icon:hover {
            background-color: #ddd;
        }

        .expand-icon svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
        }

        td[title], th[title] {
            cursor: pointer;
        }

        @media (max-width: 768px) {
            .table-container {
                margin-bottom: 20px;
            }
        }
        .method-registered {
            color: #107C10;
            text-align: center;
            font-weight: bold;
        }
        .method-not-registered {
            color: #D83B01;
            text-align: center;
        }
        .strong-method {
            background-color:#57A773;
        }
        .weak-method {
            background-color: #EE6352;
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
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
        }
        .checkmark {
            color: #0a5a0a;
            font-size: 18px;
            font-weight: bold;
        }
        .x-mark {
            color: #b92e02;
            font-size: 18px;
            font-weight: bold;
        }
        .switch-container {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        .switch {
            position: relative;
            display: inline-block;
            width: 60px;
            height: 30px;
            margin-right: 10px;
        }
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 30px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 22px;
            width: 22px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background-color: #c0392b;
        }
        input:checked + .slider:before {
            transform: translateX(30px);
        }
        .switch-label {
            font-size: 14px;
        }
        .hide-disabled-btn {
            display: none;
        }
        .switches-group {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        [data-syncuser='true'] {
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            overflow: auto;
        }

        .modal-content {
            background-color: white;
            margin: 2% auto;
            padding: 20px;
            width: 95%;
            max-width: none;
            border-radius: 8px;
            position: relative;
        }

        .close-modal {
            color: #666;
            position: absolute;
            top: 15px;
            right: 15px;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            z-index: 1001;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background-color: #f0f0f0;
            transition: all 0.2s ease;
        }

        .close-modal:hover {
            background: #e74c3c;
            color: white;
        }

        .fullscreen-table-container {
            width: 100%;
            overflow-x: auto;
        }

        .fullscreen-table-container table {
            width: 100%;
            table-layout: auto;
        }

        .fullscreen-table-container th,
        .fullscreen-table-container td {
            white-space: normal;
        }

        body.modal-open {
            overflow: hidden;
        }

        .export-csv-button {
            padding: 8px 15px;
            background-color: #eee;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-left: auto;
            margin-right: 10px;
        }

        .export-csv-button:hover, .expand-icon:hover {
            background: #e74c3c;
            color: white;
            border-color: #e74c3c;
        }

        .export-csv-button svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
        }

        .expand-icon {
            margin-left: 0;
        }

        .button-group {
            margin-left: auto;
            display: flex;
        }

        .filter-container {
            display: flex;
            margin-bottom: 20px;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js"></script>
</head>
<body>
   <div class="header-container">
    <div class="header-content">
        <div>
            <h1>Microsoft Entra Authentication Methods Report</h1>
            <div class="header-subtitle">Overview of authentication methods registered by users</div>
        </div>
        <div class="report-info">
            <div class="report-date">Generated: $(Get-Date -Format "MMMM d, yyyy")</div>
            <div class="tenant">Org: $organisationName</div>
        </div>
    </div>
</div>
    <div class="content-container">
        <div class="progress-container" style="max-width: 100%; margin-bottom: 30px;">
            <div class="progress-title">Progress Towards Passwordless Authentication</div>
            <div class="progress-bar-container">
                <div class="progress-bar" style="width: $($passwordlessCapablePercentage)%"></div>
                <div class="progress-text">$passwordlessCapablePercentage% Complete</div>
            </div>
            <div class="progress-info">
                <span>0%</span>
                <span>Target: 100% of users passwordless capable</span>
                <span>100%</span>
            </div>
            <div class="progress-legend">
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #57A773;"></div>
                    <span>$totalPasswordlessUsersCount users passwordless capable</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #e0e0e0;"></div>
                    <span>$($totalUsersCount - $totalPasswordlessUsersCount) users still need passwordless capability</span>
                </div>
            </div>
        </div>

        <div class="summary-stats">
            <div class="stat-card">
                <div class="stat-title">Total Users</div>
                <div class="stat-value">$totalUsersCount</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">MFA Capable Users</div>
                <div class="stat-value">$totalMFACapableUsersCount</div>
                <div class="stat-percentage">$MfaCapablePercentage% of users</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Strong Auth Methods</div>
                <div class="stat-value">$totalStrongAuthUsersCount</div>
                <div class="stat-percentage">$strongAuthPercentage% of users</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Passwordless Capable</div>
                <div class="stat-value">$totalPasswordlessUsersCount</div>
                <div class="stat-percentage">$passwordlessCapablePercentage% of users</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Strong + Weak Auth</div>
                <div class="stat-value">$totalBothMethodTypesCount</div>
                <div class="stat-percentage">$bothMethodsPercentage% of users</div>
            </div>
        </div>

        <div class="search-container">
            <input type="text" id="searchBox" placeholder="Search for a user..." onkeyup="searchTable()">
        </div>

        <div class="switches-group">
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideDisabledSwitch" onchange="toggleDisabledMethods()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide Disabled Authentication Methods</span>
            </div>

            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideMfaCapableSwitch" onchange="toggleMfaCapableUsers()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide MFA Capable Users</span>
            </div>

            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideETXUsersSwitch" onchange="toggleETXUsers()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide External Users</span>
            </div>

            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideSyncUsersSwitch" onchange="toggleSyncUsers()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide Sync_ Account</span>
            </div>
        </div>

        <div class="filter-container">
            <button class="filter-button active" onclick="filterTable('all')">All Users</button>
            <button class="filter-button" onclick="filterTable('privileged')">Privileged Users</button>
            <button class="filter-button" onclick="filterTable('passwordless')">Passwordless Capable</button>
            <button class="filter-button" onclick="filterTable('strong')">Strong Methods</button>
            <button class="filter-button" onclick="filterTable('mixed')">Strong+Weak Methods</button>
            <button class="filter-button" onclick="filterTable('weak')">Weak Methods Only</button>
            <div class="button-group">
                <button class="export-csv-button" onclick="exportTableToCSV()" title="Export table to CSV file">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Export CSV
                </button>
                <button class="expand-icon" onclick="openFullscreenTable()" title="Expand table to full screen">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path>
                    </svg>
                    Expand
                </button>
            </div>
        </div>

        <div class="table-container">
            <table id="authMethodsTable">
                <thead>
                    <tr>
                        <th style="width: 14%;">User Principal Name</th>
                        <th style="width: 7%;">Default Method</th>
                        <th style="width: 5%;">MFA</th>
                        <th style="width: 5%;">Pless</th>
"@)

    foreach ($method in $MethodTypes) {
        $cssClass = if ($method.Strength -eq "Strong") { "strong-method" } else { "weak-method" }

        $isDisabled = $MethodsDisabledByPolicy.Name -contains $method.Name

        if ($isDisabled) {
            [void]$html.AppendLine("                    <th class=`"$cssClass diagonal-header`" data-disabled=`"true`"><div>$($method.Name)</div></th>`n")
        }
        else {
            [void]$html.AppendLine("                    <th class=`"$cssClass diagonal-header`" ><div>$($method.Name)</div></th>`n")
        }
    }

    [void]$html.AppendLine(@"
                </tr>
            </thead>
            <tbody>
"@)

    for ($i = 0; $i -lt $UserRegistrations.Count; $i++) {
        $user = $UserRegistrations[$i]

        $userMethods = $user.methodsRegistered
        $userHasStrong = $false
        $userHasWeak = $false
        $isPrivileged = $false
        $isSyncUser = $false

        foreach ($method in $userMethods) {
            if ($strongMethodTypes -contains $method) {
                $userHasStrong = $true
            }
            if ($weakMethodTypes.type -contains $method) {
                $userHasWeak = $true
            }
        }

        if ($PrivilegedUsersRegistrationDetails.userPrincipalName -contains $user.userPrincipalName) {
            $isPrivileged = $true
        }

        if (($user.userPrincipalName -like "Sync_*") -or ($user.userPrincipalName -like "ADToAADSyncServiceAccount*")) {
            $isSyncUser = $true
        }

        $dataAttributes = ""
        if ($userHasStrong) { $dataAttributes += "data-hasstrong='true' " }
        if ($userHasWeak -and -not $userHasStrong) { $dataAttributes += "data-weakonly='true' " }
        if ($userHasStrong -and $userHasWeak) { $dataAttributes += "data-mixed='true' " }
        if ($user.isPasswordlessCapable) { $dataAttributes += "data-passwordless='true' " }
        if ($user.isMfaCapable) { $dataAttributes += "data-mfacapable='true' " }
        if ($user.userPrincipalName -like "*#EXT#*") { $dataAttributes += "data-externaluser='true' " }
        if ($isPrivileged) { $dataAttributes += "data-privileged='true' " }
        if ($isSyncUser) { $dataAttributes += "data-syncuser='true' " }

        [void]$html.AppendLine("                <tr $dataAttributes>`n")
        [void]$html.AppendLine("                    <td>$($user.userPrincipalName)</td>`n")
        [void]$html.AppendLine("                    <td>$($user.defaultmfaMethod)</td>`n")
        [void]$html.AppendLine("                    <td>$(if($user.isMfaCapable) {"<span class='checkmark'>✓</span>"} else {"<span class='x-mark'>✗</span>"})</td>`n")
        [void]$html.AppendLine("                    <td>$(if($user.isPasswordlessCapable) {"<span class='checkmark'>✓</span>"} else {"<span class='x-mark'>✗</span>"})</td>`n")

        foreach ($method in $MethodTypes) {
            $isRegistered = $userMethods -contains $method.type
            [void]$html.AppendLine("                    <td>$(if($isRegistered) {"<span class='checkmark'>✓</span>"} else {"<span class='x-mark'>✗</span>"})</td>`n")
        }

        [void]$html.AppendLine("                </tr>`n")
    }

    [void]$html.AppendLine(@"
            </tbody>
        </table>
    </div>

    <div id="tableModal" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeFullscreenTable()">&times;</span>
            <h2>Authentication Methods - Expanded View</h2>
            <div class="fullscreen-table-container">
            </div>
        </div>
    </div>

    <div class="footer">
        <p>Authentication Methods report generated via Microsoft Graph API | $organisationName</p>
    </div>

    <script>
        let totalUsers = $totalUsersCount;
        let mfaCapableUsers = $totalMFACapableUsersCount;
        let strongAuthUsers = $totalStrongAuthUsersCount;
        let passwordlessUsers = $totalPasswordlessUsersCount;
        let mixedAuthUsers = $totalBothMethodTypesCount;

        let externalUserCounts = {
            total: 0,
            mfaCapable: 0,
            strongAuth: 0,
            passwordless: 0,
            mixedAuth: 0
        };

        let syncUserCounts = {
            total: 0,
            mfaCapable: 0,
            strongAuth: 0,
            passwordless: 0,
            mixedAuth: 0
        };

        document.addEventListener('DOMContentLoaded', function() {
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                if (row.hasAttribute('data-externaluser')) {
                    externalUserCounts.total++;
                    if (row.hasAttribute('data-mfacapable')) externalUserCounts.mfaCapable++;
                    if (row.hasAttribute('data-hasstrong')) externalUserCounts.strongAuth++;
                    if (row.hasAttribute('data-passwordless')) externalUserCounts.passwordless++;
                    if (row.hasAttribute('data-mixed')) externalUserCounts.mixedAuth++;
                }

                if (row.hasAttribute('data-syncuser')) {
                    syncUserCounts.total++;
                    if (row.hasAttribute('data-mfacapable')) syncUserCounts.mfaCapable++;
                    if (row.hasAttribute('data-hasstrong')) syncUserCounts.strongAuth++;
                    if (row.hasAttribute('data-passwordless')) syncUserCounts.passwordless++;
                    if (row.hasAttribute('data-mixed')) syncUserCounts.mixedAuth++;
                }
            }
        });

        function updateSummaryStats(hideExternal, hideSync) {
            let adjustedTotal = totalUsers;
            let adjustedMfa = mfaCapableUsers;
            let adjustedStrong = strongAuthUsers;
            let adjustedPasswordless = passwordlessUsers;
            let adjustedMixed = mixedAuthUsers;

            if (hideExternal) {
                adjustedTotal -= externalUserCounts.total;
                adjustedMfa -= externalUserCounts.mfaCapable;
                adjustedStrong -= externalUserCounts.strongAuth;
                adjustedPasswordless -= externalUserCounts.passwordless;
                adjustedMixed -= externalUserCounts.mixedAuth;
            }

            if (hideSync) {
                adjustedTotal -= syncUserCounts.total;
                adjustedMfa -= syncUserCounts.mfaCapable;
                adjustedStrong -= syncUserCounts.strongAuth;
                adjustedPasswordless -= syncUserCounts.passwordless;
                adjustedMixed -= syncUserCounts.mixedAuth;
            }

            const mfaPercentage = adjustedTotal > 0 ? Math.round((adjustedMfa / adjustedTotal) * 100 * 100) / 100 : 0;
            const strongPercentage = adjustedTotal > 0 ? Math.round((adjustedStrong / adjustedTotal) * 100 * 100) / 100 : 0;
            const passwordlessPercentage = adjustedTotal > 0 ? Math.round((adjustedPasswordless / adjustedTotal) * 100 * 100) / 100 : 0;
            const mixedPercentage = adjustedTotal > 0 ? Math.round((adjustedMixed / adjustedTotal) * 100 * 100) / 100 : 0;

            document.querySelector('.stat-card:nth-child(1) .stat-value').textContent = adjustedTotal;

            document.querySelector('.stat-card:nth-child(2) .stat-value').textContent = adjustedMfa;
            document.querySelector('.stat-card:nth-child(2) .stat-percentage').textContent = mfaPercentage + '% of users';

            document.querySelector('.stat-card:nth-child(3) .stat-value').textContent = adjustedStrong;
            document.querySelector('.stat-card:nth-child(3) .stat-percentage').textContent = strongPercentage + '% of users';

            document.querySelector('.stat-card:nth-child(4) .stat-value').textContent = adjustedPasswordless;
            document.querySelector('.stat-card:nth-child(4) .stat-percentage').textContent = passwordlessPercentage + '% of users';

            document.querySelector('.stat-card:nth-child(5) .stat-value').textContent = adjustedMixed;
            document.querySelector('.stat-card:nth-child(5) .stat-percentage').textContent = mixedPercentage + '% of users';

            const progressBar = document.querySelector('.progress-bar');
            const progressText = document.querySelector('.progress-text');
            const passwordlessLegend = document.querySelector('.legend-item:first-child span');
            const nonPasswordlessLegend = document.querySelector('.legend-item:last-child span');

            progressBar.style.width = passwordlessPercentage + '%';
            progressText.textContent = passwordlessPercentage + '% Complete';
            passwordlessLegend.textContent = adjustedPasswordless + ' users passwordless capable';
            nonPasswordlessLegend.textContent = (adjustedTotal - adjustedPasswordless) + ' users still need passwordless capability';
        }

        function searchTable() {
            const input = document.getElementById('searchBox');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('authMethodsTable');
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

        let currentPresetFilter = 'all';

        function filterTable(filterType) {
            const buttons = document.querySelectorAll('.filter-button');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            currentPresetFilter = filterType;
            applyAllFilters();
        }

        function applyAllFilters() {
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');

            const hideMfaCapable = document.getElementById('hideMfaCapableSwitch')?.checked || false;
            const hideExternal = document.getElementById('hideETXUsersSwitch')?.checked || false;
            const hideSync = document.getElementById('hideSyncUsersSwitch')?.checked || false;

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                let show = true;

                if (hideMfaCapable && row.hasAttribute('data-mfacapable')) {
                    show = false;
                }
                if (hideExternal && row.hasAttribute('data-externaluser')) {
                    show = false;
                }
                if (hideSync && row.hasAttribute('data-syncuser')) {
                    show = false;
                }

                if (show && currentPresetFilter !== 'all') {
                    if (currentPresetFilter === 'strong' && !row.hasAttribute('data-hasstrong')) {
                        show = false;
                    } else if (currentPresetFilter === 'weak' && !row.hasAttribute('data-weakonly')) {
                        show = false;
                    } else if (currentPresetFilter === 'passwordless' && !row.hasAttribute('data-passwordless')) {
                        show = false;
                    } else if (currentPresetFilter === 'mixed' && !row.hasAttribute('data-mixed')) {
                        show = false;
                    } else if (currentPresetFilter === 'privileged' && !row.hasAttribute('data-privileged')) {
                        show = false;
                    }
                }

                row.style.display = show ? '' : 'none';
            }
        }

        function toggleDisabledMethods() {
            const switchElem = document.getElementById('hideDisabledSwitch');
            const isHiding = switchElem.checked;

            const table = document.getElementById('authMethodsTable');
            const headers = table.getElementsByTagName('th');

            for (let i = 0; i < headers.length; i++) {
                if (headers[i].hasAttribute('data-disabled')) {
                    headers[i].style.display = isHiding ? 'none' : '';

                    const rows = table.getElementsByTagName('tr');
                    for (let j = 1; j < rows.length; j++) {
                        const cells = rows[j].getElementsByTagName('td');
                        if (i < cells.length) {
                            cells[i].style.display = isHiding ? 'none' : '';
                        }
                    }
                }
            }
        }

        function toggleMfaCapableUsers() {
            applyAllFilters();
        }

        function toggleETXUsers() {
            const isHiding = document.getElementById('hideETXUsersSwitch')?.checked || false;
            const hidingSync = document.getElementById('hideSyncUsersSwitch')?.checked || false;

            applyAllFilters();
            updateSummaryStats(isHiding, hidingSync);
        }

        function toggleSyncUsers() {
            const isHiding = document.getElementById('hideSyncUsersSwitch')?.checked || false;
            const hidingExt = document.getElementById('hideETXUsersSwitch')?.checked || false;

            applyAllFilters();
            updateSummaryStats(hidingExt, isHiding);
        }

        function openFullscreenTable() {
            const modal = document.getElementById('tableModal');
            const originalTable = document.getElementById('authMethodsTable');
            const fullscreenContainer = document.querySelector('.fullscreen-table-container');

            const clonedTable = originalTable.cloneNode(true);
            clonedTable.id = 'fullscreenTable';

            fullscreenContainer.innerHTML = '';
            fullscreenContainer.appendChild(clonedTable);

            modal.style.display = 'block';
            document.body.classList.add('modal-open');

            applyActiveFiltersToFullscreenTable();
        }

        function closeFullscreenTable() {
            const modal = document.getElementById('tableModal');
            modal.style.display = 'none';
            document.body.classList.remove('modal-open');
        }

        function applyActiveFiltersToFullscreenTable() {
            const originalTable = document.getElementById('authMethodsTable');
            const fullscreenTable = document.getElementById('fullscreenTable');

            if (!originalTable || !fullscreenTable) return;

            const originalRows = originalTable.getElementsByTagName('tr');
            const fullscreenRows = fullscreenTable.getElementsByTagName('tr');

            for (let i = 1; i < originalRows.length && i < fullscreenRows.length; i++) {
                fullscreenRows[i].style.display = originalRows[i].style.display;
            }

            const originalHeaders = originalTable.querySelectorAll('th');
            const fullscreenHeaders = fullscreenTable.querySelectorAll('th');

            for (let i = 0; i < originalHeaders.length && i < fullscreenHeaders.length; i++) {
                if (originalHeaders[i].style.display === 'none') {
                    fullscreenHeaders[i].style.display = 'none';

                    for (let j = 1; j < fullscreenRows.length; j++) {
                        const cells = fullscreenRows[j].getElementsByTagName('td');
                        if (i < cells.length) {
                            cells[i].style.display = 'none';
                        }
                    }
                }
            }
        }

        window.onclick = function(event) {
            const modal = document.getElementById('tableModal');
            if (event.target === modal) {
                closeFullscreenTable();
            }
        }

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape' || event.keyCode === 27) {
                closeFullscreenTable();
            }
        });

        function exportTableToCSV() {
            let csvContent = [];

            const table = document.getElementById('authMethodsTable');
            const headerRow = table.querySelector('thead tr');
            const headerCells = headerRow.querySelectorAll('th');

            let headerCsvRow = [];
            for (let i = 0; i < headerCells.length; i++) {
                if (headerCells[i].style.display !== 'none') {
                    let cellText = headerCells[i].textContent.trim();
                    cellText = cellText.replace(/"/g, '""');
                    headerCsvRow.push('"' + cellText + '"');
                }
            }
            csvContent.push(headerCsvRow.join(','));

            const dataRows = table.querySelectorAll('tbody tr');
            for (let i = 0; i < dataRows.length; i++) {
                if (dataRows[i].style.display === 'none') continue;

                let csvRow = [];
                const cells = dataRows[i].querySelectorAll('td');

                for (let j = 0; j < cells.length; j++) {
                    if (cells[j].style.display === 'none') continue;

                    let cellText = cells[j].textContent.trim();
                    if (cellText === '✓') cellText = 'Yes';
                    if (cellText === '✗') cellText = 'No';

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
            downloadLink.setAttribute('download', 'Entra_Auth_Methods_Report_' + date + '.csv');
            document.body.appendChild(downloadLink);

            downloadLink.click();
            document.body.removeChild(downloadLink);
        }

        document.addEventListener('DOMContentLoaded', function() {
            const headers = document.querySelectorAll('#authMethodsTable thead th');
            headers.forEach((header, index) => {
                header.addEventListener('click', () => sortTable(index));
                header.style.cursor = 'pointer';
            });
        });

        function sortTable(columnIndex) {
            const table = document.getElementById('authMethodsTable');
            if (!table) return;

            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr')).filter(row => row.style.display !== 'none');
            const headers = table.querySelectorAll('thead th');
            const header = headers[columnIndex];

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

    </script>
</body>
</html>
"@)

    $OutputPath = Join-Path -Path $outpath -ChildPath "Entra_Authentication_Methods_Report.html"

    $html.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-output "HTML report generated at $OutputPath"

    if ($openBrowser) {
        Start-Process $OutputPath
    }
}

Generate-EntraAuthReport -UserRegistrations $userRegistrationsReport -MethodTypes $AllMethods -OutputPath $OutputPath
