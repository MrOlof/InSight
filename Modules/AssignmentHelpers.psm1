# AssignmentHelpers.psm1
# Author: Kosta Wadenfalk
# GitHub: https://github.com/MrOlof

function Get-GroupAssignments {
    <#
    .SYNOPSIS
        Gets all Intune policy and app assignments for a specific group
    .PARAMETER GroupId
        The Azure AD group ID (GUID)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $assignments = @()

    try {
        Write-LogDebug -Message "Fetching all policy types for group: $GroupId" -Source 'Assignments'

        # Define all policy types to check
        $policyTypes = @(
            @{ Name = "Device Configuration"; Endpoint = "deviceManagement/deviceConfigurations" }
            @{ Name = "Settings Catalog"; Endpoint = "deviceManagement/configurationPolicies" }
            @{ Name = "Compliance Policy"; Endpoint = "deviceManagement/deviceCompliancePolicies" }
            @{ Name = "App Configuration"; Endpoint = "deviceAppManagement/mobileAppConfigurations" }
            @{ Name = "App Protection (iOS)"; Endpoint = "deviceAppManagement/iosManagedAppProtections" }
            @{ Name = "App Protection (Android)"; Endpoint = "deviceAppManagement/androidManagedAppProtections" }
            @{ Name = "Endpoint Security (Antivirus)"; Endpoint = "deviceManagement/intents" }
            @{ Name = "Update Rings"; Endpoint = "deviceManagement/deviceManagementScripts" }
        )

        foreach ($policyType in $policyTypes) {
            try {
                $uri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)"
                $policies = Invoke-GraphRequest -Uri $uri -Method GET

                if ($policies.value) {
                    foreach ($policy in $policies.value) {
                        # Get assignments for this policy
                        $assignmentsUri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)('$($policy.id)')/assignments"

                        try {
                            $policyAssignments = Invoke-GraphRequest -Uri $assignmentsUri -Method GET

                            if ($policyAssignments.value) {
                                foreach ($assignment in $policyAssignments.value) {
                                    # Check if this assignment targets our group
                                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                                        $assignment.target.groupId -eq $GroupId) {

                                        # Handle blank names - use displayName, then name, then fallback
                                        $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) {
                                            $policy.displayName
                                        } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) {
                                            $policy.name
                                        } else {
                                            "Unnamed $($policyType.Name) ($($policy.id.Substring(0,8))...)"
                                        }

                                        $assignments += [PSCustomObject]@{
                                            Type = $policyType.Name
                                            Name = $policyName
                                            Id = $policy.id
                                            Intent = if ($assignment.intent) { $assignment.intent } else { "Assign" }
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-LogDebug -Message "Could not fetch assignments for $($policy.displayName): $_" -Source 'Assignments'
                        }
                    }
                }
            }
            catch {
                Write-LogWarning -Message "Error fetching $($policyType.Name): $_" -Source 'Assignments'
            }
        }

        # Check managed apps
        try {
            $appsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
            $apps = Invoke-GraphRequest -Uri $appsUri -Method GET

            if ($apps.value) {
                foreach ($app in $apps.value) {
                    try {
                        $appAssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/assignments"
                        $appAssignments = Invoke-GraphRequest -Uri $appAssignmentsUri -Method GET

                        if ($appAssignments.value) {
                            foreach ($assignment in $appAssignments.value) {
                                if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                                    $assignment.target.groupId -eq $GroupId) {

                                    $assignments += [PSCustomObject]@{
                                        Type = "Application"
                                        Name = $app.displayName
                                        Id = $app.id
                                        Intent = $assignment.intent
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-LogDebug -Message "Could not fetch app assignments for $($app.displayName): $_" -Source 'Assignments'
                    }
                }
            }
        }
        catch {
            Write-LogWarning -Message "Error fetching applications: $_" -Source 'Assignments'
        }

        Write-LogInfo -Message "Found $($assignments.Count) assignments for group $GroupId" -Source 'Assignments'
        return $assignments
    }
    catch {
        Write-LogError -Message "Error in Get-GroupAssignments: $_" -Source 'Assignments'
        throw
    }
}

function Find-OrphanedAssignments {
    <#
    .SYNOPSIS
        Finds policies and apps with no assignments or assigned to empty groups
    #>

    $noAssignments = @()
    $emptyGroupAssignments = @()

    try {
        Write-LogInfo -Message "Scanning for orphaned assignments..." -Source 'Assignments'

        # Define policy types to check
        $policyTypes = @(
            @{ Name = "Device Configuration"; Endpoint = "deviceManagement/deviceConfigurations" }
            @{ Name = "Settings Catalog"; Endpoint = "deviceManagement/configurationPolicies" }
            @{ Name = "Compliance Policy"; Endpoint = "deviceManagement/deviceCompliancePolicies" }
            @{ Name = "App Configuration"; Endpoint = "deviceAppManagement/mobileAppConfigurations" }
        )

        foreach ($policyType in $policyTypes) {
            try {
                $uri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)"
                $policies = Invoke-GraphRequest -Uri $uri -Method GET

                if ($policies.value) {
                    foreach ($policy in $policies.value) {
                        $assignmentsUri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)('$($policy.id)')/assignments"

                        try {
                            $policyAssignments = Invoke-GraphRequest -Uri $assignmentsUri -Method GET

                            if (-not $policyAssignments.value -or $policyAssignments.value.Count -eq 0) {
                                # No assignments
                                $noAssignments += [PSCustomObject]@{
                                    Type = $policyType.Name
                                    Name = if ($policy.displayName) { $policy.displayName } else { $policy.name }
                                    Id = $policy.id
                                }
                            }
                            else {
                                # Check if assigned to empty groups
                                foreach ($assignment in $policyAssignments.value) {
                                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                                        $groupId = $assignment.target.groupId

                                        # Check if group has members
                                        try {
                                            $groupMembersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members/`$count"
                                            $memberCount = Invoke-GraphRequest -Uri $groupMembersUri -Method GET -ConsistencyLevel 'eventual'

                                            if ($memberCount -eq 0) {
                                                # Get group name
                                                $groupUri = "https://graph.microsoft.com/v1.0/groups/$groupId"
                                                $group = Invoke-GraphRequest -Uri $groupUri -Method GET

                                                $emptyGroupAssignments += [PSCustomObject]@{
                                                    Type = $policyType.Name
                                                    Name = if ($policy.displayName) { $policy.displayName } else { $policy.name }
                                                    Id = $policy.id
                                                    GroupId = $groupId
                                                    GroupName = $group.displayName
                                                }
                                            }
                                        }
                                        catch {
                                            Write-LogDebug -Message "Could not check group $groupId members: $_" -Source 'Assignments'
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-LogDebug -Message "Could not fetch assignments for $($policy.displayName): $_" -Source 'Assignments'
                        }
                    }
                }
            }
            catch {
                Write-LogWarning -Message "Error checking $($policyType.Name): $_" -Source 'Assignments'
            }
        }

        $results = @{
            NoAssignments = $noAssignments
            EmptyGroups = $emptyGroupAssignments
            TotalOrphaned = $noAssignments.Count + $emptyGroupAssignments.Count
        }

        Write-LogInfo -Message "Orphaned scan complete. No Assignments: $($noAssignments.Count), Empty Groups: $($emptyGroupAssignments.Count)" -Source 'Assignments'
        return $results
    }
    catch {
        Write-LogError -Message "Error in Find-OrphanedAssignments: $_" -Source 'Assignments'
        throw
    }
}

function Show-AssignmentResults {
    <#
    .SYNOPSIS
        Shows a modern dialog with detailed assignment results
    .PARAMETER GroupName
        Name of the group
    .PARAMETER Assignments
        Array of assignments
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [array]$Assignments
    )

    # Create WPF Window
    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Assignment Results - $GroupName"
        Width="900" Height="600"
        WindowStartupLocation="CenterScreen"
        Background="#F5F5F5">
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <StackPanel Grid.Row="0" Margin="0,0,0,20">
            <TextBlock Text="Assignment Results" FontSize="24" FontWeight="SemiBold" Foreground="#1F1F1F"/>
            <TextBlock Text="$GroupName" FontSize="16" Foreground="#666666" Margin="0,4,0,0"/>
        </StackPanel>

        <!-- Summary -->
        <Border Grid.Row="1" Background="White" BorderBrush="#E0E0E0" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,0,16">
            <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE946;" FontFamily="Segoe MDL2 Assets" FontSize="20" Foreground="#0078D4" VerticalAlignment="Center" Margin="0,0,12,0"/>
                <TextBlock FontSize="14" VerticalAlignment="Center">
                    <Run Text="Total Assignments Found:" FontWeight="SemiBold"/>
                    <Run Text="$($Assignments.Count)" FontWeight="Bold" Foreground="#0078D4"/>
                </TextBlock>
            </StackPanel>
        </Border>

        <!-- DataGrid -->
        <DataGrid Grid.Row="2" x:Name="AssignmentsDataGrid"
                  AutoGenerateColumns="False"
                  IsReadOnly="True"
                  CanUserAddRows="False"
                  CanUserDeleteRows="False"
                  SelectionMode="Extended"
                  GridLinesVisibility="None"
                  HeadersVisibility="Column"
                  AlternatingRowBackground="#F9F9F9"
                  Background="White"
                  BorderBrush="#E0E0E0"
                  BorderThickness="1"
                  RowHeight="36">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="200">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="FontWeight" Value="SemiBold"/>
                            <Setter Property="Foreground" Value="#0078D4"/>
                            <Setter Property="Padding" Value="12,0,0,0"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="*">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="Padding" Value="12,0,0,0"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Intent" Binding="{Binding Intent}" Width="120">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="Padding" Value="12,0,0,0"/>
                            <Setter Property="FontStyle" Value="Italic"/>
                            <Setter Property="Foreground" Value="#666666"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
            </DataGrid.Columns>
            <DataGrid.ColumnHeaderStyle>
                <Style TargetType="DataGridColumnHeader">
                    <Setter Property="Background" Value="#F5F5F5"/>
                    <Setter Property="Foreground" Value="#333333"/>
                    <Setter Property="FontWeight" Value="SemiBold"/>
                    <Setter Property="Padding" Value="12,8"/>
                    <Setter Property="BorderBrush" Value="#E0E0E0"/>
                    <Setter Property="BorderThickness" Value="0,0,0,2"/>
                </Style>
            </DataGrid.ColumnHeaderStyle>
        </DataGrid>

        <!-- Buttons -->
        <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
            <Button x:Name="ExportCSVButton" Content="Export to CSV" Padding="16,8" Margin="0,0,12,0" Background="#F5F5F5" BorderBrush="#CCCCCC" BorderThickness="1" Cursor="Hand">
                <Button.Style>
                    <Style TargetType="Button">
                        <Setter Property="Template">
                            <Setter.Value>
                                <ControlTemplate TargetType="Button">
                                    <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>
                                    <ControlTemplate.Triggers>
                                        <Trigger Property="IsMouseOver" Value="True">
                                            <Setter Property="Background" Value="#E8E8E8"/>
                                        </Trigger>
                                    </ControlTemplate.Triggers>
                                </ControlTemplate>
                            </Setter.Value>
                        </Setter>
                    </Style>
                </Button.Style>
            </Button>
            <Button x:Name="CloseButton" Content="Close" Padding="16,8" Background="#0078D4" Foreground="White" BorderThickness="0" Cursor="Hand">
                <Button.Style>
                    <Style TargetType="Button">
                        <Setter Property="Template">
                            <Setter.Value>
                                <ControlTemplate TargetType="Button">
                                    <Border Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>
                                    <ControlTemplate.Triggers>
                                        <Trigger Property="IsMouseOver" Value="True">
                                            <Setter Property="Background" Value="#005A9E"/>
                                        </Trigger>
                                    </ControlTemplate.Triggers>
                                </ControlTemplate>
                            </Setter.Value>
                        </Setter>
                    </Style>
                </Button.Style>
            </Button>
        </StackPanel>
    </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $dialog = [Windows.Markup.XamlReader]::Load($reader)

    # Get controls
    $dataGrid = $dialog.FindName('AssignmentsDataGrid')
    $exportButton = $dialog.FindName('ExportCSVButton')
    $closeButton = $dialog.FindName('CloseButton')

    # Populate DataGrid
    $dataGrid.ItemsSource = $Assignments

    # Export to CSV button
    $exportButton.Add_Click({
        try {
            $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
            $saveDialog.Filter = "CSV files (*.csv)|*.csv"
            $saveDialog.DefaultExt = ".csv"
            $saveDialog.FileName = "Assignments_$(($GroupName -replace '[^a-zA-Z0-9]', '_'))_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

            if ($saveDialog.ShowDialog()) {
                $Assignments | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.MessageBox]::Show("Assignments exported successfully to:`n$($saveDialog.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
        catch {
            [System.Windows.MessageBox]::Show("Error exporting to CSV: $($_.Exception.Message)", "Export Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })

    # Close button
    $closeButton.Add_Click({
        $dialog.Close()
    })

    # Show dialog
    $dialog.ShowDialog() | Out-Null
}

function Get-DeviceAssignments {
    <#
    .SYNOPSIS
        Gets all Intune policy and app assignments for a specific device based on its group memberships
    .PARAMETER DeviceName
        The device display name
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )

    try {
        Write-LogInfo -Message "Searching for device: $DeviceName" -Source 'Assignments'

        # Search for device
        $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$DeviceName'"
        $deviceResult = Invoke-GraphRequest -Uri $uri -Method GET

        if (-not $deviceResult.value -or $deviceResult.value.Count -eq 0) {
            Write-LogWarning -Message "Device not found: $DeviceName" -Source 'Assignments'
            return @{
                Found = $false
                DeviceName = $DeviceName
                Assignments = @()
            }
        }

        $device = $deviceResult.value[0]
        Write-LogInfo -Message "Found device: $($device.displayName) (ID: $($device.id))" -Source 'Assignments'

        # Get device's group memberships (transitive to include nested groups)
        $membershipUri = "https://graph.microsoft.com/v1.0/devices/$($device.id)/transitiveMemberOf"
        $memberships = Invoke-GraphRequest -Uri $membershipUri -Method GET

        if (-not $memberships.value -or $memberships.value.Count -eq 0) {
            Write-LogInfo -Message "Device is not a member of any groups" -Source 'Assignments'
            return @{
                Found = $true
                DeviceId = $device.id
                DeviceName = $device.displayName
                GroupCount = 0
                Assignments = @()
            }
        }

        Write-LogInfo -Message "Device is member of $($memberships.value.Count) groups, scanning policies once..." -Source 'Assignments'

        # Build hashtable of group IDs for fast lookup
        $groupIds = @{}
        foreach ($group in $memberships.value) {
            if ($group.'@odata.type' -eq '#microsoft.graph.group') {
                $groupIds[$group.id] = $true
            }
        }

        # Scan all policy types ONCE and check if assigned to any of the device's groups
        $allAssignments = @()
        $processedPolicies = @{}  # Track to avoid duplicates

        $policyTypes = @(
            @{ Name = "Device Configuration"; Endpoint = "deviceManagement/deviceConfigurations" }
            @{ Name = "Settings Catalog"; Endpoint = "deviceManagement/configurationPolicies" }
            @{ Name = "Compliance Policy"; Endpoint = "deviceManagement/deviceCompliancePolicies" }
            @{ Name = "App Configuration"; Endpoint = "deviceAppManagement/mobileAppConfigurations" }
            @{ Name = "App Protection (iOS)"; Endpoint = "deviceAppManagement/iosManagedAppProtections" }
            @{ Name = "App Protection (Android)"; Endpoint = "deviceAppManagement/androidManagedAppProtections" }
            @{ Name = "Endpoint Security (Antivirus)"; Endpoint = "deviceManagement/intents" }
            @{ Name = "Update Rings"; Endpoint = "deviceManagement/deviceManagementScripts" }
        )

        foreach ($policyType in $policyTypes) {
            try {
                $uri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)"
                $policies = Invoke-GraphRequest -Uri $uri -Method GET

                if ($policies.value) {
                    foreach ($policy in $policies.value) {
                        $assignmentsUri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)('$($policy.id)')/assignments"

                        try {
                            $policyAssignments = Invoke-GraphRequest -Uri $assignmentsUri -Method GET

                            if ($policyAssignments.value) {
                                foreach ($assignment in $policyAssignments.value) {
                                    # Check if assignment targets any of the device's groups
                                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                                        $groupIds.ContainsKey($assignment.target.groupId)) {

                                        $key = "$($policyType.Name)|$($policy.id)"
                                        if (-not $processedPolicies.ContainsKey($key)) {
                                            $processedPolicies[$key] = $true
                                            # Handle blank names - use displayName, then name, then fallback
                                            $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) {
                                                $policy.displayName
                                            } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) {
                                                $policy.name
                                            } else {
                                                "Unnamed $($policyType.Name) ($($policy.id.Substring(0,8))...)"
                                            }
                                            $allAssignments += [PSCustomObject]@{
                                                Type = $policyType.Name
                                                Name = $policyName
                                                Id = $policy.id
                                                Intent = if ($assignment.intent) { $assignment.intent } else { $null }
                                            }
                                            break  # Found a match for this policy, no need to check other assignments
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-LogDebug -Message "Could not get assignments for $($policyType.Name): $($policy.displayName)" -Source 'Assignments'
                        }
                    }
                }
            }
            catch {
                Write-LogWarning -Message "Error fetching $($policyType.Name): $_" -Source 'Assignments'
            }
        }

        Write-LogInfo -Message "Found $($allAssignments.Count) unique policy/app assignments for device" -Source 'Assignments'

        return @{
            Found = $true
            DeviceId = $device.id
            DeviceName = $device.displayName
            GroupCount = $groupIds.Count
            Assignments = $allAssignments
        }
    }
    catch {
        Write-LogError -Message "Error getting device assignments: $_" -Source 'Assignments'
        throw
    }
}

function Get-UserAssignments {
    <#
    .SYNOPSIS
        Gets all Intune policy and app assignments for a specific user based on their group memberships
    .PARAMETER UserPrincipalName
        The user's UPN (email address)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    try {
        Write-LogInfo -Message "Searching for user: $UserPrincipalName" -Source 'Assignments'

        # Get user by UPN
        $uri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
        try {
            $user = Invoke-GraphRequest -Uri $uri -Method GET
        }
        catch {
            Write-LogWarning -Message "User not found: $UserPrincipalName" -Source 'Assignments'
            return @{
                Found = $false
                UserPrincipalName = $UserPrincipalName
                Assignments = @()
            }
        }

        Write-LogInfo -Message "Found user: $($user.displayName) ($($user.userPrincipalName))" -Source 'Assignments'

        # Get user's group memberships (transitive to include nested groups)
        $membershipUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/transitiveMemberOf"
        $memberships = Invoke-GraphRequest -Uri $membershipUri -Method GET

        if (-not $memberships.value -or $memberships.value.Count -eq 0) {
            Write-LogInfo -Message "User is not a member of any groups" -Source 'Assignments'
            return @{
                Found = $true
                UserId = $user.id
                UserPrincipalName = $user.userPrincipalName
                DisplayName = $user.displayName
                GroupCount = 0
                Assignments = @()
            }
        }

        Write-LogInfo -Message "User is member of $($memberships.value.Count) groups, scanning policies once..." -Source 'Assignments'

        # Build hashtable of group IDs for fast lookup
        $groupIds = @{}
        foreach ($group in $memberships.value) {
            if ($group.'@odata.type' -eq '#microsoft.graph.group') {
                $groupIds[$group.id] = $true
            }
        }

        # Scan all policy types ONCE and check if assigned to any of the user's groups
        $allAssignments = @()
        $processedPolicies = @{}  # Track to avoid duplicates

        $policyTypes = @(
            @{ Name = "Device Configuration"; Endpoint = "deviceManagement/deviceConfigurations" }
            @{ Name = "Settings Catalog"; Endpoint = "deviceManagement/configurationPolicies" }
            @{ Name = "Compliance Policy"; Endpoint = "deviceManagement/deviceCompliancePolicies" }
            @{ Name = "App Configuration"; Endpoint = "deviceAppManagement/mobileAppConfigurations" }
            @{ Name = "App Protection (iOS)"; Endpoint = "deviceAppManagement/iosManagedAppProtections" }
            @{ Name = "App Protection (Android)"; Endpoint = "deviceAppManagement/androidManagedAppProtections" }
            @{ Name = "Endpoint Security (Antivirus)"; Endpoint = "deviceManagement/intents" }
            @{ Name = "Update Rings"; Endpoint = "deviceManagement/deviceManagementScripts" }
        )

        foreach ($policyType in $policyTypes) {
            try {
                $uri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)"
                $policies = Invoke-GraphRequest -Uri $uri -Method GET

                if ($policies.value) {
                    foreach ($policy in $policies.value) {
                        $assignmentsUri = "https://graph.microsoft.com/beta/$($policyType.Endpoint)('$($policy.id)')/assignments"

                        try {
                            $policyAssignments = Invoke-GraphRequest -Uri $assignmentsUri -Method GET

                            if ($policyAssignments.value) {
                                foreach ($assignment in $policyAssignments.value) {
                                    # Check if assignment targets any of the user's groups
                                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and
                                        $groupIds.ContainsKey($assignment.target.groupId)) {

                                        $key = "$($policyType.Name)|$($policy.id)"
                                        if (-not $processedPolicies.ContainsKey($key)) {
                                            $processedPolicies[$key] = $true
                                            # Handle blank names - use displayName, then name, then fallback
                                            $policyName = if (-not [string]::IsNullOrWhiteSpace($policy.displayName)) {
                                                $policy.displayName
                                            } elseif (-not [string]::IsNullOrWhiteSpace($policy.name)) {
                                                $policy.name
                                            } else {
                                                "Unnamed $($policyType.Name) ($($policy.id.Substring(0,8))...)"
                                            }
                                            $allAssignments += [PSCustomObject]@{
                                                Type = $policyType.Name
                                                Name = $policyName
                                                Id = $policy.id
                                                Intent = if ($assignment.intent) { $assignment.intent } else { $null }
                                            }
                                            break  # Found a match for this policy, no need to check other assignments
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-LogDebug -Message "Could not get assignments for $($policyType.Name): $($policy.displayName)" -Source 'Assignments'
                        }
                    }
                }
            }
            catch {
                Write-LogWarning -Message "Error fetching $($policyType.Name): $_" -Source 'Assignments'
            }
        }

        Write-LogInfo -Message "Found $($allAssignments.Count) unique policy/app assignments for user" -Source 'Assignments'

        return @{
            Found = $true
            UserId = $user.id
            UserPrincipalName = $user.userPrincipalName
            DisplayName = $user.displayName
            GroupCount = $groupIds.Count
            Assignments = $allAssignments
        }
    }
    catch {
        Write-LogError -Message "Error getting user assignments: $_" -Source 'Assignments'
        throw
    }
}

function Show-ModernNotification {
    <#
    .SYNOPSIS
        Shows a modern styled notification dialog
    .PARAMETER Title
        The title of the notification
    .PARAMETER Message
        The message to display
    .PARAMETER Icon
        Icon type: Info, Success, Warning, Error
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Icon = 'Info'
    )

    # Icon colors and symbols
    $iconConfig = @{
        'Info' = @{ Color = '#0078D4'; Symbol = '&#xE946;' }
        'Success' = @{ Color = '#107C10'; Symbol = '&#xE73E;' }
        'Warning' = @{ Color = '#FF8C00'; Symbol = '&#xE7BA;' }
        'Error' = @{ Color = '#D13438'; Symbol = '&#xE7BA;' }
    }

    $config = $iconConfig[$Icon]

    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$Title"
        Width="450"
        SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize"
        WindowStyle="None"
        AllowsTransparency="True"
        Background="Transparent">
    <Border Background="White" CornerRadius="8" BorderBrush="#E0E0E0" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect Color="#000000" Opacity="0.2" BlurRadius="10" ShadowDepth="2"/>
        </Border.Effect>
        <Grid Margin="24">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <Grid Grid.Row="0" Margin="0,0,0,16">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Column="0" Text="$($config.Symbol)" FontFamily="Segoe MDL2 Assets" FontSize="32" Foreground="$($config.Color)" VerticalAlignment="Center" Margin="0,0,16,0"/>
                <TextBlock Grid.Column="1" Text="$Title" FontSize="18" FontWeight="SemiBold" Foreground="#333333" VerticalAlignment="Center"/>
            </Grid>

            <TextBlock Grid.Row="1" Text="$Message" FontSize="14" Foreground="#666666" TextWrapping="Wrap" Margin="0,0,0,20"/>

            <Button Grid.Row="2" x:Name="OkButton" Content="OK" Padding="24,8" Background="#0078D4" Foreground="White" BorderThickness="0" HorizontalAlignment="Right" Cursor="Hand" FontSize="14">
                <Button.Style>
                    <Style TargetType="Button">
                        <Setter Property="Template">
                            <Setter.Value>
                                <ControlTemplate TargetType="Button">
                                    <Border Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>
                                    <ControlTemplate.Triggers>
                                        <Trigger Property="IsMouseOver" Value="True">
                                            <Setter Property="Background" Value="#005A9E"/>
                                        </Trigger>
                                    </ControlTemplate.Triggers>
                                </ControlTemplate>
                            </Setter.Value>
                        </Setter>
                    </Style>
                </Button.Style>
            </Button>
        </Grid>
    </Border>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $dialog = [Windows.Markup.XamlReader]::Load($reader)

    $okButton = $dialog.FindName('OkButton')
    $okButton.Add_Click({
        $dialog.Close()
    })

    $dialog.ShowDialog() | Out-Null
}

# Export functions
Export-ModuleMember -Function Get-GroupAssignments, Find-OrphanedAssignments, Show-AssignmentResults, Get-DeviceAssignments, Get-UserAssignments, Show-ModernNotification
