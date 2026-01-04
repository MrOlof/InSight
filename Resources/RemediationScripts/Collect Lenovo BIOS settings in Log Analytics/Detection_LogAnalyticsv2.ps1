# Info about DCE, DCR, Table
$DcrImmutableId = "" # id available in DCR > JSON view > immutableId
$DceURI = "" # available in DCE > Logs Ingestion value
$Table = "Lenovo_BIOSSettings_CL" # custom log to create

# Info about app registration
$appId = "" #the app ID created and granted permissions
$tenantId = "" #the tenant ID in which the Data Collection Endpoint resides
$appSecret = "" #the secret created for the above app - never store your secrets in the source code

$Export_All_Settings = $True # Choose True or False. This part allows you to export all settings or just some of them
# If Export_All_Settings is set to some, add settings to export below
$Settings_to_add = @("SecurityChip",
"TXTFeature",
"SecureBoot",
"Secure_Boot",
"DeviceGuard",
"Device_Guard",
"KernelDMAProtection",
"KeyboardLayout",
"DataExecutionPrevention",
"Chassis_Intrusion_Detection",
"BottomCoverTamperDetected",
"InternalStorageTamper")	


$WMI_computersystem = gwmi win32_computersystem
$Manufacturer = $WMI_computersystem.manufacturer
If($Manufacturer -ne "LENOVO")
	{
		write-output "Poste non Lenovo"	
		EXIT 0	
	}
		
	
# Info about the model
$Get_Current_Model_MTM = ($WMI_computersystem.Model).Substring(0,4)
$Get_Current_Model_FamilyName = $WMI_computersystem.SystemFamily.split(" ")[1]	
$ModelMTM = ((gwmi win32_computersystem).Model).Substring(0,4)	

# Info about the BIOS version
$BIOS_Version = Get-ciminstance -class win32_bios
$Current_BIOS_Version = $BIOS_Version.SMBIOSBIOSVersion
$Current_BIOS_Version_ID = $Current_BIOS_Version.Split("(")[0]	
$BIOS_Maj_Version = $BIOS_Version.SystemBiosMajorVersion 
$BIOS_Min_Version = $BIOS_Version.SystemBiosMinorVersion 
$Script:Get_Current_BIOS_Version = "$BIOS_Maj_Version.$BIOS_Min_Version"				

# Info about the BIOS date
$BIOS_release_date = (gwmi win32_bios | select *).ReleaseDate								
$Format_BIOS_release_date = [DateTime]::new((([wmi]"").ConvertToDateTime($BIOS_release_date)).Ticks, 'Local').ToUniversalTime()	

# Info about BIOS password
$IsPasswordSet = (gwmi -Class Lenovo_BiosPasswordSettings -Namespace root\wmi).PasswordState
If($IsPasswordSet -eq 2)
	{
		$PasswordStatus = "Enable"
	}Else{
		$PasswordStatus = "Disable"
	}	

# Info about the current user
$Current_User_Profile = Get-ChildItem Registry::\HKEY_USERS | Where-Object { Test-Path "$($_.pspath)\Volatile Environment" } | ForEach-Object { (Get-ItemProperty "$($_.pspath)\Volatile Environment").USERPROFILE }
$Username = $Current_User_Profile.split("\")[2]	

# Info about the chassis
$Chassis = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes
$Device_Chassis = [string]$chassis
If($Chassis -eq 9 -or $Chassis -eq 10 -or $Chassis -eq 14) 
	{
		$Chassis_Type = "Laptop"
	}Else{
		$Chassis_Type = "Desktop"
	}	

$TimeGenerated = Get-Date ([datetime]::UtcNow) -Format O

function Get_Lenovo_BIOS_Settings {
    $Script:Get_BIOS_Settings = Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\wmi |
        Where-Object { $_.CurrentSetting -ne "" } |
        Select-Object `
            @{Name = "ComputerName"; Expression = { $env:computername }},
            @{Name = "Setting"; Expression = { $_.CurrentSetting.Split(",")[0] }},
            @{Name = "Value"; Expression = { $_.CurrentSetting.Split(",")[1] }},
            @{Name = "ModelFamilyName"; Expression = { $Get_Current_Model_FamilyName }},
            @{Name = "ModelMTM"; Expression = { $ModelMTM }},
            @{Name = "ChassisDevice"; Expression = { $Device_Chassis }},
            @{Name = "ChassisType"; Expression = { $Chassis_Type }},
            @{Name = "BIOSCurrentVersion"; Expression = { $Get_Current_BIOS_Version }},
            @{Name = "BIOSCurrentVersionFull"; Expression = { $Current_BIOS_Version }},
            @{Name = "CurrentBIOSDate"; Expression = { $Format_BIOS_release_date }},
            @{Name = "PasswordStatus"; Expression = { $PasswordStatus }},
            @{Name = "IsPasswordSet"; Expression = { $IsPasswordSet }},
            @{Name = "Manufacturer"; Expression = { $Manufacturer }},
            @{Name = "TimeGenerated"; Expression = {$TimeGenerated}}  			
    return $Get_BIOS_Settings
}
		
If($Export_All_Settings -eq $False)
	{	
		$BIOS_Props = Get_Lenovo_BIOS_Settings | Where-Object {
			$Settings_to_add -contains $_.Setting
		}	
	}Else{	
		$BIOS_Props = Get_Lenovo_BIOS_Settings	
}

	
#**************************************************************************************************
# 							This part will upload data to Log Analytics
#**************************************************************************************************
$Body_JSON = $BIOS_Props | ConvertTo-Json	

Add-Type -AssemblyName System.Web

# Getting token through the azure app from Azure monitor pipeline
$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

# Sending data to Log Analytics Custom Log
$headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
$uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2023-01-01";
$uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $Body_JSON -Headers $headers;
