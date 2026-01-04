#************************************************************************************************************************
# 												Part to fill
#************************************************************************************************************************
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$LogType = "Lenovo_BIOSSettings_CL" # Custom log to create in lo Analytics
$TimeStampField = "" # let to blank
#************************************************************************************************************************

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


# Log analytics functions
# More info there: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
# More info there: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}


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
            @{Name = "Manufacturer"; Expression = { $Manufacturer }}  
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
$BIOS_SettingsResultJson = $BIOS_Props | ConvertTo-Json	

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($BIOS_SettingsResultJson))
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params	