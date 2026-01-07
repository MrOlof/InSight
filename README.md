<div align="center">

# InSight

A PowerShell GUI tool for Microsoft Intune that provides insights and visibility where the Intune portal falls short.

Blog Post
https://mrolof.dev/blog/insight-intune-gui

</div>

## Features

📊 **Device Ownership**: Analyze device ownership for user groups.

💾 **Configuration Backup**: Export your entire Intune configuration to JSON files. 

🎯 **Assignment Tracking**: View policy and app assignments for specific groups and find orphaned policies.

📱 **Application Insights**: View all Intune applications with version tracking and export capabilities.

🔨 **Remediation Scripts**: Browse a library of community remediation scripts ready for deployment.


## Screenshots

### Main 
<img width="1612" height="1212" alt="image" src="https://github.com/user-attachments/assets/c701aff6-a5a7-454f-9477-55b092089a77" />

### Device Ownership 
Analyze device ownership for user groups
<img width="1504" height="928" alt="image" src="https://github.com/user-attachments/assets/1cf922a2-5556-40b5-a51e-3c43f365a9ce" />

### Configuration Backup
Export your entire Intune configuration
<img width="1566" height="1123" alt="image" src="https://github.com/user-attachments/assets/2e3cc0e6-6165-4dfe-a471-0e95f7c40d1c" />

### Assignment Tracking
View policy and app assignments
<img width="1605" height="1212" alt="image" src="https://github.com/user-attachments/assets/7e53e46d-078e-4110-8915-d30c13d7c717" />

### Applications
View updates for applications and possible MSstore availability 
<img width="1605" height="1219" alt="image" src="https://github.com/user-attachments/assets/940d24bb-86da-4c0f-9a65-d9d5b0d08ef3" />


## Installation

### From Source

Clone the repository:
```powershell
git clone https://github.com/MrOlof/InSight.git
cd InSight
```

Run the application:
```powershell
.\Start-InSight.ps1
```

## Usage

1. **Launch the Application**: Run `Start-InSight.ps1`
2. **Sign In**: Authenticate with your Microsoft Account
3. **Grant Permissions**: Accept the required Microsoft Graph API permissions
4. **Select a Tool**: Choose from the left sidebar (Applications, Configurations, Assignments, etc.)
5. **Perform Analysis**: Use the tool's features to analyze or export data

### Common Workflows

**Backup Intune Configuration:**
1. Click Backup in the left menu
2. Select destination folder
3. Configure options (include assignments, exclude built-in policies, API version)
4. Click Start Backup
5. Wait 30-60 seconds for completion

**Analyze Device Ownership:**
1. Click Device Ownership
2. Search for a user group
3. Click Analyze Devices
4. Review results categorized by device count
5. Export to CSV if needed

**Find Orphaned Policies:**
1. Click Assignments
2. Scroll to Orphaned Policies section
3. Click Find Orphaned Policies
4. Review configurations without assignments



## Features in Detail

### Authentication
- MSAL-based OAuth2 authentication
- Automatic token refresh
- Session management with PIM support
- Permission tracking and validation

### Configuration Backup
Supported resource types:
- Device Compliance Policies
- Device Configuration Profiles
- Settings Catalog Policies
- Device Management Scripts
- Proactive Remediations (Health Scripts)
- Applications (metadata)
- Autopilot Profiles
- Endpoint Security Policies
- Administrative Templates

Optional features:
- Include policy and profile assignments
- Exclude built-in policies
- API version selection (v1.0 or Beta)
- Timestamped backup folders

### Assignment Analysis
- Device group assignment tracking
- User group assignment tracking
- Orphaned policy detection
- Empty group identification
- Export capabilities

## Architecture

Built with:
- **UI Framework**: Windows Presentation Foundation (WPF)
- **Authentication**: Microsoft Authentication Library (MSAL)
- **API**: Microsoft Graph API
- **Data Format**: JSON

## Project Structure

```
InSight/
├── Start-InSight.ps1              # Main launcher
├── Modules/
│   ├── AuthenticationManager.psm1  # MSAL authentication
│   ├── ConfigurationManager.psm1   # App settings
│   ├── LoggingManager.psm1         # Logging functions
│   ├── PermissionManager.psm1      # Permission validation
│   ├── ScriptManager.psm1          # Script registry
│   └── AssignmentHelpers.psm1      # Assignment analysis
├── Resources/
│   ├── MainWindow.xaml             # Main UI definition
│   ├── DeviceOwnershipView.xaml    # Device ownership UI
│   └── RemediationScripts.json     # Script library
├── Scripts/
│   ├── Get-GroupDeviceOwnershipAnalysis.ps1
│   └── ScriptTemplate.ps1
└── Logs/                           # Application logs
```

## Configuration

Settings are stored in `%LOCALAPPDATA%\IntuneAdmin\config.json`:

```json
{
  "Data": {
    "ExportPath": "C:\\IntuneExports"
  },
  "Logging": {
    "Level": "Info",
    "RetentionDays": 30
  }
}
```

## Security

- Read-only by default for safety
- MSAL OAuth2 authentication
- Local token caching with encryption
- Automatic token refresh
- No credentials stored in code
- Comprehensive logging with sensitive data redaction

## Required Permissions

The application requests the following Microsoft Graph API permissions:
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementApps.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `User.Read.All`
- `Directory.Read.All`
- `Group.Read.All`

## Logging

Logs are stored in `C:\Logs\IntuneAdmin\`:
- File format: `IntuneAdmin_YYYY-MM-DD.log`
- Levels: DEBUG, INFO, WARNING, ERROR
- Automatic rotation with configurable retention (default 30 days)

## Contributing

Contributions are welcome. Please:
1. Fork the repository
2. Create a feature branch
3. Test in your Intune environment
4. Submit a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Kosta Wadenfalk**
- GitHub: [@MrOlof](https://github.com/MrOlof)

## Acknowledgments

- Microsoft Graph API
- Microsoft Authentication Library (MSAL)
- PowerShell Community
