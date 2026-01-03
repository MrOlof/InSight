# InSight

InSights where Intune falls short.

A PowerShell GUI tool that gives you better visibility into your Microsoft Intune environment. Built because the Intune portal doesn't always show you what you need to know.

## What it does

**Device Ownership Analysis**
Ever wonder which users in a group actually have devices? This tool analyzes group memberships and shows you who has zero devices, one device, or multiple devices. Export the results to CSV for reporting.

**Configuration Backup**
Export your entire Intune configuration to JSON files. Includes compliance policies, device configs, settings catalog, scripts, app protection policies, and endpoint security settings. Choose between v1.0 or Beta API.

**Assignment Tracking**
See what policies and apps are assigned to specific groups. Find orphaned policies that aren't assigned to anyone. Identify empty groups wasting your assignments.

**Application Insights**
View all your Intune apps in one place. Check versions and export to CSV/JSON for documentation.

**Remediation Scripts**
Browse a library of community remediation scripts you can deploy to Intune.

## Getting Started

**Requirements:**
- Windows 10/11
- PowerShell 5.1 or later
- An Intune admin account

**Install:**
```powershell
git clone https://github.com/MrOlof/InSight.git
cd InSight
.\Start-InSight.ps1
```

Sign in with your Microsoft account and grant the permissions when prompted. The app uses read-only permissions by default.

## How to Use

The interface is straightforward. Sign in, pick a tool from the left sidebar, and go.

**Quick example - Backup your config:**
1. Click Backup
2. Choose where to save it
3. Click Start Backup
4. Done in about 30-60 seconds

**Find users with no devices:**
1. Click Device Ownership
2. Search for your group
3. Click Analyze
4. See the results sorted by device count

## Technical Details

Built with PowerShell and WPF. Uses MSAL for authentication and Microsoft Graph API for data. Logs are saved to `C:\Logs\IntuneAdmin\` and config is stored in your local AppData folder.

The tool is read-only by default. Nothing gets modified in your tenant unless you explicitly deploy something.

## About

Created by [MrOlof](https://github.com/MrOlof) for anyone managing Intune who wishes the portal did more.

Licensed under MIT. Use it however you want.

## Contributing

Found a bug? Have an idea? Open an issue or submit a PR. Just keep it simple and test it first.

---

If this saves you time, star the repo.
