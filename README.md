# Pulse Secure Complete Uninstall Script

A comprehensive PowerShell script to fully remove Pulse Secure (now Ivanti Secure Access) VPN client software from Windows systems, including all components, registry entries, ActiveX controls, and per-user data.

## Why This Script?

The standard Pulse Secure uninstaller often leaves behind residual files, registry entries, and per-user data. This script was developed to address incomplete uninstalls across enterprise environments where clean removal is required before deploying new VPN solutions.

## Development Process

This script was developed iteratively to solve a real enterprise deployment 
challenge. Initial versions of this script were tested and refined based on failures 
encountered across 30+ production workstations, with each version addressing 
specific edge cases like ActiveX controls, hung uninstallers, and orphaned 
registry entries. After 4 versions, it is able to be run back to back without error, successfully removing Pulse Secure on each run.

## Features

- **Dynamic Uninstaller Detection** - Automatically locates PulseUninstall.exe on the system
- **Multiple Removal Methods** - Uses official uninstaller, winget, MSI, and registry-based removal
- **Per-User Cleanup** - Removes registry keys and AppData for all user profiles (including offline users)
- **ActiveX Control Removal** - Handles Downloaded Program Files cleanup and COM unregistration
- **Timeout Protection** - Prevents script from hanging on unresponsive uninstallers
- **Silent Mode** - Supports unattended execution for remote deployment
- **Detailed Reporting** - Provides summary of all actions taken

## Usage

```powershell
# Interactive mode
.\PulseSecureUninstall.ps1

# Silent mode (for remote/unattended deployment)
.\PulseSecureUninstall.ps1 -Silent
