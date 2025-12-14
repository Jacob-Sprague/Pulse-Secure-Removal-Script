# Pulse Secure Complete Uninstall Script

A comprehensive PowerShell script to fully remove Pulse Secure (now Ivanti Secure Access) VPN client software from Windows systems, including all components, registry entries, ActiveX controls, and per-user data.

## Why This Script?

The standard Pulse Secure uninstaller often leaves behind residual files, registry entries, and per-user data. This script was developed to address incomplete uninstalls across enterprise environments where clean removal is required before deploying new VPN solutions.

## Development Process

This script was developed iteratively to solve a real enterprise deployment 
challenge. Initial versions of this script were tested and refined based on errors 
encountered across 50+ production workstations, with each version addressing 
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
.\pulseRemove.ps1

# Silent mode (for remote/unattended deployment)
.\pulseRemove.ps1 -Silent
```

## How It Works

The script executes in a logical sequence, with each step building on the previous one to ensure complete removal.

---

### Step 1: Administrative Privilege Check
The script requires elevated privileges to modify system files, registry keys, and services. If not running as admin, it exits immediately with instructions to re-run properly.

---

### Step 2: Pre-Flight Installation Check
Before making any changes, the script surveys the system to find:
- Installation folders in Program Files
- Registered products in the Windows registry
- Related Windows services
- ActiveX controls in Downloaded Program Files

This helps determine the scope of cleanup required and provides useful diagnostic output.

---

### Step 3: Stop Services and Kill Processes

Files cannot be deleted while they're in use. This step:
- Stops Pulse Secure services (PulseSecureService, dsNcService, etc.)
- Disables services to prevent automatic restart
- Terminates any running Pulse Secure processes

This prevents "file in use" errors during removal.

---

### Step 4: Locate and Run Official Uninstaller

Rather than hardcoding the uninstaller path, the script:
1. Searches common installation directories first (fast)
2. Falls back to a full drive search if needed (thorough)
3. Executes the uninstaller with silent flags
4. Includes timeout protection to prevent hanging

Using the official uninstaller ensures proper removal of core components.

---

### Step 5: Remove Subcomponents

Pulse Secure installs several subcomponents (especially when deployed via web portal). This step attempts removal using:
1. **Winget** - Windows package manager (if available)
2. **Registry-based uninstall** - Reads UninstallString from registry and executes it
3. **MSI uninstall** - For MSI-packaged components using msiexec

Each method has timeout protection to prevent the script from hanging on unresponsive uninstallers.

---

### Step 6: ActiveX Control Cleanup

Web-based Pulse Secure deployments install ActiveX controls in `C:\Windows\Downloaded Program Files`. These require special handling:
1. Unregister DLL/OCX files using regsvr32
2. Delete the physical files
3. Release cached COM objects

This catches components that standard uninstallers often miss.

---

### Step 7: Remove System Registry Keys

Removes system-wide registry keys that store application settings:
- `HKLM:\Software\Pulse Secure`
- `HKLM:\Software\WOW6432Node\Pulse Secure`
- `HKLM:\Software\Juniper Networks`
- `HKLM:\Software\WOW6432Node\Juniper Networks`

---

### Step 8: Remove Per-User Registry Keys

Each user who ran Pulse Secure has their own registry entries. This step:
1. Enumerates all user profiles on the machine
2. For logged-in users: Accesses their registry directly via HKEY_USERS
3. For offline users: Temporarily loads their NTUSER.DAT hive
4. Removes Pulse Secure keys from each user's registry
5. Properly unloads hives with garbage collection to prevent access errors

This ensures complete cleanup regardless of which users are currently logged in.

---

### Step 9: Delete Installation Folders

Deletes the main installation folders and any remaining files that weren't removed by the official uninstaller:
- `C:\Program Files (x86)\Pulse Secure`
- `C:\Program Files\Pulse Secure`
- `C:\Program Files (x86)\Common Files\Pulse Secure`
- Related Juniper Networks folders

---

### Step 10: Clean Up User Profile Data

Iterates through all user profiles and removes:
- `AppData\Local\Pulse Secure`
- `AppData\Roaming\Pulse Secure`
- Related Juniper Networks folders

This removes cached data, logs, and user preferences for all users on the machine.

---

### Step 11: Verification

Performs a final scan to verify cleanup was successful:
- Checks for remaining installation folders
- Scans registry for any remaining product entries
- Looks for leftover services

If any orphaned registry entries are found (entries pointing to files that no longer exist), they are forcibly removed.

---

### Step 12: Summary Report

Outputs a comprehensive summary including:
- Whether the official uninstaller was found and executed
- Number of services stopped
- Number of processes terminated
- Components uninstalled
- ActiveX controls removed
- Registry keys deleted
- Folders cleaned up

This provides documentation of exactly what the script did for troubleshooting and verification purposes.
