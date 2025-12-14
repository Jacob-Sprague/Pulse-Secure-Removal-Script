#=============================================================================
# Pulse Secure Complete Uninstall Script
# Version: 4.1
# Purpose: Fully removes Pulse Secure, Juniper, and Ivanti VPN software
#          including all registry entries, files, and per-user configurations
#
# Changes in V4.1:
#   - Added timeout protection to prevent script from hanging
#   - Removed retry logic that could show UI prompts
#   - Fixed COM cache release to not block indefinitely
#   - All external processes now have timeout protection
#=============================================================================

param(
    [switch]$Silent = $false  # Use -Silent for unattended execution (no prompts)
)

#-----------------------------------------------------------------------------
# SECTION 1: ADMINISTRATIVE PRIVILEGE CHECK
#-----------------------------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges."
    Write-Warning "Please right-click PowerShell and select 'Run as Administrator'."
    exit 1
}

Write-Host "Running as Administrator: $isAdmin" -ForegroundColor Green
Write-Host "Silent Mode: $Silent" -ForegroundColor Gray
Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "   Pulse Secure Complete Uninstall Script" -ForegroundColor Cyan
Write-Host "                 Version 4.1" -ForegroundColor Cyan
Write-Host "=============================================`n" -ForegroundColor Cyan

#-----------------------------------------------------------------------------
# SECTION 2: INITIALIZE TRACKING VARIABLES
#-----------------------------------------------------------------------------

$exeRemoved = $false
$removedComponents = @()
$regRemoved = @()
$userRegRemoved = @()
$servicesRemoved = @()
$processesKilled = @()
$foldersDeleted = @()
$activeXRemoved = @()

#-----------------------------------------------------------------------------
# SECTION 3: HELPER FUNCTIONS
#-----------------------------------------------------------------------------

function Start-ProcessWithTimeout {
    <#
    .SYNOPSIS
        Starts a process and waits for it with a timeout to prevent hanging.
    .PARAMETER FilePath
        The executable to run
    .PARAMETER ArgumentList
        Arguments to pass to the executable
    .PARAMETER TimeoutSeconds
        Maximum time to wait (default 60 seconds)
    .PARAMETER WindowStyle
        Window style (default Hidden)
    .RETURNS
        A custom object with ExitCode and TimedOut properties
    #>
    param(
        [string]$FilePath,
        [string]$ArgumentList = "",
        [int]$TimeoutSeconds = 60,
        [System.Diagnostics.ProcessWindowStyle]$WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    )
    
    $result = [PSCustomObject]@{
        ExitCode = -1
        TimedOut = $false
        Error = $null
    }
    
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $ArgumentList
        $psi.WindowStyle = $WindowStyle
        $psi.UseShellExecute = $true
        
        $process = [System.Diagnostics.Process]::Start($psi)
        
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        
        if ($completed) {
            $result.ExitCode = $process.ExitCode
        } else {
            Write-Host "      Process timed out after $TimeoutSeconds seconds. Terminating..." -ForegroundColor Yellow
            try {
                $process.Kill()
                $process.WaitForExit(5000)
            } catch {
                # Process may have already exited
            }
            $result.TimedOut = $true
        }
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        if ($process) {
            $process.Dispose()
        }
    }
    
    return $result
}

function Load-RegistryHive {
    param(
        [string]$KeyPath,
        [string]$HivePath
    )
    
    $result = reg load $KeyPath $HivePath 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        return $true
    } else {
        Write-Warning "Failed to load registry hive: $result"
        return $false
    }
}

function Unload-RegistryHive {
    param(
        [string]$KeyPath
    )
    
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    Start-Sleep -Milliseconds 500
    
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $result = reg unload $KeyPath 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
        
        if ($attempt -lt $maxAttempts) {
            Write-Host "  Unload attempt $attempt failed, retrying..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            [gc]::Collect()
        }
    }
    
    Write-Warning "Could not unload registry hive after $maxAttempts attempts: $KeyPath"
    return $false
}

#-----------------------------------------------------------------------------
# SECTION 4: PRE-FLIGHT INSTALLATION CHECK
#-----------------------------------------------------------------------------

Write-Host "--- Pre-Flight Installation Check ---`n" -ForegroundColor Cyan

$installState = @{
    UninstallerFound = $false
    UninstallerPath = $null
    FoldersExist = $false
    RegistryEntries = @()
    ServicesFound = @()
    ActiveXFound = $false
}

# Check if Pulse Secure folders exist
$pulseFolders = @(
    "C:\Program Files (x86)\Pulse Secure",
    "C:\Program Files\Pulse Secure"
)

foreach ($folder in $pulseFolders) {
    if (Test-Path $folder) {
        $installState.FoldersExist = $true
        Write-Host "Found installation folder: $folder" -ForegroundColor Yellow
        
        $contents = Get-ChildItem $folder -Recurse -ErrorAction SilentlyContinue | 
            Measure-Object -Property Length -Sum
        Write-Host "  Contents: $($contents.Count) files, $([math]::Round($contents.Sum / 1KB, 2)) KB" -ForegroundColor Gray
    }
}

# Check registry for installed products
$installState.RegistryEntries = @(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
) | Where-Object { 
    ($_.DisplayName -match 'Pulse Secure|Juniper.*(Setup|Network|Access|VPN)|Ivanti.*(Secure|Connect|Access)') -or 
    ($_.Publisher -match 'Pulse Secure|Juniper Networks|Ivanti.*Secure')
}

if ($installState.RegistryEntries.Count -gt 0) {
    Write-Host "Found $($installState.RegistryEntries.Count) registered product(s):" -ForegroundColor Yellow
    $installState.RegistryEntries | ForEach-Object { 
        Write-Host "  - $($_.DisplayName)" -ForegroundColor Gray 
    }
}

# Check for services
$serviceNames = @("PulseSecureService", "dsNcService", "JuniperAccessService", "PulseClient*")
foreach ($svcPattern in $serviceNames) {
    $found = Get-Service -Name $svcPattern -ErrorAction SilentlyContinue
    if ($found) {
        $installState.ServicesFound += $found
    }
}

if ($installState.ServicesFound.Count -gt 0) {
    Write-Host "Found $($installState.ServicesFound.Count) related service(s):" -ForegroundColor Yellow
    $installState.ServicesFound | ForEach-Object {
        Write-Host "  - $($_.Name) ($($_.Status))" -ForegroundColor Gray
    }
}

# Check for ActiveX controls
$downloadedProgramFilesPath = "$env:SystemRoot\Downloaded Program Files"
if (Test-Path $downloadedProgramFilesPath) {
    $activeXFiles = Get-ChildItem -Path $downloadedProgramFilesPath -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match 'Pulse|Juniper|dsSetupCtrl|SetupClientCtrl' }
    if ($activeXFiles) {
        $installState.ActiveXFound = $true
        Write-Host "Found ActiveX controls in Downloaded Program Files:" -ForegroundColor Yellow
        $activeXFiles | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }
    }
}

# Summary
Write-Host ""
$nothingFound = (-not $installState.FoldersExist -and 
                 $installState.RegistryEntries.Count -eq 0 -and 
                 $installState.ServicesFound.Count -eq 0 -and 
                 -not $installState.ActiveXFound)

if ($nothingFound) {
    Write-Host "Pulse Secure does not appear to be installed on this system." -ForegroundColor Green
    
    if ($Silent) {
        Write-Host "Silent mode: Continuing with cleanup to check for remnants..." -ForegroundColor Yellow
    } else {
        $continue = Read-Host "Continue with cleanup anyway to check for remnants? (Y/N)"
        if ($continue -notmatch '^[Yy]$') {
            Write-Host "Exiting script. No changes made." -ForegroundColor Cyan
            exit 0
        }
    }
} else {
    Write-Host "Pulse Secure installation detected. Proceeding with removal...`n" -ForegroundColor Yellow
}

#-----------------------------------------------------------------------------
# SECTION 5: STOP SERVICES AND KILL PROCESSES
#-----------------------------------------------------------------------------

Write-Host "--- Stopping Services and Processes ---`n" -ForegroundColor Cyan

$servicesToStop = @(
    "PulseSecureService",
    "dsNcService", 
    "JuniperAccessService",
    "PulseTray",
    "dsAccessService"
)

foreach ($serviceName in $servicesToStop) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($service) {
        Write-Host "Found service: $serviceName (Status: $($service.Status))"
        
        if ($service.Status -eq 'Running') {
            try {
                Write-Host "  Stopping service..." -ForegroundColor Yellow
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                Write-Host "  Service stopped." -ForegroundColor Green
            } catch {
                Write-Warning "  Failed to stop service: $($_.Exception.Message)"
            }
        }
        
        try {
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
            Write-Host "  Service disabled." -ForegroundColor Green
            $servicesRemoved += $serviceName
        } catch {
            Write-Warning "  Failed to disable service: $($_.Exception.Message)"
        }
    }
}

$processPatterns = @(
    "PulseSecure*",
    "PulseTray",
    "PulseUI",
    "dsAccessService",
    "dsNcService",
    "JamUI",
    "JuniperSetupClient*"
)

foreach ($pattern in $processPatterns) {
    $processes = Get-Process -Name $pattern -ErrorAction SilentlyContinue
    
    foreach ($proc in $processes) {
        Write-Host "Found process: $($proc.Name) (PID: $($proc.Id))"
        try {
            $proc | Stop-Process -Force -ErrorAction Stop
            Write-Host "  Process terminated." -ForegroundColor Green
            $processesKilled += $proc.Name
        } catch {
            Write-Warning "  Failed to terminate process: $($_.Exception.Message)"
        }
    }
}

if ($servicesRemoved.Count -eq 0 -and $processesKilled.Count -eq 0) {
    Write-Host "No running services or processes found." -ForegroundColor Gray
}

Start-Sleep -Seconds 2

#-----------------------------------------------------------------------------
# SECTION 6: FIND AND RUN THE OFFICIAL UNINSTALLER
#-----------------------------------------------------------------------------

Write-Host "`n--- Locating and Running Official Uninstaller ---`n" -ForegroundColor Cyan

$uninstallerPath = $null

$commonSearchPaths = @(
    "C:\Program Files (x86)\Pulse Secure",
    "C:\Program Files\Pulse Secure",
    "$env:ProgramFiles\Pulse Secure",
    "${env:ProgramFiles(x86)}\Pulse Secure",
    "C:\Program Files (x86)\Common Files\Pulse Secure",
    "C:\Program Files\Common Files\Pulse Secure"
)

Write-Host "Searching common installation directories..." -ForegroundColor Gray

foreach ($searchPath in $commonSearchPaths) {
    if (Test-Path $searchPath) {
        $found = Get-ChildItem -Path $searchPath -Filter "PulseUninstall.exe" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        
        if ($found) {
            $uninstallerPath = $found.FullName
            Write-Host "Found uninstaller: $uninstallerPath" -ForegroundColor Green
            break
        }
    }
}

if (-not $uninstallerPath) {
    Write-Host "Not found in common locations. Searching entire drive..." -ForegroundColor Yellow
    Write-Host "(This may take 1-2 minutes, please wait)" -ForegroundColor Gray
    
    $allUninstallers = Get-ChildItem -Path C:\ -Filter "PulseUninstall.exe" -Recurse -ErrorAction SilentlyContinue
    
    if ($allUninstallers.Count -gt 1) {
        Write-Host "Multiple uninstallers found:" -ForegroundColor Yellow
        $allUninstallers | ForEach-Object { 
            Write-Host "  - $($_.FullName) (Modified: $($_.LastWriteTime))" -ForegroundColor Gray 
        }
        $uninstallerPath = ($allUninstallers | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
        Write-Host "Using most recent: $uninstallerPath" -ForegroundColor Cyan
    } elseif ($allUninstallers.Count -eq 1) {
        $uninstallerPath = $allUninstallers[0].FullName
        Write-Host "Found uninstaller: $uninstallerPath" -ForegroundColor Green
    }
}

if ($uninstallerPath) {
    Write-Host "`nExecuting uninstaller with silent flag (timeout: 120 seconds)..." -ForegroundColor Cyan
    
    $uninstallResult = Start-ProcessWithTimeout -FilePath $uninstallerPath `
        -ArgumentList "/silent=1" `
        -TimeoutSeconds 120
    
    if ($uninstallResult.TimedOut) {
        Write-Warning "Uninstaller timed out. Continuing with manual cleanup..."
    } elseif ($uninstallResult.ExitCode -eq 0) {
        Write-Host "Uninstaller completed successfully (Exit Code: 0)" -ForegroundColor Green
        $exeRemoved = $true
    } else {
        Write-Warning "Uninstaller finished with Exit Code: $($uninstallResult.ExitCode)"
        Write-Host "Continuing with cleanup..." -ForegroundColor Yellow
        $exeRemoved = $true
    }
    
    Write-Host "Waiting 30 seconds for system to complete cleanup..." -ForegroundColor Gray
    Start-Sleep -Seconds 30
} else {
    Write-Host "PulseUninstall.exe was not found on this system." -ForegroundColor Yellow
    Write-Host "Proceeding with alternative removal methods..." -ForegroundColor Yellow
}

#-----------------------------------------------------------------------------
# SECTION 7: REMOVE SUBCOMPONENTS
#-----------------------------------------------------------------------------

Write-Host "`n--- Removing Subcomponents ---`n" -ForegroundColor Cyan

$subcomponents = @(
    "Pulse Secure Setup Client 64-bit Activex Control",
    "Pulse Secure Setup Client Activex Control",
    "Juniper Setup Client",
    "Juniper Networks Setup Client Activex Control",
    "Juniper Networks Host Checker"
)

$wingetAvailable = Get-Command winget -ErrorAction SilentlyContinue

if ($wingetAvailable) {
    Write-Host "Winget is available. Attempting winget-based removal..." -ForegroundColor Gray
    
    foreach ($component in $subcomponents) {
        Write-Host "  Checking for: $component"
        
        $wingetResult = Start-ProcessWithTimeout -FilePath "winget" `
            -ArgumentList "uninstall --name `"$component`" --silent --accept-source-agreements" `
            -TimeoutSeconds 60
        
        if ($wingetResult.TimedOut) {
            Write-Host "    Winget timed out for this component" -ForegroundColor Yellow
        } elseif ($wingetResult.ExitCode -eq 0) {
            Write-Host "    Uninstalled via winget: $component" -ForegroundColor Green
            $removedComponents += $component
        } elseif ($wingetResult.ExitCode -eq -1978335212) {
            Write-Host "    Not found in winget database (this is normal)" -ForegroundColor Gray
        } else {
            Write-Host "    Winget returned code: $($wingetResult.ExitCode)" -ForegroundColor Gray
        }
    }
}

Write-Host "`nPerforming registry-based uninstall scan..." -ForegroundColor Cyan

$uninstallEntries = @(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
) | Where-Object { 
    ($_.DisplayName -match 'Pulse Secure|Juniper.*(Setup|Network|Access|VPN)|Ivanti.*(Secure|Connect|Access)') -or 
    ($_.Publisher -match 'Pulse Secure|Juniper Networks|Ivanti.*Secure')
}

if ($uninstallEntries.Count -eq 0) {
    Write-Host "No registered Pulse/Juniper/Ivanti products found in registry." -ForegroundColor Gray
} else {
    Write-Host "Found $($uninstallEntries.Count) registered product(s) to remove:" -ForegroundColor Yellow
    
    foreach ($entry in $uninstallEntries) {
        $productName = $entry.DisplayName
        $productGuid = $entry.PSChildName
        
        Write-Host "`n  Processing: $productName"
        
        if ($productGuid -match '^\{[0-9A-Fa-f\-]{36}\}$') {
            Write-Host "    Type: MSI Package ($productGuid)" -ForegroundColor Gray
            Write-Host "    Running msiexec /x (timeout: 120 seconds)..." -ForegroundColor Gray
            
            $msiResult = Start-ProcessWithTimeout -FilePath "msiexec.exe" `
                -ArgumentList "/x $productGuid /quiet /norestart" `
                -TimeoutSeconds 120
            
            if ($msiResult.TimedOut) {
                Write-Warning "    MSI uninstall timed out"
            } elseif ($msiResult.ExitCode -eq 0) {
                Write-Host "    Successfully uninstalled." -ForegroundColor Green
                $removedComponents += $productName
            } elseif ($msiResult.ExitCode -eq 1605) {
                Write-Host "    Product already removed." -ForegroundColor Gray
            } else {
                Write-Warning "    MSI uninstall failed (Exit Code: $($msiResult.ExitCode))"
            }
            
        } elseif ($entry.UninstallString) {
            Write-Host "    Type: EXE-based uninstaller" -ForegroundColor Gray
            
            $uninstallCmd = $entry.UninstallString
            
            # Check if QuietUninstallString exists
            if ($entry.QuietUninstallString) {
                $uninstallCmd = $entry.QuietUninstallString
                Write-Host "    Using QuietUninstallString" -ForegroundColor Gray
            } elseif ($uninstallCmd -notmatch '/silent|/quiet|/S\b|/s\b|/SILENT|/QUIET|-silent|-quiet') {
                if ($uninstallCmd -match 'Pulse|Juniper') {
                    $uninstallCmd = "$uninstallCmd /silent"
                    Write-Host "    Added /silent flag" -ForegroundColor Gray
                }
            }
            
            Write-Host "    Running (timeout: 60 seconds): $uninstallCmd" -ForegroundColor Gray
            
            $exeResult = Start-ProcessWithTimeout -FilePath "cmd.exe" `
                -ArgumentList "/c `"$uninstallCmd`"" `
                -TimeoutSeconds 60
            
            if ($exeResult.TimedOut) {
                Write-Warning "    Uninstaller timed out (may have required user interaction)"
                Write-Host "    Will attempt manual file cleanup instead." -ForegroundColor Yellow
            } elseif ($exeResult.ExitCode -eq 0) {
                Write-Host "    Successfully uninstalled." -ForegroundColor Green
                $removedComponents += $productName
            } else {
                Write-Warning "    Uninstall returned code: $($exeResult.ExitCode)"
                Write-Host "    Will attempt manual file cleanup." -ForegroundColor Yellow
            }
        } else {
            Write-Warning "    No uninstall method available for this product."
        }
    }
}

Start-Sleep -Seconds 5

#-----------------------------------------------------------------------------
# SECTION 7B: SPECIAL HANDLING FOR ACTIVEX CONTROLS
#-----------------------------------------------------------------------------

Write-Host "`n--- Checking for ActiveX Controls in Downloaded Program Files ---`n" -ForegroundColor Cyan

$downloadedProgramFilesPath = "$env:SystemRoot\Downloaded Program Files"

if (Test-Path $downloadedProgramFilesPath) {
    $pulseActiveX = Get-ChildItem -Path $downloadedProgramFilesPath -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match 'Pulse|Juniper|dsSetupCtrl|SetupClientCtrl' }
    
    if ($pulseActiveX) {
        Write-Host "Found Pulse Secure ActiveX components:" -ForegroundColor Yellow
        $pulseActiveX | ForEach-Object { Write-Host "  - $($_.FullName)" -ForegroundColor Gray }
        
        foreach ($file in $pulseActiveX) {
            if ($file.Extension -match '\.(dll|ocx)$') {
                Write-Host "  Attempting to unregister: $($file.Name)" -ForegroundColor Yellow
                
                $regsvr = Start-ProcessWithTimeout -FilePath "regsvr32.exe" `
                    -ArgumentList "/u /s `"$($file.FullName)`"" `
                    -TimeoutSeconds 30
                
                if ($regsvr.TimedOut) {
                    Write-Host "    Unregister timed out" -ForegroundColor Yellow
                } elseif ($regsvr.ExitCode -eq 0) {
                    Write-Host "    Unregistered successfully." -ForegroundColor Green
                } else {
                    Write-Host "    Unregister returned code: $($regsvr.ExitCode) (may already be unregistered)" -ForegroundColor Gray
                }
            }
            
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                Write-Host "    Deleted: $($file.Name)" -ForegroundColor Green
                $activeXRemoved += $file.Name
            } catch {
                Write-Host "    Could not delete (may require reboot): $($file.Name)" -ForegroundColor Yellow
            }
        }
        
        # Release cached COM objects - NON-BLOCKING
        Write-Host "`n  Releasing cached COM objects..." -ForegroundColor Gray
        try {
            Start-Process -FilePath "rundll32.exe" `
                -ArgumentList "occache.dll,CoFreeUnusedLibrariesEx" `
                -WindowStyle Hidden -ErrorAction SilentlyContinue
            
            # Brief pause but don't wait for it
            Start-Sleep -Seconds 2
            
            # Kill any hung rundll32 processes we just started
            Get-Process -Name "rundll32" -ErrorAction SilentlyContinue | 
                Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-10) } |
                Stop-Process -Force -ErrorAction SilentlyContinue
            
            Write-Host "  COM cache release initiated." -ForegroundColor Green
        } catch {
            Write-Host "  Could not release COM cache (non-critical)." -ForegroundColor Gray
        }
    } else {
        Write-Host "No Pulse Secure ActiveX components found in Downloaded Program Files." -ForegroundColor Gray
    }
} else {
    Write-Host "Downloaded Program Files folder not found (this is normal)." -ForegroundColor Gray
}

#-----------------------------------------------------------------------------
# SECTION 8: REMOVE SYSTEM-WIDE REGISTRY KEYS
#-----------------------------------------------------------------------------

Write-Host "`n--- Removing System Registry Keys ---`n" -ForegroundColor Cyan

$systemRegPaths = @(
    "HKLM:\Software\Pulse Secure",
    "HKLM:\Software\WOW6432Node\Pulse Secure",
    "HKLM:\Software\Juniper Networks",
    "HKLM:\Software\WOW6432Node\Juniper Networks"
)

foreach ($regPath in $systemRegPaths) {
    Write-Host "Checking: $regPath"
    
    if (Test-Path $regPath) {
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            Write-Host "  Deleted." -ForegroundColor Green
            $regRemoved += $regPath
        } catch {
            Write-Warning "  Failed to delete: $($_.Exception.Message)"
        }
    } else {
        Write-Host "  Not present (already clean)." -ForegroundColor Gray
    }
}

#-----------------------------------------------------------------------------
# SECTION 9: REMOVE PER-USER REGISTRY KEYS
#-----------------------------------------------------------------------------

Write-Host "`n--- Removing Per-User Registry Keys ---`n" -ForegroundColor Cyan

$userKeysToCheck = @(
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\Juniper_Setup_Client",
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\Pulse_Setup_Client",
    "Software\Pulse Secure",
    "Software\Juniper Networks"
)

if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

$profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$allUserProfiles = Get-ChildItem $profileListPath -ErrorAction SilentlyContinue | 
    Where-Object { 
        $_.PSChildName -notmatch "_Classes" -and
        $_.PSChildName -match "^S-1-5-21-"
    }

Write-Host "Found $($allUserProfiles.Count) user profile(s) to check.`n"

foreach ($profile in $allUserProfiles) {
    $sidValue = $profile.PSChildName
    $hkuPath = "HKU:\$sidValue"
    $hiveLoaded = $false
    
    $profileImagePath = (Get-ItemProperty -Path $profile.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
    $userName = Split-Path $profileImagePath -Leaf
    
    Write-Host "Checking user: $userName (SID: $sidValue)" -ForegroundColor Cyan
    
    if (-not (Test-Path $hkuPath)) {
        Write-Host "  User is not logged in. Loading registry hive..." -ForegroundColor Yellow
        
        $ntUserDatPath = Join-Path $profileImagePath "NTUSER.DAT"
        
        if (Test-Path $ntUserDatPath) {
            $hiveLoaded = Load-RegistryHive -KeyPath "HKU\$sidValue" -HivePath $ntUserDatPath
            
            if (-not $hiveLoaded) {
                Write-Warning "  Could not load hive. Skipping this user."
                continue
            }
        } else {
            Write-Host "  NTUSER.DAT not found. Skipping this user." -ForegroundColor Gray
            continue
        }
    }
    
    foreach ($subKey in $userKeysToCheck) {
        $fullKeyPath = "HKU:\$sidValue\$subKey"
        
        if (Test-Path $fullKeyPath) {
            Write-Host "  Found: $subKey" -ForegroundColor Yellow
            try {
                Remove-Item -Path $fullKeyPath -Recurse -Force -ErrorAction Stop
                Write-Host "    Deleted." -ForegroundColor Green
                $userRegRemoved += "$userName\$subKey"
            } catch {
                Write-Warning "    Failed to delete: $($_.Exception.Message)"
            }
        } else {
            Write-Host "  Not present: $subKey" -ForegroundColor Gray
        }
    }
    
    if ($hiveLoaded) {
        Write-Host "  Unloading registry hive..." -ForegroundColor Gray
        $unloadResult = Unload-RegistryHive -KeyPath "HKU\$sidValue"
        
        if (-not $unloadResult) {
            Write-Warning "  Hive may remain loaded until next reboot."
        }
    }
    
    Write-Host ""
}

#-----------------------------------------------------------------------------
# SECTION 10: DELETE INSTALLATION FOLDERS
#-----------------------------------------------------------------------------

Write-Host "--- Removing Installation Folders ---`n" -ForegroundColor Cyan

$foldersToDelete = @(
    "C:\Program Files (x86)\Pulse Secure",
    "C:\Program Files\Pulse Secure",
    "C:\Program Files (x86)\Juniper Networks",
    "C:\Program Files\Juniper Networks",
    "C:\Program Files (x86)\Common Files\Pulse Secure",
    "C:\Program Files\Common Files\Pulse Secure"
)

foreach ($folderPath in $foldersToDelete) {
    if (Test-Path $folderPath) {
        Write-Host "Found: $folderPath"
        
        $remainingFiles = Get-ChildItem -Path $folderPath -Recurse -ErrorAction SilentlyContinue
        if ($remainingFiles) {
            Write-Host "  Contains $($remainingFiles.Count) remaining file(s)" -ForegroundColor Gray
        }
        
        try {
            Remove-Item -Path $folderPath -Recurse -Force -ErrorAction Stop
            Write-Host "  Deleted successfully." -ForegroundColor Green
            $foldersDeleted += $folderPath
        } catch {
            Write-Warning "  Failed to delete: $($_.Exception.Message)"
            Write-Host "  This folder may be deleted after a reboot." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Not present: $folderPath" -ForegroundColor Gray
    }
}

#-----------------------------------------------------------------------------
# SECTION 11: CLEAN UP USER PROFILE DATA
#-----------------------------------------------------------------------------

Write-Host "`n--- Removing User Profile Data ---`n" -ForegroundColor Cyan

$userProfilesPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue).ProfilesDirectory
if (-not $userProfilesPath) { $userProfilesPath = "C:\Users" }

$userFolders = Get-ChildItem $userProfilesPath -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

$userDataFound = $false

foreach ($userFolder in $userFolders) {
    $userName = $userFolder.Name
    
    $appDataPaths = @(
        (Join-Path $userFolder.FullName "AppData\Local\Pulse Secure"),
        (Join-Path $userFolder.FullName "AppData\Roaming\Pulse Secure"),
        (Join-Path $userFolder.FullName "AppData\LocalLow\Pulse Secure"),
        (Join-Path $userFolder.FullName "AppData\Local\Juniper Networks"),
        (Join-Path $userFolder.FullName "AppData\Roaming\Juniper Networks")
    )
    
    $foundForThisUser = $false
    
    foreach ($appDataPath in $appDataPaths) {
        if (Test-Path $appDataPath) {
            if (-not $foundForThisUser) {
                Write-Host "User: $userName" -ForegroundColor Cyan
                $foundForThisUser = $true
                $userDataFound = $true
            }
            
            try {
                Remove-Item -Path $appDataPath -Recurse -Force -ErrorAction Stop
                Write-Host "  Deleted: $appDataPath" -ForegroundColor Green
                $foldersDeleted += $appDataPath
            } catch {
                Write-Warning "  Failed to delete: $appDataPath"
            }
        }
    }
}

if (-not $userDataFound) {
    Write-Host "No user profile data found to remove." -ForegroundColor Gray
}

#-----------------------------------------------------------------------------
# SECTION 12: VERIFICATION
#-----------------------------------------------------------------------------

Write-Host "`n--- Verification ---`n" -ForegroundColor Cyan

$remainingIssues = @()

Write-Host "Checking for remaining installation folders..."
foreach ($folder in $foldersToDelete) {
    if (Test-Path $folder) {
        Write-Host "  Still exists: $folder" -ForegroundColor Yellow
        $remainingIssues += "Folder: $folder"
    }
}

Write-Host "Checking for remaining registry entries..."
$remainingProducts = @(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
) | Where-Object { 
    ($_.Publisher -match 'Pulse Secure|Juniper Networks|Ivanti.*Secure') -or 
    ($_.DisplayName -match 'Pulse Secure|Juniper.*(Setup|Network|Access|VPN)|Ivanti.*(Secure|Connect|Access)') 
}

if ($remainingProducts) {
    Write-Host "  Found remaining registered products:" -ForegroundColor Yellow
    foreach ($product in $remainingProducts) {
        Write-Host "    - $($product.DisplayName)" -ForegroundColor Yellow
        $remainingIssues += "Product: $($product.DisplayName)"
    }
} else {
    Write-Host "  No registered products remaining." -ForegroundColor Green
}

Write-Host "Checking for remaining services..."
$remainingServices = Get-Service -Name "*Pulse*", "*Juniper*" -ErrorAction SilentlyContinue
if ($remainingServices) {
    foreach ($svc in $remainingServices) {
        Write-Host "  Service still exists: $($svc.Name)" -ForegroundColor Yellow
        $remainingIssues += "Service: $($svc.Name)"
    }
} else {
    Write-Host "  No related services remaining." -ForegroundColor Green
}

#-----------------------------------------------------------------------------
# SECTION 12B: FORCE REMOVE ORPHANED REGISTRY ENTRIES
#-----------------------------------------------------------------------------

if ($remainingProducts.Count -gt 0) {
    Write-Host "`n--- Attempting Force Removal of Orphaned Registry Entries ---`n" -ForegroundColor Cyan
    
    foreach ($product in $remainingProducts) {
        $productName = $product.DisplayName
        $productKey = $product.PSPath
        
        $installLocation = $product.InstallLocation
        $uninstallString = $product.UninstallString
        
        $filesExist = $false
        
        if ($installLocation -and (Test-Path $installLocation)) {
            $filesExist = $true
        }
        
        if ($uninstallString -and -not $filesExist) {
            $exePath = $uninstallString -replace '"', '' -replace '\s+/.*$', '' -replace '\s+-.*$', ''
            if ($exePath -and (Test-Path $exePath)) {
                $filesExist = $true
            }
        }
        
        if (-not $filesExist) {
            Write-Host "Product files no longer exist: $productName" -ForegroundColor Yellow
            Write-Host "  Removing orphaned registry entry..." -ForegroundColor Yellow
            
            try {
                Remove-Item -Path $productKey -Recurse -Force -ErrorAction Stop
                Write-Host "  Registry entry removed." -ForegroundColor Green
                $regRemoved += "Orphaned: $productName"
                $remainingIssues = $remainingIssues | Where-Object { $_ -ne "Product: $productName" }
            } catch {
                Write-Warning "  Failed to remove registry entry: $($_.Exception.Message)"
            }
        } else {
            Write-Host "Product files still exist for: $productName" -ForegroundColor Yellow
            Write-Host "  File location: $(if ($installLocation) { $installLocation } else { $exePath })" -ForegroundColor Gray
            Write-Host "  Manual removal may be required." -ForegroundColor Yellow
        }
    }
}

Write-Host ""
if ($remainingIssues.Count -eq 0) {
    Write-Host "VERIFICATION PASSED: All Pulse Secure components have been removed." -ForegroundColor Green
} else {
    Write-Host "VERIFICATION: $($remainingIssues.Count) item(s) may require attention:" -ForegroundColor Yellow
    $remainingIssues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "`nSome items may be removed after a system reboot." -ForegroundColor Gray
}

#-----------------------------------------------------------------------------
# SECTION 13: CHECK FOR INSTALL LOG
#-----------------------------------------------------------------------------

Write-Host "`n--- Checking for Installation Logs ---`n" -ForegroundColor Cyan

$possibleLogLocations = @(
    "C:\Program Files (x86)\Pulse Secure\Pulse\install.log",
    "C:\Program Files\Pulse Secure\Pulse\install.log",
    "$env:TEMP\PulseSecure*.log",
    "$env:TEMP\Juniper*.log"
)

$logFound = $false

foreach ($logPattern in $possibleLogLocations) {
    $logFiles = Get-ChildItem -Path $logPattern -ErrorAction SilentlyContinue
    
    foreach ($logFile in $logFiles) {
        $logFound = $true
        Write-Host "Found log file: $($logFile.FullName)" -ForegroundColor Cyan
        Write-Host "Last 30 lines:" -ForegroundColor Gray
        Write-Host ("-" * 50) -ForegroundColor Gray
        Get-Content $logFile.FullName -Tail 30 -ErrorAction SilentlyContinue | 
            ForEach-Object { Write-Host $_ -ForegroundColor Gray }
        Write-Host ("-" * 50) -ForegroundColor Gray
        Write-Host ""
    }
}

if (-not $logFound) {
    Write-Host "No installation log files found." -ForegroundColor Gray
}

#-----------------------------------------------------------------------------
# SECTION 14: SUMMARY REPORT
#-----------------------------------------------------------------------------

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "           CLEANUP SUMMARY REPORT" -ForegroundColor Cyan
Write-Host "=============================================`n" -ForegroundColor Cyan

Write-Host "Official Uninstaller Executed: " -NoNewline
if ($exeRemoved) {
    Write-Host "Yes" -ForegroundColor Green
} else {
    Write-Host "No (not found)" -ForegroundColor Yellow
}

Write-Host "`nServices Stopped/Disabled: " -NoNewline
if ($servicesRemoved.Count -gt 0) {
    Write-Host "$($servicesRemoved.Count)" -ForegroundColor Green
    $servicesRemoved | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "None found" -ForegroundColor Gray
}

Write-Host "`nProcesses Terminated: " -NoNewline
if ($processesKilled.Count -gt 0) {
    Write-Host "$($processesKilled.Count)" -ForegroundColor Green
    $processesKilled | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "None found" -ForegroundColor Gray
}

Write-Host "`nComponents Uninstalled: " -NoNewline
if ($removedComponents.Count -gt 0) {
    Write-Host "$($removedComponents.Count)" -ForegroundColor Green
    $removedComponents | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "None found/removed" -ForegroundColor Gray
}

Write-Host "`nActiveX Controls Removed: " -NoNewline
if ($activeXRemoved.Count -gt 0) {
    Write-Host "$($activeXRemoved.Count)" -ForegroundColor Green
    $activeXRemoved | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "None found" -ForegroundColor Gray
}

Write-Host "`nSystem Registry Keys Removed: " -NoNewline
if ($regRemoved.Count -gt 0) {
    Write-Host "$($regRemoved.Count)" -ForegroundColor Green
    $regRemoved | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "None found" -ForegroundColor Gray
}

Write-Host "`nPer-User Registry Keys Removed: " -NoNewline
if ($userRegRemoved.Count -gt 0) {
    Write-Host "$($userRegRemoved.Count)" -ForegroundColor Green
    $userRegRemoved | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "None found" -ForegroundColor Gray
}

Write-Host "`nFolders Deleted: " -NoNewline
if ($foldersDeleted.Count -gt 0) {
    Write-Host "$($foldersDeleted.Count)" -ForegroundColor Green
    $foldersDeleted | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "None found" -ForegroundColor Gray
}

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "             CLEANUP COMPLETE" -ForegroundColor Cyan
Write-Host "=============================================`n" -ForegroundColor Cyan

if ($remainingIssues.Count -gt 0) {
    Write-Host "NOTE: Some items could not be fully removed." -ForegroundColor Yellow
    Write-Host "A system REBOOT is recommended to complete cleanup." -ForegroundColor Yellow
} else {
    Write-Host "All Pulse Secure components have been successfully removed." -ForegroundColor Green
    Write-Host "A system reboot is recommended to ensure all changes take effect." -ForegroundColor Gray
}

if (-not $Silent) {
    Write-Host "`nPress any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} else {
    Write-Host "`nScript completed in silent mode." -ForegroundColor Green
}

#=============================================================================
# END OF SCRIPT
#=============================================================================