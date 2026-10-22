#Requires -Version 5.1
<#
.SYNOPSIS
    Removes Microsoft Edge, Edge Update, and optionally WebView2 from Windows 10/11.

.DESCRIPTION
    Production uninstaller that combines:
      1. Integrated Services Region policy unlock (non-EU official uninstall path)
      2. Native setup.exe silent uninstall
      3. AppX / provisioned package cleanup
      4. Services, scheduled tasks, folders, and orphan registry cleanup
      5. Reinstall blocking via EdgeUpdate policy keys

    Based on the public CyberCPU Tech method for IntegratedServicesRegionPolicySet.json:
    https://www.youtube.com/watch?v=nE5avDD2rnY

.PARAMETER RemoveWebView2
    Also remove Microsoft Edge WebView2 Runtime. May break apps that embed WebView2.

.PARAMETER SkipRegionPolicy
    Skip editing IntegratedServicesRegionPolicySet.json (EU devices or if already patched).

.PARAMETER SkipReinstallBlock
    Do not write registry keys that block Edge from being reinstalled by Windows Update.

.PARAMETER SkipAppDataCleanup
    Do not delete user-level Edge profile folders under AppData.

.PARAMETER Force
    Run without interactive confirmation prompts.

.PARAMETER NoRebootPrompt
    Do not suggest or offer a reboot at the end.

.EXAMPLE
    .\edge-remover.ps1

.EXAMPLE
    .\edge-remover.ps1 -RemoveWebView2 -Force

.NOTES
    Tested on Windows 10/11 x64. Requires Administrator. Not supported on Windows S Mode.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$RemoveWebView2,
    [switch]$SkipRegionPolicy,
    [switch]$SkipReinstallBlock,
    [switch]$SkipAppDataCleanup,
    [switch]$Force,
    [switch]$NoRebootPrompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Bootstrap / elevation ---

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevation {
    $argList = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', ('"{0}"' -f $PSCommandPath)
    )

    foreach ($name in @(
            'RemoveWebView2', 'SkipRegionPolicy', 'SkipReinstallBlock',
            'SkipAppDataCleanup', 'Force', 'NoRebootPrompt'
        )) {
        if (Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue) {
            $argList += ('-{0}' -f $name)
        }
    }

    Write-Host '[*] Administrator privileges required. Accept the UAC prompt to continue.' -ForegroundColor Cyan
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -Wait
    exit $LASTEXITCODE
}

if (-not (Test-IsAdministrator)) {
    Invoke-SelfElevation
}

#endregion

#region --- Logging helpers ---

function Write-Step([string]$Message) {
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-WarnMsg([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-ErrMsg([string]$Message) {
    Write-Host "[x] $Message" -ForegroundColor Red
}

function Write-Detail([string]$Message) {
    Write-Host "    $Message" -ForegroundColor DarkGray
}

#endregion

#region --- Core helpers ---

function Stop-EdgeProcesses {
    Write-Step 'Stopping Edge-related processes...'
    $names = @('msedge', 'msedgewebview2', 'MicrosoftEdgeUpdate', 'MicrosoftEdge')
    foreach ($name in $names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Detail "Stopping $($_.ProcessName) (PID $($_.Id))"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 2
}

function Stop-EdgeServices {
    Write-Step 'Stopping and disabling Edge update services...'
    foreach ($serviceName in @('edgeupdate', 'edgeupdatem')) {
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Detail "Service not present: $serviceName"
            continue
        }
        try {
            if ($svc.Status -ne 'Stopped') {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
            }
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Detail "Stopped and disabled: $serviceName"
        }
        catch {
            Write-WarnMsg "Could not stop service $serviceName : $($_.Exception.Message)"
        }
    }
}

function Disable-EdgeScheduledTasks {
    Write-Step 'Disabling Edge scheduled tasks...'
    $knownTasks = @(
        '\MicrosoftEdgeUpdateTaskMachineCore',
        '\MicrosoftEdgeUpdateTaskMachineUA',
        '\MicrosoftEdgeUpdateTaskUserCore',
        '\MicrosoftEdgeUpdateTaskUserUA'
    )

    foreach ($taskPath in $knownTasks) {
        $taskName = Split-Path -Leaf $taskPath
        $folder = Split-Path -Parent $taskPath
        if ($folder -eq '\') { $folder = '\' }
        try {
            Disable-ScheduledTask -TaskName $taskName -TaskPath $folder -ErrorAction Stop | Out-Null
            Unregister-ScheduledTask -TaskName $taskName -TaskPath $folder -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            Write-Detail "Removed task: $taskPath"
        }
        catch {
            Write-Detail "Task not found or already removed: $taskPath"
        }
    }

    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -match 'Edge' -or $_.TaskPath -match 'Edge' } |
        ForEach-Object {
            try {
                Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue | Out-Null
                Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                Write-Detail "Removed task: $($_.TaskPath)$($_.TaskName)"
            }
            catch {
                Write-Detail "Could not remove task: $($_.TaskName)"
            }
        }
}

function Enable-EdgeRegionPolicies {
    param(
        [string]$PolicyFile = "$env:Windir\System32\IntegratedServicesRegionPolicySet.json"
    )

    if ($SkipRegionPolicy) {
        Write-WarnMsg 'Skipping Integrated Services Region policy patch (-SkipRegionPolicy).'
        return $false
    }

    if (-not (Test-Path -LiteralPath $PolicyFile)) {
        Write-WarnMsg "Policy file not found (older Windows build?): $PolicyFile"
        return $false
    }

    Write-Step 'Patching IntegratedServicesRegionPolicySet.json (non-EU uninstall unlock)...'

    $backupFile = Join-Path $env:TEMP ('IntegratedServicesRegionPolicySet.json.{0}.bak' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Copy-Item -LiteralPath $PolicyFile -Destination $backupFile -Force
    Write-Detail "Backup saved: $backupFile"

    & takeown.exe /f $PolicyFile /a | Out-Null
    & icacls.exe $PolicyFile /grant 'Administrators:(F)' /grant 'SYSTEM:(F)' | Out-Null

    $content = Get-Content -LiteralPath $PolicyFile -Raw -Encoding UTF8
    $targets = @(
        'Edge is uninstallable.',
        'User can disable web search.',
        'Third party search providers show in search.'
    )

    $changed = 0
    foreach ($target in $targets) {
        $pattern = '(?s)(\{\s*"\$comment":\s*"' + [regex]::Escape($target) + '".*?"defaultState":\s*")disabled(")'
        if ($content -match $pattern) {
            $content = [regex]::Replace($content, $pattern, '${1}enabled${2}', 1)
            Write-Detail "Enabled policy: $target"
            $changed++
        }
        elseif ($content -match ('(?s)"\$comment":\s*"' + [regex]::Escape($target) + '".*?"defaultState":\s*"enabled"')) {
            Write-Detail "Already enabled: $target"
        }
        else {
            Write-WarnMsg "Policy block not found: $target"
        }
    }

    if ($changed -gt 0) {
        Set-Content -LiteralPath $PolicyFile -Value $content -Encoding UTF8 -NoNewline
        Write-Ok "Region policy file updated ($changed change(s))."
    }
    else {
        Write-Ok 'Region policy file already patched or partially patched.'
    }

    return $true
}

function Invoke-NativeEdgeUninstall {
    param(
        [ValidateSet('Edge', 'WebView')]
        [string]$Component
    )

    $relativePaths = @{
        Edge    = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe"
        WebView = "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application\*\Installer\setup.exe"
    }

    $argsByComponent = @{
        Edge    = @('--uninstall', '--system-level', '--verbose-logging', '--force-uninstall')
        WebView = @('--uninstall', '--msedgewebview', '--system-level', '--verbose-logging', '--force-uninstall')
    }

    $setups = @(Get-ChildItem -Path $relativePaths[$Component] -ErrorAction SilentlyContinue)
    if ($setups.Count -eq 0) {
        Write-Detail "No $Component setup.exe found."
        return @()
    }

    $exitCodes = @()
    foreach ($setup in $setups) {
        Write-Step "Running native uninstaller for $Component : $($setup.FullName)"
        $proc = Start-Process -FilePath $setup.FullName -ArgumentList $argsByComponent[$Component] -Wait -PassThru -WindowStyle Hidden
        $code = $proc.ExitCode
        $exitCodes += $code
        if ($code -eq 0) {
            Write-Ok "$Component uninstaller exit code: 0"
        }
        elseif ($code -eq 532) {
            Write-WarnMsg "$Component uninstaller exit code 532 (reboot may be required before uninstall completes)."
        }
        else {
            Write-WarnMsg "$Component uninstaller exit code: $code"
        }
    }

    return $exitCodes
}


function Remove-EdgeAppxPackages {
    Write-Step 'Removing Edge-related AppX packages...'

    $includeWebView = [bool]$RemoveWebView2

    $patterns = @(
        'MicrosoftEdge'
        'Microsoft\.MicrosoftEdge'
    )

    if ($includeWebView) {
        $patterns += 'WebView'
    }

    $matchesPattern = {
        param([string]$Name)

        if ([string]::IsNullOrWhiteSpace($Name)) {
            return $false
        }

        foreach ($pattern in $patterns) {
            if ($Name -match $pattern) {
                return $true
            }
        }

        return $false
    }

    Write-Step 'Searching installed Edge AppX packages...'

    $installedPackages = @(
        Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    )

    foreach ($package in $installedPackages) {
        $name = $package.Name

        if (-not (& $matchesPattern $name)) {
            continue
        }

        if (-not $includeWebView -and $name -match 'WebView') {
            continue
        }

        Write-Detail "Removing AppX: $($package.PackageFullName)"

        try {
            Remove-AppxPackage `
                -Package $package.PackageFullName `
                -AllUsers `
                -ErrorAction Stop

            Write-Detail "Successfully removed: $($package.PackageFullName)"
        }
        catch {
            Write-Detail "Failed to remove $($package.PackageFullName): $($_.Exception.Message)"
        }
    }

    Write-Step 'Searching provisioned Edge AppX packages...'

    $provisionedPackages = @(
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    )

    foreach ($package in $provisionedPackages) {
        $name = $package.DisplayName

        if (-not (& $matchesPattern $name)) {
            continue
        }

        if (-not $includeWebView -and $name -match 'WebView') {
            continue
        }

        Write-Detail "Removing provisioned package: $($package.DisplayName)"

        try {
            Remove-AppxProvisionedPackage `
                -Online `
                -PackageName $package.PackageName `
                -ErrorAction Stop |
                Out-Null

            Write-Detail "Successfully removed provisioned package: $($package.DisplayName)"
        }
        catch {
            Write-Detail "Failed to remove provisioned package $($package.DisplayName): $($_.Exception.Message)"
        }
    }

    Write-Step 'Edge-related AppX package removal completed.'
}


function Remove-EdgeDirectories {
    Write-Step 'Removing leftover Edge directories...'

    $folders = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeCore",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate"
    )
    if ($RemoveWebView2) {
        $folders += "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView"
    }

    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) {
            continue
        }
        try {
            & takeown.exe /f $folder /r /d y | Out-Null
            & icacls.exe $folder /grant 'Administrators:(F)' /t /c | Out-Null
            Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction Stop
            Write-Detail "Removed: $folder"
        }
        catch {
            Write-WarnMsg "Could not fully remove $folder : $($_.Exception.Message)"
        }
    }
}

function Remove-EdgeUserData {
    if ($SkipAppDataCleanup) {
        Write-WarnMsg 'Skipping AppData cleanup (-SkipAppDataCleanup).'
        return
    }

    Write-Step 'Removing user-level Edge data folders...'
    $relativePaths = @(
        'Local\Microsoft\Edge',
        'Local\Microsoft\EdgeUpdate',
        'Local\Microsoft\Edge User Data'
    )
    if ($RemoveWebView2) {
        $relativePaths += 'Local\Microsoft\EdgeWebView'
    }

    $userRoots = @($env:LOCALAPPDATA)
    try {
        $userRoots += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'AppData\Local' }
    }
    catch {
        Write-Detail 'Could not enumerate all user profiles for AppData cleanup.'
    }

    foreach ($root in ($userRoots | Select-Object -Unique)) {
        foreach ($rel in $relativePaths) {
            $path = Join-Path $root $rel
            if (Test-Path -LiteralPath $path) {
                try {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                    Write-Detail "Removed: $path"
                }
                catch {
                    Write-WarnMsg "Could not remove $path : $($_.Exception.Message)"
                }
            }
        }
    }
}

function Set-EdgeReinstallBlock {
    if ($SkipReinstallBlock) {
        Write-WarnMsg 'Skipping reinstall block registry keys (-SkipReinstallBlock).'
        return
    }

    Write-Step 'Applying registry keys to discourage Edge reinstall via Windows Update...'

    # Microsoft Edge Update application GUIDs (Stable vs WebView2 are separate products).
    $edgeStableGuid = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
    $webView2Guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'

    $edgeUpdateKey = 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate'
    if (-not (Test-Path $edgeUpdateKey)) {
        New-Item -Path $edgeUpdateKey -Force | Out-Null
    }
    New-ItemProperty -Path $edgeUpdateKey -Name 'DoNotUpdateToEdgeWithChromium' -Value 1 -PropertyType DWord -Force | Out-Null

    $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
    if (-not (Test-Path $policyKey)) {
        New-Item -Path $policyKey -Force | Out-Null
    }

    New-ItemProperty -Path $policyKey -Name 'InstallDefault' -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $policyKey -Name 'UpdateDefault' -Value 0 -PropertyType DWord -Force | Out-Null

    $productGuids = @($edgeStableGuid)
    if ($RemoveWebView2) {
        $productGuids += $webView2Guid
    }

    foreach ($guid in $productGuids) {
        foreach ($prefix in @('Install', 'Update', 'Uninstall')) {
            $valueName = '{0}{1}' -f $prefix, $guid
            New-ItemProperty -Path $policyKey -Name $valueName -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Detail "Set $valueName = 0"
        }
    }

    Write-Ok 'Reinstall block registry keys written.'
}


function Remove-OrphanUninstallEntries {
    Write-Step 'Cleaning orphan uninstall registry entries...'

    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $targetNames = @(
        'Microsoft Edge',
        'Microsoft Edge WebView2 Runtime'
    )

    foreach ($regPath in $paths) {
        if (-not (Test-Path -LiteralPath $regPath)) {
            continue
        }

        $entries = @(
            Get-ChildItem -LiteralPath $regPath -ErrorAction SilentlyContinue
        )

        foreach ($entry in $entries) {
            try {
                $properties = Get-ItemProperty `
                    -LiteralPath $entry.PSPath `
                    -ErrorAction Stop

                $displayName = $properties.DisplayName
                $uninstallString = $properties.UninstallString

                if ([string]::IsNullOrWhiteSpace([string]$displayName)) {
                    continue
                }

                if ($targetNames -notcontains $displayName) {
                    continue
                }

                if ([string]::IsNullOrWhiteSpace([string]$uninstallString)) {
                    continue
                }

                if ($uninstallString -notmatch '(?i)setup\.exe') {
                    continue
                }

                $setupPath = $null

                if ($uninstallString -match '"([^"]*setup\.exe)"') {
                    $setupPath = $Matches[1]
                }
                elseif ($uninstallString -match '(?i)([A-Za-z]:\\.*?setup\.exe)') {
                    $setupPath = $Matches[1].Trim('"')
                }

                if ([string]::IsNullOrWhiteSpace($setupPath)) {
                    Write-Detail "Cannot determine setup.exe path for: $displayName"
                    continue
                }

                if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
                    Write-Detail "Removing orphan entry: $displayName"
                    Write-Detail "Registry key: $($entry.Name)"
                    Write-Detail "Missing executable: $setupPath"

                    Remove-Item `
                        -LiteralPath $entry.PSPath `
                        -Recurse `
                        -Force `
                        -ErrorAction Stop

                    Write-Detail "Successfully removed orphan entry: $displayName"
                }
            }
            catch {
                Write-Detail "Failed to process registry entry '$($entry.Name)': $($_.Exception.Message)"
            }
        }
    }

    Write-Step 'Orphan uninstall registry cleanup completed.'
}


function Enable-EdgeUninstallRegistry {
    Write-Step 'Enabling uninstall flags in Edge uninstall registry keys...'
    $keys = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView'
    )
    foreach ($key in $keys) {
        if (Test-Path $key) {
            New-ItemProperty -Path $key -Name 'NoRemove' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Detail "NoRemove=0: $key"
        }
    }
}

function Get-EdgeRemovalStatus {
    $status = [ordered]@{
        EdgeFolderExists    = Test-Path "${env:ProgramFiles(x86)}\Microsoft\Edge"
        WebViewFolderExists = Test-Path "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView"
        EdgeUpdateFolder    = Test-Path "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate"
        MsEdgeCommand       = [bool](Get-Command msedge -ErrorAction SilentlyContinue)
        EdgeAppxCount       = @(
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'Edge' -and ($RemoveWebView2 -or $_.Name -notmatch 'WebView') }
        ).Count
    }
    return $status
}

#endregion

#region --- Main ---

Write-Host ''
Write-Host '============================================================' -ForegroundColor White
Write-Host ' Microsoft Edge Remover (edge-remover)' -ForegroundColor White
Write-Host ' Windows 10 / 11  |  Administrator required' -ForegroundColor DarkGray
Write-Host '============================================================' -ForegroundColor White
Write-Host ''

if (-not $Force) {
    $scope = 'Microsoft Edge browser, Edge Update, and Edge Core'
    if ($RemoveWebView2) {
        $scope += ', and Edge WebView2 Runtime'
    }
    Write-WarnMsg "This will remove: $scope"
    Write-WarnMsg 'Some Windows features and third-party apps may depend on WebView2.'
    $answer = Read-Host 'Type YES to continue'
    if ($answer -ne 'YES') {
        Write-ErrMsg 'Aborted by user.'
        exit 1
    }
}

try {
    Stop-EdgeProcesses
    Stop-EdgeServices
    Disable-EdgeScheduledTasks
    $policyPatched = Enable-EdgeRegionPolicies
    Enable-EdgeUninstallRegistry

    Invoke-NativeEdgeUninstall -Component 'Edge' | Out-Null
    if ($RemoveWebView2) {
        Invoke-NativeEdgeUninstall -Component 'WebView' | Out-Null
    }

    Remove-EdgeAppxPackages
    Remove-EdgeDirectories
    Remove-EdgeUserData
    Set-EdgeReinstallBlock
    Remove-OrphanUninstallEntries

    $status = Get-EdgeRemovalStatus
    Write-Host ''
    Write-Host '--- Verification ---' -ForegroundColor White
    Write-Detail "Edge folder present     : $($status.EdgeFolderExists)"
    Write-Detail "WebView folder present  : $($status.WebViewFolderExists)"
    Write-Detail "EdgeUpdate folder       : $($status.EdgeUpdateFolder)"
    Write-Detail "msedge command available: $($status.MsEdgeCommand)"
    Write-Detail "Edge AppX packages left : $($status.EdgeAppxCount)"

    $edgeRemoved = -not $status.EdgeFolderExists -and -not $status.MsEdgeCommand
    $webViewRemoved = (-not $RemoveWebView2) -or (-not $status.WebViewFolderExists)

    if ($edgeRemoved -and $webViewRemoved) {
        Write-Ok 'Microsoft Edge removal completed successfully.'
    }
    else {
        Write-WarnMsg 'Edge may be partially removed.'
        if ($policyPatched) {
            Write-WarnMsg 'Reboot, then try Settings > Apps > Microsoft Edge > Uninstall if a ghost entry remains.'
        }
    }

    if (-not $NoRebootPrompt) {
        Write-Host ''
        Write-WarnMsg 'A reboot is recommended so Windows refreshes app lists and policy changes.'
        if (-not $Force) {
            $reboot = Read-Host 'Reboot now? (y/N)'
            if ($reboot -match '^[Yy]$') {
                shutdown.exe /r /t 15 /c 'edge-remover: rebooting to finalize Edge removal'
                Write-Ok 'Reboot scheduled in 15 seconds. Run shutdown /a to cancel.'
            }
        }
    }
}
catch {
    Write-ErrMsg $_.Exception.Message
    exit 1
}

Write-Host ''
exit 0

#endregion
