[CmdletBinding()]
param(
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

if (-not $IsWindows -and $env:OS -ne "Windows_NT") {
    throw "This cleanup script is for Windows."
}

$HostName = "com.localgatekeys.app"
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\LocalGateKeys"
$DataDir = Join-Path $env:LOCALAPPDATA "LocalGateKeys"

# Stop the current user's installed processes when possible.
Get-Process -Name "localgatekeys-agent","localgatekeys-native-host" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

foreach ($key in @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName",
    "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName"
)) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $key
}

$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path $RunKey -Name "LocalGateKeys" -ErrorAction SilentlyContinue

# Remove only the current user's shortcuts created by the LocalGateKeys installer.
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "LocalGateKeys.lnk"
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "LocalGateKeys"
Remove-Item -Force -ErrorAction SilentlyContinue $DesktopShortcut
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StartMenuDir

if (Test-Path $InstallRoot) {
    Remove-Item -Recurse -Force $InstallRoot
}

if ($RemoveData) {
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir
    }
    Write-Host "Removed the current-user LocalGateKeys installation and encrypted local data." -ForegroundColor Green
} else {
    # Preserve vault/profile data by default.
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "$HostName.json")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "$HostName.firefox.json")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "install.json")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "agent-state.json")

    Write-Host "Removed LocalGateKeys from %LOCALAPPDATA%\Programs for this Windows user." -ForegroundColor Green
    Write-Host "Encrypted LocalGateKeys profile data was preserved at: $DataDir"
    Write-Host "Use -RemoveData only if you intentionally want to erase the encrypted profiles too."
}
