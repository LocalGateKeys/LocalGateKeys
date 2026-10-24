[CmdletBinding()]
param(
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
if (-not $IsWindows -and $env:OS -ne "Windows_NT") { throw "This uninstaller is for Windows." }

$HostName = "com.localgatekeys.app"
foreach ($key in @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName",
    "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName",
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.localvault.prototype",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.localvault.prototype"
)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $key }

$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
foreach ($value in @("LocalGateKeys", "LocalVaultPrototype")) {
    Remove-ItemProperty -Path $RunKey -Name $value -ErrorAction SilentlyContinue
}

$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\LocalGateKeys"
if (Test-Path $InstallRoot) { Remove-Item -Recurse -Force $InstallRoot }

$DataDir = Join-Path $env:LOCALAPPDATA "LocalGateKeys"
if ($RemoveData) {
    if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
    Write-Host "LocalGateKeys and this user's local vault data were removed." -ForegroundColor Green
} else {
    # Preserve vaults by default. Remove only generated bridge/install state.
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "$HostName.json")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "$HostName.firefox.json")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "install.json")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataDir "agent-state.json")
    Write-Host "LocalGateKeys was removed. Encrypted profile data was preserved at $DataDir" -ForegroundColor Green
    Write-Host "Run again with -RemoveData only if you intentionally want to delete it."
}
