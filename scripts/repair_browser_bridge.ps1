[CmdletBinding()]
param([string]$ExtensionId = "hojebpmbiibhbhhkohgongojilojijmb")
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This script requires Windows.' }
if ($ExtensionId -notmatch '^[a-p]{32}$') { throw 'Invalid extension ID.' }
# Repair the copy containing this script. Do not install/copy the program into AppData.
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$Python = Join-Path $Root '.venv\Scripts\python.exe'
$HostExe = Join-Path $Root '.venv\Scripts\localgatekeys-native-host.exe'
$Mode = 'repository'
$ExtensionRoot = Join-Path $Root 'browser-extension'
# An explicitly installed private app copy keeps its environment one directory up.
# This fallback never copies/installs a program; it repairs only that selected copy.
if (!(Test-Path -LiteralPath $Python) -and (Split-Path $Root -Leaf) -eq 'app') {
    $InstallRoot = Split-Path $Root -Parent
    $InstalledPython = Join-Path $InstallRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $InstalledPython) {
        $Python = $InstalledPython
        $HostExe = Join-Path $InstallRoot '.venv\Scripts\localgatekeys-native-host.exe'
        $ExtensionRoot = Join-Path $InstallRoot 'browser-extension'
        $Mode = 'installed'
    }
}
if (!(Test-Path -LiteralPath $Python) -or !(Test-Path -LiteralPath $HostExe)) {
    throw 'Repository virtual environment/launcher missing. Run .\.venv\Scripts\python.exe -m pip install -e . first.'
}
$DataDir = Join-Path $env:LOCALAPPDATA 'LocalGateKeys'
if ($env:LOCALGATEKEYS_DATA_DIR) { $DataDir = $env:LOCALGATEKEYS_DATA_DIR }
$HostName = 'com.localgatekeys.app'
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
# Restrict the data directory to the current Windows user without requiring
# SeSecurityPrivilege.  Set-Acl can attempt to write security descriptor
# sections that non-elevated users are not permitted to change on some systems.
# icacls is used here to modify only the DACL that LocalGateKeys needs.
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$SidValue = $Identity.User.Value

# Grant this SID first, so removing inherited ACEs cannot temporarily remove
# our own access. These are DACL-only edits, not owner/SACL updates.
$Grant = "*$SidValue`:(OI)(CI)F"
& icacls.exe $DataDir /grant:r $Grant | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not apply current-user permissions to LocalGateKeys data directory."
}
& icacls.exe $DataDir /inheritance:r | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not disable inherited permissions on LocalGateKeys data directory."
}
$Utf8 = New-Object Text.UTF8Encoding($false)
$Origin = "chrome-extension://$ExtensionId/"
# Mirrors localvault.browser_bridge: Chromium browsers share one manifest
# (allowed_origins); Firefox gets its own manifest (allowed_extensions with the
# Gecko add-on id, FIREFOX_EXTENSION_ID) under the Mozilla registry root.
$FirefoxExtensionId = 'localgatekeys@localgatekeys.app'
$ManifestPath = Join-Path $DataDir "$HostName.json"
$FirefoxManifestPath = Join-Path $DataDir "$HostName.firefox.json"
$Manifest = [ordered]@{name=$HostName; description='LocalGateKeys browser bridge'; path=$HostExe; type='stdio'; allowed_origins=@($Origin)}
[IO.File]::WriteAllText($ManifestPath, ($Manifest | ConvertTo-Json -Depth 5), $Utf8)
$FirefoxManifest = [ordered]@{name=$HostName; description='LocalGateKeys browser bridge'; path=$HostExe; type='stdio'; allowed_extensions=@($FirefoxExtensionId)}
[IO.File]::WriteAllText($FirefoxManifestPath, ($FirefoxManifest | ConvertTo-Json -Depth 5), $Utf8)
# New-Item -Force and Set-Item are idempotent: re-running only refreshes the paths.
foreach ($Browser in @('Google\Chrome', 'Microsoft\Edge')) {
    $Key = "HKCU:\Software\$Browser\NativeMessagingHosts\$HostName"
    New-Item -Force -Path $Key | Out-Null
    Set-Item -Path $Key -Value $ManifestPath
}
$FirefoxKey = "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName"
New-Item -Force -Path $FirefoxKey | Out-Null
Set-Item -Path $FirefoxKey -Value $FirefoxManifestPath
$ActualInterpreter = (& $Python -c "import os,psutil; print(psutil.Process(os.getpid()).exe())").Trim()
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $ActualInterpreter)) { throw 'Cannot identify Python executable.' }
$Config = [ordered]@{
    version=7; bridge_revision='024'; product='LocalGateKeys'; scope='current_user'; mode=$Mode; install_root=$Root;
    allowed_extension_origins=@($Origin); allowed_firefox_extensions=@($FirefoxExtensionId); native_host_path=$HostExe;
    native_host_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $HostExe).Hash;
    interpreter_path=$ActualInterpreter; interpreter_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $ActualInterpreter).Hash;
    # A venv python.exe can start the base interpreter as a separate process.
    # Pin this one specific intermediate executable as well as the actual Python.
    venv_redirector_path=$Python; venv_redirector_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $Python).Hash
}
[IO.File]::WriteAllText((Join-Path $DataDir 'install.json'), ($Config | ConvertTo-Json -Depth 5), $Utf8)
& $Python -c "import json; from localvault.native_host import self_test; print(json.dumps(self_test(), indent=2))"
if ($LASTEXITCODE -ne 0) { throw 'Native host self-test failed.' }
Write-Host 'Current-user bridge repaired. No program was copied to AppData; profiles were not changed.' -ForegroundColor Green
Write-Host "Reload the extension from: $ExtensionRoot"
Write-Host "Firefox: native-messaging manifest registered at $FirefoxKey (temporary add-on from npm run build:firefox)."

Write-Host 'Bridge patch 024: launcher, Python interpreter and venv redirector pins refreshed.'
Write-Host 'Exit the running app (including tray) and restart it from this repository.'
Write-Host 'Then choose a profile and use the browser extension Connection test.'
Write-Host 'For a read-only diagnostic report: .\scripts\test_browser_bridge.ps1'
