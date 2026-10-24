[CmdletBinding()]
param(
    [string]$ExtensionId = "hojebpmbiibhbhhkohgongojilojijmb"
)

$ErrorActionPreference = "Stop"
if (-not $IsWindows -and $env:OS -ne "Windows_NT") {
    throw "This installer is for Windows."
}
if ($ExtensionId -notmatch '^[a-p]{32}$') {
    throw "ExtensionId must be a 32-character Chromium extension ID."
}

# Per-user installation only. Nothing is written to Program Files or HKLM and
# the script intentionally does not request elevation.
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\LocalGateKeys"
$AppRoot = Join-Path $InstallRoot "app"
$Venv = Join-Path $InstallRoot ".venv"
$ExtensionRoot = Join-Path $InstallRoot "browser-extension"
$DataDir = Join-Path $env:LOCALAPPDATA "LocalGateKeys"

New-Item -ItemType Directory -Force -Path $InstallRoot, $AppRoot, $DataDir | Out-Null

# Copy only application source needed by the installed Python package. pip then
# installs from this user-owned private copy, so the installed program does not
# depend on the development folder remaining in place.
foreach ($name in @("pyproject.toml", "LICENSE", "README.md")) {
    $source = Join-Path $SourceRoot $name
    if (Test-Path $source) { Copy-Item -Force $source (Join-Path $AppRoot $name) }
}
# Runtime dependencies come only from the hash-pinned lock (see below).
$LockSource = Join-Path $SourceRoot "requirements.lock.txt"
if (-not (Test-Path -LiteralPath $LockSource -PathType Leaf)) { throw "Missing requirements.lock.txt in $SourceRoot." }
Copy-Item -Force $LockSource (Join-Path $AppRoot "requirements.lock.txt")
# The build backend (setuptools, wheel) for installing the app itself, hash-pinned too.
$BuildLockSource = Join-Path $SourceRoot "requirements-build.lock.txt"
if (-not (Test-Path -LiteralPath $BuildLockSource -PathType Leaf)) { throw "Missing requirements-build.lock.txt in $SourceRoot." }
Copy-Item -Force $BuildLockSource (Join-Path $AppRoot "requirements-build.lock.txt")
# The window is a WebView2 page built from webui\ into src\localvault\assets\ui (needs Node.js once).
$UiIndex = Join-Path $SourceRoot "src\localvault\assets\ui\index.html"
$Npm = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
if ($Npm -and (Test-Path -LiteralPath (Join-Path $SourceRoot "webui\package.json"))) {
    Push-Location (Join-Path $SourceRoot "webui")
    try {
        & $Npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed for webui." }
        & $Npm run build
        if ($LASTEXITCODE -ne 0) { throw "The webui build failed." }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path -LiteralPath $UiIndex -PathType Leaf)) {
    throw "The LocalGateKeys window is not built. Install Node.js 20+ and run this script again."
}
if (Test-Path (Join-Path $AppRoot "src")) { Remove-Item -Recurse -Force (Join-Path $AppRoot "src") }
Copy-Item -Recurse -Force (Join-Path $SourceRoot "src") (Join-Path $AppRoot "src")
# UI assets and repair tools belong to the private application copy too.
foreach ($name in @("assets", "scripts")) {
    $source = Join-Path $SourceRoot $name
    $destination = Join-Path $AppRoot $name
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw "Missing application folder: $name" }
    if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force }
    Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
}
if (Test-Path $ExtensionRoot) { Remove-Item -Recurse -Force $ExtensionRoot }
Copy-Item -Recurse -Force (Join-Path $SourceRoot "browser-extension") $ExtensionRoot

$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) {
    if ($Python) {
        & py -3 -m venv $Venv
    } else {
        $Python = Get-Command python -ErrorAction Stop
        & $Python.Source -m venv $Venv
    }
}
$VenvPython = Join-Path $Venv "Scripts\python.exe"
# The lock pins wheels (numpy 2.5 among them) that need Python 3.12 or newer.
& $VenvPython -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "LocalGateKeys needs Python 3.12 or newer. Install it, delete $Venv and run this script again."
}
# Every third-party package comes from the hash-pinned locks; a download whose
# hash does not match is refused. The app itself is installed without
# dependencies and without build isolation (which would fetch setuptools and
# wheel unpinned), using the hash-pinned build backend instead.
& $VenvPython -m pip install --require-hashes -r (Join-Path $AppRoot "requirements.lock.txt")
if ($LASTEXITCODE -ne 0) { throw "Locked dependency installation failed." }
& $VenvPython -m pip install --require-hashes -r (Join-Path $AppRoot "requirements-build.lock.txt")
if ($LASTEXITCODE -ne 0) { throw "Locked build backend installation failed." }
& $VenvPython -m pip install --no-deps --no-build-isolation -e $AppRoot
if ($LASTEXITCODE -ne 0) { throw "LocalGateKeys package installation failed." }

$HostExe = Join-Path $Venv "Scripts\localgatekeys-native-host.exe"
$AgentExe = Join-Path $Venv "Scripts\localgatekeys-agent.exe"
if (-not (Test-Path $HostExe) -or -not (Test-Path $AgentExe)) {
    throw "LocalGateKeys launchers were not created correctly."
}

# High-resolution per-user shortcuts. The ICO contains 16..256 px variants so
# Windows can choose the correct taskbar/Start/Desktop size without scaling a
# tiny bitmap. No all-users shortcut or elevated write is performed.
$IconPath = Join-Path $AppRoot "assets\icons\localgatekeys.ico"
if (-not (Test-Path -LiteralPath $IconPath -PathType Leaf)) {
    throw "Missing LocalGateKeys multi-resolution icon: $IconPath"
}
$WshShell = New-Object -ComObject WScript.Shell
$DesktopDir = [Environment]::GetFolderPath("Desktop")
$ProgramsDir = [Environment]::GetFolderPath("Programs")
$StartMenuDir = Join-Path $ProgramsDir "LocalGateKeys"
New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
foreach ($ShortcutPath in @(
    (Join-Path $DesktopDir "LocalGateKeys.lnk"),
    (Join-Path $StartMenuDir "LocalGateKeys.lnk")
)) {
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $AgentExe
    $Shortcut.WorkingDirectory = $InstallRoot
    $Shortcut.IconLocation = "$IconPath,0"
    # ASCII source only: Windows PowerShell 5.1 reads a BOM-less script as ANSI, so a
    # literal em dash breaks parsing. Build it from its code point instead.
    $Shortcut.Description = "LocalGateKeys $([char]0x2014) Your Keys. Your Control."
    $Shortcut.Save()
}

# Restrict the installation and data directories to the current Windows SID.
$CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($path in @($InstallRoot, $DataDir)) {
    & icacls $path /inheritance:r /grant:r "*${CurrentSid}:(OI)(CI)F" | Out-Null
}

$HostName = "com.localgatekeys.app"
$ManifestPath = Join-Path $DataDir "$HostName.json"
# Firefox uses allowed_extensions with the Gecko add-on id (mirrors localvault.browser_bridge).
$FirefoxExtensionId = "localgatekeys@localgatekeys.app"
$FirefoxManifestPath = Join-Path $DataDir "$HostName.firefox.json"
$AllowedOrigin = "chrome-extension://$ExtensionId/"
$Manifest = [ordered]@{
    name = $HostName
    description = "LocalGateKeys native messaging bridge"
    path = $HostExe
    type = "stdio"
    allowed_origins = @($AllowedOrigin)
}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ManifestPath, ($Manifest | ConvertTo-Json -Depth 4), $Utf8NoBom)
$FirefoxManifest = [ordered]@{
    name = $HostName
    description = "LocalGateKeys native messaging bridge"
    path = $HostExe
    type = "stdio"
    allowed_extensions = @($FirefoxExtensionId)
}
[System.IO.File]::WriteAllText($FirefoxManifestPath, ($FirefoxManifest | ConvertTo-Json -Depth 4), $Utf8NoBom)

$HostHash = (Get-FileHash -Algorithm SHA256 -Path $HostExe).Hash.ToUpperInvariant()
$ActualInterpreter = (& $VenvPython -c "import os,psutil; print(psutil.Process(os.getpid()).exe())").Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ActualInterpreter -PathType Leaf)) {
    throw "Cannot identify the native host interpreter."
}
$InterpreterHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ActualInterpreter).Hash

$InstallConfig = [ordered]@{
    version = 5
    mode = "installed"
    product = "LocalGateKeys"
    scope = "current_user"
    install_root = $InstallRoot
    allowed_extension_origins = @($AllowedOrigin)
    allowed_firefox_extensions = @($FirefoxExtensionId)
    native_host_path = $HostExe
    native_host_sha256 = $HostHash
    interpreter_path = $ActualInterpreter
    interpreter_sha256 = $InterpreterHash
}
[System.IO.File]::WriteAllText((Join-Path $DataDir "install.json"), ($InstallConfig | ConvertTo-Json -Depth 4), $Utf8NoBom)

$ChromeKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$EdgeKey = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"
$FirefoxKey = "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName"
New-Item -Force -Path $ChromeKey | Out-Null
New-Item -Force -Path $EdgeKey | Out-Null
New-Item -Force -Path $FirefoxKey | Out-Null
Set-Item -Path $ChromeKey -Value $ManifestPath
Set-Item -Path $EdgeKey -Value $ManifestPath
Set-Item -Path $FirefoxKey -Value $FirefoxManifestPath

# Verify that the installed native host can import before telling the user the install succeeded.
$SelfTest = & $VenvPython -c "import json; from localvault.native_host import self_test; print(json.dumps(self_test()))" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $SelfTest -ForegroundColor Red
    throw "LocalGateKeys native messaging self-test failed."
}

# Remove obsolete per-user prototype registrations. No machine-wide keys are touched.
foreach ($oldKey in @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.localvault.prototype",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.localvault.prototype"
)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $oldKey }

Write-Host ""
Write-Host "Installed LocalGateKeys for the current Windows user." -ForegroundColor Green
Write-Host "Install folder: $InstallRoot"
Write-Host "Data folder:    $DataDir"
Write-Host "Agent:          $AgentExe"
Write-Host "Extension:      $ExtensionRoot"
Write-Host ""
Write-Host "No administrator privileges or machine-wide registry keys were used."
Write-Host "Start LocalGateKeys with:"
Write-Host "  & '$AgentExe'"
