[CmdletBinding()]
param(
    # Build the frozen executables first (build_personal_installer.ps1 -SkipInstaller).
    # Without it, the existing dist-personal\ output is packaged as it is.
    [switch]$Build,
    # Directory holding LocalGateKeys\ and LocalGateKeysNativeHost\ (PyInstaller
    # output). Defaults to <OutputRoot>\dist-personal.
    [string]$DistRoot = "",
    # Same meaning as in build_personal_installer.ps1: build-msix\work and
    # dist-msix\ are created beneath it. Defaults to the source checkout.
    [string]$OutputRoot = "",
    # Store:    lays down the Store build flag (in-app updater off) and uses the
    #           Partner Center identity from -IdentityFile. Upload the unsigned
    #           .msix; Microsoft signs it after certification.
    # Sideload: test identity (CN=LocalGateKeys Test Signing) unless
    #           -IdentityFile is given; no Store flag.
    [ValidateSet("Store", "Sideload")]
    [string]$Channel = "Sideload",
    # JSON with Name, Publisher, PublisherDisplayName (and optional DisplayName)
    # copied from Partner Center > Product identity. Required for -Channel Store.
    [string]$IdentityFile = "",
    # Sign the package with a self-signed TEST certificate created by
    # scripts\msix_test_certificate.py under dist-msix\test-signing\. Sideload
    # testing only: the Store re-signs packages, and nobody else should trust it.
    [switch]$TestSign,
    # Windows SDK bin\<version>\x64 directory. Auto-detected (newest SDK).
    [string]$SdkBinPath = "",
    # Python with Pillow and cryptography. Defaults to .venv\Scripts\python.exe.
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "MSIX packages can only be built on Windows." }

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Resolve-UnderRoot([string]$Value) {
    if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
    return [IO.Path]::GetFullPath((Join-Path $Root $Value))
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputBase = $Root
} else {
    $OutputBase = Resolve-UnderRoot $OutputRoot
    if ($OutputBase.TrimEnd('\', '/') -eq $Root.TrimEnd('\', '/')) { $OutputBase = $Root }
    New-Item -ItemType Directory -Force -Path $OutputBase | Out-Null
}
if ([string]::IsNullOrWhiteSpace($DistRoot)) { $DistRoot = Join-Path $OutputBase "dist-personal" } else { $DistRoot = Resolve-UnderRoot $DistRoot }
$WorkRoot = Join-Path $OutputBase "build-msix\work"
$Layout = Join-Path $WorkRoot "layout"
$PriRoot = Join-Path $WorkRoot "pri"
$OutDir = Join-Path $OutputBase "dist-msix"
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = if (Test-Path -LiteralPath $VenvPython -PathType Leaf) { $VenvPython } else { (Get-Command python -ErrorAction Stop).Source }
}

# The test identity. Its Publisher must equal the test certificate subject.
$TestIdentity = [ordered]@{
    Name = "LocalGateKeys.Test"
    Publisher = "CN=LocalGateKeys Test Signing"
    PublisherDisplayName = "LocalGateKeys (test build)"
    DisplayName = "LocalGateKeys"
}
# Not a secret: it protects a throwaway self-signed test key in an ignored folder.
$TestPfxPassword = "localgatekeys-msix-test"

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
function Find-SdkBin {
    $kitRoots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin") |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
    foreach ($kit in $kitRoots) {
        $versions = Get-ChildItem -LiteralPath $kit -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+(\.\d+)+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($version in $versions) {
            $candidate = Join-Path $version.FullName "x64"
            if (Test-Path -LiteralPath (Join-Path $candidate "makeappx.exe") -PathType Leaf) { return $candidate }
        }
    }
    return ""
}
# SDK tools print a line per file; show their output in full only when they fail.
function Invoke-Tool([string]$Exe, [string[]]$Arguments, [string]$Label) {
    $output = & $Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Select-Object -Last 40 | Out-Host
        throw "$Label failed (exit $LASTEXITCODE)."
    }
    $output | Select-Object -Last 1 | Out-Host
}
if ([string]::IsNullOrWhiteSpace($SdkBinPath)) { $SdkBinPath = Find-SdkBin }
$MakeAppx = Join-Path $SdkBinPath "makeappx.exe"
$MakePri = Join-Path $SdkBinPath "makepri.exe"
$SignTool = Join-Path $SdkBinPath "signtool.exe"
if ([string]::IsNullOrWhiteSpace($SdkBinPath) -or -not (Test-Path -LiteralPath $MakeAppx -PathType Leaf)) {
    throw "makeappx.exe was not found. Install the Windows 10/11 SDK (App packaging tools), or pass -SdkBinPath <Windows Kits\10\bin\<version>\x64>."
}
Write-Host "Windows SDK tools: $SdkBinPath"

# ---------------------------------------------------------------------------
# Identity and version
# ---------------------------------------------------------------------------
$Identity = $TestIdentity
if (-not [string]::IsNullOrWhiteSpace($IdentityFile)) {
    $IdentityFile = Resolve-UnderRoot $IdentityFile
    $json = Get-Content -LiteralPath $IdentityFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $Identity = [ordered]@{
        Name = [string]$json.Name
        Publisher = [string]$json.Publisher
        PublisherDisplayName = [string]$json.PublisherDisplayName
        DisplayName = if ($json.DisplayName) { [string]$json.DisplayName } else { "LocalGateKeys" }
    }
} elseif ($Channel -eq "Store") {
    throw "-Channel Store needs -IdentityFile (Partner Center identity; see docs\store\MICROSOFT_STORE_CHECKLIST.md)."
}
foreach ($field in "Name", "Publisher", "PublisherDisplayName", "DisplayName") {
    $value = [string]$Identity[$field]
    if ([string]::IsNullOrWhiteSpace($value) -or $value -match '^<.*>$' -or $value -match '[<>&"]') {
        throw "Identity field '$field' is missing, still a placeholder, or contains XML special characters: '$value'"
    }
}
if ($Identity.Name -notmatch '^[A-Za-z0-9.-]{3,50}$') { throw "Identity Name must be 3-50 letters, digits, '.' or '-': $($Identity.Name)" }
if ($Identity.Publisher -notmatch '^CN=') { throw "Identity Publisher must be a distinguished name starting with CN=: $($Identity.Publisher)" }
if ($TestSign -and $Identity.Publisher -ne $TestIdentity.Publisher) {
    throw "-TestSign signs as '$($TestIdentity.Publisher)', which must equal the manifest Publisher. Drop -IdentityFile for a test package."
}

$versionSource = Get-Content -LiteralPath (Join-Path $Root "src\localvault\version.py") -Raw -Encoding UTF8
if ($versionSource -notmatch 'APP_VERSION\s*=\s*"(\d+)\.(\d+)\.(\d+)"') { throw "APP_VERSION not found in src\localvault\version.py" }
# Store packages must keep the fourth (revision) field at 0.
$PackageVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3]).0"
Write-Host "Package: $($Identity.Name) $PackageVersion ($Channel)"

# ---------------------------------------------------------------------------
# Frozen executables
# ---------------------------------------------------------------------------
if ($Build) {
    $buildArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "build_personal_installer.ps1"), "-SkipInstaller")
    if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) { $buildArgs += @("-OutputRoot", $OutputBase) }
    # Store packages are releases: hash-pinned lock and a hard Python floor, not a warning.
    if ($Channel -eq "Store") { $buildArgs += "-Release" }
    & (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe") @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "build_personal_installer.ps1 -SkipInstaller failed." }
}
$AgentDist = Join-Path $DistRoot "LocalGateKeys"
$HostDist = Join-Path $DistRoot "LocalGateKeysNativeHost"
foreach ($required in (Join-Path $AgentDist "LocalGateKeys.exe"), (Join-Path $HostDist "LocalGateKeysNativeHost.exe")) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing $required. Run with -Build, or build_personal_installer.ps1 -SkipInstaller first." }
}

# ---------------------------------------------------------------------------
# Package layout (mirrors the Inno Setup install directory)
# ---------------------------------------------------------------------------
if (Test-Path -LiteralPath $WorkRoot) { Remove-Item -LiteralPath $WorkRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Layout, $PriRoot, $OutDir | Out-Null
Copy-Item -Path (Join-Path $AgentDist "*") -Destination $Layout -Recurse -Force
$HostLayout = Join-Path $Layout "NativeHost"
New-Item -ItemType Directory -Force -Path $HostLayout | Out-Null
Copy-Item -Path (Join-Path $HostDist "*") -Destination $HostLayout -Recurse -Force
Copy-Item -LiteralPath (Join-Path $Root "assets") -Destination (Join-Path $Layout "assets") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $Root "browser-extension") -Destination (Join-Path $Layout "browser-extension") -Recurse -Force
# Licences of the bundled third-party software (audit 2026-10-24 I-23).
$Notices = Join-Path $Root "THIRD-PARTY-NOTICES.txt"
if (-not (Test-Path -LiteralPath $Notices -PathType Leaf)) { throw "Missing $Notices. Run scripts\generate_third_party_notices.py." }
Copy-Item -LiteralPath $Notices -Destination (Join-Path $Layout "THIRD-PARTY-NOTICES.txt") -Force

if ($Channel -eq "Store") {
    # The Store build flag read by localvault.distribution.is_store_build().
    $marker = Join-Path $Layout "LocalGateKeys.store-build"
    [IO.File]::WriteAllText($marker, "{`"channel`": `"store`"}`n", (New-Object Text.UTF8Encoding($false)))
}

# Logos. With makepri, scale-qualified files are indexed into resources.pri;
# without it, plain single-size files are referenced directly.
$Qualified = Test-Path -LiteralPath $MakePri -PathType Leaf
# "PackageAssets", not "Assets": the app's own assets\ folder is already in the
# layout, and package paths are case-insensitive.
$assetArgs = @((Join-Path $Root "scripts\generate_msix_assets.py"), (Join-Path $Layout "PackageAssets"))
if ($Qualified) { $assetArgs += "--qualified" }
& $Python @assetArgs
if ($LASTEXITCODE -ne 0) { throw "Generating MSIX logos failed." }

# Manifest
$template = Get-Content -LiteralPath (Join-Path $Root "build-msix\AppxManifest.xml.in") -Raw -Encoding UTF8
$manifest = $template
$tokens = [ordered]@{
    "@IDENTITY_NAME@" = $Identity.Name
    "@PUBLISHER@" = $Identity.Publisher
    "@PUBLISHER_DISPLAY_NAME@" = $Identity.PublisherDisplayName
    "@DISPLAY_NAME@" = $Identity.DisplayName
    "@VERSION@" = $PackageVersion
}
foreach ($token in $tokens.Keys) { $manifest = $manifest.Replace($token, [string]$tokens[$token]) }
if ($manifest -match '@[A-Z_]+@') { throw "Unreplaced token in AppxManifest.xml: $($Matches[0])" }
$ManifestPath = Join-Path $Layout "AppxManifest.xml"
[IO.File]::WriteAllText($ManifestPath, $manifest, (New-Object Text.UTF8Encoding($false)))

if ($Qualified) {
    # Index only the logos: a project root with just PackageAssets\ and the
    # manifest keeps makepri away from the thousands of PyInstaller files.
    Copy-Item -LiteralPath (Join-Path $Layout "PackageAssets") -Destination (Join-Path $PriRoot "PackageAssets") -Recurse -Force
    Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $PriRoot "AppxManifest.xml") -Force
    $priConfig = Join-Path $WorkRoot "priconfig.xml"
    Invoke-Tool $MakePri @("createconfig", "/cf", $priConfig, "/dq", "en-US", "/pv", "10.0.0", "/o") "makepri createconfig"
    # A single .msix carries every scale: drop the split resource packs meant for bundles.
    $priXml = Get-Content -LiteralPath $priConfig -Raw -Encoding UTF8
    $priXml = [regex]::Replace($priXml, '(?s)\s*<packaging>.*?</packaging>', '')
    [IO.File]::WriteAllText($priConfig, $priXml, (New-Object Text.UTF8Encoding($false)))
    Invoke-Tool $MakePri @("new", "/pr", $PriRoot, "/cf", $priConfig, "/mn", (Join-Path $PriRoot "AppxManifest.xml"),
        "/of", (Join-Path $Layout "resources.pri"), "/o") "makepri new"
}

# ---------------------------------------------------------------------------
# Pack (MakeAppx validates the manifest against the schema while packing)
# ---------------------------------------------------------------------------
$suffix = if ($Channel -eq "Store") { "store" } else { "sideload" }
$PackagePath = Join-Path $OutDir "LocalGateKeys_$($PackageVersion)_x64_$suffix.msix"
Invoke-Tool $MakeAppx @("pack", "/d", $Layout, "/p", $PackagePath, "/o") "makeappx pack"

if ($TestSign) {
    if (-not (Test-Path -LiteralPath $SignTool -PathType Leaf)) { throw "signtool.exe was not found next to makeappx.exe." }
    $certDir = Join-Path $OutDir "test-signing"
    & $Python (Join-Path $Root "scripts\msix_test_certificate.py") $certDir --subject $TestIdentity.Publisher --password $TestPfxPassword
    if ($LASTEXITCODE -ne 0) { throw "Creating the test certificate failed." }
    # No timestamp: a test signature only has to outlive the test.
    Invoke-Tool $SignTool @("sign", "/fd", "SHA256", "/f", (Join-Path $certDir "LocalGateKeys-TestSigning.pfx"),
        "/p", $TestPfxPassword, $PackagePath) "signtool sign"
    Write-Host ""
    Write-Host "TEST-SIGNED package (sideload testing only): $PackagePath" -ForegroundColor Yellow
    Write-Host "Trust $(Join-Path $certDir 'LocalGateKeys-TestSigning.cer') on the test machine first; see docs\store\MSIX_FEASIBILITY.md." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "Unsigned package: $PackagePath" -ForegroundColor Green
    if ($Channel -eq "Store") { Write-Host "Upload it in Partner Center; Microsoft signs Store packages." }
}
