[CmdletBinding()]
param(
    # Inno Setup 6 compiler. Auto-detected from the standard install locations.
    [string]$IsccPath = "",
    # Isolated output directory (build-personal/, dist-personal/, dist-installer/
    # are created beneath it). Defaults to the source checkout.
    [string]$OutputRoot = "",
    # Pre-staged OpenCV Zoo model directory for offline builds.
    [string]$ModelRoot = "",
    # Where the verified face-model manifest is written/read.
    [string]$ManifestPath = "",
    # Offline build: models must be pre-staged (hash-verified, never downloaded)
    # and, when a wheelhouse is present, Python dependencies are installed with
    # `pip install --no-index --find-links <wheelhouse> --require-hashes`.
    [switch]$Offline,
    # Directory of wheels for the offline dependency install.
    # Defaults to release-inputs\wheelhouse when it exists.
    [string]$Wheelhouse = "",
    # Hash-pinned lock used for dependency installation.
    [string]$LockFile = "",
    # Online build: install the dev+build lock into the venv before building.
    # Release builds (-Release, or any signed build) do this by default.
    [switch]$InstallDependencies,
    # Release build: dependencies come from the hash-pinned lock (unless
    # -Offline with a wheelhouse) and the Python minimum below is enforced.
    # Implied by -CertificateThumbprint / -PfxPath.
    [switch]$Release,
    # Release builds only: package the venv as it is instead of reinstalling the lock.
    [switch]$UseEnvironment,
    # Oldest Python the frozen runtime may come from (security fixes in the
    # interpreter and its bundled OpenSSL ship with it). Release builds fail
    # below it; other builds warn.
    [string]$MinimumPythonVersion = "3.14.9",
    # Build and self-check both frozen executables, produce the SBOM and the
    # manifest, but do not run Inno Setup (CI smoke, machines without Inno).
    [switch]$SkipInstaller,
    # Skip SBOM generation (not recommended for a release).
    [switch]$SkipSbom,

    # ---- Optional Authenticode signing -----------------------------------
    # signtool.exe (Windows SDK). Auto-detected when a certificate is given.
    [string]$SignToolPath = "",
    # SHA-1 thumbprint of a code-signing certificate in the current user's or
    # machine's certificate store (preferred: the private key never leaves it).
    [string]$CertificateThumbprint = "",
    # Alternatively a PFX file plus its password as a SecureString, e.g.
    #   -PfxPath .\cert.pfx -PfxPassword (Read-Host -AsSecureString "PFX password")
    # Without -PfxPassword the script prompts (empty = no password). The PFX is
    # imported into the current user's store for the build (non-exportable) and
    # removed afterwards, so the password never appears on a command line.
    [string]$PfxPath = "",
    [SecureString]$PfxPassword,
    # RFC 3161 timestamp authority so signatures outlive the certificate.
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
if (-not $IsWindows -and $env:OS -ne "Windows_NT") {
    throw "The personal installer can only be built on Windows."
}

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Resolve-UnderRoot([string]$Value) {
    if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
    return [IO.Path]::GetFullPath((Join-Path $Root $Value))
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputBase = $Root
} else {
    # The caller owns this isolated output root. Create only that directory;
    # all cleanup below is scoped to its generated children.
    $requestedOutput = Resolve-UnderRoot $OutputRoot
    if ($requestedOutput.TrimEnd('\', '/') -eq $Root.TrimEnd('\', '/')) {
        throw "OutputRoot must be an isolated child/output directory, not the source root."
    }
    New-Item -ItemType Directory -Force -Path $requestedOutput | Out-Null
    $OutputBase = (Resolve-Path -LiteralPath $requestedOutput -ErrorAction Stop).Path
}
$BuildRoot = Join-Path $OutputBase "build-personal"
$DistRoot = Join-Path $OutputBase "dist-personal"
$InstallerRoot = Join-Path $OutputBase "dist-installer"
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
$Python = if (Test-Path -LiteralPath $VenvPython -PathType Leaf) { $VenvPython } else { (Get-Command python -ErrorAction Stop).Source }

# ---------------------------------------------------------------------------
# Reproducibility knobs
# ---------------------------------------------------------------------------
# SOURCE_DATE_EPOCH is the de-facto standard "build time" for reproducible
# builds (https://reproducible-builds.org/specs/source-date-epoch/). It is taken
# from the commit being built so two builds of the same commit agree, and falls
# back to the current time outside a git checkout. PYTHONHASHSEED removes
# set/dict ordering noise from PyInstaller's analysis output.
$GitCommit = ""
try {
    $GitCommit = (& git -C $Root rev-parse --short=12 HEAD 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0) { $GitCommit = "" }
} catch { $GitCommit = "" }
if ([string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
    $epoch = ""
    try {
        $epoch = (& git -C $Root log -1 --format=%ct 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -ne 0) { $epoch = "" }
    } catch { $epoch = "" }
    if ([string]::IsNullOrWhiteSpace($epoch)) {
        $epoch = [string][int64]([DateTime]::UtcNow - [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).TotalSeconds
        Write-Host "SOURCE_DATE_EPOCH: no git commit time available; using the current time ($epoch)."
    } else {
        Write-Host "SOURCE_DATE_EPOCH: $($epoch.Trim()) (commit time of $GitCommit)"
    }
    $env:SOURCE_DATE_EPOCH = "$epoch".Trim()
} else {
    Write-Host "SOURCE_DATE_EPOCH: $env:SOURCE_DATE_EPOCH (inherited)"
}
if ([string]::IsNullOrWhiteSpace($env:PYTHONHASHSEED)) { $env:PYTHONHASHSEED = "0" }

# ---------------------------------------------------------------------------
# Signing configuration (validated up front so a bad option fails fast)
# ---------------------------------------------------------------------------
function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kitRoots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin") |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
    foreach ($kit in $kitRoots) {
        $versions = Get-ChildItem -LiteralPath $kit -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+(\.\d+)+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($version in $versions) {
            $candidate = Join-Path $version.FullName "x64\signtool.exe"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    return ""
}

$Signing = -not ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -and [string]::IsNullOrWhiteSpace($PfxPath))
$PfxMode = $false
if ($Signing) {
    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint) -and -not [string]::IsNullOrWhiteSpace($PfxPath)) {
        throw "Pass either -CertificateThumbprint or -PfxPath, not both."
    }
    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        $CertificateThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
        if ($CertificateThumbprint -notmatch '^[0-9A-F]{40}$') { throw "-CertificateThumbprint must be a 40-hex-digit SHA-1 thumbprint." }
    } else {
        $PfxMode = $true
        $PfxPath = Resolve-UnderRoot $PfxPath
        if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) { throw "PFX file not found: $PfxPath" }
        if (-not $PSBoundParameters.ContainsKey('PfxPassword')) {
            # Secure prompt: never echoed, never a plain string or an argument.
            $PfxPassword = Read-Host -AsSecureString "Password for $([IO.Path]::GetFileName($PfxPath)) (Enter if none)"
        }
    }
    if ([string]::IsNullOrWhiteSpace($SignToolPath)) { $SignToolPath = Find-SignTool }
    if ([string]::IsNullOrWhiteSpace($SignToolPath) -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
        throw "signtool.exe was not found. Install the Windows SDK signing tools or pass -SignToolPath."
    }
    if ($TimestampUrl -notmatch '^https?://') { throw "-TimestampUrl must be an http(s) RFC 3161 endpoint." }
    Write-Host "Code signing: enabled ($(if ($CertificateThumbprint) { "certificate $CertificateThumbprint" } else { "PFX $([IO.Path]::GetFileName($PfxPath))" }), timestamp $TimestampUrl)" -ForegroundColor Green
} elseif (-not [string]::IsNullOrWhiteSpace($SignToolPath) -or $PSBoundParameters.ContainsKey('PfxPassword')) {
    throw "Signing options were given without -CertificateThumbprint or -PfxPath."
} else {
    Write-Warning "UNSIGNED build: no -CertificateThumbprint or -PfxPath was supplied. Windows SmartScreen and browsers will warn about the executables and the installer. Do not publish an unsigned release."
}

if ($Signing -or $Release) {
    $Release = $true
    Write-Host "Release build: dependencies from the hash-pinned lock, Python >= $MinimumPythonVersion required." -ForegroundColor Green
}

# The frozen runtime (python3XX.dll, its OpenSSL, sqlite, ...) is copied from
# this interpreter, so an old patch release ships its known fixes missing
# (audit 2026-10-24 L-9).
$PythonVersionText = "$(& $Python -c "import platform, sys; sys.stdout.write(platform.python_version())")".Trim()
if ($LASTEXITCODE -ne 0 -or $PythonVersionText -notmatch '^(\d+\.\d+\.\d+)') { throw "Could not read the Python version of $Python." }
$PythonVersion = [version]$Matches[1]
if ($MinimumPythonVersion -notmatch '^\d+\.\d+\.\d+$') { throw "-MinimumPythonVersion must look like 3.14.9." }
if ($PythonVersion -lt [version]$MinimumPythonVersion) {
    $message = "Python $PythonVersionText is older than $MinimumPythonVersion; rebuild the venv on Python $MinimumPythonVersion or later (pass -MinimumPythonVersion to change the floor)."
    if ($Release) { throw $message }
    Write-Warning $message
} else {
    Write-Host "Python $PythonVersionText (minimum $MinimumPythonVersion)"
}

# PFX mode: import the certificate into the current user's store (private key
# not exportable) for the length of the build, then sign by thumbprint like the
# store mode. Removed again in the final block unless it was already there.
$PfxImportedThumbprint = $null
function Import-SigningPfx {
    if (-not $PfxMode -or $script:CertificateThumbprint) { return }
    $importArgs = @{ FilePath = $PfxPath; CertStoreLocation = "Cert:\CurrentUser\My" }
    if ($PfxPassword -and $PfxPassword.Length -gt 0) { $importArgs["Password"] = $PfxPassword }
    $before = @(Get-ChildItem -LiteralPath "Cert:\CurrentUser\My" | ForEach-Object Thumbprint)
    $imported = @(Import-PfxCertificate @importArgs | Where-Object { $_.HasPrivateKey })
    if ($imported.Count -ne 1) { throw "The PFX must hold exactly one certificate with a private key." }
    $thumbprint = $imported[0].Thumbprint.ToUpperInvariant()
    if ($before -notcontains $thumbprint) { $script:PfxImportedThumbprint = $thumbprint }
    $script:CertificateThumbprint = $thumbprint
}

function Remove-SigningPfx {
    if ($script:PfxImportedThumbprint) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($script:PfxImportedThumbprint)" -DeleteKey -ErrorAction SilentlyContinue
        $script:PfxImportedThumbprint = $null
    }
}

function Invoke-CodeSign([string[]]$Paths) {
    Import-SigningPfx
    $arguments = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl, "/sha1", $script:CertificateThumbprint)
    $arguments += $Paths
    & $SignToolPath @arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for: $($Paths -join ', ')" }
    Assert-Signed $Paths
}

function Test-Signed([string]$Path) {
    & $SignToolPath verify /pa /q $Path 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Assert-Signed([string[]]$Paths) {
    foreach ($path in $Paths) {
        if (-not (Test-Signed $path)) { throw "Authenticode signature verification failed: $path" }
        Write-Host "Signed and verified: $path"
    }
}

# ---------------------------------------------------------------------------
# Dependencies (hash-pinned). Default: use the environment as-is, like before.
# ---------------------------------------------------------------------------
$LockFile = if ([string]::IsNullOrWhiteSpace($LockFile)) { Join-Path $Root "requirements-dev.lock.txt" } else { Resolve-UnderRoot $LockFile }
$DependencySource = "environment"
if ($Release -and -not $Offline -and -not $InstallDependencies) {
    if ($UseEnvironment) {
        Write-Warning "Release build packaging the venv as it is (-UseEnvironment): dependencies are not re-verified against the lock."
    } else {
        $InstallDependencies = [switch]::Present
    }
}
if ($Offline) {
    if ([string]::IsNullOrWhiteSpace($Wheelhouse)) {
        $defaultWheelhouse = Join-Path $Root "release-inputs\wheelhouse"
        if (Test-Path -LiteralPath $defaultWheelhouse -PathType Container) { $Wheelhouse = $defaultWheelhouse }
    } else {
        $Wheelhouse = Resolve-UnderRoot $Wheelhouse
        if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) { throw "Wheelhouse directory not found: $Wheelhouse" }
    }
    if ($Wheelhouse) {
        if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) { throw "Lock file not found: $LockFile" }
        Write-Host "Offline dependency install from $Wheelhouse (lock: $([IO.Path]::GetFileName($LockFile)))"
        # --no-index: never contact PyPI. --find-links: wheels come only from the staged
        # wheelhouse. --require-hashes: every wheel must match the lock's SHA-256.
        & $Python -m pip install --no-index --find-links $Wheelhouse --require-hashes -r $LockFile
        if ($LASTEXITCODE -ne 0) { throw "Offline hash-pinned dependency installation failed." }
        & $Python -m pip install --no-index --no-deps --no-build-isolation -e $Root
        if ($LASTEXITCODE -ne 0) { throw "Offline editable project installation failed." }
        $DependencySource = "wheelhouse"
    } else {
        Write-Host "Offline build without a wheelhouse: using the already-installed environment."
    }
} elseif ($InstallDependencies) {
    if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) { throw "Lock file not found: $LockFile" }
    & $Python -m pip install --require-hashes -r $LockFile
    if ($LASTEXITCODE -ne 0) { throw "Hash-pinned dependency installation failed." }
    # No build isolation: setuptools and wheel come hash-pinned from the lock.
    & $Python -m pip install --no-deps --no-build-isolation -e $Root
    if ($LASTEXITCODE -ne 0) { throw "Editable project installation failed." }
    $DependencySource = "lock"
}

# ---------------------------------------------------------------------------
# Models and environment preflight (unchanged behavior)
# ---------------------------------------------------------------------------
$FetchArgs = @{}
if ($Offline) { $FetchArgs["Offline"] = $true }
if (-not [string]::IsNullOrWhiteSpace($ModelRoot)) { $FetchArgs["ModelRoot"] = $ModelRoot }
$FetchManifestPath = if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    Join-Path $OutputBase "release-inputs\face-models.manifest.json"
} else {
    Resolve-UnderRoot $ManifestPath
}
$FetchArgs["ManifestPath"] = $FetchManifestPath
# Fetch only the public, hash-pinned OpenCV model files needed by the optional
# ordinary-webcam route. This is a build-time operation; the installed app does
# not download models or upload camera data. Existing verified files are reused.
& (Join-Path $Root "scripts\fetch_face_models.ps1") @FetchArgs
if (-not $?) { throw "Camera model download/integrity verification failed." }

# Refuse to package missing imports, camera runtime files, or a stale source tree.
# This opens no camera, vault, Windows Hello prompt, or biometric data.
& $Python (Join-Path $Root "scripts\check_build_environment.py")
if ($LASTEXITCODE -ne 0) {
    throw 'Build prerequisites failed. Run .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock.txt (then pip install --no-deps --no-build-isolation -e .) from the project root, then rebuild.'
}

# Every personal release starts from empty generated folders. This prevents old
# prototype binaries, demo vaults, or stale PyInstaller analysis from leaking in.
foreach ($path in @(
    (Join-Path $BuildRoot "agent"),
    (Join-Path $BuildRoot "native"),
    $DistRoot,
    $InstallerRoot
)) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $path | Out-Null
}

# Generate the installer script inside the isolated output root. The checked
# in template uses paths relative to the source checkout; copying it verbatim
# would make an isolated build read stale payloads or fail to find assets.
$IssTemplate = Join-Path $Root "build-personal\LocalGateKeys-Personal.iss"
if (-not (Test-Path -LiteralPath $IssTemplate -PathType Leaf)) {
    throw "Installer script template was not found: $IssTemplate"
}
# The generated script gets its own name: with the default OutputRoot the build
# directory is the template's directory, and writing to the template's own path
# baked this machine's absolute paths into the tracked file.
$IssScript = Join-Path $BuildRoot "LocalGateKeys-Personal.generated.iss"
$IssText = [IO.File]::ReadAllText($IssTemplate)
$IssReplacements = [ordered]@{
    "OutputDir=..\dist-installer" = "OutputDir=$InstallerRoot"
    "SetupIconFile=..\assets\icons\localgatekeys.ico" = "SetupIconFile=$(Join-Path $Root 'assets\icons\localgatekeys.ico')"
    'Source: "..\dist-personal\LocalGateKeys\*"' = 'Source: "' + (Join-Path $DistRoot 'LocalGateKeys\*') + '"'
    'Source: "..\dist-personal\LocalGateKeysNativeHost\*"' = 'Source: "' + (Join-Path $DistRoot 'LocalGateKeysNativeHost\*') + '"'
    'Source: "..\assets\*"' = 'Source: "' + (Join-Path $Root 'assets\*') + '"'
    'Source: "..\browser-extension\*"' = 'Source: "' + (Join-Path $Root 'browser-extension\*') + '"'
    'Source: "..\THIRD-PARTY-NOTICES.txt"' = 'Source: "' + (Join-Path $Root 'THIRD-PARTY-NOTICES.txt') + '"'
}
# The notices must describe the dependencies being packaged (audit 2026-10-24 I-23).
& $Python (Join-Path $Root "scripts\generate_third_party_notices.py") --check
if ($LASTEXITCODE -ne 0) {
    $message = "THIRD-PARTY-NOTICES.txt does not match the installed dependencies: run scripts\generate_third_party_notices.py and commit it."
    if ($Release) { throw $message }
    Write-Warning $message
}
foreach ($Placeholder in $IssReplacements.Keys) {
    if (-not $IssText.Contains($Placeholder)) {
        throw "Installer template is missing the expected line '$Placeholder': $IssTemplate"
    }
    $IssText = $IssText.Replace($Placeholder, $IssReplacements[$Placeholder])
}
# Windows shows AppVersion in Installed apps: take it from the app, not the template.
# Not "| Select-Object -First 1": that stops the pipeline and kills Python (exit -1).
$AppVersion = "$(& $Python -c "import sys; sys.path.insert(0, r'$Root\src'); from localvault.version import APP_VERSION; print(APP_VERSION)")".Trim()
if ($LASTEXITCODE -ne 0 -or "$AppVersion" -notmatch '^\d+\.\d+\.\d+$') {
    throw "Could not read APP_VERSION from src\localvault\version.py."
}
$VersionDefine = [regex]'(?m)^#define AppVersion "[^"]*"'
if (-not $VersionDefine.IsMatch($IssText)) {
    throw "Installer template is missing the '#define AppVersion' line: $IssTemplate"
}
$IssText = $VersionDefine.Replace($IssText, "#define AppVersion `"$AppVersion-personal`"", 1)
# With a certificate in the store, let Inno Setup sign Setup.exe and the
# generated uninstaller through its SignTool hook (defined on the ISCC command
# line below). PFX mode signs the installer afterwards instead so the PFX
# password is never placed in the Inno command string.
$InnoSigns = $Signing -and -not [string]::IsNullOrWhiteSpace($CertificateThumbprint)
if ($InnoSigns) {
    $IssText = $IssText.Replace("[Setup]`r`n", "[Setup]`r`nSignTool=lgksign`r`nSignedUninstaller=yes`r`n")
    $IssText = $IssText.Replace("[Setup]`n", "[Setup]`nSignTool=lgksign`nSignedUninstaller=yes`n")
    if ($IssText -notmatch 'SignTool=lgksign') { throw "Could not inject the SignTool directive into the installer script." }
}
[IO.File]::WriteAllText($IssScript, $IssText, [Text.UTF8Encoding]::new($false))

function Get-PythonVersionOf([string]$Distribution) {
    $value = & $Python -c "import importlib.metadata as m, sys; sys.stdout.write(m.version(sys.argv[1]))" $Distribution 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) { return $null }
    return "$value".Trim()
}

Push-Location $Root
try {
    # The WebView2 page (webui/, Svelte) builds into src\localvault\assets\ui, which the spec bundles.
    $Npm = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
    if (-not $Npm) { throw "npm (Node.js) is required to build the LocalGateKeys window (webui)." }
    Push-Location (Join-Path $Root "webui")
    try {
        & $Npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed for webui." }
        & $Npm run build
        if ($LASTEXITCODE -ne 0) { throw "The webui build failed." }
    } finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Root "src\localvault\assets\ui\index.html") -PathType Leaf)) {
        throw "The webui build did not produce src\localvault\assets\ui\index.html."
    }
    & $Python -m PyInstaller --clean --noconfirm --distpath $DistRoot --workpath (Join-Path $BuildRoot "agent") (Join-Path $Root "LocalGateKeys.spec")
    if ($LASTEXITCODE -ne 0) { throw "LocalGateKeys PyInstaller build failed." }

    & $Python -m PyInstaller --clean --noconfirm --distpath $DistRoot --workpath (Join-Path $BuildRoot "native") (Join-Path $Root "LocalGateKeysNativeHost.spec")
    if ($LASTEXITCODE -ne 0) { throw "LocalGateKeysNativeHost PyInstaller build failed." }

    $Required = @(
        (Join-Path $DistRoot "LocalGateKeys\LocalGateKeys.exe"),
        (Join-Path $DistRoot "LocalGateKeysNativeHost\LocalGateKeysNativeHost.exe")
    )
    foreach ($path in $Required) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing build output: $path" }
    }

    # Sign both frozen executables before anything hashes or packages them.
    if ($Signing) { Invoke-CodeSign $Required }

    # Check both frozen payloads before compiling a successful-looking installer.
    # No profile is loaded, native key created, biometric read or GUI displayed.
    foreach ($exe in $Required) {
        $process = Start-Process -FilePath $exe -ArgumentList "--check-build" -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -ne 0) { throw "Packaged dependency/asset self-check failed: $exe" }
    }

    # Production payload must never contain development/demo/test data files.
    $Forbidden = Get-ChildItem -LiteralPath $DistRoot -Recurse -File | Where-Object {
        $relative = $_.FullName.Substring($DistRoot.Length).TrimStart('\')
        $relative -match '(?i)(^|\\)(demo|tests?)(\\|$)' -or
        $_.Name -match '(?i)^((vault|profiles|agent-state)\.json|.*\.(hello|face)\.json)$'
    }
    if ($Forbidden) {
        $names = ($Forbidden | ForEach-Object FullName) -join "`n"
        throw "Production payload contains forbidden development/user data:`n$names"
    }

    # Software bill of materials: Python environment + vendored models + extension.
    $SbomPath = Join-Path $InstallerRoot "LocalGateKeys-Setup-Personal.sbom.cdx.json"
    $SbomRow = $null
    if (-not $SkipSbom) {
        & (Join-Path $Root "scripts\generate_sbom.ps1") -Python $Python -OutputPath $SbomPath -ModelManifestPath $FetchManifestPath
        if (-not $? -or -not (Test-Path -LiteralPath $SbomPath -PathType Leaf)) { throw "SBOM generation failed." }
        $SbomRow = [ordered]@{
            path = "dist-installer/" + [IO.Path]::GetFileName($SbomPath)
            format = "CycloneDX JSON"
            size = [int64](Get-Item -LiteralPath $SbomPath).Length
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SbomPath).Hash.ToUpperInvariant()
        }
    } else {
        Write-Warning "SBOM generation skipped (-SkipSbom)."
    }

    $Installer = Join-Path $InstallerRoot "LocalGateKeys-Setup-Personal.exe"
    $InstallerRow = $null
    $InnoVersion = $null
    if ($SkipInstaller) {
        Write-Host "Skipping Inno Setup (-SkipInstaller): frozen executables were built and self-checked." -ForegroundColor Yellow
    } else {
        if (-not $IsccPath) {
            # @() keeps a single match an array; otherwise [0] is its first character.
            $Candidates = @(@(
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
                "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
            ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
            if ($Candidates) { $IsccPath = $Candidates[0] }
        }
        if (-not $IsccPath -or -not (Test-Path -LiteralPath $IsccPath -PathType Leaf)) {
            throw "Inno Setup 6 ISCC.exe was not found. Pass -IsccPath explicitly, or use -SkipInstaller."
        }
        $InnoVersion = (Get-Item -LiteralPath $IsccPath).VersionInfo.ProductVersion

        # /O is required because the .iss file has a historical relative default;
        # it keeps an explicit OutputRoot fully isolated from retained artifacts.
        $IsccArguments = @("/O$InstallerRoot")
        if ($InnoSigns) {
            # $q = quote, $f = file placeholder (Inno Setup SignTool syntax).
            $IsccArguments += ('/Slgksign=$q' + $SignToolPath + '$q sign /fd SHA256 /td SHA256 /tr ' + $TimestampUrl + ' /sha1 ' + $CertificateThumbprint + ' $f')
        }
        $IsccArguments += $IssScript
        & $IsccPath @IsccArguments
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup build failed." }

        if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
            throw "Installer was not produced: $Installer"
        }
        if ($Signing) {
            # Inno may already have signed Setup.exe (store certificate mode);
            # otherwise sign it now. Either way the result must verify.
            if (-not (Test-Signed $Installer)) { Invoke-CodeSign @($Installer) } else { Assert-Signed @($Installer) }
        }
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToUpperInvariant()
        $HashFile = Join-Path $InstallerRoot "LocalGateKeys-Setup-Personal.sha256"
        [IO.File]::WriteAllText($HashFile, "$Hash  LocalGateKeys-Setup-Personal.exe`r`n", [Text.ASCIIEncoding]::new())
        $InstallerRow = [ordered]@{
            path = "dist-installer/LocalGateKeys-Setup-Personal.exe"
            size = [int64](Get-Item -LiteralPath $Installer).Length
            sha256 = $Hash
        }
    }

    function Get-ArtifactManifestRows([string]$Directory, [string]$BasePath) {
        $rows = New-Object System.Collections.Generic.List[object]
        if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return @() }
        foreach ($file in (Get-ChildItem -LiteralPath $Directory -Recurse -File | Sort-Object FullName)) {
            # [IO.Path]::GetRelativePath is unavailable in Windows PowerShell 5.1.
            $baseFull = (Resolve-Path -LiteralPath $BasePath).Path.TrimEnd('\')
            $relative = $file.FullName.Substring($baseFull.Length + 1).Replace('\', '/')
            [void]$rows.Add([ordered]@{
                path = $relative
                size = [int64]$file.Length
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToUpperInvariant()
            })
        }
        return $rows.ToArray()
    }

    # Pinned tool versions make two manifests of the same commit comparable and
    # explain any difference. Versions, not paths: nothing machine-specific.
    $Tools = [ordered]@{
        python = (& $Python -c "import platform, sys; sys.stdout.write(platform.python_version())").Trim()
        pyinstaller = Get-PythonVersionOf "pyinstaller"
        pyinstaller_hooks_contrib = Get-PythonVersionOf "pyinstaller-hooks-contrib"
        pip = Get-PythonVersionOf "pip"
        setuptools = Get-PythonVersionOf "setuptools"
        cyclonedx_bom = Get-PythonVersionOf "cyclonedx-bom"
        inno_setup = $InnoVersion
        signtool = if ($Signing) { (Get-Item -LiteralPath $SignToolPath).VersionInfo.FileVersion } else { $null }
        windows = [string][Environment]::OSVersion.Version
    }
    $SigningRow = $null
    if ($Signing) {
        $SigningRow = [ordered]@{
            method = if ($PfxMode) { "pfx-imported" } else { "certificate-store" }
            certificate_thumbprint_sha1 = if ($CertificateThumbprint) { $CertificateThumbprint } else { $null }
            digest = "SHA256"
            timestamp_url = $TimestampUrl
        }
    }

    # Keep metadata stable across repeated invocations: no wall-clock timestamps
    # or machine-specific absolute paths are included. SOURCE_DATE_EPOCH is a
    # function of the commit, so it is stable too.
    $Manifest = [ordered]@{
        schema = 2
        artifact = "LocalGateKeys-Setup-Personal.exe"
        git_commit = if ($GitCommit) { $GitCommit } else { $null }
        source_date_epoch = [int64]$env:SOURCE_DATE_EPOCH
        signed = [bool]$Signing
        signing = $SigningRow
        upx = $false
        dependency_source = $DependencySource
        tools = $Tools
        installer = $InstallerRow
        sbom = $SbomRow
        model_manifest = [ordered]@{ name = [IO.Path]::GetFileName($FetchManifestPath); size = [int64](Get-Item -LiteralPath $FetchManifestPath).Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $FetchManifestPath).Hash.ToUpperInvariant() }
        payload = @(Get-ArtifactManifestRows $DistRoot $OutputBase)
    }
    $ReleaseManifest = Join-Path $InstallerRoot "LocalGateKeys-Setup-Personal.manifest.json"
    $ManifestTemp = "$ReleaseManifest.tmp"
    $Utf8NoBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($ManifestTemp, (($Manifest | ConvertTo-Json -Depth 6) + [Environment]::NewLine), $Utf8NoBom)
    Move-Item -LiteralPath $ManifestTemp -Destination $ReleaseManifest -Force

    if ($InstallerRow) {
        Write-Host "Built clean personal installer: $Installer" -ForegroundColor Green
        Write-Host "SHA256: $($InstallerRow.sha256)"
    } else {
        Write-Host "Built frozen executables under: $DistRoot" -ForegroundColor Green
    }
    if ($SbomRow) { Write-Host "SBOM: $SbomPath" }
    Write-Host "Manifest: $ReleaseManifest"
    if (-not $Signing) { Write-Warning "UNSIGNED build (manifest records signed: false)." }
}
finally {
    Pop-Location
    Remove-SigningPfx
}
