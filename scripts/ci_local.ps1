<#
Runs the GitHub CI jobs (.github/workflows/ci.yml) on this PC, plus the suites
CI does not cover yet (web UI, Android core, licence Worker).

  .\scripts\ci_local.ps1               # every Windows job except the build
  .\scripts\ci_local.ps1 -Build        # also the build-smoke job (PyInstaller frozen executables the MSIX packages, slow; never the retired installer)
  .\scripts\ci_local.ps1 -Only node,kotlin
  .\scripts\ci_local.ps1 -Snapshot     # also the public-snapshot privacy check
  .\scripts\ci_local.ps1 -SkipSecurity # leave out pip-audit / npm audit / bandit (needs network)

The security job (scripts/security_scan.py) fails on any known vulnerability in
the Python locks, high/critical npm advisories, and bandit HIGH findings, minus
the accepted ones in scripts/security_ignore.txt.

The Swift job needs the Mac: scripts/ci_local_mac.sh. The pre-push hook in
.githooks runs this script; enable it once with
  git config core.hooksPath .githooks
Exit code 0 only when every gating step passed (ruff and mypy stay advisory,
as in CI).
#>
[CmdletBinding()]
param(
    # Comma-separated jobs: python, node, webui, kotlin, worker, dotnet, security (default: all).
    [string]$Only = "",
    [switch]$Build,
    [switch]$Snapshot,
    # Skip the security scanners (they query PyPI and the npm registry).
    [switch]$SkipSecurity,
    # Use the environment as-is (no locked pip / npm ci install).
    [switch]$NoInstall
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"
$env:PYTHONUTF8 = "1"
$results = [System.Collections.Generic.List[object]]::new()
$Jobs = @($Only -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$unknown = @($Jobs | Where-Object { $_ -notin @("python", "node", "webui", "kotlin", "worker", "dotnet", "security") })
if ($unknown.Count -gt 0) { throw "Unknown job(s): $($unknown -join ', ')" }

function Want([string]$job) { $Jobs.Count -eq 0 -or $Jobs -contains $job }

# Runs one step in $dir; a failing gating step is recorded, not thrown, so
# every job still runs and the summary lists all failures.
function Step([string]$name, [string]$dir, [scriptblock]$body, [switch]$Advisory) {
    Write-Host "`n=== $name" -ForegroundColor Cyan
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $ok = $true
    Push-Location $dir
    try {
        $global:LASTEXITCODE = 0
        & $body
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    } catch {
        Write-Host $_ -ForegroundColor Red
        $ok = $false
    } finally {
        Pop-Location
    }
    $state = if ($ok) { "pass" } elseif ($Advisory) { "advisory" } else { "FAIL" }
    $results.Add([pscustomobject]@{ Step = $name; Result = $state; Seconds = [int]$watch.Elapsed.TotalSeconds })
}

# Always runs (cheap): no browser-profile files may be tracked (a committed Edge profile once leaked cookies).
Step "repo: no browser-profile files tracked" $Root {
    $bad = @(git ls-files | Where-Object { ($_ -split '/')[-1] -in @("Local State", "Login Data", "Cookies", "Web Data") })
    if ($bad.Count -gt 0) { $bad | ForEach-Object { Write-Host "tracked browser-profile file: $_" -ForegroundColor Red }; $global:LASTEXITCODE = 1 }
}

if (Want "python") {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "Virtual environment is missing. Create it with: py -3 -m venv .venv"
    }
    if (-not $NoInstall) {
        Step "python: locked dependencies" $Root {
            & $Python -m pip install -q --require-hashes -r requirements-dev.lock.txt
            if ($LASTEXITCODE -eq 0) { & $Python -m pip install -q --no-deps --no-build-isolation -e . }
        }
    }
    Step "python: ruff (advisory)" $Root { & $Python -m ruff check src tests scripts --quiet --statistics } -Advisory
    Step "python: mypy (advisory)" $Root { & $Python -m mypy } -Advisory
    Step "python: i18n catalogs" $Root { & $Python scripts/i18n_check.py }
    # Parallel when pytest-xdist is installed (dev extra): about 3 minutes instead of 10+.
    $xdist = @(); & $Python -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('xdist') is None)"; if ($LASTEXITCODE -eq 0) { $xdist = @("-n", "auto") }
    Step "python: pytest" $Root { & $Python -m pytest -q -p no:cacheprovider @xdist }
}

if (Want "node") {
    if (-not $NoInstall) { Step "node: npm ci" $Root { npm ci --no-audit --no-fund --loglevel=error } }
    Step "node: npm test" $Root { npm test }
    Step "node: syntax-check extension scripts" $Root {
        Get-ChildItem browser-extension -Filter *.js -File | ForEach-Object {
            node --check $_.FullName
            if ($LASTEXITCODE -ne 0) { throw "Syntax error in $($_.Name)" }
        }
    }
}

if (Want "webui") {
    $dir = Join-Path $Root "webui"
    if (-not $NoInstall) { Step "webui: npm ci" $dir { npm ci --no-audit --no-fund --loglevel=error } }
    Step "webui: vitest" $dir { npm test }
    Step "webui: vite build" $dir { npm run build }
}

if (Want "kotlin") {
    Step "kotlin: lgk-core and app unit tests" (Join-Path $Root "android") {
        # --no-daemon: a Gradle daemon outlives the build (hours) and keeps the caller's output pipe open,
        # so `git push` from the pre-push hook never returned when its output was piped.
        .\gradlew.bat --no-daemon -q --console=plain :lgk-core:test :app:testDebugUnitTest
    }
}

if (Want "worker") {
    foreach ($w in @(@("license-issuer", "licence Worker"), @("update-feed", "update Worker"))) {
        $dir = Join-Path $Root "cloudflare\$($w[0])"
        # Both Workers pin wrangler as a devDependency (exact version, lockfile); install it so `npx wrangler` is the pinned one.
        if (-not $NoInstall -and (Test-Path -LiteralPath (Join-Path $dir "package-lock.json"))) {
            Step "worker: npm ci ($($w[0]))" $dir { npm ci --no-audit --no-fund --loglevel=error }
        }
        Step "worker: $($w[1]) tests" $dir { npm test }
    }
}

if (Want "dotnet") {
    # The Windows passkey provider (windows-passkey-provider/). The .NET 10 SDK may be a per-user install that is
    # not on PATH; prefer it, since global.json asks for 10.0.x.
    $dotnet = Join-Path $env:LOCALAPPDATA "Microsoft\dotnet10\dotnet.exe"
    if (Test-Path -LiteralPath $dotnet -PathType Leaf) {
        $env:DOTNET_ROOT = Split-Path $dotnet
    } else {
        $dotnet = "dotnet"
    }
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
    $env:DOTNET_NOLOGO = "1"
    # Locked restore, as GitHub CI (CI=true): a drifted packages.lock.json fails here too.
    Step "dotnet: locked restore" $Root {
        & $dotnet restore windows-passkey-provider\LocalGateKeys.PasskeyProvider.sln --locked-mode
    }
    Step "dotnet: passkey provider tests" $Root {
        & $dotnet test windows-passkey-provider\LocalGateKeys.PasskeyProvider.sln -c Release --no-restore
    }
}

if ((Want "security") -and -not $SkipSecurity) {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "Virtual environment is missing. Create it with: py -3 -m venv .venv"
    }
    # pip-audit and bandit come from the hash-pinned dev lock (installed by the python job).
    Step "security: pip-audit, npm audit, bandit" $Root { & $Python -I scripts/security_scan.py }
}

if ($Build) {
    # The build refuses output folders other accounts can write, so use an
    # owner-only folder (granted by SID: the user and the PC may share a name).
    $out = Join-Path $env:LOCALAPPDATA "lgk-ci-build"
    if (-not (Test-Path -LiteralPath $out)) {
        New-Item -ItemType Directory -Path $out | Out-Null
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        icacls $out /inheritance:r /grant:r "*${sid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    }
    # Only the frozen executables build_msix_package.ps1 packages (there is no installer).
    Step "build-smoke: frozen executables (MSIX input)" $Root {
        .\scripts\build_personal_installer.ps1 -SkipInstaller -OutputRoot $out
    }
}

if ($Snapshot) {
    $out = Join-Path $env:TEMP "lgk-public-snapshot"
    # Git Bash, not the WSL bash.exe that comes first on PATH.
    $git = (Get-Command git).Source
    $bash = @("..\..\bin\bash.exe", "..\bin\bash.exe") |
        ForEach-Object { Join-Path (Split-Path $git) $_ } |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $bash) { throw "Git Bash not found next to $git" }
    Step "public snapshot: privacy check" $Root { & $bash scripts/public_snapshot/make_snapshot.sh HEAD $out }
}

Write-Host "`n=== Summary" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($results | Where-Object { $_.Result -eq "FAIL" })
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) step(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "All gating steps passed." -ForegroundColor Green
exit 0
