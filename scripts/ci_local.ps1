<#
Runs the GitHub CI jobs (.github/workflows/ci.yml) on this PC, plus the suites
CI does not cover yet (web UI, Android core, licence Worker).

  .\scripts\ci_local.ps1               # every Windows job except the build
  .\scripts\ci_local.ps1 -Build        # also the build-smoke job (PyInstaller, slow)
  .\scripts\ci_local.ps1 -Only node,kotlin
  .\scripts\ci_local.ps1 -Snapshot     # also the public-snapshot privacy check

The Swift job needs the Mac: scripts/ci_local_mac.sh. The pre-push hook in
.githooks runs this script; enable it once with
  git config core.hooksPath .githooks
Exit code 0 only when every gating step passed (ruff and mypy stay advisory,
as in CI).
#>
[CmdletBinding()]
param(
    # Comma-separated jobs: python, node, webui, kotlin, worker (default: all).
    [string]$Only = "",
    [switch]$Build,
    [switch]$Snapshot,
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
$unknown = @($Jobs | Where-Object { $_ -notin @("python", "node", "webui", "kotlin", "worker") })
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
    Step "python: pytest" $Root { & $Python -m pytest -q -p no:cacheprovider }
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
    Step "kotlin: lgk-core tests" (Join-Path $Root "android") { .\gradlew.bat -q --console=plain :lgk-core:test }
}

if (Want "worker") {
    $dir = Join-Path $Root "cloudflare\license-issuer"
    # The Worker has no dependencies (node:test only), so there may be no lock to install from.
    if (-not $NoInstall -and (Test-Path -LiteralPath (Join-Path $dir "package-lock.json"))) {
        Step "worker: npm ci" $dir { npm ci --no-audit --no-fund --loglevel=error }
    }
    Step "worker: licence Worker tests" $dir { npm test }
}

if ($Build) {
    Step "build-smoke: frozen executables" $Root {
        .\scripts\build_personal_installer.ps1 -SkipInstaller -OutputRoot (Join-Path $env:TEMP "lgk-ci-build")
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
