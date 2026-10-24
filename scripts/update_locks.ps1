[CmdletBinding()]
param(
    # Interpreter used to resolve the locks. Resolve on the OLDEST interpreter
    # the project supports in CI (currently 3.12/3.13) so no marker-gated
    # dependency is dropped for the newer ones.
    [string]$Python = "",
    # Re-resolve every package to its newest allowed version instead of keeping
    # the pins that still satisfy pyproject.toml.
    [switch]$Upgrade,
    # Also populate release-inputs\wheelhouse with every wheel in the dev lock,
    # for `build_personal_installer.ps1 -Offline`.
    [switch]$Wheelhouse
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = Join-Path $Root ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { $Python = (Get-Command python -ErrorAction Stop).Source }
}

# pip-tools itself comes from the hash-pinned dev lock (never an unpinned index
# install): reuse it only when the installed version is the locked one.
$DevLock = Join-Path $Root "requirements-dev.lock.txt"
$pinLine = Select-String -LiteralPath $DevLock -Pattern '^pip-tools==(\S+)' | Select-Object -First 1
if (-not $pinLine) { throw "requirements-dev.lock.txt has no pip-tools pin; add pip-tools to the dev extra and lock it by hand once." }
$pipToolsPin = $pinLine.Matches[0].Groups[1].Value
# Prints the installed pip-tools version or an empty line; never writes stderr (Stop preference).
$installed = & $Python -c "import importlib.metadata as m; print({(d.metadata['Name'] or '').lower(): d.version for d in m.distributions()}.get('pip-tools', ''))"
if ($LASTEXITCODE -ne 0 -or "$installed".Trim() -ne $pipToolsPin) {
    Write-Host "Installing pip-tools $pipToolsPin from the hash-pinned dev lock ..."
    & $Python -m pip install --require-hashes -r $DevLock
    if ($LASTEXITCODE -ne 0) {
        throw "Installing pip-tools from requirements-dev.lock.txt (--require-hashes) failed; fix the lock or the interpreter ($Python) and retry."
    }
}

$Common = @("--generate-hashes", "--strip-extras", "--allow-unsafe", "--resolver=backtracking")
if ($Upgrade) { $Common += "--upgrade" }

Push-Location $Root
try {
    Write-Host "Resolving runtime lock with $Python ..."
    & $Python -m piptools compile @Common --output-file requirements.lock.txt pyproject.toml
    if ($LASTEXITCODE -ne 0) { throw "Runtime lock generation failed." }

    Write-Host "Resolving development + build lock ..."
    & $Python -m piptools compile @Common --extra dev --extra build --output-file requirements-dev.lock.txt pyproject.toml
    if ($LASTEXITCODE -ne 0) { throw "Development lock generation failed." }

    # pip-tools 7.6 prints "--no-index" in the header although the index was used;
    # keep the recorded command honest so copy/paste reproduces the resolution.
    foreach ($lock in @("requirements.lock.txt", "requirements-dev.lock.txt")) {
        $text = [IO.File]::ReadAllText((Join-Path $Root $lock))
        [IO.File]::WriteAllText((Join-Path $Root $lock), $text.Replace(" --no-index", ""), [Text.UTF8Encoding]::new($false))
    }

    # The build backend lock for install_windows.ps1 (--no-build-isolation): the
    # setuptools and wheel entries of the dev lock, pins and hashes unchanged.
    $devLines = [IO.File]::ReadAllText((Join-Path $Root "requirements-dev.lock.txt")).Replace("`r`n", "`n").Split("`n")
    $build = [Collections.Generic.List[string]]::new()
    foreach ($line in @("#",
            "# Build backend for ``pip install --no-build-isolation`` of LocalGateKeys itself",
            "# (pyproject.toml [build-system]). The setuptools and wheel pins and hashes are",
            "# copied from requirements-dev.lock.txt by scripts/update_locks.ps1; do not edit.",
            "#")) { $build.Add($line) }
    foreach ($name in @("setuptools", "wheel")) {
        $start = [Array]::FindIndex($devLines, [Predicate[string]]{ param($l) $l.StartsWith("$name==") })
        if ($start -lt 0) { throw "requirements-dev.lock.txt has no $name pin." }
        $build.Add($devLines[$start])
        for ($i = $start + 1; $i -lt $devLines.Length -and $devLines[$i].StartsWith("    --hash=sha256:"); $i++) {
            $build.Add($devLines[$i])
        }
    }
    [IO.File]::WriteAllText((Join-Path $Root "requirements-build.lock.txt"), (($build -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false))

    if ($Wheelhouse) {
        $house = Join-Path $Root "release-inputs\wheelhouse"
        New-Item -ItemType Directory -Force -Path $house | Out-Null
        Write-Host "Downloading wheels into $house ..."
        & $Python -m pip download --require-hashes -r requirements-dev.lock.txt --dest $house
        if ($LASTEXITCODE -ne 0) { throw "Wheelhouse download failed." }
    }
    Write-Host "Locks updated. Review the diff, then run scripts\run_tests.ps1 to install and test from the new lock." -ForegroundColor Green
}
finally {
    Pop-Location
}
