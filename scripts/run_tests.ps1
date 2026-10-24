[CmdletBinding()]
param(
    # Skip dependency installation (use the environment as-is).
    [switch]$NoInstall,
    # Collect branch coverage for src/localvault and write coverage.xml.
    [switch]$Coverage,
    # Hash-pinned development lock file. Regenerate with scripts/update_locks.ps1.
    [string]$LockFile = "",
    # Anything else is passed straight to pytest (for example: -k vault -x).
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$PytestArgs
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Virtual environment is missing. Create it with: py -3 -m venv .venv"
}
if ([string]::IsNullOrWhiteSpace($LockFile)) {
    $LockFile = Join-Path $Root "requirements-dev.lock.txt"
} elseif (-not [IO.Path]::IsPathRooted($LockFile)) {
    $LockFile = [IO.Path]::GetFullPath((Join-Path $Root $LockFile))
}

if (-not $NoInstall) {
    if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) {
        throw "Development lock file not found: $LockFile"
    }
    # Every third-party package comes from the hash-pinned lock; a wheel whose
    # hash does not match is refused. The project itself is installed editable
    # without dependencies so the lock stays the single source of truth, and
    # without build isolation: setuptools and wheel come from the lock too.
    & $Python -m pip install --require-hashes -r $LockFile
    if ($LASTEXITCODE -ne 0) { throw "Locked dependency installation failed." }
    & $Python -m pip install --no-deps --no-build-isolation -e $Root
    if ($LASTEXITCODE -ne 0) { throw "Editable project installation failed." }
}

$Arguments = @()
if ($Coverage) {
    $Arguments += @("--cov=localvault", "--cov-branch", "--cov-report=term-missing", "--cov-report=xml")
}
if ($PytestArgs) { $Arguments += $PytestArgs }

Push-Location $Root
try {
    & $Python -m pytest @Arguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
