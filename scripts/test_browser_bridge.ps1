[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This diagnostic script requires Windows.' }
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (!(Test-Path -LiteralPath $Python)) {
    throw 'Run this script from the repository containing .venv, not the extracted patch folder.'
}
& $Python -m localvault.bridge_diagnostics
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Connection test did not pass. Share the sanitized report above; do not share install.json, agent-state.json or vault files.' -ForegroundColor Yellow
}
