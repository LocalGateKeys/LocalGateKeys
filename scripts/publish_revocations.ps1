[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Licence ids to revoke, one per line (every currently revoked id: the list
    # replaces the previous one). Omit to sign an EMPTY list.
    [string]$IdsFile,
    # Release signing key PEM (the key in updates.PUBLISHER_KEYS, never the licence key).
    [string]$Key,
    # Or: environment variable holding the encrypted key PEM text.
    [string]$KeyEnv,
    # Environment variable holding the key password (default: prompt).
    [string]$PasswordEnv,
    [string]$Out = "revocations.json",
    [string]$Bucket = "localgatekeys-releases",
    # Sign and verify only; do not upload.
    [switch]$NoUpload
)

# Signs the licence revocation list and uploads it as the R2 object
# revocations.json, served by cloudflare/update-feed at /revocations.json.
#
# Run with no -IdsFile once now so /revocations.json stops returning 404
# (audit 2026-10-24 L-3). Afterwards build the ids file from the licence
# Worker's refund records; see cloudflare/license-issuer/README.md,
# "Refunds and revocation".
#
# Requires `wrangler login` (once) for the upload and the venv. Use -WhatIf for a dry run.

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Key) -eq [string]::IsNullOrWhiteSpace($KeyEnv)) {
    throw "Pass exactly one of -Key (PEM file) or -KeyEnv (environment variable)."
}

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
$Python = if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
    $VenvPython
} else {
    (Get-Command python -ErrorAction Stop).Source
}

$TempIds = $null
if ([string]::IsNullOrWhiteSpace($IdsFile)) {
    $TempIds = [System.IO.Path]::GetTempFileName()
    $IdsPath = $TempIds
    Write-Host "No -IdsFile: signing an empty revocation list."
} else {
    $IdsPath = (Resolve-Path -LiteralPath $IdsFile).Path
}

try {
    $SignArgs = @("$Root\scripts\sign_release_manifest.py", "revocations", "--ids-file", $IdsPath, "--out", $Out)
    if ($Key) { $SignArgs += @("--key", $Key) } else { $SignArgs += @("--key-env", $KeyEnv) }
    if ($PasswordEnv) { $SignArgs += @("--password-env", $PasswordEnv) }
    & $Python @SignArgs
    if ($LASTEXITCODE -ne 0) { throw "Signing the revocation list failed." }
} finally {
    if ($TempIds) { Remove-Item -LiteralPath $TempIds -Force -ErrorAction SilentlyContinue }
}

# --- The client must accept it ------------------------------------------------
$OutPath = (Resolve-Path -LiteralPath $Out).Path
# Fed on stdin: Windows PowerShell mangles double quotes in native arguments.
@"
import json, sys
sys.path.insert(0, r'$Root\src')
sys.path.insert(0, r'$Root\scripts')
from localvault import updates
# Exactly what the app runs on a downloaded list (updates.fetch_revocations).
keys = updates.revocation_keys()
if not keys:
    sys.exit("updates.PUBLISHER_KEYS is empty")
manifest = updates._verified_revocations(open(r'$OutPath', 'rb').read(), keys)
print(f"OK: verifies against PUBLISHER_KEYS ({len(manifest['revoked'])} revoked, published {manifest['published']})")
"@ | & $Python -
if ($LASTEXITCODE -ne 0) { throw "The signed list does not verify against updates.PUBLISHER_KEYS (wrong key?)." }

if ($NoUpload) {
    Write-Host "Signed $OutPath (not uploaded)."
    return
}
if ($PSCmdlet.ShouldProcess("$Bucket/revocations.json", "wrangler r2 object put")) {
    & wrangler r2 object put "$Bucket/revocations.json" --file $OutPath --content-type application/json --remote
    if ($LASTEXITCODE -ne 0) { throw "Upload failed: revocations.json" }
    Write-Host "Uploaded revocations.json to $Bucket." -ForegroundColor Green
}
