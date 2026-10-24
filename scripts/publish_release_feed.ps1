[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Signed bundle produced by `sign_release_manifest.py sign`.
    [Parameter(Mandatory = $true)]
    [string]$Bundle,
    # Every file listed in the manifest's artifacts, e.g. the Setup .exe.
    [Parameter(Mandatory = $true)]
    [string[]]$Artifact,
    [string]$Bucket = "localgatekeys-releases"
)

# Publishes a signed release to the Cloudflare release feed (cloudflare/update-feed).
#
# Before uploading anything it checks that the bundle verifies against the
# publisher keys compiled into src/localvault/updates.py, that every artifact
# hash, size and URL matches the manifest, and that the sequence is higher than
# the one currently live. Artifacts are uploaded first and stable.json last, so
# clients never see a manifest whose downloads are missing.
#
# Requires `wrangler login` (once) and the venv. Use -WhatIf for a dry run.

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
$Python = if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
    $VenvPython
} else {
    (Get-Command python -ErrorAction Stop).Source
}

$BundlePath = (Resolve-Path -LiteralPath $Bundle).Path

# --- What the shipped client trusts -----------------------------------------
$ClientConfig = & $Python -c @"
import json, sys
sys.path.insert(0, r'$Root\src')
from localvault import updates
print(json.dumps({'feed_url': updates.RELEASE_FEED_URL, 'keys': list(updates.PUBLISHER_KEYS.values())}))
"@
if ($LASTEXITCODE -ne 0) { throw "Could not read RELEASE_FEED_URL / PUBLISHER_KEYS from updates.py." }
$ClientConfig = $ClientConfig | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($ClientConfig.feed_url) -or $ClientConfig.keys.Count -eq 0) {
    throw "RELEASE_FEED_URL and PUBLISHER_KEYS must both be set in src/localvault/updates.py before publishing."
}
$FeedUri = [Uri]$ClientConfig.feed_url
if ($FeedUri.AbsolutePath -ne "/stable.json") {
    throw "RELEASE_FEED_URL must end in /stable.json to match the Worker: $($ClientConfig.feed_url)"
}
$Origin = $FeedUri.GetLeftPart([UriPartial]::Authority)

# --- Signature --------------------------------------------------------------
$VerifyArgs = @("$Root\scripts\sign_release_manifest.py", "verify", "--bundle", $BundlePath)
foreach ($Key in $ClientConfig.keys) { $VerifyArgs += @("--public-key", $Key) }
& $Python @VerifyArgs
if ($LASTEXITCODE -ne 0) { throw "The bundle does not verify against the keys compiled into the client." }

$Manifest = (Get-Content -LiteralPath $BundlePath -Raw -Encoding utf8 | ConvertFrom-Json).manifest
$Version = $Manifest.app_version

# --- Artifacts match the manifest -------------------------------------------
$Uploads = @()
$Remaining = @{}
foreach ($Path in $Artifact) {
    $Item = Get-Item -LiteralPath $Path
    $Remaining[$Item.Name] = $Item
}
foreach ($Entry in $Manifest.artifacts) {
    if (-not $Remaining.ContainsKey($Entry.name)) {
        throw "Manifest lists $($Entry.name) but it was not passed with -Artifact."
    }
    $Item = $Remaining[$Entry.name]
    $Remaining.Remove($Entry.name)
    $ExpectedUrl = "$Origin/releases/$Version/$($Entry.name)"
    if ($Entry.url -ne $ExpectedUrl) {
        throw "Artifact URL for $($Entry.name) must be $ExpectedUrl (manifest has $($Entry.url))."
    }
    $Stream = [System.IO.File]::OpenRead($Item.FullName)
    try { $Hash = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($Stream)) -replace "-", "").ToLowerInvariant() } finally { $Stream.Dispose() }
    if ($Hash -ne $Entry.sha256 -or $Item.Length -ne [int64]$Entry.size) {
        throw "$($Entry.name) does not match the sha256/size in the signed manifest."
    }
    $Uploads += [pscustomobject]@{ Key = "releases/$Version/$($Entry.name)"; File = $Item.FullName }
}
if ($Remaining.Count -gt 0) {
    throw "Not listed in the manifest: $($Remaining.Keys -join ', ')"
}

# --- Sequence moves forward -------------------------------------------------
try {
    # Cloudflare blocks PowerShell's default user agent; identify like the client.
    $Live = Invoke-RestMethod -Uri $ClientConfig.feed_url -Method Get -MaximumRedirection 0 -TimeoutSec 10 -UserAgent "LocalGateKeys-publisher"
} catch {
    # Windows PowerShell raises WebException, PowerShell 7 HttpResponseException;
    # both carry the HTTP response.
    $Response = $_.Exception.Response
    if ($null -eq $Response) { throw "Could not read the live feed: $($_.Exception.Message)" }
    $Status = [int]$Response.StatusCode
    if ($Status -ne 404) { throw "Could not read the live feed (HTTP $Status): $($_.Exception.Message)" }
    $Live = $null
}
if ($null -eq $Live) {
    Write-Host "No live feed yet; this is the first release."
} else {
    if ([int64]$Manifest.sequence -le [int64]$Live.manifest.sequence) {
        throw "Sequence $($Manifest.sequence) is not higher than the live sequence $($Live.manifest.sequence)."
    }
    Write-Host "Live feed: $($Live.manifest.app_version) (sequence $($Live.manifest.sequence))"
}

# --- Upload: artifacts first, feed last -------------------------------------
function Send-Object([string]$Key, [string]$File, [string]$ContentType) {
    if ($PSCmdlet.ShouldProcess("$Bucket/$Key", "wrangler r2 object put")) {
        & wrangler r2 object put "$Bucket/$Key" --file $File --content-type $ContentType --remote
        if ($LASTEXITCODE -ne 0) { throw "Upload failed: $Key" }
    }
}
foreach ($Upload in $Uploads) {
    Send-Object $Upload.Key $Upload.File "application/octet-stream"
}
Send-Object "stable.json" $BundlePath "application/json"

Write-Host "Published $Version (sequence $($Manifest.sequence)) to $($ClientConfig.feed_url)" -ForegroundColor Green
