[CmdletBinding()]
param(
    # Interpreter whose site-packages are described. Defaults to the project venv,
    # which is also the environment PyInstaller freezes.
    [string]$Python = "",
    # Destination CycloneDX JSON file.
    [string]$OutputPath = "",
    # Hash-pinned face-model manifest written by scripts/fetch_face_models.ps1.
    [string]$ModelManifestPath = "",
    # Browser extension source directory.
    [string]$ExtensionDir = "",
    # CycloneDX schema version understood by downstream tooling.
    [string]$SpecVersion = "1.6"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Resolve-UnderRoot([string]$Value, [string]$Default) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
    return [IO.Path]::GetFullPath((Join-Path $Root $Value))
}

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = if (Test-Path -LiteralPath $VenvPython -PathType Leaf) { $VenvPython } else { (Get-Command python -ErrorAction Stop).Source }
}
$OutputPath = Resolve-UnderRoot $OutputPath (Join-Path $Root "dist-installer\LocalGateKeys.sbom.cdx.json")
$ModelManifestPath = Resolve-UnderRoot $ModelManifestPath (Join-Path $Root "release-inputs\face-models.manifest.json")
$ExtensionDir = Resolve-UnderRoot $ExtensionDir (Join-Path $Root "browser-extension")

foreach ($required in @($ModelManifestPath, (Join-Path $ExtensionDir "manifest.json"), (Join-Path $Root "pyproject.toml"))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "SBOM input is missing: $required" }
}

& $Python -c "import cyclonedx_py" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "cyclonedx-bom is not installed in $Python. Install the dev lock: python -m pip install --require-hashes -r requirements-dev.lock.txt"
}

# A fixed timestamp keeps two SBOMs of the same commit byte-identical. Prefer a
# value the build script already exported; otherwise use the commit time.
if ([string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
    $epoch = ""
    try { $epoch = (& git -C $Root log -1 --format=%ct 2>$null | Select-Object -First 1) } catch { $epoch = "" }
    if ([string]::IsNullOrWhiteSpace($epoch)) { $epoch = [string][int64][Math]::Floor((Get-Date -Date (Get-Date).ToUniversalTime() -UFormat %s)) }
    $env:SOURCE_DATE_EPOCH = $epoch.Trim()
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
$EnvironmentSbom = "$OutputPath.environment.tmp"
if (Test-Path -LiteralPath $EnvironmentSbom) { Remove-Item -LiteralPath $EnvironmentSbom -Force }

Push-Location $Root
try {
    & $Python -m cyclonedx_py environment $Python `
        --pyproject (Join-Path $Root "pyproject.toml") `
        --mc-type application `
        --spec-version $SpecVersion `
        --output-reproducible `
        --output-format JSON `
        --output-file $EnvironmentSbom
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $EnvironmentSbom -PathType Leaf)) {
        throw "cyclonedx-py failed to describe the Python environment."
    }

    & $Python (Join-Path $Root "scripts\sbom_merge.py") `
        --sbom $EnvironmentSbom `
        --output $OutputPath `
        --model-manifest $ModelManifestPath `
        --extension-dir $ExtensionDir
    if ($LASTEXITCODE -ne 0) { throw "Adding the model and extension components to the SBOM failed." }
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $EnvironmentSbom) { Remove-Item -LiteralPath $EnvironmentSbom -Force }
}

$Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $OutputPath).Hash.ToUpperInvariant()
[IO.File]::WriteAllText("$OutputPath.sha256", "$Hash  $([IO.Path]::GetFileName($OutputPath))`r`n", [Text.ASCIIEncoding]::new())
Write-Host "SBOM: $OutputPath" -ForegroundColor Green
Write-Host "SBOM SHA256: $Hash"
