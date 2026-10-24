[CmdletBinding()]
param(
    [switch]$Offline,
    [string]$ModelRoot = "",
    [string]$ManifestPath = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ModelDir = if ([string]::IsNullOrWhiteSpace($ModelRoot)) {
    Join-Path $Root "src\localvault\models"
} elseif ([IO.Path]::IsPathRooted($ModelRoot)) {
    [IO.Path]::GetFullPath($ModelRoot)
} else {
    [IO.Path]::GetFullPath((Join-Path $Root $ModelRoot))
}
$ModelDir = [IO.Path]::GetFullPath($ModelDir)
New-Item -ItemType Directory -Force -Path $ModelDir | Out-Null
$ManifestPath = if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    Join-Path $ModelDir "face-models.manifest.json"
} elseif ([IO.Path]::IsPathRooted($ManifestPath)) {
    [IO.Path]::GetFullPath($ManifestPath)
} else {
    [IO.Path]::GetFullPath((Join-Path $ModelDir $ManifestPath))
}

$Models = @(
    @{
        Name = "face_detection_yunet_2023mar.onnx"
        Sha256 = "8F2383E4DD3CFBB4553EA8718107FC0423210DC964F9F4280604804ED2552FA4"
        Urls = @(
            "https://huggingface.co/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar.onnx?download=true",
            "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
        )
    },
    @{
        Name = "face_recognition_sface_2021dec_int8bq.onnx"
        Sha256 = "FB143EEA07838AA532D1C95DF5F69899974EA0140E1FBA05E94204BE13ED74EE"
        Urls = @(
            "https://huggingface.co/opencv/face_recognition_sface/resolve/main/face_recognition_sface_2021dec_int8bq.onnx?download=true",
            "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec_int8bq.onnx"
        )
    }
)

function Test-ModelHash([string]$Path, [string]$Expected) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    return ((Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant() -eq $Expected.ToUpperInvariant())
}

$ManifestRows = New-Object System.Collections.Generic.List[object]
foreach ($Model in $Models) {
    $Destination = Join-Path $ModelDir $Model.Name
    if (Test-ModelHash $Destination $Model.Sha256) {
        Write-Host "Verified camera model: $($Model.Name)"
    } else {
        if (Test-Path -LiteralPath $Destination) {
            if ($Offline) {
                throw "Offline model verification failed: $($Model.Name) is present but its hash is not trusted."
            }
            Remove-Item -LiteralPath $Destination -Force
        }

        if ($Offline) {
            throw "Offline model verification failed: $($Model.Name) is not pre-staged."
        }

        $Downloaded = $false
        $Failures = New-Object System.Collections.Generic.List[string]
        foreach ($Url in $Model.Urls) {
            $Temporary = "$Destination.download-$([Guid]::NewGuid().ToString('N'))"
            try {
                Write-Host "Downloading public OpenCV model $($Model.Name)..."
                Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Temporary -MaximumRedirection 8
                if (-not (Test-ModelHash $Temporary $Model.Sha256)) {
                    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Temporary).Hash.ToUpperInvariant()
                    throw "SHA256 mismatch (received $Actual)"
                }
                Move-Item -LiteralPath $Temporary -Destination $Destination -Force
                $Downloaded = $true
                break
            }
            catch {
                [void]$Failures.Add("$Url -> $($_.Exception.Message)")
                if (Test-Path -LiteralPath $Temporary) { Remove-Item -LiteralPath $Temporary -Force }
            }
        }
        if (-not $Downloaded) {
            throw "Could not securely download $($Model.Name). The master-password route is unaffected. Details:`n$($Failures -join "`n")"
        }
        Write-Host "Downloaded and verified camera model: $($Model.Name)" -ForegroundColor Green
    }

    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToUpperInvariant()
    if ($Actual -ne $Model.Sha256.ToUpperInvariant()) {
        throw "Model hash changed while staging: $($Model.Name)"
    }
    [void]$ManifestRows.Add([ordered]@{
        name = $Model.Name
        sha256 = $Actual
        size = [int64](Get-Item -LiteralPath $Destination).Length
    })
}

# The manifest intentionally contains no timestamps, absolute paths, or URLs.
# Sorting and hash verification make it stable across repeated offline builds.
$Manifest = [ordered]@{
    schema = 1
    models = @($ManifestRows | Sort-Object -Property name)
}
$ManifestParent = Split-Path -Parent $ManifestPath
New-Item -ItemType Directory -Force -Path $ManifestParent | Out-Null
$ManifestTemp = "$ManifestPath.tmp"
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
# Windows PowerShell's ConvertTo-Json emits CRLF; the tracked manifest is LF, so
# normalise to keep a rebuild from showing the file as modified.
[IO.File]::WriteAllText($ManifestTemp, ((($Manifest | ConvertTo-Json -Depth 5) -replace "`r`n", "`n") + "`n"), $Utf8NoBom)
Move-Item -LiteralPath $ManifestTemp -Destination $ManifestPath -Force
Write-Host "Verified camera model manifest: $ManifestPath"
