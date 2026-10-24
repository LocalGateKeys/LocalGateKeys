[CmdletBinding()]
param(
    [string]$Basetemp = "",
    [switch]$RunBrowserE2E,
    [string]$ChromiumPath = ""
)

$ErrorActionPreference = "Stop"

# This harness deliberately names its scan roots and pytest files.  It does not
# recursively inspect the repository root, generated ACL-artifact directories,
# user profiles, or backup collections.
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
$Python = if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
    $VenvPython
} else {
    (Get-Command python -ErrorAction Stop).Source
}

$RootFull = $Root.TrimEnd('\', '/')
if ([string]::IsNullOrWhiteSpace($Basetemp)) {
    $BasetempPath = Join-Path $Root (".offline-release-pytest-" + [guid]::NewGuid().ToString("N"))
} else {
    if ([IO.Path]::IsPathRooted($Basetemp)) {
        $BasetempPath = [IO.Path]::GetFullPath($Basetemp)
    } else {
        $BasetempPath = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Basetemp))
    }
}
$BasetempFull = $BasetempPath.TrimEnd('\', '/')
$insideRoot = $BasetempFull.StartsWith($RootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
if (-not $insideRoot -or $BasetempFull -eq $RootFull) {
    throw "Basetemp must be a child of the workspace root: $RootFull"
}
New-Item -ItemType Directory -Force -Path $BasetempFull | Out-Null

$script:CheckResults = [System.Collections.Generic.List[object]]::new()
$script:FailureCount = 0

function Invoke-OfflineCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    try {
        & $Action
        $script:CheckResults.Add([pscustomobject]@{ Name = $Name; Status = "PASS" })
        Write-Host "PASS  $Name" -ForegroundColor Green
    } catch {
        $script:FailureCount++
        $detail = $_.Exception.Message
        $script:CheckResults.Add([pscustomobject]@{ Name = $Name; Status = "FAIL"; Detail = $detail })
        Write-Host "FAIL  $Name :: $detail" -ForegroundColor Red
    }
}

Push-Location $Root
try {
    Invoke-OfflineCheck -Name "Python compileall (src, scripts, tests)" -Action {
        & $Python -m compileall -q src scripts tests
        if ($LASTEXITCODE -ne 0) { throw "compileall exited with code $LASTEXITCODE" }
    }

    Invoke-OfflineCheck -Name "Runtime source scans (cloud, telemetry, capture)" -Action {
        # These are high-confidence runtime red flags, not a ban on ordinary
        # words such as "cloud" in comments or on explicit LAN/backup code.
        $patterns = [ordered]@{
            "capture primitive: global hook" = 'SetWindowsHookEx|WH_KEYBOARD|GetAsyncKeyState|ReadProcessMemory|GetClipboardData|pyperclip|pynput|keyboard\.hook|ImageGrab|BitBlt'
            "capture primitive: UI text extraction" = 'CurrentValue|ValuePattern\.Value|\.texts\(\)|\bget_value\('
            "cloud SDK import" = '(?m)^\s*(?:from|import)\s+(?:boto3|dropbox|httpx|aiohttp|requests|google\.cloud|azure\.storage)\b'
            "telemetry SDK or provider" = '\b(?:sentry_sdk|opentelemetry|segment|mixpanel|posthog|amplitude|datadog|newrelic|firebase)\b'
            "telemetry event call" = '\b(?:telemetry|analytics)\.(?:track|capture|identify|send|event)\s*\('
            "cloud telemetry endpoint" = 'https?://[^\s"'']*(?:sentry\.io|segment\.com|mixpanel\.com|posthog\.com|amplitude\.com|datadoghq\.com|newrelic\.com|firebaseio\.com|google-analytics\.com)'
        }
        $scanRoots = @(
            (Join-Path $Root "src"),
            (Join-Path $Root "browser-extension")
        )
        $sourceFiles = foreach ($scanRoot in $scanRoots) {
            Get-ChildItem -LiteralPath $scanRoot -Recurse -File | Where-Object {
                $_.Extension.ToLowerInvariant() -in @(".py", ".js", ".cjs")
            }
        }
        $findings = [System.Collections.Generic.List[object]]::new()
        foreach ($file in $sourceFiles) {
            $text = Get-Content -LiteralPath $file.FullName -Raw
            foreach ($entry in $patterns.GetEnumerator()) {
                if (-not [regex]::IsMatch($text, $entry.Value, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                    continue
                }
                $lines = $text -split "`r?`n"
                for ($index = 0; $index -lt $lines.Count; $index++) {
                    if ([regex]::IsMatch($lines[$index], $entry.Value, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                        $relative = [IO.Path]::GetRelativePath($Root, $file.FullName)
                        $findings.Add("$relative`:$($index + 1) [$($entry.Key)] $($lines[$index].Trim())")
                        break
                    }
                }
            }
        }
        if ($findings.Count -gt 0) {
            throw "Suspicious runtime source patterns found:`n$($findings -join "`n")"
        }
        Write-Host "  Scanned $($sourceFiles.Count) runtime source files under src/ and browser-extension/."
    }

    $focusedTests = @(
        # Compile/commit/publication/restore fault paths.
        "tests/test_attachments.py",
        "tests/test_backup_v2.py",
        "tests/test_recovery.py",
        "tests/test_transfer.py",
        "tests/test_transfer_ui.py",
        # Explicitly opt-in, socket-free LAN sync contracts.
        "tests/test_sync.py",
        "tests/test_sync_ui.py",
        # Next-release migration, OCR, import/reminder, sync, and UI contracts.
        "tests/test_legacy_migration.py",
        "tests/test_next_release_faults.py",
        "tests/test_next_release_ocr.py",
        "tests/test_next_release_sync_transport.py",
        "tests/test_next_release_sync_vault.py",
        "tests/test_next_release_import_reminders.py",
        "tests/test_next_release_ui.py",
        "tests/test_feature_sync_ui.py",
        # Browser/native/identity release contracts without a live account.
        # The identity nodes below are deliberately the no-tmp_path contracts;
        # this Windows environment cannot reliably clean pytest tmp_path ACLs.
        "tests/test_identity_fill.py::test_identity_schema_is_closed_text_only",
        "tests/test_identity_fill.py::test_identity_release_denies_changed_scope_and_consumes_capability",
        "tests/test_identity_fill.py::test_identity_release_is_selected_only_and_one_use",
        "tests/test_identity_fill.py::test_identity_release_expires_and_lock_invalidates",
        "tests/test_identity_fill.py::test_selected_field_normalization_rejects_credential_like_names",
        "tests/test_identity_fill.py::test_identity_context_requires_browser_document_and_exact_origin",
        "tests/test_extension_manifest.py",
        "tests/test_browser_bridge_registration.py::test_personal_installer_repairs_before_launch_and_unregisters_on_uninstall",
        "tests/test_browser_bridge_registration.py::test_packaged_agent_has_native_bridge_maintenance_cli",
        "tests/test_browser_bridge_registration.py::test_in_app_repair_does_not_depend_on_repository_powershell",
        "tests/test_browser_bridge_registration.py::test_extension_manifest_key_matches_expected_extension_id",
        "tests/test_install_hardening.py",
        # Strict-offline and generic capture policy checks.
        "tests/test_no_capture_primitives.py",
        "tests/test_settings.py::test_strict_offline_defaults_on",
        "tests/test_release019.py::test_strict_offline_breach_check_never_calls_fetch"
    )

    Invoke-OfflineCheck -Name "Focused offline pytest contracts" -Action {
        $pytestArgs = @(
            "-m", "pytest",
            "-q",
            "--basetemp", $BasetempFull,
            "--maxfail=1"
        ) + $focusedTests
        & $Python @pytestArgs
        if ($LASTEXITCODE -ne 0) { throw "pytest exited with code $LASTEXITCODE" }
    }

    if ($RunBrowserE2E) {
        Invoke-OfflineCheck -Name "Optional offline Chromium browser E2E" -Action {
            & $Python -c "import playwright.sync_api"
            if ($LASTEXITCODE -ne 0) {
                throw "Playwright is not installed in the selected Python environment"
            }
            $browserArgs = @("tests/browser_e2e_019.py")
            if (-not [string]::IsNullOrWhiteSpace($ChromiumPath)) {
                $browserArgs += $ChromiumPath
            }
            & $Python @browserArgs
            if ($LASTEXITCODE -ne 0) { throw "browser_e2e_019.py exited with code $LASTEXITCODE" }
        }
    } else {
        Write-Host "SKIP  Optional offline Chromium browser E2E (use -RunBrowserE2E when Playwright/Chromium are installed)" -ForegroundColor Yellow
        $script:CheckResults.Add([pscustomobject]@{ Name = "Optional offline Chromium browser E2E"; Status = "SKIP" })
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Offline release verification summary" -ForegroundColor Cyan
Write-Host "  Python:   $Python"
Write-Host "  Basetemp: $BasetempFull"
$CheckResults | ForEach-Object {
    $suffix = if ($_.Detail) { " :: $($_.Detail)" } else { "" }
    Write-Host ("  {0,-5} {1}{2}" -f $_.Status, $_.Name, $suffix)
}

if ($FailureCount -gt 0) {
    Write-Error "$FailureCount offline release verification check(s) failed."
    exit 1
}
Write-Host "All required offline release checks passed." -ForegroundColor Green
exit 0
