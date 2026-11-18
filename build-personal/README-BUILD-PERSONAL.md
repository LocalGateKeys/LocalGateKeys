# LocalGateKeys frozen executable build

LocalGateKeys for Windows ships only through the Microsoft Store. The Inno
Setup installer was removed on 2026-11-18. `scripts\build_personal_installer.ps1`
(name kept to avoid churn) builds the frozen executables that
`scripts\build_msix_package.ps1` packs into the MSIX.

Run from a normal (non-elevated) PowerShell on Windows:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build_personal_installer.ps1 -OutputRoot ci-build   # frozen executables (MSIX input)
```

Prerequisites:

- `.venv` with the project installed from the hash-pinned lock
  (`python -m pip install --require-hashes -r requirements-dev.lock.txt`, then
  `python -m pip install --no-deps -e .`), or pass `-InstallDependencies` to let
  the script do it.
- Node.js 20+ with npm: the script runs `npm ci` and `npm run build` in `webui\`
  (the WebView2 window) before PyInstaller.
- Windows SDK `signtool.exe` only when signing.

What the script does, in order:

1. Sets `SOURCE_DATE_EPOCH` from the commit time (falls back to now) and
   `PYTHONHASHSEED=0` so repeated builds of one commit are comparable.
2. Optionally installs dependencies (`-InstallDependencies` online, or
   `-Offline -Wheelhouse <dir>` with `--no-index --find-links --require-hashes`).
3. Fetches/verifies the two hash-pinned OpenCV Zoo models (`-Offline` requires
   them to be pre-staged) and runs the environment preflight.
4. Deletes prior generated `build-personal\agent`, `build-personal\native`,
   `dist-personal`, and `dist-installer` contents, then freezes
   `LocalGateKeys`, `LocalGateKeysNativeHost` and `lgk` with PyInstaller (UPX
   disabled).
5. Signs the executables when a certificate was supplied, runs each with
   `--check-build`, and rejects payloads containing demo/test directories or
   user-data files such as `vault.json`, `profiles.json`, `agent-state.json`.
6. Writes the CycloneDX SBOM (`scripts\generate_sbom.ps1`).
7. Writes `LocalGateKeys-Setup-Personal.manifest.json` with payload hashes,
   tool versions, SBOM hash, `signed` state and `source_date_epoch`.

## Switches

| Switch | Purpose |
|---|---|
| `-OutputRoot <dir>` | Build into an isolated directory instead of the checkout. |
| `-Offline` | No network: models must be pre-staged (`-ModelRoot`), dependencies come from `-Wheelhouse` (default `release-inputs\wheelhouse` when present). |
| `-Wheelhouse <dir>` / `-LockFile <file>` | Offline dependency source and the hash lock to enforce. |
| `-ModelRoot <dir>` / `-ManifestPath <file>` | Pre-staged model directory for offline builds, and where the verified face-model manifest is written/read. |
| `-InstallDependencies` | Online install of `requirements-dev.lock.txt` with `--require-hashes` before building. Release builds do this by default. |
| `-Release` | Release build: dependencies from the hash-pinned lock (unless `-Offline` with a wheelhouse) and the Python minimum is enforced. Implied by `-CertificateThumbprint` / `-PfxPath`. |
| `-UseEnvironment` | Release builds only: package the venv as it is instead of reinstalling the lock. |
| `-MinimumPythonVersion <x.y.z>` | Oldest Python the frozen runtime may come from (default `3.14.9`). Release builds fail below it; other builds warn. |
| `-SkipInstaller` | Accepted for older command lines; has no effect. |
| `-SkipSbom` | Skip SBOM generation (not for releases). |
| `-CertificateThumbprint <sha1>` | Sign with a certificate from the Windows certificate store (preferred). |
| `-PfxPath <file> -PfxPassword (Read-Host -AsSecureString)` | Sign with a PFX file. |
| `-SignToolPath <signtool.exe>` | Override auto-detection from the Windows SDK. |
| `-TimestampUrl <url>` | RFC 3161 TSA; default `http://timestamp.digicert.com`. |

Without a certificate the script prints an **UNSIGNED build** warning and the
manifest records `"signed": false`. Do not publish such a build.

Successful output: the executables under `dist-personal\`, and under
`dist-installer\` (folder name kept for CI):

- `LocalGateKeys-Setup-Personal.manifest.json`
- `LocalGateKeys-Setup-Personal.sbom.cdx.json`

See [../docs/RELEASE_CHECKLIST.md](../docs/RELEASE_CHECKLIST.md) for the full
release procedure, including the reproducible-build comparison.
