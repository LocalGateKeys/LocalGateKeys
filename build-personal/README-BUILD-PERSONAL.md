# LocalGateKeys personal installer build

Run from a normal (non-elevated) PowerShell on Windows:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build_personal_installer.ps1
```

Prerequisites:

- `.venv` with the project installed from the hash-pinned lock
  (`python -m pip install --require-hashes -r requirements-dev.lock.txt`, then
  `python -m pip install --no-deps -e .`), or pass `-InstallDependencies` to let
  the script do it.
- Node.js 20+ with npm: the script runs `npm ci` and `npm run build` in `webui\`
  (the WebView2 window) before PyInstaller.
- Inno Setup 6, unless you pass `-SkipInstaller`. If it is installed somewhere
  non-standard, pass `-IsccPath "C:\path\to\ISCC.exe"`.
- Windows SDK `signtool.exe` only when signing.

What the script does, in order:

1. Sets `SOURCE_DATE_EPOCH` from the commit time (falls back to now) and
   `PYTHONHASHSEED=0` so repeated builds of one commit are comparable.
2. Optionally installs dependencies (`-InstallDependencies` online, or
   `-Offline -Wheelhouse <dir>` with `--no-index --find-links --require-hashes`).
3. Fetches/verifies the two hash-pinned OpenCV Zoo models (`-Offline` requires
   them to be pre-staged) and runs the environment preflight.
4. Deletes prior generated `build-personal\agent`, `build-personal\native`,
   `dist-personal`, and `dist-installer` contents, then freezes both executables
   with PyInstaller (UPX disabled).
5. Signs both executables when a certificate was supplied, runs each with
   `--check-build`, and rejects payloads containing demo/test directories or
   user-data files such as `vault.json`, `profiles.json`, `agent-state.json`.
6. Writes the CycloneDX SBOM (`scripts\generate_sbom.ps1`).
7. Compiles the installer with Inno Setup (skipped with `-SkipInstaller`),
   signs/verifies it, and writes the `.sha256` sidecar.
8. Writes `LocalGateKeys-Setup-Personal.manifest.json` with payload hashes,
   tool versions, SBOM hash, `signed` state and `source_date_epoch`.

## Switches

| Switch | Purpose |
|---|---|
| `-OutputRoot <dir>` | Build into an isolated directory instead of the checkout. |
| `-Offline` | No network: models must be pre-staged (`-ModelRoot`), dependencies come from `-Wheelhouse` (default `release-inputs\wheelhouse` when present). |
| `-Wheelhouse <dir>` / `-LockFile <file>` | Offline dependency source and the hash lock to enforce. |
| `-InstallDependencies` | Online install of `requirements-dev.lock.txt` with `--require-hashes` before building. |
| `-SkipInstaller` | Stop after PyInstaller, self-check, SBOM and manifest (CI smoke). |
| `-SkipSbom` | Skip SBOM generation (not for releases). |
| `-CertificateThumbprint <sha1>` | Sign with a certificate from the Windows certificate store (preferred). Inno Setup then also signs the uninstaller. |
| `-PfxPath <file> -PfxPassword (Read-Host -AsSecureString)` | Sign with a PFX file. |
| `-SignToolPath <signtool.exe>` | Override auto-detection from the Windows SDK. |
| `-TimestampUrl <url>` | RFC 3161 TSA; default `http://timestamp.digicert.com`. |

Without a certificate the script prints an **UNSIGNED build** warning and the
manifest records `"signed": false`. Do not publish such a build.

Successful output (under `dist-installer\`):

- `LocalGateKeys-Setup-Personal.exe` and `.sha256`
- `LocalGateKeys-Setup-Personal.manifest.json`
- `LocalGateKeys-Setup-Personal.sbom.cdx.json` and `.sha256`

The installer does not consume `%LOCALAPPDATA%\LocalVaultPrototype`. On first
LocalGateKeys startup, legacy data is only detected and offered for explicit
import; choosing **Start fresh** does not delete the legacy source.

See [../docs/RELEASE_CHECKLIST.md](../docs/RELEASE_CHECKLIST.md) for the full
release procedure, including the reproducible-build comparison.
