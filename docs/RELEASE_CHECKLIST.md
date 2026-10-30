# Release checklist

Work through every section in order. Each produces an artifact that the next
one consumes, and the manifest written at the end records all of them.
Remaining release gates and their evidence are tracked in
NEXT_RELEASE_IMPLEMENTATION_STATUS.md
and NEXT_RELEASE_CLOSURE_PLAN.md.

## 1. Freeze the source

- [ ] `CHANGELOG.md`: move *Unreleased* under a dated version heading.
- [ ] Bump `version` in `pyproject.toml`, `src/localvault/version.py`,
      `browser-extension/manifest.json` and `AppVersion` in
      `build-personal/LocalGateKeys-Personal.iss`; keep them identical.
- [ ] CI green on `main` (ruff, pytest 3.12/3.13, Node tests, build smoke).
- [ ] Tag the commit. Everything below is built from that tag.

## 2. Update and verify the dependency locks

- [ ] `.\scripts\update_locks.ps1` on the oldest supported interpreter (3.12 or
      3.13); review the diff for unexpected new packages.
- [ ] `.\scripts\run_tests.ps1` (installs from `requirements-dev.lock.txt` with
      `--require-hashes`, then runs the suite). Any hash mismatch is a stop.
- [ ] For an offline build: `.\scripts\update_locks.ps1 -Wheelhouse` populates
      `release-inputs\wheelhouse`; copy it to the build machine with the locks.

## 3. Build (reproducibly)

```powershell
.\scripts\build_personal_installer.ps1 -OutputRoot build-A -Offline `
    -ModelRoot src\localvault\models -IsccPath "<path>\ISCC.exe" `
    -CertificateThumbprint <40-hex-sha1>
```

- [ ] Signing makes it a release build (same as `-Release`): dependencies are
      reinstalled from the hash-pinned lock (or the `-Offline` wheelhouse), the
      venv's Python must be at least `-MinimumPythonVersion` (default 3.14.9),
      and `THIRD-PARTY-NOTICES.txt` must match the installed packages
      (`python scripts\generate_third_party_notices.py` regenerates it). A PFX is
      imported into the user's certificate store for the build and removed
      afterwards; the script prompts for its password.
- [ ] Models verified against `release-inputs\face-models.manifest.json`
      (never downloaded during an `-Offline` build).
- [ ] Both executables pass `--check-build`; no forbidden demo/test/user-data
      files in the payload (the script fails otherwise).
- [ ] `SOURCE_DATE_EPOCH` printed by the script equals the tag's commit time.
- [ ] UPX is off (`upx: false` in the manifest; both `.spec` files say
      `upx=False`).

## 4. Reproducible-build comparison

- [ ] Run the identical command a second time into `build-B` (ideally on a
      second clean machine with the same wheelhouse).
- [ ] Compare the two manifests' `payload` arrays and `tools` objects:

```powershell
$a = Get-Content build-A\dist-installer\*.manifest.json | ConvertFrom-Json
$b = Get-Content build-B\dist-installer\*.manifest.json | ConvertFrom-Json
Compare-Object ($a.payload | % { "$($_.path) $($_.sha256)" }) ($b.payload | % { "$($_.path) $($_.sha256)" })
```

- [ ] Any difference must be explained (signature timestamps differ by design;
      anything else is a reproducibility bug to record in the release notes).

## 5. SBOM

- [ ] `dist-installer\LocalGateKeys-Setup-Personal.sbom.cdx.json` exists and
      its SHA-256 matches `manifest.sbom.sha256`.
- [ ] It lists both ONNX models with the manifest hashes and the browser
      extension with the expected version.
- [ ] Review for packages that should not be in a release payload
      (test/dev tools are expected in the *environment* SBOM; the frozen
      payload only contains what PyInstaller collected).

## 6. Code signing

- [ ] `manifest.signed` is `true`; `manifest.signing.certificate_thumbprint_sha1`
      is the release certificate.
- [ ] `signtool verify /pa /v` succeeds for `LocalGateKeys.exe`,
      `LocalGateKeysNativeHost.exe`, `LocalGateKeys-Setup-Personal.exe` and the
      uninstaller inside an installed copy (`unins000.exe`).
- [ ] Signatures carry an RFC 3161 timestamp (the default TSA is
      `http://timestamp.digicert.com`).
- [ ] A build with `signed: false` is never published.

## 7. Manifest and checksums

- [ ] `LocalGateKeys-Setup-Personal.manifest.json` (schema 2): `git_commit`
      matches the tag, `tools.pyinstaller` matches `pyproject.toml`'s pin,
      `installer.sha256` equals `LocalGateKeys-Setup-Personal.sha256`.
- [ ] Publish the installer, `.sha256`, manifest and SBOM together.

## 8. Install validation

- [ ] Clean Windows VM, network disabled: install, first run, bridge repair,
      extension load, save/fill on the demo page, lock/unlock, uninstall keeps
      profile data. Record results in the release's validation document
      (template: UI_RELEASE_ACCEPTANCE.md).

## 9. Update-feed publication

The app checks for updates only when the user asks and only against fixed
HTTPS URLs compiled into `src/localvault/updates.py`.

- [ ] `RELEASE_FEED_URL` (the Cloudflare Worker, must not change) and
      `PUBLISHER_KEYS` are set; `BUILD_DATE` is bumped. See [UPDATES.md](UPDATES.md).
- [ ] Sign the release manifest with a `--sequence` above the live one.
- [ ] **Next release (audit 2026-10-24 I-11):** raise `min_supported_version`
      in the manifest to this release's version, so clients from before the
      Pillow 13 / dependency bump (`1de3cf1`) are told they are unsupported.
      The live feed still says `0.3.0`; do not edit the live `stable.json`
      by hand, publish the change with the release.
- [ ] Sign `stable.json` with `--published` set to a timestamp on the
      `BUILD_DATE` day (for example `2026-10-15T12:00:00Z`), so a licence that
      ends near that date does not show a false "update not covered" warning.
- [ ] Publish with `scripts/publish_release_feed.ps1`, which uploads the
      installer first and `stable.json` last.
- [ ] From an installed previous version, run **Check for updates**: it must
      report the new version and open the release page only on request.
- [ ] Confirm Strict offline mode still performs no request.
- [ ] `LICENSE_KEYS` in `src/localvault/licensing.py` holds the licence public
      key. See [LICENSING.md](LICENSING.md).
- [ ] Run the frozen `LocalGateKeys.exe --check-build --release`; it must exit 0
      (it fails when `LICENSE_KEYS` is empty). No build script runs this yet.
- [ ] `PURCHASE_URL` is set in `src/localvault/app/licence_view.py` (empty hides the
      Buy buttons).
- [ ] `revocations.json` is present in the R2 bucket
      (`scripts\publish_revocations.ps1 -Key <release key>` signs and uploads
      an empty list, so `/revocations.json` does not 404), and refunds the
      licence Worker recorded since the last list are in it
      (cloudflare/license-issuer/README.md, "Refunds and revocation").

## 9b. Accessibility (Windows)

- [ ] Narrator: the sidebar, sync pill, palette, item list, detail pane and setup guide read every button
      by name; Tab reaches every control with a visible focus ring.
- [ ] Windows text size at 200% (Settings > Accessibility > Text size): no clipped text on the vault,
      Settings, Sync status and setup pages, in the dark and the light theme.
- [ ] `npm test` in webui/ passes `a11y.test.js` (axe audit and 4.5:1 token contrast, both themes).

## 10. Announce

- [ ] Release notes = the CHANGELOG section plus the manifest/SBOM hashes and
      the certificate thumbprint.
