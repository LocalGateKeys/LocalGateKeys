# Release checklist

Work through every section in order. Each produces an artifact that the next
one consumes, and the manifest written at the end records all of them.
Record the evidence for each gate with the release.

**Windows ships only through the Microsoft Store (since 2026-11-09).** A
release is the MSIX package uploaded to Partner Center
(store/MICROSOFT_STORE_CHECKLIST.md);
the Store signs and delivers it. The Inno Setup installer was removed on
2026-11-18; steps marked *final installer release only* no longer apply.

## 1. Freeze the source

- [ ] `CHANGELOG.md`: move *Unreleased* under a dated version heading.
- [ ] Bump `version` in `pyproject.toml`, `src/localvault/version.py`,
      `browser-extension/manifest.json`; keep them identical.
- [ ] CI green on `main` (ruff, pytest 3.12/3.13, Node tests, build smoke).
- [ ] Tag the commit. Everything below is built from that tag.

## 2. Update and verify the dependency locks

- [ ] `.\scripts\update_locks.ps1` on the oldest supported interpreter (3.12 or
      3.13); review the diff for unexpected new packages.
- [ ] `.\scripts\run_tests.ps1` (installs from `requirements-dev.lock.txt` with
      `--require-hashes`, then runs the suite). Any hash mismatch is a stop.
- [ ] `.\scripts\ci_local.ps1 -Only security` is clean (pip-audit, npm audit,
      bandit; accepted findings only in `scripts\security_ignore.txt`).
- [ ] For an offline build: `.\scripts\update_locks.ps1 -Wheelhouse` populates
      `release-inputs\wheelhouse`; copy it to the build machine with the locks.

## 3. Build (reproducibly)

```powershell
.\scripts\build_personal_installer.ps1 -SkipInstaller -Release -OutputRoot build-A -Offline `
    -ModelRoot src\localvault\models
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_msix_package.ps1 `
    -Channel Store -IdentityFile build-msix\store-identity.json
```

The first command builds the frozen executables (the MSIX input); the second
packs the Store MSIX (details and the upload: `store/MICROSOFT_STORE_CHECKLIST.md`).

- [ ] A release build (`-Release`, or signing): dependencies are
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

The Store signs the MSIX package; nothing to do for a Store release. The rest
of this section is kept for reference: no Authenticode certificate was bought,
and the installer is retired (2026-11-09).

> **Owner action (audit item W-2, no longer needed):** the direct-download `.exe` files and the
> installer can only be Authenticode-signed with a code-signing certificate, which
> the owner has to buy (an OV or EV certificate from a public CA; an EV certificate
> or a cloud signing service builds SmartScreen reputation fastest). Until one
> exists every build has `signed: false`, and the checklist below cannot be passed
> for a direct-download release. Once bought, pass its thumbprint or PFX to
> `scripts\build_personal_installer.ps1` (`-CertificateThumbprint` or `-PfxPath`).
> The Microsoft Store package does not need it (the Store signs it).

- [ ] `manifest.signed` is `true`; `manifest.signing.certificate_thumbprint_sha1`
      is the release certificate.
- [ ] `signtool verify /pa /v` succeeds for `LocalGateKeys.exe`,
      `LocalGateKeysNativeHost.exe`, `LocalGateKeys-Setup-Personal.exe` and the
      uninstaller inside an installed copy (`unins000.exe`).
- [ ] Signatures carry an RFC 3161 timestamp (the default TSA is
      `http://timestamp.digicert.com`).
- [ ] A build with `signed: false` is never published. Once the code-signing certificate exists this is absolute:
      no unsigned `.exe` or installer ships, and a build that prints "UNSIGNED build" is for local testing only.
      (Owner steps to get the certificate: `docs/store/SUBMISSION_CHECKLIST.md` section 6.)

## 7. Manifest and checksums (final installer release only)

- [ ] `LocalGateKeys-Setup-Personal.manifest.json` (schema 2): `git_commit`
      matches the tag, `tools.pyinstaller` matches `pyproject.toml`'s pin,
      `installer.sha256` equals `LocalGateKeys-Setup-Personal.sha256`.
- [ ] Publish the installer, `.sha256`, manifest and SBOM together.

## 8. Install validation

- [ ] Clean Windows VM, network disabled: install the MSIX (sideload test build
      or the Store flight), first run, bridge repair, extension load, save/fill
      on the demo page, lock/unlock, uninstall keeps profile data. Record
      results in the release's validation document.
- [ ] *Final installer release only:* from an installed installer build, update
      to 0.4.12, unlock, and check the "moved to the Microsoft Store" notice and
      its Settings row; uninstall the installer build, install from the Store,
      and confirm the vault is still there.

## 9. Update-feed publication (final installer release only)

Store builds are updated by the Store and never read the feed. The feed is
published once more, for 0.4.12, then frozen: the update Worker
(`LAST_INSTALLER_RELEASE` = `0.4.12`) refuses anything newer with a 410 that
points to the Store. See [UPDATES.md](UPDATES.md). The licence items at the end
of this section (`LICENSE_KEYS`, `--check-build --release`, `PURCHASE_URL`,
`revocations.json`) apply to every release.

The installer app checks for updates only when the user asks and only against fixed
HTTPS URLs compiled into `src/localvault/updates.py`.

- [ ] `RELEASE_FEED_URL` (the Cloudflare Worker, must not change) and
      `PUBLISHER_KEYS` are set; `BUILD_DATE` is bumped. See [UPDATES.md](UPDATES.md).
- [ ] Sign the release manifest with a `--sequence` above the live one.
- [ ] **Next release (audit 2026-10-24 I-11):** raise `min_supported_version`
      in the manifest to this release's version, so clients from before the
      Pillow 13 / dependency bump (`1de3cf1`) are told they are unsupported.
      The latest feed manifest (`release-feed/stable-0.4.9.unsigned.json`)
      says `0.4.7`; do not edit the live `stable.json`
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

- [ ] Release notes = the CHANGELOG section plus the manifest/SBOM hashes.
