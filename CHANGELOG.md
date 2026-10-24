# Changelog

Newest first. Entries before October 2026 are condensed from the patch notes
that used to live in the repository root; the originals are preserved verbatim
under docs/archive/. Numbered release documents with full
detail: docs/RELEASE_020.md, docs/RELEASE_019.md.
Current implementation and validation status: docs/NEXT_RELEASE_IMPLEMENTATION_STATUS.md.

## Unreleased

### Security and privacy (scan of 2026-10-24, docs/SECURITY_SCAN_2026-10-24.md)
- Website icons are off by default again, and strict offline mode now blocks them. Settings files
  before v7 load with icons off (v6 had switched them on for everyone). iPhone: off by default too.
- The privacy policy has a new section 2.5 on website icons and breach checks (effective 24 October 2026).
- Pillow 12.3.0 -> 13.0.0 (35 advisories, including heap overflow writes in image decoders),
  setuptools 84.0.0 -> 84.2.1, BouncyCastle 1.80.2 -> 1.86 (Android), vite 8.3.2 -> 8.3.5 (webui dev).

### Android
- The Kotlin core of the Android app (`android/lgk-core`, no app yet) is done: it ports the iPhone
  core and passes every shared sync and backup test vector. The desktop accepts the keyring, sync
  file and phone backup it writes (`tests/vectors/*/from_android/`).

### Desktop
- Import & export has "Restore phone backup…": bring back logins, notes, cards,
  identities and the licence from an Android or iPhone `.lgkm` backup, once the
  Android and iPhone apps support backups (no phone app writes them yet). It
  merges like sync and never overwrites a newer version; items deleted on the
  phone move to the trash and are counted. A Pro licence in the backup makes
  this computer Pro when it verifies on this version (restore again to bring
  back items the free plan held back). Items this version cannot read are
  skipped and counted, and never take a free-plan slot. The menu entry is
  hidden until a phone app writes backups (`phoneBackup` in
  `ImportExportMenu.svelte`).

## 0.4.5 (2026-10-23)

### Desktop
- Buy Pro from the app: the prompts shown at the 4-item limit and for Pro
  features (sync, two-factor codes, attachments) have a Buy Pro button, and so
  has Tools > Licence. It opens the checkout at localgatekeys.app/buy; paste the
  key from the licence page into Tools > Licence.
- A licence whose name is the buyer's email shows it once ("Licensed to:
  you@example.com").

## 0.4.4 (2026-10-23)

### Updates
- In-app update checks trust a new release signing key. 0.4.0 to 0.4.3 cannot
  verify feeds signed with it, so install 0.4.4 by hand once; later updates are
  announced in the app again.

### Desktop
- The lock screen shows the LocalGateKeys logo, name and tagline above the
  unlock card, and the profile chooser can add a profile.
- Links to the privacy policy and licence agreement.

## 0.4.3 (2026-10-22)

### Browser extension
- The save prompt now follows a sign-in that lands on another subdomain of the
  same site (for example login.example.com to www.example.com) for 12 seconds
  in the same tab. The login is saved for the address it was typed on, and the
  prompt and the desktop confirmation name that address. Never across a public
  suffix or for IP addresses; filling stays exact to the address.

## 0.4.2 (2026-10-22)

### Features
- Item tiles show bundled site logos and item-kind icons instead of letters.
- A login's current two-factor code is shown at the top of its details.
- A One-time codes card above the item list on Home shows the live code of
  each two-factor login; click a code to copy it. Logins that always ask for
  the master password show their code hidden.
- When an action is blocked by a setting, the message offers a one-click fix
  ("Turn on and ..." or "Open settings"). Notices can link to the right page,
  offer Undo or the error log, can be closed, and pause while hovered.
- The item list takes keyboard input from anywhere on Home, and Settings has a
  search box.

### Security
- The master password is now held in a wipeable buffer from the moment it
  reaches the app, Argon2id runs on that buffer directly, and it is erased
  when the operation that took it ends. The WebView2 page and the bridge's JSON
  decoding keep short-lived copies that the app cannot erase.

### Changed
- Website icons are on by default and are downloaded from each site's own
  address, also in Strict offline mode; turn them off in Settings.

## 0.4.1 (2026-10-19)

### Store
- The app trusts the Microsoft Edge Add-ons extension (ID `oclkjglnfefdmhddgicmbadaoehakbjj`) next to the developer build.

### Features
- Device sync, two-factor (TOTP) codes and attachments are now Pro features;
  Free keeps the 4-item limit and everything else. Nothing is locked: without
  Pro, existing two-factor codes and documents stay viewable, copyable,
  fillable and exportable and can be removed; only adding or changing them,
  and syncing, need Pro. File imports keep two-factor keys as hidden fields on
  Free; encrypted transfers leave new documents out. Sync stops on Free and
  resumes with a licence. The Sync page and the login editor say so, with a
  way to enter a licence.

- Device sync (Tools > Sync), free: keep logins and typed items in step across
  your PCs with no LocalGateKeys server and no account. Choose Wi-Fi sync
  (pair with a one-use QR code, 120 seconds) or a cloud folder you already use
  (OneDrive, Dropbox, Google Drive, iCloud Drive), or both. The cloud provider
  only sees encrypted files plus their count, sizes and timestamps, and the
  member device names in the key file. The folder is protected by a sync
  password (12+ characters, rated Strong; write it down). Changing it or
  removing a device needs a new password, and QR-paired devices then pair again.
  Edits made on two devices at once keep both versions; the second is marked
  "(sync conflict)". Deletes go to the trash on the other devices. Collections,
  documents and attachments do not sync yet, and logins that arrive by sync
  start with auto sign-in set to "never". Read [docs/SYNC.md](docs/SYNC.md)
  before choosing Wi-Fi first: a Wi-Fi-only group cannot add a cloud folder
  later.
- Free and Pro are now split by item count. Free keeps every feature, including
  device sync and desktop app fill, up to 4 live items (every kind counts, the
  trash does not). Pro removes the limit: US$4.99 one-time, lifetime updates.
  Over the limit nothing is hidden or locked; only adding new items is blocked
  (new logins, typed items, desktop bindings, templates, restore from trash and
  the browser extension's save of a new login). Updating an existing
  login is never blocked, and items arriving by sync are never blocked.
- Licences are lifetime (`updates_until` 9999-12-31 for newly issued ones) and
  are checked offline, with no account or activation. A licence is a signed file
  or `LGK1-` text.
- The licence survives a reinstall, and an encrypted copy kept inside the vault
  restores Pro after a backup restore on a new PC. Removing the licence keeps it
  removed on every profile until a licence is installed again.
- Tools > Licence shows the licence status and lets you paste or open a
  licence file. A licence problem never blocks unlocking or deletes data.
- Installing an update shows a warning first when an older licence does not
  cover that build.
- Refunded licences can be revoked. The list is fetched after an update check
  and cached; it is best-effort, because the app works offline.
- Encrypted transfer import brings in new records only up to the free slots
  left; the preview says how many will be skipped and offers Pro. Updates to
  existing records are never limited.
- Importing from another password manager past the limit writes nothing and
  opens the upgrade dialog; the review shows the free slots left. Bringing in
  just the free slots there is planned, not yet implemented.

## 0.4.0 (2026-10-15)

### Features

- Scheduled backups (Settings > Backups): daily or weekly at a set local
  time. Each run writes a full encrypted `.lgk` (attachments included) to
  `Backups/Scheduled`, checks it, and only then deletes the oldest. You can
  keep only the latest backup or the latest plus the previous one (the
  default). Runs happen while the vault is unlocked. A run missed while the
  app was closed happens once at the next unlock, and the last successful
  run is recorded so a restart does not repeat it. Pre-restore safety
  backups, rolling backups and manual exports are never counted or deleted.
- Scheduled backups use a backup password that is kept only inside the
  encrypted vault, never in settings files or logs, and it leaves memory
  when the vault locks. You set it in Settings (entered twice) and can
  change or clear it there. Without one, scheduled backups stay off and
  Settings says why. Keep the password written down: restoring after a disk
  failure needs it, and the copy inside the vault is lost with the disk.
- Optional "Also copy backups to" folder, for a OneDrive, Google Drive,
  Dropbox or Proton Drive sync folder. Each scheduled backup is copied there
  atomically, and the same retention applies, deleting only files the app
  created. Only encrypted backups are copied, never the live vault or
  settings, and the app makes no network calls. If the folder is missing or
  unwritable, the local backup is still kept, the error goes to the error
  log and a warning shows in the status bar.
- New home shell: a navy sidebar (Vault, item types, collections, smart
  views and Tools) replaces the More menu, with a top bar, a status bar
  showing the auto-lock countdown and clipboard timer, and an icon rail in
  narrow windows.
- Ctrl+K opens a command palette for items, actions and settings.
- Ctrl+N opens a one-screen New item chooser for every item kind (number
  keys 1-9 and type-to-filter); the empty-vault action opens it too.
- Overview cards for password health, upcoming reminders, backup status and
  a quick generator.
- Filter chips above the list (All, Needs attention, No 2FA, Expiring),
  usable from the keyboard.
- A persistent detail pane beside the list with copy buttons, a gated
  password reveal and a live 2FA code for items that allow it.
- Dark mode parity across the shell, and a narrow-window layout that stacks
  the detail pane under the list.
- New vault-dial logo across the app window, taskbar, tray, sidebar,
  field-fill buttons and browser extension. Vector sources are in
  `assets/brand/`; `scripts/generate_brand_icons.py` regenerates every raster.

## Unreleased (improvement pass, 2026-10-05 / 2026-10-06)

### Security

- Vault format v3: a random data key encrypts the catalog and is wrapped by
  the Argon2id password key, by Windows Hello and camera wrappers, and by an
  optional 24-word BIP39 recovery phrase. Password changes re-wrap only the
  data key; `rotate_data_key()` re-encrypts after a suspected leak. v1/v2
  vaults are promoted on first unlock through the migration journal.
- Recovery phrase: show-once card with retype challenge in Recovery Center,
  "Forgot your master password?" entry point on the unlock dialog.
- Rollback anchor authenticated with an HMAC keyed from the data key and
  DPAPI-sealed on Windows; restoring an older backup requires confirmation.
- Master-password attempts are throttled with a persisted, HMAC-protected
  counter; the unlock dialog shows the countdown.
- Sync typed-item records use random GCM nonces with the item id, revision,
  sender and counter bound in associated data; channel key via HKDF. v1
  records are refused.
- Attachment sidecars no longer expose plaintext size and SHA-256.
- Backups and transfers use the vault's Argon2id parameters; readers accept
  a bounded parameter range.
- TOTP secrets are decoded into wiped bytearrays; otpauth and migration
  parsing is strictly bounded; optional per-code confirmation setting.
- Local IPC: DPAPI-protected agent token with owner-only ACL, client pin
  anchored to the browser native-messaging registration (plus install
  directory and Authenticode signer for frozen builds), broker-issued
  one-time gesture nonces instead of a client-asserted flag, lease-free
  `ping`, gated non-Windows TCP fallback, hardened frame codec.
- Signed update manifests (Ed25519, monotonic sequence, build-date freeze
  check); checks stay disabled until a publisher key is embedded.
- Transfer packages are decoded as strict UTF-8 (fuzz finding).

### Features

- Export to Bitwarden-compatible CSV/JSON, KeePass 2 XML and encrypted
  KDBX4, behind master-password reauth and explicit warnings.
- Import from KDBX 3/4, 1Password 1PUX/CSV, LastPass, Dashlane, Bitwarden
  JSON (including password-protected), Chrome and KeePass CSV with column
  mapping, per-row decisions and transactional apply.
- New item kinds: payment card, bank account, SSH key, API key, Wi-Fi and a
  passkey scaffold, with masked protected fields in the editor.
- Card autofill through the extension with per-field approval and a trusted
  native confirmation; PIN is never filled.
- Multiple URLs per login with exact-origin, host, base-domain and
  starts-with match modes; the browser offers matches ranked exact first.
- One vault list for credentials and typed items with a schema-driven type
  filter, collections and pinned smart views; typed trash merged into
  Recently deleted; saved-view builder.
- Search: tokenized matching, `tag:` `url:` `type:` `user:` prefixes, fuzzy
  fallback, relevance then recency ranking.
- Change master password reachable from Settings and the More menu;
  keyboard shortcut table with F1 cheat sheet; System appearance option.
- Generator: larger word list, passphrase options, custom symbols, minimum
  counts, username and alias generator, zxcvbn-style strength estimate.
- Password health: weak/reused/no 2FA/old categories, sorting, opt-in
  rate-limited HIBP scan.
- Structured custom-field editor; recovery codes masked until reauth;
  saving an entry policy no longer locks the vault.
- Browser extension: same-origin iframes, shadow DOM, Firefox build and
  native-messaging registration, explicit CSP, sign-in heuristics in nine
  languages, jsdom test suite.

### Engineering

- Repository initialised with a real `.gitignore`; build outputs, VM
  screenshots and test temp roots archived outside the tree.
- ruff safe autofixes applied; the three legacy one-line style rules are
  ignored in `pyproject.toml` until the UI modules are reflowed.

## Unreleased (engineering health, 2026-10-05)

- Test temp directories now live under a single absolute, gitignored root
  (`.pytest-tmp/<uuid>`), fixing `test_missing_versioned_exe_follows_newest_folder`.
- Real lint rules (`E F B S UP I W`), a strict mypy profile for the security
  boundary modules, coverage configuration, and a `fuzz` marker in `pyproject.toml`.
- Hash-pinned dependency locks (`requirements.lock.txt`, `requirements-dev.lock.txt`);
  `scripts/run_tests.ps1` installs with `--require-hashes`;
  `scripts/update_locks.ps1` regenerates them.
- Reproducible builds: UPX disabled in both PyInstaller specs, PyInstaller pinned,
  `SOURCE_DATE_EPOCH` derived from the commit, tool versions recorded in the manifest.
- Optional Authenticode signing in `scripts/build_personal_installer.ps1`
  (`-CertificateThumbprint` or `-PfxPath`), explicit "UNSIGNED build" warning and
  `signed: false` in the manifest otherwise; `-SkipInstaller` for CI smoke builds;
  `-Offline` installs from a hash-pinned wheelhouse.
- CycloneDX SBOM (`scripts/generate_sbom.ps1`) covering the Python environment,
  the two vendored ONNX face models and the browser extension.
- GitHub Actions CI (lint, types, tests on 3.12/3.13, Node extension tests,
  build smoke) and Dependabot.
- Seeded mutation fuzz tests for the vault, backup, transfer, IPC frame and
  otpauth-migration parsers (`tests/fuzz/`). Finding recorded for the owning
  module: `transfer.inspect_transfer` leaks `UnicodeEncodeError` on lone surrogates.
- Documentation consolidated: this changelog, `docs/CONTRIBUTING.md`,
  `docs/RELEASE_CHECKLIST.md`; historical notes and agent hand-off prompts moved
  to `docs/archive/`; obsolete patch-applier scripts (`apply_patch_019/020.py`) removed.

## Desktop fixes 025-034 (September 2026, app 0.3.3)

Numbered desktop/browser fixes validated by `tests/test_*02x.py` / `*03x.py`:
WebView stability (025), dynamic-layout fallback (027), sign-in mapping (028),
unique sign-in names (030), multi-account settings (031), the DPI-safe account
chooser with keyboard activation (032, notes),
desktop multi-account (033) and UI polish (034).

## 2026-09-18 - Three-step camera liveness and earlier automatic save prompt

Original notes

- Camera verification reduced to three visible liveness steps (closer, right,
  left); liveness advances only on frames that also match the enrolled face.
- Browser save/update prompt fires on same-document form removal, same-origin
  URL changes and `DOMContentLoaded`; explicit "Did you just sign in?" prompt
  when success is uncertain; pending login discarded on visible Log out.
- Pending credentials stay in desktop-process memory with a 90 s expiry; the
  extension receives only non-secret `age_ms` metadata.
- Validation: 371 Python tests, 22 service-worker cases.

## 2026-09-17 - 0.3.3: RGB camera verification and automatic save prompt

Original notes -
native-host test fix

- Password-first unlock with an optional, per-profile enrolled **Use camera**
  route using the public OpenCV Zoo YuNet/SFace models (hash-pinned, fetched at
  build time, never downloaded by the installed app).
- Embeddings and the wrapping secret protected with current-user DPAPI; vault key
  wrapped with AES-256-GCM and bound to profile, vault header and record id.
  Explicitly a convenience method, not certified presentation-attack detection.
- Native broker returns the canonical `pending_token`; focus-out prompting removed;
  prompt suppressed when a visible login error is detected.
- `tests/test_bridge023.py` routes the portable ping test to the loopback server
  it creates (test-harness mismatch, not a production bridge change).
- Validation: 370 Python tests, 22 service-worker cases (Linux; Windows webcam,
  DPAPI and installer not validated in that environment).

## 2026-09-17 - Password-first unlock and optional local Windows Hello

Original notes -
validation report -
patch manifest

- Master password is the default unlock again; the old webcam-frame
  confirmation is removed from the unlock path.
- Optional Windows Hello route: vault-key envelope protected by a real
  Microsoft Passport KSP RSA-2048/OAEP-SHA256 private-key operation with
  per-use policy checks; sidecar `vault.hello.json` bound to profile and header.
  Not TPM-attested; requires Hello-compatible hardware.
- Unlock work moved off the Tk thread; cancellation rejects late results.
- Validation (Linux, native behavior mocked): 351 tests passed, build check
  marker `password-first-local-hello-1`, 21 service-worker cases.

## 2026-09-17 - Camera and browser reliability patch

Original notes

- Local webcam presence-confirmation window before unlock and reauthentication
  (live preview only; superseded by the entries above).
- Master-password dialogs centred on the active monitor and raised to foreground.
- Save/update detection for submit, Enter, pointer-driven login, SPA flows and
  same-origin redirects; redirect-recovery credentials held in process memory for
  at most 45 s; non-interactive bridge requests time out after 15 s.

## Release 024 - Browser bridge production patch

Original notes

- Production native-messaging registration in `browser_bridge.py`;
  `--repair-browser-bridge` / `--unregister-browser-bridge` CLI modes.
- Installer repairs Chrome/Edge native-host registration (HKCU) before first
  launch; uninstaller removes it without deleting vault data.
- Build script auto-detects per-user Inno Setup 6.

## Releases 019 and 020 (app 0.3.0 - 0.3.2)

See docs/RELEASE_020.md, docs/VALIDATION_020.md,
docs/RELEASE_019.md, docs/VALIDATION_019.md and
docs/SECURITY_019.md. The checked patch appliers those
notes mention were removed in October 2026. Early prototype checksums and the
first validation summary are archived in docs/archive/SHA256SUMS.txt,
docs/archive/PATCH_MANIFEST_SHA256.txt and
docs/archive/VALIDATION.md.
