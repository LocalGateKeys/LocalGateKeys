# LocalGateKeys

A local-first password manager for Windows, Mac, iPhone, Apple Watch and
Android, with browser extensions for Edge/Chrome and Safari. Each device keeps
its own AES-256-GCM encrypted vault; there is no LocalGateKeys account and no
LocalGateKeys server that holds your vault.

- **Windows** (the main app): an Argon2id + AES-256-GCM vault. A Manifest V3
  extension fills Chrome/Edge login forms, a separate native-messaging host
  brokers requests over an authenticated local pipe, and Windows desktop login
  windows are filled through UI Automation metadata only. Optional unlock
  routes: Windows Hello and a local webcam check. The app never installs a
  keyboard hook or reads what you type.
- **Mac** (`ios/Mac`, macOS 14+): master-password vault with optional Touch ID,
  AutoFill for passwords, one-time codes and passkeys, a Safari extension that
  offers to save logins, sync, import, backups, a menu bar panel and the
  ⌃⌥K shortcut.
- **iPhone** (`ios/App`): unlock with Face ID or the device passcode (optional
  app password), AutoFill for passwords and passkeys, a Safari extension that
  offers to save logins, sync, import and export.
- **Apple Watch** (`ios/Watch`): shows the two-factor codes you pin on the
  iPhone.
- **Android** (`android/`, Android 10+): unlock with fingerprint, face or screen
  lock (optional app password), autofill, save prompts and passkeys (Android
  14+), sync, import and backups.

Your vault data is never uploaded to us: devices sync directly over your Wi-Fi
or through encrypted files in a cloud folder you choose. A few optional or
explicit requests do leave the device (update checks on Windows, breach checks
and website icons when you turn them on, and buying Pro in the iPhone, Mac or
Android app, which sends the store's purchase record to the licence server).
What is sent, and to whom: the [privacy policy](docs/legal/privacy-policy.md)
(also at <https://localgatekeys.app/legal/privacy>).

The apps are available in English, German, Spanish, Italian, Japanese, Korean,
Dutch, Polish, Brazilian Portuguese and Simplified Chinese.

Windows app version **0.4.10**. History: [CHANGELOG.md](CHANGELOG.md). Website
and downloads: <https://localgatekeys.app>.

## Source-available, for review

The code is published so anyone can check how LocalGateKeys protects a vault.
It is **source-available, not open source**: the [licence](LICENSE)
(PolyForm Strict 1.0.0 plus a security-research permission) lets you read,
build and run it for non-commercial purposes, and change it privately only to
look for vulnerabilities. You may not redistribute it or publish modified
builds. Official builds come from <https://localgatekeys.app>, the Microsoft
Store, Edge Add-ons and Apple's App Store.

Found a vulnerability? Please report it privately, through GitHub's
**Report a vulnerability** button on this repository or by email to
security@localgatekeys.app; see the
[disclosure policy](https://localgatekeys.app/legal/vulnerability-disclosure).
Please don't open public issues for security problems.

## Editions

**Free** is the password manager: vault, browser fill, desktop app fill,
backups, recovery phrase, transfer and manual update checks, with up to 4 items
(every kind counts; the trash does not). **Pro** removes the item limit and
adds device sync, two-factor (TOTP) codes and attachments: US$4.99 one-time,
lifetime updates. Nothing is ever locked: over the limit you just cannot add new
items, and without Pro existing two-factor codes and attachments keep working;
only adding or changing them, and syncing, need Pro. Licences are
checked offline, with no account, and survive a reinstall or a backup restore.

How you get Pro depends on the device:

- **Windows:** buy on the website and install the signed licence file or key.
- **iPhone and Mac:** buy Pro in the app through the App Store. **Android:**
  buy Pro in the app through Google Play.
- After a store purchase the app sends the store's purchase record (App Store
  signed transaction or Google Play purchase token) to the licence server,
  which checks it with the store and returns an `LGK1-` licence. That licence
  syncs to your paired devices, so a free PC paired with a Pro phone becomes
  Pro. Pro on the device that bought it never depends on that request. The
  Mac takes Pro only from the App Store or from sync; it has no licence key
  entry.

Owner notes: [docs/LICENSING.md](docs/LICENSING.md).

## Device sync

Optional, part of Pro. Keep logins, notes and other items, and documents with
their files, in step across your Windows PCs, Mac, iPhone and Android phone over
your home Wi-Fi (pair with a one-use QR code), through encrypted files in a
cloud-drive folder you choose, or both. Collections do not sync. A PC or Mac
sets up the group; the iPhone and Android apps join it. Start with either: a
Wi-Fi group can add a cloud folder later without pairing again, and a
cloud-folder group can turn on Wi-Fi sync. There is no LocalGateKeys server or
account; the cloud provider sees only ciphertext and file metadata, plus the
device names in the key file. Setup, the sync password, lost devices,
conflict copies, warnings and known limitations: [docs/SYNC.md](docs/SYNC.md).
Design notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#10-device-sync).

## Status

Honest summary, October 2026:

- **No independent audit yet.** The code has had internal security reviews,
  fuzzing and automated scanning (October 2026), but no independent
  cryptographic review or third-party penetration test. Do not make
  this the only copy of important credentials; keep encrypted backups.
- **Code signing.** The Microsoft Store build is signed through the Store. The
  direct-download installer is not Authenticode-signed yet (the build script
  supports it, but there is no code-signing certificate), so SmartScreen and
  browsers warn. Update checks verify an Ed25519-signed release feed either way.
- **Platforms.** The Windows desktop app is the main app; the native host,
  Windows Hello, camera route and UI Automation fill are Windows only. The
  Windows app is in the Microsoft Store and on the website, and the Edge
  extension is in Edge Add-ons. The iPhone app is on the App Store; the Apple
  Watch app ships inside it from iPhone version 1.1. The Mac app (`ios/Mac`)
  and the Android app are built and tested but not yet in the Mac App Store or
  on Google Play; some of their manual device checks are still open. The
  vault, backup, transfer, TOTP and protocol modules are portable and tested on
  Linux CI-style runs.
- **Implemented:** encrypted vault with typed items and attachments, backup v1/v2
  and transfer packages, Windows Hello and DPAPI-protected camera unlock,
  activity history, reminders, OCR search (environment-gated), device sync over
  Wi-Fi and a cloud folder (documents included), secure sharing of one item as
  a `.lgkshare` file or QR code, passkeys in the browser extension and in the
  iPhone, Mac and Android apps, opt-in breach checks, manual update checks
  against `https://updates.localgatekeys.app/stable.json`, and the user
  interface in ten languages.
- **Environment-gated / not fully validated:** live two-peer sync, real browser
  end-to-end on a clean VM, repeated-build reproducibility, offline wheelhouse
  install.
- **Code health:** ~2,900 Python tests plus Node extension tests and seeded parser
  fuzzing run in CI; `ruff` is enabled with real rules and still reports a
  backlog of mostly stylistic findings; `mypy` is advisory until the strict
  modules are clean. One parser robustness bug found by fuzzing is recorded in
  `tests/fuzz/test_parsers_fuzz.py` (`KNOWN_ISSUES`).

## Install the browser extension

**Users:** install the LocalGateKeys desktop app first, then add the extension
from the store for your browser:

- Edge: [Microsoft Edge Add-ons, *LocalGateKeys*](https://microsoftedge.microsoft.com/addons/detail/localgatekeys/oclkjglnfefdmhddgicmbadaoehakbjj).
- Chrome: Chrome Web Store, *LocalGateKeys* (listing pending).
- Safari (iPhone and Mac): the Safari extension comes with the iPhone and Mac
  apps. Turn it on in Safari's extension settings and allow it on all
  websites; it offers to save the logins you sign in with, and the app asks
  before importing them at its next unlock. Filling in Safari uses the
  system's AutoFill: turn on LocalGateKeys in the system's AutoFill settings.

In Edge or Chrome, open any login page; the toolbar popup should show
**Connected**. If it shows **Offline**, start the app and use **Repair bridge**
in its browser-connection settings. The Edge/Chrome extension talks only to
the app on the same PC. What the apps and the website send, and to whom: the
[privacy policy](https://localgatekeys.app/legal/privacy).

**Contributors** load the unpacked extension in Developer mode (next section).
It keeps the fixed developer ID below, while store builds get store-assigned IDs
(`CHROME_WEB_STORE_EXTENSION_ID` / `EDGE_ADDONS_EXTENSION_ID` in
`src/localvault/config.py`). A source checkout trusts the developer ID and the
store IDs; installed builds trust only the store IDs (until those are assigned,
or when an empty `allow-developer-extension` file is in the data folder). Build the
store upload zips with `npm ci; npm run build:store`.

## Install (from source)

Prerequisites: Windows 10/11 with the WebView2 runtime (built in on Windows 11),
Python 3.12+, Node.js 20+ (builds the window once), current Chrome or Edge,
internet access for the initial dependency install.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install_windows.ps1
```

This creates `.venv`, installs the package and registers the native-messaging
host for the current Windows user only (HKCU). Then load the extension
unpacked (developer path; customers use the store, above): open
`chrome://extensions` or `edge://extensions`, enable **Developer mode**,
**Load unpacked**, select `browser-extension\`, and confirm the ID
`hojebpmbiibhbhhkohgongojilojijmb`. Start the app with
`.\.venv\Scripts\localgatekeys-agent.exe`; the first unlock asks for a master
password of at least 12 characters, which is never written to disk.

Prefer the installer? Build it (next section), or get the app from
<https://localgatekeys.app> or the Microsoft Store.
Uninstall with `.\scripts\uninstall_windows.ps1` (keeps the vault) or
`-DeleteVault`.

## Build

```powershell
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock.txt
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.\scripts\build_personal_installer.ps1            # needs Inno Setup 6
.\scripts\build_personal_installer.ps1 -SkipInstaller -OutputRoot ci-build   # smoke build
```

The build freezes `LocalGateKeys.exe` and the camera-free
`LocalGateKeysNativeHost.exe` with PyInstaller (UPX off, `SOURCE_DATE_EPOCH`
from the commit), self-checks both, writes a CycloneDX SBOM and a manifest with
every payload hash and tool version, then compiles the installer. Signing:
`-CertificateThumbprint <sha1>` or `-PfxPath`. Offline: `-Offline -ModelRoot
src\localvault\models -Wheelhouse release-inputs\wheelhouse`. Details in
[build-personal/README-BUILD-PERSONAL.md](build-personal/README-BUILD-PERSONAL.md)
and [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

The iPhone, Apple Watch and Mac apps build with Xcode from `ios/` (project
generated by XcodeGen; shared Swift core in `ios/LGKCore`): see
[ios/README.md](ios/README.md). The Android app builds with Gradle from
`android/`: see [android/README.md](android/README.md). Both ports pass the
same shared sync and backup test vectors as the Windows app (`tests/vectors/`).

## Test

```powershell
.\scripts\run_tests.ps1                 # installs the dev lock, runs pytest
.\.venv\Scripts\python.exe -m pytest    # just the suite (~5 min; -m "not fuzz" to skip fuzzing)
npm ci; npm test                        # extension tests (node --test + jsdom, dev-only)
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe -m mypy
```

Temporary files are written to `.pytest-tmp\` inside the checkout (absolute
path; gitignored) because the default `%TEMP%` location is ACL-restricted on the
validation image. The manual security and compatibility matrix is in
[docs/TEST_PLAN.md](docs/TEST_PLAN.md).

## Building and testing

[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) describes the development loop and
the dependency-lock workflow. CI (`.github/workflows/ci.yml`) runs lint, types,
tests on Python 3.12/3.13, Node tests and a build smoke on `windows-latest`.
Code contributions are not accepted under the current licence; bug reports and
security reports are welcome.

## Security

Threat model, what is and is not protected, and how to report a vulnerability:
[SECURITY.md](SECURITY.md). Design rationale: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
TOTP handling: [docs/TOTP_SECURITY_DESIGN.md](docs/TOTP_SECURITY_DESIGN.md).

## The central design decision

LocalGateKeys does **not** install a global keyboard hook, record keystrokes,
scrape the screen, inject code into games, or read existing password-field
values.

Browser pages are handled by an extension with explicit user interaction.
Desktop apps are handled differently: the app inspects only UI-control
metadata, asks the user to enter a credential into its own window during
first-time binding, and later writes the saved credential to the mapped
controls. If an app exposes no suitable controls, it refuses to proceed.

This is intentional. A generic mechanism that silently observes every password
typed into every process is functionally a credential logger, even when built
with good intentions.

## Capability matrix

| Target | Detection/capture approach | Behavior |
|---|---|---|
| Chrome/Edge web page | Isolated Manifest V3 content script | Manual fill/save after clicking the extension; optional automatic save prompt can be enabled per exact site |
| App opens system Chrome/Edge | Same browser extension, scoped to the resulting web origin | Works the same as a normal browser tab; the launching app is irrelevant |
| Steam/launcher native sign-in window | Windows UI Automation metadata (`Edit` controls and `IsPassword`) | Explicit bind, credential entered in LocalGateKeys, then fill by hotkey; never reads the current password value |
| Steam/launcher embedded Chromium/WebView | UI Automation only if accessible edit controls are exposed | The app/window/control can be checked, but not the embedded page origin; warns at bind time and requires confirmation on every fill, otherwise fails closed |
| Custom-rendered game UI / anti-cheat protected UI | No safe generic credential interface | Unsupported; no keylogging, screen scraping, DLL injection, or input interception |
| Passkeys | Browser extension WebAuthn bridge on Windows; the system credential provider APIs on iPhone, Mac and Android; keys stored in the vault | Created and used in Chrome/Edge with consent; created and used through AutoFill on iPhone and Mac and through Credential Manager on Android 14+; iPhone imports passkeys from Apple Passwords (P-256 only) |
| QR sign-in, OAuth device codes, push MFA | Provider-specific flow | Not stored or automated (TOTP codes for saved logins are supported) |

## Architecture

```text
Browser page                       Windows desktop app
     |                                      |
isolated content script                  UI Automation
     | (exact origin)                       | (metadata only)
MV3 service worker                   explicit bind/fill
     |                                      |
Chromium Native Messaging host-------------+
                     |
     authenticated named-pipe / loopback IPC
                     |
             LocalGateKeys agent UI
                     |
        Argon2id -> AES-256-GCM vault
                     |
        %LOCALAPPDATA%\LocalGateKeys\<profile>
```

The browser extension does not receive the entire vault. Each request is
scoped to the sender tab's exact `scheme://host:port` origin. The desktop agent
verifies the executable path and SHA-256, saved window title, complete
edit-control layout, optional Authenticode certificate thumbprint, and an
unambiguous control match before filling. It never clicks **Sign in**.

## Trying it out

### Browser demo

Start the local test page in a second PowerShell window with
`.\scripts\run_demo.ps1` and open `http://localhost:8000/login.html`.

Manual one-time save and fill:

1. Enter a test password in the page.
2. Click the LocalGateKeys extension and choose **Save the filled login**.
3. Approve the exact origin and username in the desktop prompt.
4. Clear both page fields, click the extension and choose **Fill once on this page**.
5. Verify that the fields are filled but the form is not submitted.

Manual actions use Chrome's temporary `activeTab` access; the extension does
not need permanent access to every website. **Enable automatic prompts on this
site** requests persistent access for that exact origin (with its explicit
port) and shows the in-page save prompt after a detected sign-in.

### Safe desktop demo

Run `.\scripts\run_desktop_demo.ps1` (a local WinForms login window), choose
**Bind desktop app (3 s)** in LocalGateKeys, switch to the demo window, confirm
the detected username/password fields, enter a test credential into the
LocalGateKeys dialogs (not the demo), clear the demo fields, focus the demo and
press `Ctrl+Shift+Space`. The fields are filled; the button is not clicked.

### Steam experiment

Use a non-critical test account with recovery options; Steam Guard, QR
sign-in, CAPTCHA and passkeys are not handled. Run the metadata-only inspector
`.\.venv\Scripts\localgatekeys-inspect.exe --delay 3 > steam-uia.json`, switch
to Steam's sign-in window during the delay, and inspect the report (executable
path and SHA-256, window title, signer, exposed edit-control metadata; no field
values). If a field reports `"is_password": true`, bind it; if controls exist
but are not marked protected, binding is allowed only after a warning and
confirmation on every fill; if the field is Chromium/CEF/WebView content, the
page origin cannot be verified and every fill asks again; if `edit_controls`
is empty, the UI is custom-rendered and nothing generic will be attempted.
Discord is recognized only as `Discord.exe` inside the versioned
`%LOCALAPPDATA%\Discord\app-*` family with a valid Discord Inc. signature.

### Manual update checks

**Check for updates** (sidebar and tray) is manual only; Strict offline mode
prevents any request. The feed is
`https://updates.localgatekeys.app/stable.json` (`RELEASE_FEED_URL` in
`src/localvault/updates.py`): a release manifest signed with an Ed25519
publisher key compiled into the app, which also refuses a feed older than the
newest one it has verified. Redirects must stay on the feed origin, and the
checker never downloads or installs files. Microsoft Store builds are updated
by the Store. Details: [docs/UPDATES.md](docs/UPDATES.md).

## Local files

```text
%LOCALAPPDATA%\LocalGateKeys\...\vault.json          Argon2 parameters + AES-GCM ciphertext
%LOCALAPPDATA%\LocalGateKeys\...\vault.hello.json    optional Windows Hello envelope
%LOCALAPPDATA%\LocalGateKeys\...\vault.face.json     optional DPAPI-protected camera envelope
%LOCALAPPDATA%\LocalGateKeys\agent-state.json, install.json, com.localgatekeys.app.json
```

Labels, usernames, targets and passwords are all inside the encrypted payload.
`LOCALGATEKEYS_DATA_DIR` overrides the root. A legacy `LocalVaultPrototype`
directory is only detected and offered for explicit import on first start.

## Current limitations

- Python cannot guarantee complete zeroization of immutable password strings in
  process memory.
- The direct-download installer is not Authenticode-signed yet; Windows warns.
  The Microsoft Store build is signed by the Store.
- Native Messaging and the local pipe protect boundaries from accidental misuse,
  not from malware already running as the same Windows user.
- The extension supports top-level login forms; cross-origin iframes and
  identity-provider redirects to another origin still need **Save current**.
- Automatic browser prompting is heuristic.
- UI Automation and `SendInput` compatibility varies by application and
  integrity level; an elevated application cannot be filled from a non-elevated
  process. Embedded browser controls have no trustworthy origin signal and are
  never filled silently.
- Exact executable hash, window-title, signer and control-layout checks trade
  compatibility for safety; app updates require rebinding.
- The camera route is a convenience check, not certified presentation-attack
  detection; prefer Windows Hello.
- Public sharing and background breach monitoring are out of scope; breach
  checks run only when you turn them on and press the check button (a
  5-character hash prefix goes to Have I Been Pwned). Collections do not sync;
  documents and their files sync only between devices that all run a version
  that supports it (see [docs/SYNC.md](docs/SYNC.md)).
