# LocalGateKeys

A local-first password manager for Windows, Mac, iPhone, Apple Watch and
Android, with browser extensions for Edge, Chrome, Firefox and Safari. Each device keeps
its own AES-256-GCM encrypted vault; there is no LocalGateKeys account and no
LocalGateKeys server that holds your vault.

- **Windows** (the main app): an Argon2id + AES-256-GCM vault. A Manifest V3
  extension fills Chrome/Edge login forms, a separate native-messaging host
  brokers requests over an authenticated local pipe, and Windows desktop login
  windows are filled through UI Automation metadata only. Optional unlock
  routes: Windows Hello and a local webcam check. The app never installs a
  keyboard hook or reads what you type. Ctrl+Alt+K opens a small quick-search
  palette; in the browser, the icon in a login field opens an account menu
  under the field, with a password generator on sign-up forms.
  The Microsoft Store (MSIX) build can also be your Windows 11 passkey provider (Windows 11
  24H2 or later; off by default, Settings › Autofill, then Windows Settings › Accounts › Passkeys).
- **Mac** (`ios/Mac`, macOS 14+): master-password vault with optional Touch ID,
  AutoFill for passwords, one-time codes and passkeys, a Safari extension that
  offers to save logins, sync, import (including CXF files), CXF export, backups, a menu bar panel and the
  ⌃⌥K shortcut.
- **iPhone** (`ios/App`): unlock with Face ID or the device passcode (optional
  app password), AutoFill for passwords and passkeys, a Safari extension that
  offers to save logins, sync, import (including CXF files) and export (including CXF), plus lock-screen and
  Home-screen widgets for pinned codes.
- **Apple Watch** (`ios/Watch`): shows the two-factor codes you pin on the
  iPhone, with a complication.
- **Android** (`android/`, Android 10+): unlock with fingerprint, face or screen
  lock (optional app password), autofill, save prompts and passkeys (Android
  14+), sync, import (including CXF files), CXF export, backups, a home-screen widget and a Quick Settings tile for pinned codes.

Your vault data is never uploaded to us: devices sync directly over your Wi-Fi
or through encrypted files in a cloud folder you choose. A few optional or
explicit requests do leave the device (update checks in the retired Windows
installer builds and the signed licence revocation list on Windows, breach checks
and website icons when you turn them on, and buying Pro in the iPhone, Mac or
Android app, which sends the store's purchase record to the licence server).
What is sent, and to whom: the [privacy policy](docs/legal/privacy-policy.md)
(also at <https://localgatekeys.app/legal/privacy>).

The apps are available in English, German, Spanish, Italian, Japanese, Korean,
Dutch, Polish, Brazilian Portuguese and Simplified Chinese.

Windows app version **0.4.12** (in Microsoft Store certification on 2026-11-14); Mac app 1.3 on the Mac App Store. History: [CHANGELOG.md](CHANGELOG.md). Website:
<https://localgatekeys.app>. Windows download: the
[Microsoft Store](https://apps.microsoft.com/detail/9PNWCNLQ6597) only.

## Source-available, for review

The code is published so anyone can check how LocalGateKeys protects a vault.
It is **source-available, not open source**: the [licence](LICENSE)
(PolyForm Strict 1.0.0 plus a security-research permission) lets you read,
build and run it for non-commercial purposes, and change it privately only to
look for vulnerabilities. You may not redistribute it or publish modified
builds. Official builds come from the Microsoft Store, Edge Add-ons, the
Chrome Web Store and Apple's App Store (licence files from <https://localgatekeys.app>).

Found a vulnerability? Please report it privately, through GitHub's
**Report a vulnerability** button on this repository or by email to
security@localgatekeys.app; see the
[disclosure policy](https://localgatekeys.app/legal/vulnerability-disclosure).
Please don't open public issues for security problems.

## Editions

**Free** is the password manager: vault, browser fill, desktop app fill,
backups, recovery phrase, transfer and manual update checks, with up to 7 items
(every kind counts; the trash does not). **Pro** removes the item limit and
adds device sync, two-factor (TOTP) codes, attachments, emergency access and a duress password:
US$29.99 one-time.
One payment. Every update, forever, free. Buyers of the earlier US$4.99 Pro
keep lifetime Pro and every future update, free. Nothing is ever locked: over the limit you just cannot add new
items, and without Pro existing two-factor codes and attachments keep working;
only adding or changing them, and syncing, need Pro. Licences are
checked offline, with no account, and survive a reinstall or a backup restore.

**Recovery.** Besides the recovery phrase, Pro has emergency access: you split the phrase into up to five shards for
people you trust, with a waiting period that any of your devices can veto, and no account or server. Any holders
who have enough shards and work together can open your backup at once, so choose people who would not act together.
A duress password (Windows, iPhone, Android) opens a sample vault for someone forcing you to unlock; it is not
hidden from someone who examines your files. See `docs/DISASTER_RECOVERY_RUNBOOK.md`.

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
cloud-drive folder you choose, or both. Collections sync; share a collection with family
(Pro, through a shared folder). A PC or Mac
sets up the group; the iPhone and Android apps join it. Start with either: a
Wi-Fi group can add a cloud folder later without pairing again, and a
cloud-folder group can turn on Wi-Fi sync. There is no LocalGateKeys server or
account; the cloud provider sees only ciphertext and file metadata, plus the
device names in the key file. Setup, the sync password, lost devices,
conflict copies, warnings and known limitations: [docs/SYNC.md](docs/SYNC.md).
Design notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#10-device-sync).

## Status

Honest summary, November 2026:

- **No independent audit yet.** The code has had internal security reviews,
  fuzzing and automated scanning (October 2026), but no independent
  cryptographic review or third-party penetration test. Do not make
  this the only copy of important credentials; keep encrypted backups.
- **Code signing.** The Windows app ships only through the Microsoft Store
  (from November 2026), and the Store signs the package. The earlier
  direct-download installer was never Authenticode-signed; 0.4.12 is its last
  release and tells its users to move to the Store. Installer builds still
  verify an Ed25519-signed release feed until they move.
- **Platforms.** The Windows desktop app is the main app; the native host,
  Windows Hello, camera route and UI Automation fill are Windows only. The
  Windows app is in the Microsoft Store (its only download); the browser
  extension is in Edge Add-ons and Firefox Add-ons (Chrome Web Store: in review
  on 2026-11-14). The iPhone app is on the App Store; the Apple
  Watch app ships inside it from iPhone version 1.1. The Mac app (`ios/Mac`)
  is on the Mac App Store. The Android app is built and tested but not yet on
  Google Play; some of its manual device checks are still open. The
  vault, backup, transfer, TOTP and protocol modules are portable and tested on
  Linux CI-style runs.
- **Implemented:** encrypted vault with typed items and attachments, backup v1/v2
  and transfer packages, Windows Hello and DPAPI-protected camera unlock,
  activity history, reminders, OCR search (environment-gated), device sync over
  Wi-Fi and a cloud folder (documents included), secure sharing of one item as
  a `.lgkshare` file or QR code, passkeys in the browser extension and in the
  iPhone, Mac and Android apps, lookalike-site warnings (browser extensions
  and the Android autofill save prompt), manual update checks
  in the last installer builds (the Store updates the Store build), and the user
  interface in eleven languages; on all four apps, "2FA available", "passkey available" and
  "not HTTPS" Security check rows (bundled 2fa.directory data), Markdown in notes, a Wi-Fi QR
  code and a security-answer generator, and a printable emergency kit; and, for developers, an SSH agent (Windows and Mac) with Git signing, a
  plain-secrets scan and JWT decoding on API-key items; (Pro, Windows) a Local Agent Gate: `lgk mcp` lets AI
  agents such as Claude Code sign in to a site you approve per task, and run one approved command with the API keys,
  SSH keys or notes you allowed; no tool reply contains a password (a password filled into a page can still be read by an agent that
  drives that browser), and every request goes into a hash-chained access log (`docs/AGENTS.md`); a Network activity
  list of every connection the Windows app makes; and (Pro) emergency access and a duress password (Windows,
  iPhone and Android; the Mac in its next release).
- **Environment-gated / not fully validated:** live two-peer sync, real browser
  end-to-end on a clean VM, repeated-build reproducibility, offline wheelhouse
  install.
- **Code health:** ~2,900 Python tests plus Node extension tests and seeded parser
  fuzzing run in CI; `ruff` is enabled with real rules and still reports a
  backlog of mostly stylistic findings; `mypy` is advisory until the strict
  modules are clean. One parser robustness bug found by fuzzing is recorded in
  `tests/fuzz/test_parsers_fuzz.py` (`KNOWN_ISSUES`).
- **Power-user pack (November 2026, Windows core):** backup restore test,
  password change assistant, several vaults (Pro; free holds one), printable
  vault health report, expiring/one-use/revocable shares and an estate pack
  template. They are in the Windows app (the Security center has the restore test and the health report).

## Key file and YubiKey

Optionally the master password can need a key file and/or a YubiKey as well (Settings › Unlocking on Windows and Mac;
the app password on iPhone and Android). The vault key is derived from the password plus the factors, in the style of
KeePass: a stolen vault file and a guessed password are not enough. The key file is read as KeePass reads it (a KeePass XML key file, a raw 32-byte file or a
64-hex-digit file; any other file is hashed); the YubiKey uses HMAC-SHA1 challenge-response
in slot 2 (Windows over USB HID, Mac over USB, iPhone over NFC with a YubiKey 5 NFC, Android over NFC or USB). Keep a
copy of the key file and the recovery phrase: lose a factor and the phrase is the only way back in, and a reset
with the phrase removes the factors. Windows Hello, security key and camera shortcuts are device-bound and keep working when a
factor is added (they open the vault without the factors); they are removed and refused only when "Always ask for the
key file / YubiKey" is on. Details: [SECURITY.md](SECURITY.md).

## Install the browser extension

**Users:** install the LocalGateKeys desktop app first (Windows: from the
[Microsoft Store](https://apps.microsoft.com/detail/9PNWCNLQ6597)), then add the extension
from the store for your browser:

- Edge: [Microsoft Edge Add-ons, *LocalGateKeys*](https://microsoftedge.microsoft.com/addons/detail/localgatekeys/oclkjglnfefdmhddgicmbadaoehakbjj).
- Chrome: [Chrome Web Store, *LocalGateKeys*](https://chromewebstore.google.com/detail/localgatekeys/fcilinmkccknaoeobcdnploacggajbdg).
- Firefox (Windows): [Firefox Add-ons, *LocalGateKeys*](https://addons.mozilla.org/firefox/addon/localgatekeys/).
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

Customers get the Windows app from the
[Microsoft Store](https://apps.microsoft.com/detail/9PNWCNLQ6597); there is no
installer download any more.
Uninstall the developer install with `.\scripts\uninstall_windows.ps1` (keeps the vault) or
`-DeleteVault`.

## Build

```powershell
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock.txt
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.\scripts\build_personal_installer.ps1 -SkipInstaller -OutputRoot ci-build   # frozen executables
.\scripts\build_msix_package.ps1                                             # Store package (MSIX)
```

The first command freezes `LocalGateKeys.exe` and the camera-free
`LocalGateKeysNativeHost.exe` with PyInstaller (UPX off, `SOURCE_DATE_EPOCH`
from the commit), self-checks both and writes a CycloneDX SBOM and a manifest
with every payload hash and tool version; `build_msix_package.ps1` uses it to
build the MSIX for the Microsoft Store. Offline: `-Offline -ModelRoot
src\localvault\models -Wheelhouse release-inputs\wheelhouse`. Windows ships
only through the Microsoft Store; there is no Inno Setup installer any more
(removed 2026-11-18). Details in
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

## Developer

Opt-in features for developers, all off by default. Turn them on in Settings › Developer.

- **SSH agent:** keys stored as SSH-key items are served to `ssh` and `git` after you approve each use (and optionally
  remember it for 10 minutes). On Windows set `SSH_AUTH_SOCK` from the Developer page (it asks first); on the Mac add
  `IdentityAgent` with the printed socket path to `~/.ssh/config`. Agent forwarding is refused when `ssh` sends session binding; older clients (such as OpenSSH 8.1 in Windows 10) cannot be checked, so do not use `ssh -A`.
- **Git signing:** the Developer page can set Git to sign commits with an SSH key from the vault (needs Git 2.34+).
- **Command line:** in the Microsoft Store build (one app execution alias, the browser bridge's) run
  `LocalGateKeysNativeHost.exe lgk ...` for `lgk ...` and `LocalGateKeysNativeHost.exe mcp` for `lgk mcp`
  (`claude mcp add localgatekeys -- LocalGateKeysNativeHost.exe mcp`). To type `lgk`, add this line to your
  PowerShell profile: `function lgk { LocalGateKeysNativeHost.exe lgk @args }`.
- **Secrets scan:** finds `.env` files with plain secrets in a folder you pick and offers to move them into the vault
  and replace them with references. It also finds plain SSH keys. It reads files and never deletes anything. "Use references" is Windows-only.

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
| Passkeys | Browser extension WebAuthn bridge on Windows; the optional Windows 11 (24H2+) passkey provider in the Store build; the system credential provider APIs on iPhone, Mac and Android; keys stored in the vault | Created and used in Chrome, Edge and Firefox with consent; created and used through AutoFill on iPhone and Mac and through Credential Manager on Android 14+; iPhone imports passkeys from Apple Passwords (P-256 only) |
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

Microsoft Store builds are updated by the Store and never check a feed. The
last installer builds (up to 0.4.12) keep a manual **Check for updates**
(sidebar and tray); Strict offline mode
prevents any request. The feed is
`https://updates.localgatekeys.app/stable.json` (`RELEASE_FEED_URL` in
`src/localvault/updates.py`): a release manifest signed with an Ed25519
publisher key compiled into the app, which also refuses a feed older than the
newest one it has verified. Redirects must stay on the feed origin, and the
checker never downloads or installs files. The feed stays at 0.4.12, which
tells installer users to move to the Store. Details: [docs/UPDATES.md](docs/UPDATES.md).

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
- The Windows app ships only through the Microsoft Store, which signs it. The
  retired installer builds (up to 0.4.12) were not Authenticode-signed.
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
- Public sharing and background breach monitoring are out of scope; the
  breach checks run online
  only when you ask and agree (a 5-character hash prefix goes to Have I Been Pwned). Collections sync, and
  Pro can share one through a shared folder;
  documents and their files sync only between devices that all run a version
  that supports it (see [docs/SYNC.md](docs/SYNC.md)).
