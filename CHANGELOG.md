# Changelog

Newest first. Entries before October 2026 are condensed from the patch notes
that used to live in the repository root; the original notes are not part of
this repository.

## Unreleased

In the source since 0.4.11. Windows 0.4.12 was sent to Microsoft Store certification on 2026-11-14, and the
browser extension 0.4.12 is on Edge Add-ons and Firefox Add-ons (Chrome Web Store: in review). The Mac app 1.3 is
on the Mac App Store (2026-11-14). The Android app is not on Google Play yet.

### Windows: the Inno Setup installer pipeline is removed (2026-11-18)
- Windows ships only through the Microsoft Store. `build-personal/LocalGateKeys-Personal.iss` and the Inno Setup part
  of `scripts/build_personal_installer.ps1` are gone; the script now only builds the frozen executables the MSIX packs.

### Safari (Mac and iPhone): the new save prompt (2026-11-17)
- **Safari shows the same save prompt as Chrome, Edge and Firefox**, drawn in the extension's own panel frame: the
  username can be edited before saving (the app checks the new name when it saves), Not now and Never on this site as
  before. A page that blocks the frame (strict CSP) gets the older in-page prompt instead. Safari still cannot list
  a site's saved logins, so it never offers to choose which one to update. The prompt narrows on small screens.

### iPhone: Safari no longer asks to save a login AutoFill just filled (2026-11-17)
- **No "Save / update?" prompt after signing in with a login filled by LocalGateKeys AutoFill** (QuickType bar or the
  list). AutoFill leaves a short-lived marker for the site and username (keyed hashes, nothing made from the
  password); the Safari extension skips the prompt for that sign-in. A login typed by hand, a new login and a later
  sign-in with another password still prompt. Not on the Mac yet.

### A device keeps its id when it leaves sync and joins again (2026-11-17)
- **No more duplicate rows after Leave sync.** Windows, Mac, iPhone and Android: Leave sync keeps the device's id
  and keys in the vault. Pairing again over Wi-Fi, or joining the same cloud folder again, uses them, and the
  other devices update the existing row instead of adding one. Reset sync, a reinstall and a removed device still
  get a new id. Nothing sent between devices or written to the folder changed.
- **With a device on an earlier version:** the first pairing after Leave is refused, the device says "The other
  device could not pair this device under its earlier name. Show a new code there and scan it again.", and the
  second pairing works under a new id, as before.

### iPhone and Android: Sync automatically (2026-11-17)
- **A "Sync automatically" switch in Settings, on by default.** On: the phone syncs when you unlock, when you come
  back to the app while it is still unlocked (new) and after an edit. Off: it syncs only on Sync now or
  pull-to-refresh.

### Mac settings and Windows fixes (2026-11-13 and 2026-11-14)
- **Mac: open documents in their default app** with the Windows rules: only with "Open documents in other apps" on,
  only document, image, audio and video types, a one-time warning, each decrypted copy in its own private temporary
  folder with the quarantine mark, and every copy deleted when the vault locks, at quit and at the next launch.
- **Mac: auto-lock can count activity anywhere on the Mac (the default) or only in LocalGateKeys**, as on Windows.
- **Mac: more Windows settings.** Ask before copying a 2FA code, how many automatic backups to keep as you save,
  a custom quick-access shortcut, a Help & diagnostics section, and one Settings view for both windows with the
  backup schedule and the weekly restore test.
- **iPhone and Android: the restore test also checks a computer's full backup** (`.lgk` / `.lgkfull`) with its
  backup and master passwords; on the iPhone it reads the picked file directly, so iCloud Drive and other
  providers work.
- **Windows:** a file dialog asked for while the app sits in the tray shows the main window first, so the dialog is
  no longer hidden; Save As starts in the `LOCALGATEKEYS_DATA_DIR` folder when one is set; Network activity reloads
  when you come back to the Security center; nothing is cut off at the 900 x 600 minimum window; the Store build's
  Developer page no longer shows the `lgk mcp` line (the Store package has no `lgk`; it shows the Store command).
- **Starter collections** (Personal, Work, Travel, Emergency) are shown in your language on every platform.

- **Free plan now holds 7 items (was 15).** Pro (US$29.99 lifetime) is unchanged.

### AI agents: secrets for commands, exposure tracking, the Mac, and a network ledger
- **AI agents can run a command with your secrets (Pro, Windows).** Two new `lgk mcp` tools: `list_secrets` shows
  the titles and field names, never the values, of the API keys, SSH keys and notes you allowed; `run_with_secrets`
  runs one command with those secrets in its environment after you approve that exact command line, folder and set
  of secrets. The output comes back with the secrets masked, and the command is stopped at its time limit. The
  command itself receives the secrets and can send them anywhere, so approve only a command you would run yourself.
- API keys, SSH keys and notes have an "AI agents may use this item" switch: off by default, this device only.
  Imported, shared and restored items arrive with it off. Settings › Developer lists recent AI agent runs (agent,
  command, secrets used, outcome), never a value. `lgk run` masks overlapping secrets as one span.
- **Exposed to an AI agent.** Password health has a new group: every login whose password an AI agent filled into a
  page, and every API key, SSH key or note a `run_with_secrets` command received, with the agent's name and date,
  until you change it. The item shows the same notice and logins offer the change-password assistant; "Dismiss"
  hides it on this PC. It is worked out from this PC's logs; nothing new is synced or stored in the vault. For an
  API key, SSH key or note, any save of the item clears it.
- **Network activity.** The Security center lists every connection LocalGateKeys makes to the internet: update
  checks, the licence revocation list, breach checks, website icons, and sync with your devices on the local
  network, each with the time, the host and the result. Websites you saved are shown for the running session only
  and never written to disk; sync peers are shown as "Local network". A test fails if any code opens a connection
  without recording it.
- **Mac (Pro; built and unit-tested on a Mac on 2026-11-13, manual checks open): `lgk mcp`.** The same three sign-in tools and rules as on Windows
  (`list_sites`, `request_login`, `fill_login`), turned on in Settings › Developer. Each request opens an approval
  panel; "Approve once" is the only yes, optionally with Touch ID. An approved sign-in is filled in Safari only after
  your click on the LocalGateKeys icon in the sign-in field and a second click on the login; a login with a passkey
  is never filled with its password. The "AI agents may use this login" switch is set in the Windows app for now.

### Command line and AI agents in the Microsoft Store version
- The Store package may declare only one app execution alias (the browser bridge's), so the bridge exe now also runs
  the `lgk` command line: `LocalGateKeysNativeHost.exe lgk <command>` and `LocalGateKeysNativeHost.exe mcp` (the MCP
  server, `claude mcp add localgatekeys -- LocalGateKeysNativeHost.exe mcp`). A PowerShell profile line,
  `function lgk { LocalGateKeysNativeHost.exe lgk @args }`, brings back `lgk`. Browser launches are unchanged; started
  by anything but a browser, the app gives the bridge exe the CLI service only (switch, item allow list, approvals,
  access log), never the browser broker. The Developer page shows the commands in the Store version.
- AI agents see only the logins you switch to "AI agents may use this login" (login editor, off by default; other
  logins answer like a site with no login). A login with a saved passkey signs in with the passkey for an agent and
  never fills its password; the approval says which will happen.

### Power-user pack
- **Backup restore test.** The newest backup can be restored into a scratch folder under the data folder, unlocked
  once, counted and deleted again; the live vault is never touched. A changed password reports "the backup uses
  the old password". "Test now" on the Security page. Weekly by default (Settings › Backups switch): a verified
  scheduled backup counts as the week's test; without one, the next unlock opens the newest rolling backup with
  the unlocked key. No password is ever stored. Mac, iPhone and Android have "Test now".
- **Password change assistant.** For a weak, reused or breached login the app works out the site's change-password
  page: a short curated list first, then the site's standard `/.well-known/change-password` address, then the
  sign-in page. It only opens the page; it never fills in a third-party site.
- **Several vaults.** The free plan holds one vault and Pro any number; free users who already have more keep
  them. The 15-item free limit now counts the items in all vaults together.
- **Vault health report.** A one-page printable PDF (A4 or Letter) with the key-derivation settings, unlock
  factors, backup and restore-test age, devices, licence and build. No passwords or item names.
- **Expiring, one-use and revocable shares.** A shared item can expire after 1 hour instead of 24, can be marked
  one use, and the sender can revoke it: the signed notice travels over folder sync, and the sender's other
  devices then refuse to open the package. iPhone, Mac and Android send expiring and one-use shares too and honour
  revoke notices from the sync folder. The Wi-Fi QR now says that it never expires. Phones and the Mac open such packages. All three are best
  effort (`docs/formats/LGKSHARE_V1.md` v1.1).
- **Estate pack.** A new "Estate pack" template: where the will is, the executor, accounts to close, devices and
  their unlock, and the emergency-access holders.

### Windows: Microsoft Store only
- **LocalGateKeys for Windows now comes only from the Microsoft Store.** The website no longer offers the installer;
  every download link points to the Microsoft Store listing.
- **0.4.12 is the last installer release.** After unlock it shows "LocalGateKeys has moved to the Microsoft Store"
  (in all eleven languages), and Settings has a "Get LocalGateKeys from the Microsoft Store" row. To switch,
  uninstall the installer version and install LocalGateKeys from the Store: the vault stays where it is and the
  Store app opens it with the same master password. "Later" hides the notice for three days. The update server
  offers no installer updates after 0.4.12.
- **The `lgk` command-line tool is dropped for now:** a Store app cannot put it on PATH, so the Store package no
  longer contains it. It may come back later through a Store app execution alias. The 0.4.12 installer still has it.

### AI agents can sign in, your passwords stay on your PC (Pro, Windows first)
- **Local Agent Gate and `lgk mcp`:** an MCP server for Claude Code and other AI agents
  (`claude mcp add localgatekeys -- lgk mcp`). An agent can list your sites (titles and domains only), ask to sign in
  to one site, and have LocalGateKeys fill that site's sign-in form in your browser. It never sees the password.
  Each request opens an approval in the quick-search window naming the agent, the program, the site and the
  agent's stated purpose (shown as a quote); "Approve once" is the only yes, optionally confirmed with Windows Hello.
  A grant lasts five minutes, works once, only on that site's domain and only for the agent session that asked.
  Logins that ask for the master password every time are never used, no tool ever returns a secret, and an agent
  can ask at most a few times a minute, one approval at a time. Off by default: Settings › Developer › "Allow AI agents to use
  LocalGateKeys". Details: `docs/AGENTS.md`. Not usable from the Store build yet (it has no `lgk` command).
- **Tamper-evident access log:** activity events are now hash-chained; the Security check shows "Access log
  verified" or "Access log altered", and the log can be exported as JSON lines with each event's hash. The chain
  helper is also in LGKCore (Mac, iPhone) and lgk-core (Android) with a shared test vector.

### Emergency access and duress password (Pro)
- **Emergency access without an account:** split your recovery phrase into up to five shards for people you trust
  (any 2 to 5 of them can recover). Each gets a signed file, a QR code or a printed sheet. A holder asks from their own
  LocalGateKeys; after the waiting period you chose (1 to 30 days) the app opens your latest encrypted backup from a
  shared folder, unless one of your devices said No. You can also grant at once. Phones end by showing your recovery
  phrase. Limit: holders who have enough shards and work together can open the backup at once.
- **Duress password:** a second password opens a sample vault, keeps the real vault locked for the hours you choose and
  syncs nothing. On Windows, iPhone and Android; the Mac gets it in its next release. It hides your vault from someone looking over your
  shoulder or forcing you to open the app; it does not hide from someone who examines your files.
- Format: `docs/formats/LGKHEIR_V1.md`.

### All apps and the website
- **Collections sync, and Pro can share them:** collections and which items are in them now sync on Windows, Mac,
  iPhone and Android. Pro can share a collection with family through a shared folder, view-only or with edit
  rights. The owner signs who is in a share. The share password protects the items in the folder, so give it only to
  people you invite; a joiner's device syncs nothing until the owner approves it, and from then on its edits count.
  If someone damages or replaces the share's key file in the folder, the owner's device puts it back on its next
  sync, also after Pro ended. Removing someone asks you to confirm. Creating a share asks you to confirm it's you
  (master password on Windows and Mac, Face ID or passcode on iPhone, fingerprint, face or screen lock on Android).
  Deletes in a share go to Recently deleted. **Forget share link** clears the link of a device that was lost or
  reset, so you can share the collection again or delete it. Backups never contain a share's keys, and a restore
  keeps your current shares. Older app versions drop share records if you downgrade. Nothing leaves your devices; there is no server. The pricing page
  lists it in the Pro column.
- **Pricing:** Pro is US$29.99 one-time. One payment. Every update, forever, free. If you already bought Pro,
  nothing changes: you keep lifetime Pro and every future update, free. **Free tier:** 15 items instead of 4.
- **Quick wins:** the Security check lists logins on plain `http://` sites, logins whose site offers
  two-factor codes but have no code stored, and logins whose site offers passkeys (data from 2fa.directory and
  passkeys.2fa.directory, credited in the notices); notes render Markdown (headings, bold, italic, links shown as text, not
  clickable, lists, checklists, code) with a per-device "Show formatting" switch; a Wi-Fi item shows a QR code that a phone
  can scan to join; a generator for security-question answers; and a printable emergency kit (recovery steps,
  backup folders, optional recovery phrase) on Windows, Mac, iPhone and Android. On the iPhone and Android the
  kit is tied to the app password.
- **Verified site and lookalike warnings:** the browser extensions show "Verified site" on a saved site and warn
  before a login or a save on a lookalike address, such as a swapped letter or a look-alike character. The check
  runs on the device and your saved sites never leave the app. A page's own script can still bypass the warning.
  On Android, the autofill save prompt shows Verified, Related or New and asks before saving on a lookalike
  address or another suffix of a saved site.
- **Ten languages:** English, German, Spanish, Italian, Japanese, Korean, Dutch,
  Polish, Brazilian Portuguese and Simplified Chinese, in the Windows app (with
  a language picker that switches at once), the browser extension (Edge/Chrome
  and Safari), the iPhone, Mac, Apple Watch and Android apps, and the website.
- **Buy Pro in the phone and Mac apps:** an App Store purchase (iPhone and Mac)
  or a Google Play purchase (Android) now also gets you an `LGK1-` licence from
  the licence server. Pairing carries it to your PCs, so a free PC becomes Pro.
  The app sends only the store's purchase record; a refund revokes the licence.
  The Mac takes Pro only from the App Store or from sync.
- **Developer pack (opt-in, Settings › Developer):** an SSH agent that serves SSH-key items to `ssh` and `git` after
  per-use approval (agent forwarding refused when `ssh` sends session binding; older clients cannot be checked), Git commit signing setup, the `lgk` command line on Windows
  (`status`, `list`, `read`, `totp`, `run`, `inject`; installer PATH entry and MSIX alias), a plain-secrets scan
  for `.env` files, and JWT decoding on API-key items on Windows, Mac, iPhone and Android. The Mac gets the agent
  and the scan (no command line yet).
- **Key file and YubiKey (optional):** the master password (Windows, Mac) or app password (iPhone, Android) can also
  need a key file (any file, or a KeePass key file) and/or a YubiKey (HMAC-SHA1 challenge-response, slot 2; USB on Windows,
  Mac and Android, NFC on iPhone and Android). A vault with factors is a new file version (Windows v4, Apple and Android
  v2); vaults without factors are unchanged. The recovery phrase still opens the vault without factors and a reset with it
  removes them. Windows Hello, security key and camera shortcuts keep working when a factor is added; they are removed and refused only when "Always ask" is on.
  Mac backups of a factor vault are protected by the backup password only.

### CXF import and export
- **Windows:** imports Credential Exchange (CXF) files (Apple Passwords and other apps; logins, one-time codes,
  notes and passkeys, up to 16 MiB) and exports a CXF file from the Export sheet beside CSV. The export is
  unencrypted and asks you to re-authenticate before passkey keys are read.
- **Android:** imports CXF files (up to 8 MiB) and adds **Settings > Export to a CXF file…** for logins, notes
  and passkeys, behind your fingerprint, face or screen lock.
- **iPhone:** exports a CXF file (a file export, not Apple's system Credential Exchange).
- **Mac:** exports a CXF file (a file export, not Apple's system Credential Exchange).

### Quick search and inline menu
- **Windows:** the quick shortcut (Ctrl+Alt+K by default) opens a small always-on-top search palette, like the
  Mac menu bar panel: search the vault, then copy a username, password or code, or fill the app you were in.
  The palette never shows a password, locks with the vault and is hidden from screen capture. Settings can switch the shortcut back to the Quick access page.
- **Browser extension:** the LocalGateKeys icon in a login field opens an account menu right under the field
  (arrow keys and Enter work). New-password fields on sign-up and change-password forms get a Generate icon
  that fills the form's new-password fields with a strong password. Sites set to "Never for this site" show no
  inline menu; logins whose rule is "never fill" are not listed. In a login frame from another site the
  extension stays off, so no inline menu shows there.

### Mobile widgets and tiles
- **iPhone:** lock-screen and Home-screen widgets show up to 4 pinned two-factor codes. Codes stay hidden on a
  locked lock screen until Face ID. A "Copy code" Shortcuts action copies a code (Siri says "Code copied").
  Pinning a code to widgets is Pro; showing pinned codes is not.
- **Apple Watch:** a complication shows the first pinned code with a countdown ring. "Forget Apple Watch codes on
  lock" also clears it.
- **Android:** a home-screen widget shows pinned codes only before the auto-lock time (with Auto-lock
  "Immediately" it explains to set 1 minute or longer), and a Quick Settings tile copies the first pinned code
  (it asks you to unlock on the lock screen). Pinning a code to widgets is Pro; showing pinned codes is not.

### Windows passkey provider
- **Windows passkey provider (Microsoft Store build):** LocalGateKeys can serve passkeys to any app or browser on
  Windows 11 24H2 or later. It is off by default: turn it on in Settings, then enable LocalGateKeys in Windows
  Settings › Accounts › Passkeys. Every request shows the LocalGateKeys approval window and the private keys never
  leave the app; Windows gets only signatures. Windows keeps passkey site and user names (never keys) in its own
  list, also while the vault is locked; turning passkeys off in the app clears that list, and turning the switch off
  unregisters. While it is on and Windows reports it enabled, the browser extension steps aside for passkeys
  (logins, passwords and codes are unchanged). Microsoft Store build only: the installer build will not get it.

### Mac
- **The Mac app** (macOS 14+): master password with optional Touch ID, the
  vault, editor, generator and command palette.
- **Sync:** host a Wi-Fi sync group or join one, pair with Accept and a
  verification code, add a cloud folder, and see each device's last sync.
  Documents sync with their files.
- **Import and backup:** import from Safari, Chrome, Edge, Brave, Firefox,
  Bitwarden, 1Password, LastPass, KeePass, Proton Pass, Dashlane or any CSV,
  reviewing every row first; full backups that restore on Windows too,
  scheduled backups with a mirror folder, phone backup restore, a recovery
  phrase and a Recovery centre.
- **AutoFill** for passwords, one-time codes and passkeys, and a **Safari
  extension** that offers to save the logins you sign in with.
- **Menu bar and shortcut:** search the vault and copy a username, password or
  code from the menu bar; ⌃⌥K opens search from any app; optional Open at
  login.
- **Secure sharing** of one item as a `.lgkshare` file or QR code, and Receive.

### iPhone
- **Restore phone backups on the iPhone:** Settings › Import & Export › Restore from a backup (and the empty
  vault screen) opens an iPhone or Android `.lgkm` backup with its password, shows a preview and merges it like
  sync: nothing is wiped, deletions go to Recently deleted, documents come with their files. A backup this iPhone
  made restores into an empty vault, for example after reinstalling the app.
- **Import** every format the Mac reads (other password managers and
  browsers), in addition to Apple Passwords and CSV.
- **App password** (optional) instead of the device passcode, with an optional
  Face ID shortcut.
- New Vault, Sync, Security and Settings tabs; a Security tab with five checks
  and an opt-in breach check; favorites and sorting; password history with
  restore; Recently deleted with Undo; expiry reminders; scan 2FA QR codes from
  photos.
- AutoFill can insert card and identity fields.
- Documents sync with their files; secure sharing with `.lgkshare`.
- Wi-Fi sync finds the paired PC again after its address changes, and warns
  when a device brings back an older copy of the vault.

### Apple Watch
- **The Apple Watch app** shows the two-factor codes you pin on the iPhone
  (Pro). The codes stay in the watch's Keychain; "Forget Apple Watch codes
  on lock" is optional.

### Android
- **Autofill:** fill logins in apps and in known browsers, and a save prompt
  after you sign in.
- **Passkeys and passwords through Credential Manager** (Android 14+): create
  and use passkeys, and pick saved passwords.
- **Import** from other password managers; **app password** (optional) with a
  biometric shortcut.
- Favorites and sorting, password history with restore, a skippable setup with
  a "Finish setting up" card, `>` actions in search and Ctrl+K.
- Documents sync with their files; secure sharing with `.lgkshare`.
- Wi-Fi sync finds the paired PC again after its address changes, and warns
  when a device brings back an older copy of the vault.

## 0.4.11 (2026-11-06)

### Desktop
- **Developer pack (opt-in, Settings › Developer):** an SSH agent with per-use approval, Git commit signing setup,
  the `lgk` command line (`status`, `list`, `read`, `totp`, `run`, `inject`), a scan for plain SSH keys and
  `.env` files, and JWT decoding on API-key items. The Microsoft Store version does not include the `lgk` command line yet (the Developer page says so).
- **Key file and YubiKey (optional)** as extra unlock factors next to the master password, and **security key
  (FIDO2) unlock**.
- **Backups to a public key:** scheduled backups no longer need the vault open to be written.
- **Device removal and "I lost a device":** a signed removal notice erases the vault on the removed device.
- **Security check:** logins on plain `http://` sites, and logins whose site offers two-factor codes or passkeys
  you have not set up.
- **Notes with Markdown**, a **Wi-Fi QR code** for phones, a **security-answer generator** and a printable
  **emergency kit**.
- **French**, the eleventh language.
- **Sync status:** each device's "last synced" time now updates on every Wi-Fi and cloud folder sync, even
  when nothing changed (cloud folder: within about 15 minutes).
- **Connections:** the browser extension from the Chrome Web Store or Edge Add-ons no longer shows "Needs repair".
- **Hardening:** lock on user switch and remote desktop disconnect, windows hidden from screen capture, stronger
  key derivation (Argon2id 256 MiB) for new vaults and a one-time upgrade on unlock.
## 0.4.10 (2026-10-30)

### Desktop
- **New logo:** the lock screen and the top of the sidebar show the LocalGateKeys logo from the website, sharp at
  any size, with the app name above All items.
- **Sidebar:** every entry has an icon, Settings is a gear, and pages open on the right while the sidebar stays
  visible.
- **Setup guide:** skippable steps (Windows Hello, import, recovery phrase, browser extension) and a
  "Finish setting up" card until they are done or hidden. An empty vault shows an "Import your passwords" card.
- **Sort the vault list** by title, last modified or created, with favorites first.
- **Command palette:** Security check, Sync status and Show setup.
- **Password history:** restore an earlier password; up to 10 are kept for a year.
- **Secure sharing:** share an item as a `.lgkshare` file or QR code protected by a six-word code; received items
  appear in Incoming items. A shared item burns after three wrong codes. Double-clicking a `.lgkshare` file opens
  it in the app.
- **Attached documents sync** with their files over the shared folder and Wi-Fi, encrypted.
- **Phone backups** (`.lgkm`) can carry attached document files; restoring says which documents had no file.
- **Imports keep the full login address** (for example a sign-in page path), so Open website goes to the right page.
- **Wi-Fi sync:**
  - The PC announces itself on private networks, so phones find it after its IP address changes.
  - "Find again" reconnects to a paired PC that moved, from its QR code.
  - Each paired device shows when it last synced; the sync status in the sidebar opens a Sync status sheet.
  - Rollback protection: if a device brings back an older copy of the vault, the app warns you instead of
    accepting it silently.
- **Free plan and the phone apps:** a free PC paired with an iPhone or Android phone that has Pro takes the
  licence over sync and becomes Pro.
- **Accessibility:** muted and faint text now meets 4.5:1 contrast.
- **Browser extension:** no identity icon on post titles, chat boxes or lone guessed fields.

## 0.4.9 (2026-10-27)

### Desktop
- **Scan QR code** adds 2FA keys and Google Authenticator exports without opening an item first: paste a
  screenshot, choose or drop an image, or use the webcam. Replacing an existing 2FA key asks first.
- Wi-Fi sync with a phone: the PC now records syncs the phone starts ("Last synced" no longer stays at
  "Not synced yet") and shows the new items at once instead of after a lock and unlock.
- After a sync that added, changed or removed items, a "Synced" notice says how many.
- Windows Hello works with key providers that refuse SHA-256 padding.

### iOS
- Import and export, in Settings, Import & Export:
  - **Apple Passwords import (iOS 26 and later).** In the Passwords app, open the menu, choose
    "Export Data to Another App", then pick LocalGateKeys. Logins, 2FA codes and passkeys come across
    (passkeys with P-256 keys only).
  - **CSV import from Files.** It accepts Apple Passwords and Chrome or Edge CSV files only. For any other
    password manager, import in the Windows app.
  - Importing the same file again adds nothing.
  - On the free plan the vault holds 4 items. Extra items are not stored, and the result says how many
    are waiting: "upgrade to Pro, then import again".
  - **Export is free.** An encrypted backup (`.lgkm`) needs a password of at least 12 characters, typed
    twice and never stored, and can be restored in the desktop app. A CSV is unencrypted and holds logins
    only, because passkeys can't go in a CSV; the app warns you first.

## 0.4.8 (2026-10-25)

### Desktop
- The Microsoft Store version can be rated from Settings ("Rate LocalGateKeys"), and asks once, from
  the third unlock, whether you want to rate it. It opens the Store app; LocalGateKeys sends nothing,
  and the prompt never appears in strict offline mode.
- Installing Pro after buying takes one click: the licence page has an "Install in LocalGateKeys"
  button. It opens the app through a `localgatekeys://install-licence/` link; the app checks the
  licence's signature, asks before installing it and names whose licence it is (and whose it
  replaces). A running app picks the licence up at once. Both installers register the link.
  Pasting the key or opening the licence file still works.

### Android
- The Android app (`android/app`, Android 10 and later; not on Google Play yet) has:
  - an unlock with your fingerprint, face or screen lock;
  - the vault, item details, the editor and the password generator;
  - Wi-Fi sync with a PC by pairing code, and sync through a cloud folder;
  - phone backups and restore;
  - settings;
  - the US$4.99 Pro unlock through Google Play.

  It speaks the desktop's current Wi-Fi pairing: the phone shows a verification code and
  waits until you choose Accept on the PC.

  It was checked live against the desktop's sync code: pairing, sync both ways, a cloud folder,
  and a phone backup restored on the desktop. `android/RELEASE.md` lists what is left before
  release. Autofill, saving logins and passkeys come next.

## 0.4.7 (2026-10-24)

- Fixes 0.4.6 not starting ("Cannot find win-arm64"): the installer left out
  WebView2 runtime files the window needs. The build check now loads the window's
  renderer, so a build missing them fails before release. Includes everything in
  0.4.6 below.

## 0.4.6 (2026-10-24, withdrawn: did not start)

Security release. Everyone on 0.4.5 or older should update: this release fixes
every finding of three audits on 2026-10-24 (static analysis, fuzzing, a
Windows assessment, a live-service scan and code review). Details are in
SECURITY.md.

### Security
- Browser save prompts no longer reveal whether a typed password matches the
  saved one; the app compares them after you click Save ("Already saved").
- Wi-Fi sync uses fresh keys for every connection (forward secrecy). Pairing a
  new device shows the same 6-digit code on both screens and needs Accept on
  this PC. Older devices are asked to update.
- Sync checks each device's signing key from the group key file, so a group
  member cannot impersonate another device.
- Turning off camera unlock now replaces the encryption key and shows a new
  recovery phrase once; the old phrase stops working.
- The unlock delay after wrong passwords can no longer be reset by deleting
  its files. Vaults saved by 0.4.6 cannot be opened by older versions.
- The installer only installs into your own app folder, and the app loads
  system DLLs only from Windows. The download is 39 MB smaller.
- Malformed vaults, backups, transfer files and browser messages are refused
  cleanly instead of crashing; plus fixes for site matching with full-width
  dots, sync conflict notices that repeated, and attachment reading on older
  cryptography versions.
- Built on Python 3.14.9 (OpenSSL 3.5.9).

### Security and privacy (scan of 2026-10-24)
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
  `docs/RELEASE_CHECKLIST.md`; historical patch notes moved out of the
  repository; obsolete patch-applier scripts (`apply_patch_019/020.py`) removed.

## Desktop fixes 025-034 (September 2026, app 0.3.3)

Numbered desktop/browser fixes validated by `tests/test_*02x.py` / `*03x.py`:
WebView stability (025), dynamic-layout fallback (027), sign-in mapping (028),
unique sign-in names (030), multi-account settings (031), the DPI-safe account
chooser with keyboard activation (032),
desktop multi-account (033) and UI polish (034).

## 2026-09-18 - Three-step camera liveness and earlier automatic save prompt

- Camera verification reduced to three visible liveness steps (closer, right,
  left); liveness advances only on frames that also match the enrolled face.
- Browser save/update prompt fires on same-document form removal, same-origin
  URL changes and `DOMContentLoaded`; explicit "Did you just sign in?" prompt
  when success is uncertain; pending login discarded on visible Log out.
- Pending credentials stay in desktop-process memory with a 90 s expiry; the
  extension receives only non-secret `age_ms` metadata.
- Validation: 371 Python tests, 22 service-worker cases.

## 2026-09-17 - 0.3.3: RGB camera verification and automatic save prompt

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

- Local webcam presence-confirmation window before unlock and reauthentication
  (live preview only; superseded by the entries above).
- Master-password dialogs centred on the active monitor and raised to foreground.
- Save/update detection for submit, Enter, pointer-driven login, SPA flows and
  same-origin redirects; redirect-recovery credentials held in process memory for
  at most 45 s; non-interactive bridge requests time out after 15 s.

## Release 024 - Browser bridge production patch

- Production native-messaging registration in `browser_bridge.py`;
  `--repair-browser-bridge` / `--unregister-browser-bridge` CLI modes.
- Installer repairs Chrome/Edge native-host registration (HKCU) before first
  launch; uninstaller removes it without deleting vault data.
- Build script auto-detects per-user Inno Setup 6.

## Releases 019 and 020 (app 0.3.0 - 0.3.2)

The release notes for 019 and 020 are not part of this repository; the
security notes from that time are in [docs/SECURITY_019.md](docs/SECURITY_019.md).
The checked patch appliers those notes mention were removed in October 2026.
