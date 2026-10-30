# Releasing LocalGateKeys for Android

The owner works through this list for each Google Play release. Leave every box unchecked in git. Tick them in a
copy for each release.

## Before the first release (once)

- [ ] Google Play developer account: pay US$25 once and pass identity verification.
- [ ] Create the app in Play Console with app id `app.localgatekeys.android`.
- [ ] In-app product `pro_unlimited`:
  - one-time (managed, non-consumable);
  - US$4.99;
  - **not** family-shared;
  - title and description from the upgrade sheet copy.
- [ ] Store listing: name, short and full description, icon, feature graphic, phone screenshots (take them from the app
  in light and dark).
- [ ] Website legal pages: add Android / Google Play to the EULA (`website/public/legal/eula.html`) and the privacy
  policy (`website/public/legal/privacy.html`), then deploy the website (needs the owner's OK). Play requires a privacy
  policy that covers the app. Enter its URL in Play Console.
- [ ] Data-safety form: **Purchase history** (app functionality), not shared; nothing else collected. This matches
  the privacy policy (`docs/legal/privacy-policy.md`, section 7.3): the app sends the Google Play purchase token to
  the licence server so a purchase unlocks the PC too. It holds only while Play Billing's datatransport/CCT telemetry
  and the unused play-services location, base and tasks modules are excluded from the build. Check
  `:app:dependencies --configuration releaseRuntimeClasspath` before you answer. The app's only network use is TCP to
  the paired PC on the local network, Play Billing through the Play Store app, and
  `https://licenses.localgatekeys.app/play/claim` (the licence server, purchase token only).
- [ ] A new developer account needs a closed test with at least 12 testers for 14 days before production
  access.
- [ ] Acknowledgements: `app/src/main/assets/licenses/argon2kt-LICENSE.txt` is the verbatim upstream LICENSE of
  argon2kt tag `v1.6.0` (sha256 `05ad83ab16adef6c1385bdf20ece73e6e7cb373243ea3015819d5441ff65a595`). If the argon2kt
  version in `gradle/libs.versions.toml` changes, fetch it again for that tag.

## Signing (upload key and Play App Signing)

Never commit a keystore, its passwords or a `keystore.properties` (`.gitignore` excludes `*.jks`, `*.keystore` and
`keystore.properties`).

- [ ] Generate the upload key (one time):
  ```
  keytool -genkeypair -v -keystore <path>\lgk-android-upload.jks -alias lgk-upload ^
          -keyalg RSA -keysize 4096 -validity 10000
  ```
  Keep the keystore file and both passwords in the password manager, with an offline copy.
- [ ] Play Console › Setup › App signing: enrol in Play App Signing (Google holds the app signing key), and register
  the upload key certificate (`keytool -export -rfc -keystore ... -alias lgk-upload -file upload_cert.pem`).
- [ ] Sign the bundle outside git. Either sign it after the build:
  ```
  android\gradlew -p android :app:bundleRelease
  jarsigner -keystore <path>\lgk-android-upload.jks ^
            android\app\build\outputs\bundle\release\app-release.aab lgk-upload
  ```
  or add a local, uncommitted `signingConfig` that reads the keystore path and passwords from environment variables.
- [ ] If the upload key is lost, ask Google for an upload key reset in Play Console. The app signing key is not
  affected.

## Each release

- [ ] Bump `versionCode` (must grow) and `versionName` in `app/build.gradle.kts`.
- [ ] Full suites from the repository root, all passing:
  ```
  android/gradlew -p android :lgk-core:test :app:testDebugUnitTest :app:connectedDebugAndroidTest :app:assembleRelease
  .venv/Scripts/python.exe -m pytest -p no:cacheprovider tests
  ```
  Run the device tests on `LGK_API36` and `LGK_API29`.
- [ ] Live checks with the desktop (`scripts/android_live_peer.py`, see `android/README.md`): Wi-Fi pairing and sync
  both ways, the cloud folder, and a phone backup restored on the desktop.
- [ ] Build the signed bundle (above) and upload it to the internal testing track.
- [ ] **Real Play purchase run on internal testing**, with the Play Billing telemetry and unused play-services modules excluded from the build (see the Data-safety item). Use a licence-tester
  account on a real phone:
  - [ ] Buy `pro_unlimited`: the sheet shows Pro, and the purchase is **acknowledged** (Play Console › Order
    management shows it acknowledged, not refunded after 3 days).
  - [ ] Restore purchases after reinstalling the app: Pro comes back.
  - [ ] Cancelled and pending purchases show the right message and leave the free plan in place.
  - [ ] Logcat shows `BillingLogger: Skipping logging since initialization failed.` and no crash.
- [ ] Install the R8 release build (`:app:assembleRelease`) on `LGK_API29` and `LGK_API36` and smoke it: unlock, the
  vault, add an item, the Sync screen.
- [ ] Owner's-phone checks: a OneDrive and a Dropbox folder through their Android apps' document providers;
  Google Drive shows the notice that its Android app cannot be chosen as a sync folder.
- [ ] Owner's phone: press the power button while the folder picker is open. The app comes back locked.
- [ ] Release notes for the store. Mention the behaviours that differ from what users may expect:
  - Clipboard: a copied secret is cleared only if it is still our copy. If the app is not in front when
    the time is up, it is cleared when you come back.
  - Autofill and keyboards: LocalGateKeys' own screens are excluded from other autofill services, and keyboards are asked not to
    learn what you type in the app.
  - System picker: choosing a folder or backup file in the system picker keeps the app unlocked for up to 2 minutes, even
    with "Auto-lock after leaving the app: Immediately". Turning the screen off locks it.
  - Backup password: the backup password must pass the same strength check as the desktop's sync password.
- [ ] Wi-Fi sync after an IP change (task 11): pair with the PC, give the PC a new address (new DHCP lease or a
  different router), then Sync now on the phone: it finds the PC by its announcement and syncs with no re-pairing;
  the next sync dials the new address directly. With the PC network set to Public nothing is found.
- [ ] Find again (task 11): with the PC moved and not announced (Public network, or mDNS blocked), Sync now shows
  "Can't find your PC on this network" with Find again on the Wi-Fi card. Scan the PC's Show QR code: "Found your PC
  at ..." and the sync runs, with no Accept prompt on the PC and the same pairing. Scan another PC's (or another
  group's) QR: "That QR code is from a different device", and the stored address is unchanged.
- [ ] Secure sharing (UX workstream 9), two phones or phone and PC: open a login, tap Share: six words show. Send
  as a file to the other device (Quick Share, a messenger or Files); there, open the `.lgkshare` from Files: the app
  opens (after the unlock) on Receive with "Shared by Android phone". Type the words with dashes or capitals: the
  preview shows kind, title and user name only; Add to vault adds it as a new item that syncs. Open the same file
  again: "already opened". Three wrong codes delete it. On the free plan with 4 items, Add shows the Pro sheet.
  Show as a QR code on a small item and scan it in Settings › Receive a shared item › Scan QR code. Passkeys and
  files have no Share button. After the share sheet returns, `adb shell run-as app.localgatekeys.android ls
  cache/open-documents` is empty, and `no_backup/share-inbox` is empty after Add or Reject. `adb logcat` shows
  no code, item text or package content.
- [ ] Favorites and sorting: star an item on the item screen and from the long-press menu; it shows as a favorite
  on the PC after sync, and one set on the PC comes back. Each sort option and "Favorites first" survive a restart.
- [ ] Unsaved draft (task 6): open New login, type a label, username and password, press Home; with Auto-lock
  Immediately come back and unlock: "Continue your unsaved item?" appears, Continue opens the editor with the values,
  Save works; Discard opens nothing. Edit an item, leave, change it on the PC and sync before unlocking: the prompt
  says it changed and Continue opens a new item. Swipe the app away from Recents mid-edit: the prompt still comes.
  Cancel or Back in the editor: no prompt next time. Erase vault and Sync Leave delete it. `adb shell run-as
  app.localgatekeys.android ls no_backup` shows `editor-draft.bin`, and its bytes contain none of the typed text.
- [ ] Import from other apps (task 5c), on a real phone from the Files app / Downloads: Settings › Import from a
  file with a Chrome passwords CSV, a Bitwarden password-protected .json (a wrong password asks again) and a
  1Password .1pux. The review shows Add / Skip / Replace, the free plan stops at 4 items with "Needs Pro", Import
  saves once, the items show in the vault and reach the PC at the next sync; importing the same file again adds
  nothing. A LastPass or KeePass file says to import it on the PC. Android's Credential Manager import is not offered.
- [ ] App password (task 7): Settings › App password › Use an app password; a weak password is refused, the 24
  words show with the warning, three asked words must match, fingerprint on. Lock: the unlock screen offers the
  fingerprint prompt whose button says "Use app password" (no PIN/pattern option); the password opens the same vault.
  **The phone's screen lock alone cannot open it**: cancel the prompt and confirm no PIN/pattern route exists.
  `adb shell run-as app.localgatekeys.android ls files` shows `app-password.bin` and `vault-key-bio.bin` and no
  `vault-key.bin`.
- [ ] App password: five wrong passwords, then "Try again in 30 seconds" (also after swiping the app away); change
  the password (old refused, new works, phrase still works); Forgot app password? with the 24 words and a new
  password opens the vault; a wrong phrase is refused and counted.
- [ ] App password and fingerprints: enrol a new fingerprint in system Settings; the next unlock says the
  fingerprints changed and asks for the password; turning the shortcut on again works. On `LGK_API29` the prompt is
  fingerprint-only too. Turn the password off (current password needed, then the screen-lock prompt): the old
  unlock is back and `vault-key.bin` exists again. Erase vault removes both app-password files.
- [ ] Sync rollback witnesses (Part B, 2026-10-29), with a Windows build that has them: after a folder sync the
  folder holds `LocalGateKeys Sync/witness/<phone id>.lgksync` and `.lgksig`; once the PC writes its own witness
  file the phone's view turns format 2 at its next write (PC log). Wi-Fi sync with the PC: no new issue; with a PC
  from before 2026-10-29 also no issue (its `bad-message` answer to the witness is ignored). Restore an older copy of
  the phone's app data (adb backup/restore) and sync: the issue `vault-rollback` appears on every sync until "This
  was me" (not built on Android yet: check the issue kind in the log) and never clears by itself.
- [ ] Part C autofill (2026-10-29, never run on a device): Settings › Autofill › Open Autofill settings, choose
  LocalGateKeys; the row says it is on. In a test app's login screen (username + password) the dropdown shows
  matching logins only after the app was paired: first "Search LocalGateKeys", pick a login, the fingerprint prompt,
  the fields fill; next time the paired login is listed first. Locked: choosing a row always shows the unlock prompt
  first (app password vaults show the password field). "Show logins in suggestions" off: only "Unlock LocalGateKeys"
  shows, with no titles or usernames. "Copy 2FA code when filling" copies the code of a login with 2FA.
- [ ] Part C autofill in Chrome (Settings › Autofill services › "Autofill using another service", Chrome restarts),
  Firefox and Samsung Internet: a site's login lists the logins matching the page (exact origin, then base domain;
  an `http://` page offers nothing). Gboard on API 30+ shows the suggestions as keyboard chips. A WebView inside an
  ordinary app is filled as that app (its web domain is not trusted).
- [ ] Part C save: sign in with a new login in Chrome; Android asks to save to LocalGateKeys; unlock, Save; the login
  shows in the vault and reaches the PC at the next sync. Sign in with a changed password: "Update password", the old
  one is in the password history. In an app: the save sheet asks for the website. Free plan with 4 items: Save shows
  the limit message, Update still works.
- [ ] Part C passkeys (Android 14+, `LGK_API34`+ emulator and the owner's phone): system Settings › Passwords,
  passkeys & accounts lists LocalGateKeys as a provider; turn it on. On webauthn.io in Chrome: register (fingerprint),
  the passkey item appears; sync to the PC and sign in there with the desktop's passkey support; create one on the PC,
  sync, and sign in on the phone. "Offer LocalGateKeys for passkeys" off: LocalGateKeys is not offered. Free plan
  full: creation offers no LocalGateKeys entry (Android shows other providers); sign-in still works.
- [ ] Part C privileged browsers: replace `app/src/main/assets/privileged_browsers.json` with Google's published
  `gpm_passkeys_privileged_apps.json` (Chrome, Edge, Firefox, Brave, Samsung, ...) and check the Chrome release
  fingerprint in the bundled file. Until then only Chrome stable is treated as a browser for passkeys: any other
  browser signs as an app (`android:apk-key-hash:` origin) and websites refuse it.
- [ ] Part C Chrome's clientDataJSON: when Chrome passes its own clientDataHash the response carries `{}` as
  clientDataJSON (Chrome replaces it). Confirm webauthn.io registration and sign-in succeed; if Chrome rejects the
  placeholder, build clientDataJSON from the request origin instead.
- [ ] Part C passwords through Credential Manager (an app that calls `getCredential` with a password option, e.g.
  the androidx sample): entries list the app's paired logins; choosing one unlocks and returns it; creating a
  password from an app is refused (save through autofill instead, which asks for the website).
- [ ] Part C erase: Settings › Erase vault removes `no_backup/fill-index.bin`; the dropdown then offers only
  "Unlock LocalGateKeys". `adb logcat` during all of the above shows no titles, usernames or passwords from the app.
- [ ] Task 12 files (Pro): plus › File or photo › Choose a file / Choose a photo / Take a photo (allow the camera)
  each adds a document; a 26 MB file says "larger than 25 MB"; on the free plan the upgrade sheet opens and no
  picker. `run-as app.localgatekeys.android ls files/Vault/attachments` shows only `<id>.<blob>.lgkblob` files and
  their bytes never contain the file's text.
- [ ] Task 12 open: Preview asks for the fingerprint or screen lock, then shows a JPEG, a PNG, a 3-page PDF and a
  .txt; a .zip says "No preview". Save writes the same bytes to Files (compare the sha256). Share to Gmail/Drive
  attaches the file; afterwards `run-as ... ls cache/open-documents` is empty, and empty again after a lock.
- [ ] Task 12 rename/delete: Rename changes the title only (Save still offers the original file name); Delete
  removes the item and, within a sync, the PC's copy; the file in `files/Vault/attachments` is gone.
- [ ] Task 12 sync folder: with the PC on a build that has attachment sync, a file added on the phone appears on
  the PC after both sync (folder `LocalGateKeys Sync/attachments/` holds `<blob>.lgkblob` and each device's
  `.lgkcap` + `.lgkcap.lgksig`); a PC file appears on the phone. With one member on an older build, the phone's
  documents stay out of its view (no `bad-peer-record` on the old device).
- [ ] Task 12 Wi-Fi: with no folder, a PC document reaches the phone over Wi-Fi in one sync (the phone fetches it);
  a phone document reaches the PC once the PC answered a `blob-get` (second sync). Turn Wi-Fi off mid-fetch: the
  item stays absent (`attachment-missing` in the log) and arrives at the next sync.
- [ ] Task 12 backups (format 2, 2026-10-29, unit-tested only): with two documents (a photo, a PDF) and a note,
  Export backup: the file grows by about the documents' size and the screen says "Backup saved." with no "left out"
  line (over 160 MiB of files it adds "N document files were left out of this backup ..."). Restore it on a fresh
  (erased, Pro) phone: the preview lists "2 document files from the backup", Restore says "2 document files
  restored" and both documents open in Preview. A format-1 backup with documents restored on a fresh phone: the
  preview says "N documents will be not restored: their files are not in this backup" and the rest is restored.
  A format-2 file from this phone restores on the PC with its files, and a PC- or iPhone-made one restores here.
- [ ] Store licence (2026-10-29, Worker deployed with `PLAY_ALLOW_TEST=1` on a test copy, licence tester account):
      buy `pro_unlimited`; Settings › Pro shows "Also unlocks Windows: pair your PC" and Copy key copies an `LGK1-`
      key. Pair a free Windows PC on a build with licence-only sync and press Sync now: the PC turns Pro and full
      sync starts; the PC stored no phone items before that. Offline at purchase: the claim happens at the next
      launch. Refund the test purchase: the next claim is refused (no retries) and the PC's weekly revocation list
      removes Pro there. Privacy and Licence Agreement open `/legal/app/` pages (after the site deploy)
- [ ] Do not promote to production before the Part C device checks above pass, or hide Settings › Autofill first.
- [ ] Promote internal → closed → production when the checks pass.
