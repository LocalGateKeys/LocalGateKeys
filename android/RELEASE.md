# Releasing LocalGateKeys for Android

The owner works through this list for each Google Play release. Leave every box unchecked in git. Tick them in a
copy for each release. Design: `docs/superpowers/specs/2026-10-23-android-app-design.md` (§9 Delivery and the owner
checklist).

## Before the first release (once)

- [ ] Google Play developer account: pay US$25 once and pass identity verification.
- [ ] Create the app in Play Console with app id `app.localgatekeys.android`.
- [ ] In-app product `pro_unlimited`:
  - one-time (managed, non-consumable);
  - US$4.99;
  - **not** family-shared;
  - title and description from the upgrade sheet copy.
- [ ] Store listing: name, short and full description, icon, feature graphic, phone screenshots (start from
  `docs/design/android/*-light.png` and `*-dark.png`).
- [ ] Website legal pages: add Android / Google Play to the EULA (`website/public/legal/eula.html`) and the privacy
  policy (`website/public/legal/privacy.html`), then deploy the website (needs the owner's OK). Play requires a privacy
  policy that covers the app. Enter its URL in Play Console.
- [ ] Data-safety form: **no data collected, no data shared**. This holds only while Ruling 23 stands: Play Billing's
  datatransport/CCT telemetry and the unused play-services location, base and tasks modules are excluded from the
  build. Check `:app:dependencies --configuration releaseRuntimeClasspath` before you answer. The app's only network
  use is TCP to the paired PC on the local network and Play Billing through the Play Store app.
- [ ] A new personal developer account needs a closed test with at least 12 testers for 14 days before production
  access.
- [ ] Acknowledgements: `app/src/main/assets/licenses/argon2kt-LICENSE.txt` is the verbatim upstream LICENSE of
  argon2kt tag `v1.6.0` (sha256 `05ad83ab16adef6c1385bdf20ece73e6e7cb373243ea3015819d5441ff65a595`). If the argon2kt
  version in `gradle/libs.versions.toml` changes, fetch it again for that tag.

## Signing (upload key and Play App Signing)

Never commit a keystore, its passwords or a `keystore.properties` (`.gitignore` excludes `*.jks`, `*.keystore` and
`keystore.properties`).

- [ ] On the owner's PC, generate the upload key (one time):
  ```
  keytool -genkeypair -v -keystore %USERPROFILE%\keys\lgk-android-upload.jks -alias lgk-upload ^
          -keyalg RSA -keysize 4096 -validity 10000
  ```
  Keep the keystore file and both passwords in the password manager, with an offline copy.
- [ ] Play Console › Setup › App signing: enrol in Play App Signing (Google holds the app signing key), and register
  the upload key certificate (`keytool -export -rfc -keystore ... -alias lgk-upload -file upload_cert.pem`).
- [ ] Sign the bundle outside git. Either sign it after the build:
  ```
  android\gradlew -p android :app:bundleRelease
  jarsigner -keystore %USERPROFILE%\keys\lgk-android-upload.jks ^
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
- [ ] **Real Play purchase run on internal testing**, with the Ruling 23 exclusions in the build. Use a licence-tester
  account on a real phone:
  - [ ] Buy `pro_unlimited`: the sheet shows Pro, and the purchase is **acknowledged** (Play Console › Order
    management shows it acknowledged, not refunded after 3 days).
  - [ ] Restore purchases after reinstalling the app: Pro comes back.
  - [ ] Cancelled and pending purchases show the right message and leave the free plan in place.
  - [ ] Logcat shows `BillingLogger: Skipping logging since initialization failed.` and no crash.
- [ ] Install the R8 release build (`:app:assembleRelease`) on `LGK_API29` and `LGK_API36` and smoke it: unlock, the
  vault, add an item, the Sync screen.
- [ ] Owner's-phone checks (spec §8): a OneDrive and a Dropbox folder through their Android apps' document providers;
  Google Drive shows the notice (Ruling 22).
- [ ] Owner's phone: press the power button while the folder picker is open. The app comes back locked.
- [ ] Release notes for the store. Mention the behaviours that differ from what users may expect:
  - Ruling 14 (clipboard): a copied secret is cleared only if it is still our copy. If the app is not in front when
    the time is up, it is cleared when you come back.
  - Ruling 15: LocalGateKeys' own screens are excluded from other autofill services, and keyboards are asked not to
    learn what you type in the app.
  - Ruling 21: choosing a folder or backup file in the system picker keeps the app unlocked for up to 2 minutes, even
    with "Auto-lock after leaving the app: Immediately". Turning the screen off locks it.
  - Ruling 26: the backup password must pass the same strength check as the desktop's sync password.
- [ ] Do not promote to production before Part C (the autofill service) ships, or hide Settings › Autofill first: its
  switches do nothing until the service exists.
- [ ] Promote internal → closed → production when the checks pass.
