# Extended security and privacy audit, 2026-10-24

Scope: `main` at cff8cd0 (after the scan fixes in docs/SECURITY_SCAN_2026-10-24.md), the
installed 0.4.5 build, and the live services localgatekeys.app, licenses.localgatekeys.app,
updates.localgatekeys.app. No repo file was changed by the audit; proofs of concept live in the
session scratchpad only.

No tool or review can prove the absence of every vulnerability. This pass combines automated
scanning, fuzzing, live testing and a manual adversarial review of every attack surface, and lists
everything it found. Findings marked *traced* were confirmed by reading code, *PoC* by running it.

## Fix status (branch security-fixes-extended-2026-10-24)

All 9 medium and 29 low findings were fixed in code, and the informational items were
fixed or documented, on 2026-10-24. Deployed the same day: licence Worker (M-2, L-1..L-3
server side), website (buy page, /recover link), update Worker with the signed empty
revocation list, a Cloudflare rate limit on /recover, Paddle adjustment webhooks.
Decisions that differ from the original suggestion: turning off camera unlock rotates
the data key only when no recovery phrase exists (L-4); network folders stay allowed as
backup mirrors and only device-namespace paths are refused (I-3); sync views are signed
in a separate signature file and pinned per peer instead of through the keyring, so
older peers keep syncing (M-7). Not verified on hardware: every Swift change (no Mac),
the real WebView2 window, Paddle's handling of `_ptxn`. Open follow-ups: the iPhone
store must persist sync signer pins; Kotlin/Swift SyncMeta should skip (not fail) an
overflowing item; release builds need Python 3.14.9+.

## What was run

| Kind | Tool / method | Result |
|---|---|---|
| Manual review | 7 parallel reviews: vault crypto & storage, browser path, sync & pairing, importers & files, WebView UI & desktop fill, server/website/supply chain, iOS & Android | findings below |
| SAST | semgrep `p/security-audit p/owasp-top-ten p/cwe-top-25 p/xss p/insecure-transport p/command-injection p/jwt p/sql-injection p/github-actions` | 33 hits, all false positives (template placeholders, documented crypto) |
| SAST (JS) | ESLint `eslint-plugin-security`, `eslint-plugin-no-unsanitized`, `svelte/no-at-html-tags` | no unsafe DOM sinks, no `{@html}`; one slow regex (L-12) |
| Secrets | gitleaks 8.30.1 over all 657 commits | 117 hits, all test vectors/fixtures; Paddle *client* token is public by design |
| Dependencies | osv-scanner 2.7.0 on every lockfile (pip, npm, SwiftPM) | clean after today's bumps |
| Shipped bundle | runtime versions, PE flags (pefile) on 234 binaries, Authenticode | see L-9, L-10, I-9 |
| Fuzzing | existing mutation suite with 3 new seeds × 20,000 iterations; new harness for licence keys, signed update feed and native-host frames (60,000 cases) | one robustness bug (L-11); no crash in licence/feed/frame parsers |
| DAST | OWASP ZAP 2.17.0 spider + active scan on all three hosts | no exploitable issue (I-10) |
| TLS | SSL Labs (unpublished) | **A+** on all 4 endpoints, TLS 1.2/1.3 only |
| Headers | Mozilla HTTP Observatory | **A+, 150/150, 12/12 tests** |

## Findings

### Medium

**M-1. A regenerated or removed recovery phrase still decrypts the current vault** (PoC)
`src/localvault/vault.py` `create_recovery_phrase` / `remove_recovery_phrase` only rewrite the
header wrapper; the data key is not rotated. The pre-change rolling backup
(`Profiles\<id>\Backups\vault-*.json`, written by that very save), `before-restore-*.json`,
`migration-v*-*.json`, older backups and shadow copies still wrap the same data key under the old
phrase. Someone holding the old phrase who later gets the profile folder unwraps the key from an old
copy and decrypts the *current* vault, including items added after revocation. Contradicts
SECURITY.md:154 ("the previous phrase stops working").
Fix: regenerating/removing an existing phrase goes through `_rotate_data_key` (new data key, purge
`vault-*.json`, purge or warn about `before-restore-*`/`migration-*`), and tell the user older
external backups still accept the old phrase.

**M-2. A Paddle payment link can deliver a buyer's licence and personal data to an attacker** (worker logic PoC; Paddle behaviour unconfirmed)
`website/src/static/buy.js:216-217` honours `?_ptxn=`; the worker takes `lgk_claim` from the paid
transaction's `custom_data` (`cloudflare/license-issuer/src/providers.js`). An attacker who starts a
checkout on /buy (claim known to them), closes it and sends the victim
`https://localgatekeys.app/buy?_ptxn=txn_…` gets the licence and the victim's name and email at
`/license/<their claim>`, while the victim's page stays "pending". Whether Paddle lets another browser
open that draft transaction needs a sandbox test.
Fix: strip `_ptxn` on /buy (or don't make /buy the default payment link); in `checkout.completed`
compare the transaction's claim with the local token; consider ignoring claims unless
`origin == "web"`.

**M-3. Save prompts act as a password-guessing oracle for page scripts, unlimited on iPhone Safari** (traced; desktop rate-limited)
`browser-extension/content.js` `onSubmit` accepts `form.requestSubmit()` (a trusted submit event),
`captureSubmission` sends `capture_browser`, and the result shows in a light-DOM panel the page can
observe and dismiss with a synthetic Escape (`content.js` keydown handler has no `isTrusted` check).
A script on the same origin that knows the username learns whether a guess equals the stored
password. Desktop: `browser_broker.py` limits probes to 10/origin and 30 total per minute.
iPhone: `background-safari.js` `capture_browser`/`check_browser` have no limit.
Fix: add the same probe limit to `background-safari.js`; check `isTrusted` on the Escape handler;
put the panel host in a closed shadow root without observable inline style; consider not comparing
passwords at capture time (only new/exists).

**M-4. iPhone AutoFill offers HTTPS logins on plain-HTTP pages** (Kotlin PoC; Swift traced)
`ios/AutoFill/Matcher.swift:35-41` passes Safari's page URL to the matcher, and the `host` /
`base_domain` rows in `ios/LGKCore/.../URLMatch.swift:232-233` (same in
`android/lgk-core/.../URLMatch.kt:93-94`) ignore the scheme. A login saved for
`https://bank.example.com` is offered on `http://bank.example.com` (any port) served by someone on
the same Wi-Fi. The desktop is safe because `browser_broker.py:91` canonicalises the origin first.
Fix: drop candidates that `Origin.canonicalize` rejects before matching (iOS now, Android autofill
later).

**M-5. iPhone "Include exact-site logins" in QuickType is on by default, contrary to the audit record** (traced)
`ios/AppShared/Settings/AppSettings.swift` defaults `quickTypeExactSites` to true; docs/AUDIT_2026-10-18.md
M11 says it is opt-in. With it on, exact-origin logins are published as loose `.domain` identities and
the QuickType fill path has no URL check (other pages, subdomains, possibly HTTP per M-4).
Fix: default off, or record it as an accepted risk in the audit doc and SECURITY.md.

### Low

- **L-1 Licence claim reuse** (PoC): if a victim's claim leaks before their webhook lands and an attacker pays with it, the victim sees the attacker's licence and data and their own licence goes to an unreachable random token (`cloudflare/license-issuer/src/index.js:72-79`). Fix: bind a claim to its first order; let buyers recover by transaction id + email.
- **L-2 KV check-then-write races** (PoC): concurrent webhooks with one claim overwrite each other; a duplicate delivery mints two licences with different ids (`index.js:74,106-108`). Fix: Durable Object / D1 unique constraint, or derive `license_id` from the order id.
- **L-3 Refunds are never revoked, and the promise is published** : the worker ignores Paddle `adjustment.*`; `revocations.json` is 404; `REVOKED_LICENSE_IDS` is empty; refunds.html §3.1 promises revocation within 7 days. Fix: store order→licence_id, queue adjustments, publish an empty signed revocation list now.
- **L-4 Camera unlock reduces at-rest strength to the Windows password and disabling it does not revoke** (traced): `face_unlock.py` DPAPI sidecar unwraps the data key; disable/profile delete don't rotate it. Fix: rotate on disable/delete; say so in the consent text.
- **L-5 Clipboard clear gives up after one failed `OpenClipboard`** (PoC): `clipboard_guard.py:175-197` drops tracking if another app holds the clipboard at that moment, so the password stays. Fix: retry and reschedule until cleared or the sequence changes.
- **L-6 Desktop confirmation popup auto-focuses Allow** (traced): `webui/src/components/Modal.svelte:26-28` + topmost activation in `web/window.py:336-348`; one Enter typed into the page approves save/2FA/card/identity prompts. Fix: focus Deny, ignore input for ~500 ms.
- **L-7 Safari extension answers "is this saved?" without Face ID** (traced): index HMAC key has no `.userPresence` (`KeychainVault.swift`); someone with the unlocked phone can test guesses offline. Fix: classify only new/exists, or document.
- **L-8 iOS hardening**: Safari extension gets the shared keychain group and whole app group (`project.yml`, `SafariSave.entitlements`); custom keyboards not refused and reveals not hidden during screen capture (`EditorView.swift:320-338`); icon fetch filters names not resolved IPs. Fix: dedicated keychain group; refuse custom keyboards; hide on `isCaptured`.
- **L-9 Bundled runtime behind**: installer ships Python 3.14.7 and OpenSSL 3.5.7; 3.14.9 / 3.5.9 are out (OpenSSL fixes CVE-2026-35189 and others, low severity). Rebuild the release on Python 3.14.9.
- **L-10 Native host bundles code it does not need**: `NativeHost\_internal` carries Tk (tcl90/tk), Pillow, SSL, asyncio; the browser launches it for every message. Trim with PyInstaller `excludes`. The installer also leaves stale files from older versions (e.g. `cryptography-50.0.1.dist-info`).
- **L-11 Import preview accepts rows that apply then rejects** (fuzz, seed 911): `import_workflow.apply` fails with "field value is too long" for a row the preview accepted, aborting the whole import. Fix: run `item_schema` limits during preview.
- **L-12 Quadratic cc-exp regex** (measured 2.7 s on a 60 kB attribute): `browser-extension/login-safety.js:226`; a hostile page can only stall its own tab's content script. Fix: cap attribute length (e.g. 256) before matching.
- **L-13 Throttle reset by deleting its state file** (PoC, outside threat model): `vault.py:1081-1084`. Fix: keep a zeroed MAC'd record instead of unlinking.

### Informational

- I-1 Anchor DPAPI seal is optional and can be stripped (`vault.py:788-792`); docs overstate it.
- I-2 `consented` flag for update checks comes from the page (`app/updates.py:58`); matters only with script injection.
- I-3 settings.json is unauthenticated; `backup_mirror_dir` accepts UNC paths (same-user attacker only).
- I-4 If the WebView navigation lock fails to install the window keeps running unprotected (`web/main.py:211-233`); destroy the window instead and check `args.Source` in `on_script_notify`.
- I-5 `ALLOW_FILE_URLS` left at pywebview default; set False.
- I-6 Desktop rebind silently adopts a new window title/layout for an identical binary (`uia.py:685-719`); documented as protected in SECURITY.md.
- I-7 SendInput typing fallback: brief focus race; UIPI-dropped input reported as success (fails safe).
- I-8 No forward secrecy on LAN sync (static X25519); iOS vault opens with the device passcode (design).
- I-9 Binaries unsigned (known); CFG off on CPython modules (normal); PFX password on signtool command line in PFX mode; release builds reuse the existing venv unless `-InstallDependencies`.
- I-10 ZAP: `style-src 'unsafe-inline'` and no SRI on /buy (Paddle requirement), `Access-Control-Allow-Origin: *` on static pages; nothing exploitable.
- I-11 Update feed: fresh installs accept any signed bundle up to 400 days old; `min_supported_version` (0.3.0) still allows Pillow-12 builds — raise it with the next release.

## Sync and pairing

Both findings need the group key G (a malicious paired device, a device about to be removed, or a
removed Wi-Fi peer that still reads the folder). The cloud provider alone cannot do either.

**M-6. Poisoned version vectors stop a device's sync, and the poison spreads** (PoC)
`sync/engine.py:84` `_check_vv` accepts counters up to 2**53-1 and `engine.py:124` `bump` raises on
overflow; `sync/vault_bridge.py:655-677` turns that into a failure of the whole view. A G-holder
publishes an item with `vv = {every member: 2**53-1}`; every device accepts it, and the next device to
edit that item can no longer sync anything (PoC: A reports `local-data … overflows` on every run; B
never gets A's edits or new items). Honest devices re-publish the vectors, so it survives rotation.
A crafted phone backup restored through `phone_restore` does the same. Kotlin `VersionVector.kt:41-45`
and Swift `VersionVector.swift:38-41` share the rule.
Fix: reject or quarantine implausible counters (e.g. > 2**40) and vv keys that are not current/past
members; on overflow skip only that item; same bound in Kotlin and Swift.

**M-7. Any member can forge another device's sync file and cut it off permanently** (PoC)
View files (`sync/group.py` `encode_view`/`decode_view`) are authenticated only by AEAD under G and are
not signed with the writer's Ed25519 key. A G-holder writes `devices/<victim>.lgksync` with chosen item
content and `counter = 2**53-1`: other devices accept the content as the victim's, the victim's next
`run_once` overflows (`folder_transport.py:660`, `vault_bridge.py:1268`) and never writes again, and
after a rotation that removes the attacker the others keep reporting `rollback` because `last_seen`
survives the epoch change (`folder_transport.py:787`). The victim gets no warning.
Fix: sign each view (header + payload hash) with the device key, with `signing_public` MAC-covered in
the keyring, verified in Python, Kotlin and Swift. At minimum: bound counters, catch the own-counter
overflow, reset `last_seen` per peer on rotation, and treat a rewrite of one's own file by someone
else as tampering.

Low / info: no forward secrecy on LAN (static-static X25519, views are also sealed under G); desktop
keeps inbound hello counters in memory only (not exploitable); an active LAN host with two addresses
can hold all 4 pre-auth listener slots; dev-checkout firewall rule names `python.exe`.

## Browser path, further findings (traced)

- **L-14 Global probe cap is shared by all sites** (`browser_broker.py:940-953`): 30 checks/min across origins; one site using three subdomains in background tabs exhausts it and save prompts stop elsewhere (DoS only). Fix: per-origin/registrable-domain limits only.
- **L-15 Same-site redirect handoff leaks the typed username** (`browser_broker.py:730-737, 816-819`): a pending capture from A is offered to any same-site origin B loaded in the tab within 12 s (user-content subdomains of non-PSL domains via an open redirect). Fix: require a browser-observed redirect chain, or hide the username on B.
- **L-16 Gesture nonce is optional while `legacy_gesture_compat` is on (default True)** (`browser_broker.py:213-238`, `settings.py`): a request without a nonce but with `user_gesture: true` is accepted. Fix: default to False now, remove after one release.
- **L-17 Passkey create dialogs can be spammed while unlocked** (`passkey_broker.py:146-167`): any HTTPS page can call `navigator.credentials.create` without a gesture, raising a focus-stealing desktop dialog every 10 s. Fix: require `navigator.userActivation.isActive` for create.
- **L-18 Safari save path weaker than desktop** (`background-safari.js:124-190`): subframes are compared only with the top frame; saves go to the app after the in-page click with no app-side confirmation; captures live 10 min and are not bound to a document. With M-3 a same-origin script can get a chosen "update password" stored. Fix: confirm in the app before import, shorter TTL, document binding.
- I-12 Grants are untyped: a 2FA grant is also accepted by `get_browser` (`browser_broker.py:328`, `session_guard.py:95`); not page-reachable. Tag grants with a kind.
- I-13 `host`/`base_domain` rows ignore the port (`origin.py:366-367`), so a `host` row for localhost fills on any local port; `starts_with` is no isolation within an origin. Compare ports in host mode; say so in the UI.
- I-14 Firefox has no `documentId`: nonces/captures bind to the frame, not the document (`background.js:239`). Add a per-document id.

## Importers and untrusted files

**M-8. Crafted import files exhaust memory before the 5,000-record limit applies** (PoC; limit placement confirmed in code)
`importers/__init__.py:197-200` `enforce_record_limit` only checks the finished list, after
`protonpass.py:169-185`, `onepassword.py:196-217`, `bitwarden.py:~300-318` and `kdbx.py:774,1002-1018`
have built every record and every diagnostic. Zip members may inflate to 64 MiB and KDBX XML to
128 MiB. Measured: a 63 KiB Proton zip peaked at 19 GB (122 s); a 16 KiB 1PUX at 3.6 GB; a 24 KiB
KDBX4 at 2.6 GB; non-object items produce millions of diagnostics that are sent to the WebView.
Contradicts SECURITY.md's claim that a crafted file cannot stall the app (nothing is half-imported:
apply is transactional).
Fix: count while iterating and stop past MAX_RECORDS; cap diagnostics (first 50 + "N more"); lower
the decompressed JSON cap to ~16 MiB; count `Entry` tags in the existing expat pre-pass for KDBX.

- **L-19 Quadratic KDBX inner-stream decryption** (PoC; code confirmed at `kdbx.py:186-189`): the keystream buffer is grown by `bytes +=` per block and XORed byte by byte; a 4 MiB protected value takes 26 s on KDBX3, ~48 MiB about an hour, and the import cannot be cancelled. Needs the user to enter the file's password. Fix: generate the keystream once, XOR via `int.from_bytes`, reject protected values larger than the field limit first.
- **L-20 "Save a copy" writes no Mark-of-the-Web, and attachment names keep bidi controls** (traced): `attachments.py:509-532`, name checks at `transfer.py:785` / `attachments.py:409` accept U+202E, so `Invoice‮fdp.exe` shows as "Invoiceexe.pdf"; "Open" is refused but the user is pointed to "Save a copy", which skips SmartScreen. Fix: ZoneId=3 on Save a copy; strip Unicode Cf/bidi characters on add and on transfer import.
- **L-21 Mark-of-the-Web failure is ignored** (traced): `attachments.py:556`; on FAT/exFAT or some shares `.doc/.xls/.ppt` still open without Protected View. Fix: refuse macro-capable types when MotW cannot be written.
- I-15 Favicon address check (`item_icons.py:132`) accepts `::a.b.c.d`, NAT64 `64:ff9b::/96`, site-local and multicast (unreachable here; TLS still required). Unwrap embedded IPv4, reject those ranges.
- I-16 `Image.open` without `formats=` for website bytes (`item_icons.py:316`); ICO header size not checked before decode (10 KiB → 115 MiB, within Pillow's bomb limit); QR paste passes up to 12 MB to every OpenCV codec (`app/qr_import.py:178`).
- I-17 `_open_copy_name` misses `NUL .pdf` / `COM¹` style reserved names (does not reproduce on Windows 11).
- I-18 Crash leftovers: `.lgk-export-*` folders are never swept; the Save-a-copy temp file inherits the folder ACL.
- I-19 CSV export formula injection is known and warned about.

## Round 2: more free tests (same day)

| Test | Tool | Result |
|---|---|---|
| Filesystem scan (vulns, secrets, misconfig) | Trivy 0.76.1 | clean; only test-fixture SSH keys in local `.pytest-tmp/` output |
| PowerShell build scripts | PSScriptAnalyzer 1.25.0 | no security-rule hits (73 `Write-Host` style warnings) |
| Firefox extension | Mozilla addons-linter | 0 errors; build includes two build scripts (I-20) |
| Vault integrity | every field and every 64th ciphertext byte flipped (214 variants) | 211 rejected, **0 yielded different secrets**; only the password wrapper's `created_at` is unauthenticated (I-21) |
| Memory and disk residue | two-process harness reading process memory after lock + disk grep | see M-9, L-22..L-26 |
| Differential fuzz of URL handling | 40,000 inputs through Python, Kotlin and the extension JS (Swift read) | see L-27..L-29, I-22 |
| Email DNS | checkdmarc | no DMARC, MTA-STS or TLS-RPT; DNSSEC off |
| GitHub repo | `gh api` | Dependabot alerts off; Actions allows any action, SHA pinning not required; branch protection needs Pro on private repos; single collaborator, no deploy keys |
| Licences | package metadata, license-checker | pystray is LGPL-3.0 and no third-party notices ship with the app (I-23) |

**M-9. Decrypted vault JSON stays in freed memory after lock** (process-memory PoC; partly a Python limitation)
After lock nothing *references* any secret and the data key and master password are gone, but freed,
un-zeroed heap still holds ~7 copies of each password/note/TOTP secret inside the decrypted catalog JSON
(`vault.py:3118` `_canonical_json(payload)` on save, `vault.py:3349-3352` decrypt at unlock,
`vault.py:2121-2123` `_entry_token`). A memory dump, hibernation file or pagefile after lock can expose
the whole vault. Fix: `AESGCM.decrypt_into`/`encrypt_into` with a `bytearray` that is zeroed after
`json.loads` / encryption; individual field strings remain a Python limitation.

- **L-22 Attachment key and plaintext survive lock** in freed memory (`attachments.py:502`). Use a `bytearray` key and `decrypt_into`, zero in `finally`.
- **L-23 Needless immutable copies of key material** (`vault.py:319,330-343,3122,3349`): `bytes(self._key)` where a `bytearray` works. (The data key was not found after lock.)
- **L-24 Backup/export passwords travel as plain `str`** (`api/bridge.py:587-591`, `app/import_export.py:376-406`); a freed copy of the backup password was found after lock. Use `SecretText` end to end.
- **L-25 "Save a copy" of a document has no owner-only ACL** (`attachments.py:509-532`; icacls showed inherited `ALL APPLICATION PACKAGES:(F)`), unlike exports. Reuse `atomic_write(..., restrict=True)`. (Pairs with L-20.)
- **L-26 Error-log scrubber misses short bare secrets** (`error_log.py:35-43`; only 1 of 15 `log_exception` calls passes `secrets=`). No real code path logged a secret, but any exception that quotes a value would be written verbatim. Log type + frames only, or pass `secrets=`.
- **L-27 Stored URLs with characters browsers forbid in hosts** (PoC): `validate_web_urls` accepts `https://paypal.com\.evil.com` (also `%2f`, `^`); its `base_domain` is `evil.com`, so the row is shown as paypal.com but fills on `login.evil.com`. Needs a crafted import or synced record. Kotlin/Swift same. Fix: reject WHATWG forbidden host code points and whitespace in `canonicalize_origin`/`_ascii_host`.
- **L-28 Malformed brackets raise a bare `ValueError`** (PoC: `https://[::1`, `https://[vzz]`) out of `canonicalize_origin`, `normalize_url`, `match_rank`, `candidates_for`, `validate_web_urls`; typing it into the login URL field (`shell/login_form.py` `_url_error`) is unhandled. Wrap in `OriginError`.
- **L-29 Kotlin/Swift URL splitting lacks Python's bracket checks**: `https://evil.com[::1]` becomes `https://[::1]` (loopback only). Port `_check_bracketed_netloc`.
- I-20 The Firefox build packages `build-safari-extension.cjs` and `build-store-package.cjs`; exclude them.
- I-21 The password wrapper's `created_at` is outside the AAD (harmless metadata).
- I-22 Parity gaps that fail closed: zone-ID IPv6 and `::ffff:127.0.0.1` (Python accepts, Kotlin rejects); Kotlin/Swift right-strip whitespace that Python keeps; short/octal IPv4 and `%`-encoded hosts typed by users never match; multiple trailing dots collapse; Safari's HTTP-loopback rule is narrower than Chrome's.
- I-23 Licence compliance: pystray (LGPL-3.0) is bundled by PyInstaller and no third-party notices file ships; Apache-2.0 deps (opencv) also need attribution. Add a THIRD-PARTY-NOTICES file to the installer and Store package.
- I-24 GitHub: turn on Dependabot alerts (free), require SHA-pinned actions, and confirm two-factor authentication on the account; data-folder ACLs rely on the installer (`config.py:216-229` is chmod-only on Windows).

## Summary of counts

9 medium, 29 low, 24 informational. No critical or high finding: no way was found to decrypt a vault
without a factor, to obtain a credential for another web origin, to run script in the WebView, or to
forge a licence or update.

Suggested order: M-1, M-6/M-7 (sync), M-8, M-3/L-18 (Safari), M-4/M-5 (iPhone), M-2/L-1..L-3
(licence server; L-3 is a published promise), then the lows.

## Confirmed sound (highlights)

Vault KDF and AEAD binding (no downgrade), rollback anchor, password-change rotation, Windows Hello
binding, licence and update-feed signature checks, backup archive handling; no stored-XSS path into
the WebView and a strict UI CSP; JS bridge call guard (199 exact names, no dunder walking);
re-authentication on reveal/export/master change; origin canonicalisation and frame-ancestry checks
in the extension; licence worker HMAC, size caps, escaping and fail-closed config; CI pinned to SHAs
with `contents: read`; hash-locked pip installs everywhere; keychain/Keystore usage, passkey rpId
checks and Safari origin checks on iOS.
