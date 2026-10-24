# Test plan

## 1. Automated portable tests

Run:

```text
PYTHONPATH=src pytest -q
```

Expected result: every collected test passes (`N passed`, no `failed`, no
`error`). The count grows with the suite, so it is not pinned here; compute it
with `PYTHONPATH=src pytest -q --collect-only | tail -1` before comparing.

Coverage includes:

- URL/origin canonicalization, default ports, non-default ports, subdomain separation, and localhost HTTP exception
- Native Messaging and local-socket framing
- vault create/unlock/upsert/find/delete behavior
- wrong master password
- authenticated-ciphertext modification
- bounded KDF metadata
- exact executable-path matching
- local-agent random-token authentication
- native-host fail-closed caller validation
- strong, unambiguous UIA selector matching and protected-type enforcement
- no single-field fallback after a selector mismatch
- executable SHA-256 and complete edit-control layout pinning
- embedded Chromium/CEF/WebView classification
- explicit-port runtime browser permissions
- desktop window-title requirements and native-message size bounds

Also run:

```text
python -m compileall -q src tests
node --check browser-extension/api.js
node --check browser-extension/heuristics.js
node --check browser-extension/login-safety.js
node --check browser-extension/background.js
node --check browser-extension/content.js
node --check browser-extension/popup.js
```

### Browser extension unit tests (Node 24, no browser needed)

```text
npm install      # dev-only: jsdom; node_modules is gitignored
npm test         # node --test tests/*.cjs tests/extension/*.test.cjs
```

`npm test` runs:

- `tests/background019.test.cjs`, `tests/popup019.test.cjs` — service worker and
  popup against `node:vm` mocks (origin pinning, documentId, destination
  changes, multi-frame dispatch, `gesture_nonce` forwarded verbatim and
  malformed nonces refused before native access, `begin_gesture_browser`
  allowed, `ping` passed through as `{ok, version, locked}` and the popup
  enabling its actions without `session_id`/`browser_enabled`/`protocol`).
- `tests/extension/background-frames.test.cjs` — same-origin iframe acceptance,
  cross-origin and cross-origin-ancestor rejection, frameId-threaded nudges,
  Firefox fallbacks (`browser.*`, no `documentId`, no `_favicon`).
- `tests/extension/background-card.test.cjs` — card-fill allow-list
  (`begin/approve/release/cancel_card_browser`) pinned to `card_protocol: 1`,
  active-tab gating and browser-derived context, typed `cc-*` field lists
  (non-card tokens, duplicates, empty and oversized lists refused), approval
  and revision validation; page `url` forwarded only for `begin_browser` /
  `get_browser`, only when its canonical origin equals the sender origin,
  with the fragment stripped, and dropped (never an error) for other origins,
  ports, schemes, credentials, lookalike hosts or malformed values.
- `tests/extension/card-fill.test.cjs` — jsdom card fill: payment-form
  detection from `autocomplete="cc-*"` and from conservative name/id
  heuristics (only inside a scope with a card-number-like field; explicit
  non-card `autocomplete` opts a control out; no OTP or identity buttons on
  card controls), approval checklist defaults (tokens present on the page,
  CVV unticked), split expiry (month `<select>`, two-digit year) and single
  `MM/YY` vs `MM/YYYY` formatting, cross-origin form refusal before any native
  call, CVV never filled unless ticked, no submit, released values blanked
  after the fill, a release carrying an unapproved token discarded, two-card
  picker (brand + `•••• last4`) and cancel.
- `tests/extension/login-safety.test.cjs`, `content.test.cjs` — jsdom DOM
  tests: `safeForm` cross-origin rejection, `onTop` overlay rejection, OTP
  split boxes, username-only first step, new-password generation, save-outcome
  heuristics (field gone / URL changed / failure banner / uncertain), open
  shadow DOM traversal, trusted-event gating, and the gesture-nonce flow
  (below): nonce from `begin_browser` forwarded with `get_browser`, expired
  nonce re-minted on a later trusted click, `gesture_nonce_invalid` retried
  once only while a click is in flight, Save clicks minting through
  `begin_gesture_browser` for `save_pending_browser`/`save_browser`, a
  `ping` without `session_id` not resetting an open fill, and the page `url`
  (fragment stripped) sent with `begin_browser`/`get_browser` with the account
  picker labelling `host` / `base_domain` / `starts_with` matches.
- `tests/extension/heuristics.test.cjs` — localized sign-in/logout/failure
  dictionaries (en, pl, de, fr, es, it, pt, nl, el) and boundary semantics.
- `tests/extension/firefox-manifest.test.cjs` — manifest invariants and the
  generated Firefox variant (`npm run build:firefox`).

Expected result: `# fail 0` in the TAP summary. The pass count is not pinned;
it is printed as `# pass N` by the same run.

### Gesture-nonce flow (broker protocol 2, hardened)

The broker (`src/localvault/browser_broker.py`, "Broker protocol fields" in
`docs/ARCHITECTURE.md`) proves that a secret-releasing or vault-writing request
descends from a user gesture with a single-use nonce instead of trusting a
`user_gesture: true` flag:

1. `begin_browser` / `begin_totp_browser` (icon click or popup action) return
   `gesture_nonce` (32 hex characters) and `gesture_expires_in: 30` next to
   the grant. The content script keeps the nonce on the operation object only,
   with a local expiry no later than 30 s, and drops it on reset.
2. The follow-up `get_browser` / `get_totp_browser` presents it as
   `gesture_nonce` (plus the legacy `user_gesture: true` for older hosts). The
   service worker forwards it verbatim after a `^[0-9a-f]{32}$` check; the
   broker binds it to the same origin and browser context, so it must travel
   with the same `operation_id` that minted it.
3. Save flows have no grant: the trusted "Save"/"Save login" click in the
   in-page panel calls `begin_gesture_browser` (`user_gesture: true`, no
   unlock) and passes the fresh nonce to `save_pending_browser` or
   `save_browser` under the same `operation_id`. `check_browser` carries no
   `session_id` any more and none is forwarded.
4. If the account picker stayed open past 30 s, the next trusted click
   re-mints via `begin_gesture_browser`; the stale nonce is never sent. A
   `gesture_nonce_invalid` / `gesture_nonce_required` reply is retried once,
   only while a trusted click is at most 5 s old; otherwise (or on a second
   rejection) the "Click again" message is shown and nothing is filled.
5. `ping` is `{ok, version, locked}` only. The page's status poll resets an
   open fill solely on `locked: true` (or a failed ping); the popup derives
   Connected/Locked/Setup from the same three fields. "Integration paused" is
   reported by the first real action (`integration_disabled`), not by `ping`.

### Firefox native-messaging registration check (Windows, current user)

`scripts/repair_browser_bridge.ps1`, `scripts/install_windows.ps1` and the
in-app repair (`localvault.browser_bridge`) write two manifests and three
registry values; `scripts/uninstall_windows.ps1` and
`scripts/remove_current_user_install.ps1` remove all of them. Re-running
repair or install is idempotent (paths are refreshed, nothing is duplicated).

```powershell
$Data = Join-Path $env:LOCALAPPDATA 'LocalGateKeys'
Get-ItemProperty 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.localgatekeys.app'   # (default) -> $Data\com.localgatekeys.app.json
Get-ItemProperty 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.localgatekeys.app'
Get-ItemProperty 'HKCU:\Software\Mozilla\NativeMessagingHosts\com.localgatekeys.app'          # (default) -> $Data\com.localgatekeys.app.firefox.json
Get-Content (Join-Path $Data 'com.localgatekeys.app.firefox.json')
```

Expected: the Chrome and Edge values point at `com.localgatekeys.app.json`
(`allowed_origins: ["chrome-extension://<id>/"]`); the Mozilla value points at
`com.localgatekeys.app.firefox.json` whose `allowed_extensions` is exactly
`["localgatekeys@localgatekeys.app"]` (the Gecko id in `manifest.json`) and
which has no `allowed_origins`. Both manifests share `name`, `type: stdio`
and the same pinned `path`. No `HKLM` key exists. After uninstall all three
keys and both manifest files are gone. Automated coverage:
`tests/test_browser_bridge_registration.py` (Python registration) and
`tests/test_install_hardening.py` / `tests/test_bridge023.py` (script text).

## 2. Browser manual matrix

Test in current Chrome and current Edge. For Firefox, load the output of
`npm run build:firefox` (`build/firefox-extension`) as a temporary add-on;
Firefox treats MV3 host permissions as optional, so grant site access in the
add-on's Permissions tab before the automatic rows (B6, B7, B14).

| ID | Scenario | Expected result |
|---|---|---|
| B1 | Open extension on unsupported `chrome://` page | Controls disabled; no content injection |
| B2 | Manual Save on localhost demo | Native desktop confirmation shows exact localhost origin and username |
| B3 | Manual Fill after clearing fields | Correct fields filled; form not submitted |
| B4 | Agent not running | Clear `agent_offline` error; no browser crash |
| B5 | Vault locked | Agent requests master password; cancel returns no credential |
| B6 | Fresh install, sign in on the demo origin (prompts are on by default; no runtime permission dialog exists) | After a trusted submit and a success signal (login form gone, URL changed, or explicit "Did you just sign in?" after ~4 s), the "Save this login?" banner appears; a visible failure message suppresses it |
| B7 | Popup: "Turn off save prompts on this site", then reload and sign in | No automatic prompt on that exact origin; manual popup actions still work; other origins still prompt |
| B8 | Save `https://example.test` then request subdomain | No match |
| B9 | Same host on a different explicit port | No match |
| B10 | Page with `autocomplete=new-password` only | No automatic current-password save prompt |
| B11 | Page with two saved accounts | Agent asks user to select one |
| B12 | Cross-origin iframe login | No icons in the frame; any request from it is refused by the service worker (`destination_changed`); no top-frame confused-deputy fill |
| B13 | Change-password page with old/new fields | Ensure new-password is not selected as current login credential |
| B14 | Revoke site access in the browser's extension settings ("On click" / "On specific sites" in Chrome; Permissions tab in Firefox) | Content script no longer injects on reload, so no icons and no save banner; the popup's Fill still works on the active tab after a click (activeTab) |
| B15 | Same-origin iframe login (demo page embedding its own login form) | Icons and save banner appear inside the frame; the fill targets the frame's form only; nothing is filled in the top document |
| B16 | Login form inside an open shadow root (web-component page) | Field icon appears; Fill and save capture work; a page overlay covering the host still blocks filling |
| B17 | Localized page (e.g. Polish, German, Greek) | Single-button auto sign-in works only for an exact localized label ("Zaloguj się", "Anmelden", "Σύνδεση"); logout controls ("Wyloguj", "Abmelden", "Αποσύνδεση") discard the pending capture |
| B18 | Firefox (temporary add-on from `npm run build:firefox`) | Fill/save work after granting site access; saved entries have the neutral icon (no favicon API); no console errors about `chrome.*` callbacks |
| B19 | Firefox registration: run `scripts\repair_browser_bridge.ps1` twice, then the registry check above | `HKCU\Software\Mozilla\NativeMessagingHosts\com.localgatekeys.app` points at `com.localgatekeys.app.firefox.json` with `allowed_extensions` = the Gecko id; second run changes nothing; Firefox's Connection test succeeds without the Chromium key |
| B20 | Gesture nonce, two saved accounts: click the field icon, wait more than 30 s, then choose an account | Fill still succeeds (a fresh nonce is minted on the click, visible in Connections diagnostics as `begin_gesture_browser`); no `legacy_gesture_compat_used` warning is recorded |
| B21 | Gesture nonce, save: sign in, click "Save login" in the banner | Login is saved; the desktop warning log shows no `legacy_gesture_compat_used`; with the setting `legacy_gesture_compat` off the flow still works |
| B22 | Replay: capture a `get_browser` request (Connections diagnostics) and resend it, or click an account after locking the vault | `gesture_nonce_invalid` / `session_changed`; the page shows "Click again"; nothing is filled and no second request is made from a timer |
| B23 | Multi-URL login: save a login with a `starts_with` row for `https://example.test/app/` and open `https://example.test/app/login#x` | The account picker lists it with "matches URL prefix"; Connections diagnostics show `begin_browser` with `url` = the page URL without `#x`; the same login is not offered on `https://example.test/other/` |
| B24 | Card fill, checkout form with `autocomplete="cc-*"` fields, one saved card | Card button on the card-number field and "Fill card…" in the popup; the in-page checklist ticks name, number and expiry, leaves the security code unticked; "Review and approve" opens the desktop review showing `•••• 1111` and a masked CVV; after Confirm the ticked fields fill, the CVV stays empty, the form is not submitted |
| B25 | Card fill, CVV ticked, then Cancel in the desktop review | `user_cancelled` shown on the page; nothing is filled; a second attempt works; ticking the CVV fills it only after the desktop review listed it |
| B26 | Card fill, checkout without `autocomplete` (fields named `cardNumber`, `exp_month` select, `exp_year` `maxlength=2`, `cvv`) | The form is detected from the names; the month `<select>` and two-digit year are set correctly (`03` / `27`), a single `MM/YY` field receives `03/27` and an `MM/YYYY` field `03/2027`; a page with only an "expiry" field and no card-number field shows no card button |
| B27 | Card fill on a form whose `action` is another origin, or inside a cross-origin iframe | "The form points to another origin" (no native call) / no card button in the frame; a replayed `release_card_browser` (Connections diagnostics) fails with `session_changed` and fills nothing |

Record browser version and extension ID with results.

## 3. Desktop demo matrix

Run `scripts\run_desktop_demo.ps1`.

| ID | Scenario | Expected result |
|---|---|---|
| D1 | Inspector on demo | Username and password edit controls listed; password reports `is_password=true` |
| D2 | Bind demo | Default mapping chooses username then protected password |
| D3 | Hotkey fill | Both values filled; sign-in button untouched |
| D4 | Rename/alter window title before fill | Exact-title check rejects fill |
| D5 | Copy demo executable to another path | Executable-path check rejects fill |
| D5a | Replace/rebuild executable at the same path | Executable SHA-256 check rejects fill and requires rebind |
| D6 | Rearrange/remove controls in source and rebuild | Full control-layout check rejects fill and requires rebind |
| D7 | Agent locked when hotkey pressed | Unlock prompt appears before release |
| D8 | Wait more than five minutes after use | Vault auto-locks |
| D9 | Run target elevated while agent is not elevated | Fill fails safely due Windows integrity isolation |

## 4. Steam compatibility experiment

Because the Steam client UI can change independently, do not assume compatibility from a previous version.

Record:

```text
Date:
Windows version/build:
Steam client build/channel:
Steam executable path:
Executable SHA-256:
Window title:
Signer status/subject/thumbprint:
Number of exposed Edit controls:
Password control exposes IsPassword: yes/no
Bind result:
Fill result:
Steam Guard / QR / CAPTCHA behavior:
Notes:
```

Procedure:

1. Use an account with working recovery and MFA.
2. Open the actual username/password sign-in view.
3. Run `localvault-inspect --delay 3` and switch to Steam.
4. Review metadata before binding.
5. Bind only if the expected sign-in controls are identifiable.
6. Clear any typed fields.
7. Press `Ctrl+Shift+Space` with the same window focused.
8. Verify the correct fields changed and no submission occurred.
9. Change to another Steam window and confirm title/control checks reject a fill.
10. After a Steam update, rerun the inspector and expect signer/control changes to require rebinding.

If no editable controls are exposed, record the result as **unsupported by safe generic UIA**. Do not add hooks, OCR, process injection, or memory access as a workaround.

## 5. Vault robustness tests before production work

Not yet implemented; required next:

- fuzz malformed JSON, base64, nonce, KDF, and payload fields
- simulate interrupted writes and disk-full conditions
- backup and recovery round trips
- very large vault performance and size limits
- Unicode normalization and international-domain cases
- concurrent writer rejection/locking
- downgrade/rollback detection
- crash dump and swap/pagefile secret exposure analysis

## 6. Security regression gates

A change must fail review if it:

- reads keyboard input globally
- reads a protected UIA password value
- accepts a browser-supplied origin without deriving the sender origin
- introduces parent-domain/subdomain fallback by default
- sends the full vault to the extension
- fills before executable/window/control validation
- automatically submits a login form
- silently permits an unprotected desktop password target
- weakens KDF/cipher settings without a format migration and review

