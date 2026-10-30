# Architecture and credential-flow rationale

## 1. Components

### Browser extension

A Chromium Manifest V3 extension composed of:

- popup: user-initiated one-time save/fill and per-origin automatic-prompt permission
- isolated content script: detects/fills standard top-level HTML login fields
- service worker: validates sender frame and exact origin, then calls Native Messaging
- Native Messaging host registration: restricts browser launch to the fixed extension ID

The extension has no static all-sites host permission. It uses `activeTab` for one-time actions and optional host permissions with explicit ports for sites where the user enables automatic prompts.

### Native Messaging host

A small stdio process that:

- validates the browser-supplied extension origin (Chromium: `chrome-extension://<id>/`; Firefox: manifest path plus the Gecko id `localgatekeys@localgatekeys.app`)
- reads Chromium's length-prefixed JSON messages
- reads the current agent endpoint and the DPAPI-protected agent token
- forwards one request to the local agent over the Windows named pipe
- returns one bounded JSON response

It has no vault key and no GUI.

### Local IPC (native host <-> agent)

The native host and the desktop agent talk over a current-user named pipe
(`\\.\pipe\LocalGateKeys-<random>`). Both ends authenticate each other:

- **Agent state file** (`agent-state.json`, `version: 3`): `transport`, `pipe`, `pid`,
  `user_sid`, `bridge_revision`, and `token` with a `protection` field. On Windows the
  token is wrapped with DPAPI (`protection: "dpapi-user"`, user scope, fixed application
  entropy, `CRYPTPROTECT_UI_FORBIDDEN`) and the file DACL is replaced by an owner-only,
  non-inherited one. When pywin32 is unavailable the token is written as
  `protection: "none"` and the diagnostics report carries the warning
  `agent_token_unprotected`. The host unprotects the token in memory and sends it on
  every frame; the agent compares it in constant time before dispatching.
- **Client pin** (`pipe_transport.ClientPinPolicy`): the executable the browser is
  registered to launch is the authority. The agent reads the HKCU
  `NativeMessagingHosts\com.localgatekeys.app` keys for Chrome, Edge and Firefox,
  follows them to the manifest `path`, and requires all registrations to agree
  (`client_pin_unregistered` / `client_pin_mismatch` otherwise). The peer process
  (`GetNamedPipeClientProcessId`) must run exactly that executable. In frozen builds
  the host must also live inside the agent's install directory and, when the agent is
  Authenticode-signed, carry the same signer thumbprint (`client_signer_mismatch`;
  the signature check is read-only, via `signature.authenticode_info`). Repository
  builds keep the pinned Python launcher chain. `install.json` is only a cross-check:
  it may veto (different path or hash) but never redirects trust. Every decision is
  fail-closed, has a fixed message in `bridge_status.MESSAGES`, is relayed by the host
  with `stage: "peer"`, and is summarised path-free in the diagnostics report under
  `client_pin_policy`.
- **Server pin**: the host checks `GetNamedPipeServerProcessId` against the recorded
  `pid` and the recorded `user_sid` against its own SID before sending the token.
- **Frames**: 4-byte big-endian length + one UTF-8 JSON object, payload at most
  `MAX_FRAME_PAYLOAD` (1 MiB). The parser rejects oversized or short frames, invalid
  UTF-8 (including lone surrogates), non-object JSON, trailing data and pathological
  nesting, raising only `ProtocolError`; a seeded 1000-iteration mutation fuzz test
  (`tests/test_ipc_hardening.py`, marker `fuzz`) guards that contract.
- **Loopback TCP** is a non-Windows development transport only. The host refuses to
  use it (`tcp_fallback_disabled`) unless `LOCALGATEKEYS_ALLOW_TCP_FALLBACK=1` is set
  (pytest is exempt), connects only to `127.0.0.1`, requires a plaintext (`protection:
  "none"`) state token, and sends the token on every frame.

#### Broker protocol fields (protocol 2)

- `ping` -> `{ok, version, locked}` only. It is unauthenticated metadata and no longer
  carries `session_id`, `profile_name`, `protocol` or `browser_enabled`.
- `session_id` (the unlock lease) is returned only by responses a later request binds
  to: `begin_browser`, `begin_totp_browser`, `begin_identity_browser` and
  `approve_identity_browser`. `get_browser`, `validate_browser`, `check_browser` and
  `release_identity_browser` no longer include it.
- **Gesture nonces.** `begin_browser`, `begin_totp_browser` and the new
  `begin_gesture_browser` (for save flows; takes `user_gesture: true`, needs no unlock)
  return `gesture_nonce` (32 hex characters = 16 random bytes) and
  `gesture_expires_in` (30 seconds). A nonce is single use and bound to the request's
  `origin` and browser `context` (tab/document). `get_browser`, `get_totp_browser`,
  `save_browser` and `save_pending_browser` must present it as `gesture_nonce`; a
  wrong, expired or reused nonce fails with `gesture_nonce_invalid` (a nonce presented
  from the wrong tab is not consumed). Without a nonce, the legacy `user_gesture: true`
  claim is accepted only while the setting `legacy_gesture_compat` (default `true`) is
  on, and every such use records the diagnostics warning `legacy_gesture_compat_used`;
  with it off the reply is `gesture_nonce_required`. A request with neither is
  `user_gesture_required`. The nonce store holds at most 64 live nonces.
- **Multi-URL candidates.** `begin_browser` and `get_browser` accept an optional
  `url` (the page URL). It must belong to the request `origin`
  (`origin_of(url) == origin`), otherwise the reply is `invalid_request`; without it
  the origin itself is matched. Candidates are resolved with
  `origin.candidates_for(entries, url)` over each login's `scope.urls` rows
  (`exact_origin` / `host` / `base_domain` / `starts_with`; a legacy login with only
  `scope.origin` behaves as one `exact_origin` row). `begin_browser` choices carry
  `match` (the best mode) and are ordered exact-origin first, then favorite, label,
  username; the grant covers every offered candidate. `get_browser` re-checks that
  the entry still matches the page and fails closed (`session_changed`) otherwise.
  A `starts_with` row only matches when `url` is supplied. Nothing else (parent
  domains, lookalike hosts) is ever offered.
- **Card fill** (`card_protocol: 1`, structured identity context required) mirrors
  the identity flow with HTML `autocomplete` tokens as field names
  (`cc-name`, `cc-number`, `cc-exp`, `cc-exp-month`, `cc-exp-year`, `cc-csc`,
  `cc-type`; the PIN has no token and is never released):
  - `begin_card_browser` `{user_gesture: true}` -> `{ok, card_protocol, choices,
    origin, session_id, profile, gesture_nonce, gesture_expires_in}`; each choice is
    `{entry_id, title, favorite, revision, brand, last4, fields}` where `fields` maps
    every token to `{label, protected, present}` and no value is included
    (`card_not_found` when the profile has no card).
  - `approve_card_browser` `{user_gesture: true, entry_id, revision, fields,
    session_id}` shows the trusted desktop review (card number as `•••• 1111`, CVV
    masked) and returns `{ok, card_protocol, approval, entry_id, revision, fields,
    session_id, gesture_nonce, gesture_expires_in}`; the approval is one use, bound
    to session lease, origin, tab/document context, item revision and the selected
    tokens, and expires after 60 seconds.
  - `release_card_browser` `{approval, entry_id, revision, fields, gesture_nonce}` is
    gesture-gated exactly like `get_browser` (nonce from `begin_card_browser` or
    `approve_card_browser`; legacy `user_gesture` only under `legacy_gesture_compat`)
    and returns `{ok, card_protocol, entry_id, revision, fields, values}` with values
    for the approved tokens only; any drift (origin, tab, revision, wider selection,
    lock/profile change, replay) consumes the approval and replies `session_changed`.
  - `cancel_card_browser` `{approval}` revokes an unused approval.

### Local agent

The trusted desktop UI and broker:

- creates/unlocks/locks the vault
- displays authoritative save confirmations
- selects among multiple matching credentials
- binds desktop applications
- verifies desktop identity and performs fill
- registers `Ctrl+Shift+Space` with `RegisterHotKey`, not a keyboard hook
- auto-locks after five minutes of secret-use inactivity

### Vault engine

Stores a single encrypted JSON payload. The KDF metadata and cipher envelope are plaintext/authenticated; all credential metadata is encrypted.

### Windows UI Automation adapter

Inspects only foreground-window and editable-control metadata. It intentionally does not call value-read APIs on password controls. Fill uses `set_edit_text` where supported, with outbound `SendInput` as a fallback.

## 2. Browser save flow

```text
User fills login form
  -> user clicks Save, or enabled-site heuristic displays prompt
  -> content script snapshots username/password only after Save approval
  -> service worker derives sender origin from browser metadata
  -> claimed origin must equal sender origin
  -> Native Messaging host verifies extension caller
  -> local agent validates lengths/origin
  -> desktop UI displays exact origin + username
  -> user approves and unlocks vault
  -> credential is encrypted and atomically saved
```

The content script clears its local credential object's password property after dispatch. JavaScript and browser internals may still retain copies; this is best-effort only.

## 3. Browser fill flow

```text
User clicks Fill
  -> content script identifies current-password field
  -> service worker validates top frame + exact origin
  -> agent unlocks and exact-origin matches
  -> user chooses entry if several exist
  -> only that username/password returns
  -> content script rechecks returned origin
  -> native input setters update the fields and fire input/change events
  -> user reviews and submits manually
```

No parent-domain, registrable-domain, or subdomain fallback exists. `https://example.com`, `https://login.example.com`, and `https://example.com:8443` are separate scopes.

## 4. External browser flow

When Steam or another application launches the system browser, LocalVault does not need to trust the launching application. The extension observes the resulting browser tab and scopes the credential to that tab's web origin.

This is the preferred flow for OAuth and account-linking pages. LocalVault should not attempt to copy credentials back into the launching app.

## 5. Desktop bind flow

```text
User clicks Bind desktop app
  -> 3-second deliberate switch window
  -> agent inspects foreground window metadata
  -> user maps username and password controls
  -> protected `IsPassword` control is preferred
  -> user enters credential into LocalVault's UI
  -> vault stores executable path/hash, title, full control-layout fingerprint, signer, selectors, credential
```

There is no generic safe way to recover the password the user already typed into an arbitrary desktop app. Windows accessibility providers are expected to protect sensitive values, and custom-rendered apps may expose no controls at all. Re-entry into the manager is therefore the safe first-save workflow.

## 6. Desktop fill flow

```text
User focuses bound login window and presses Ctrl+Shift+Space
  -> agent snapshots current foreground window
  -> exact executable-path and SHA-256 match
  -> exact complete edit-control layout match
  -> exact normalized window-title match
  -> signer-thumbprint match when pinned
  -> strongly and unambiguously resolve username/password selectors
  -> protected-type requirement, or fresh warning for approved unprotected mapping
  -> set username and password
  -> do not press Enter or click Sign in
```

A mismatch causes a visible failure with no fill.

## 7. Steam and game launchers

There are four distinct cases:

1. **External system browser:** use the browser extension.
2. **Accessible native login controls:** use explicit UIA binding and fill.
3. **Accessible embedded Chromium/CEF/WebView controls:** bind only with a warning; UIA cannot prove the embedded web origin, so every fill requires fresh confirmation.
4. **Custom-rendered or anti-cheat-protected controls:** unsupported by the generic adapter.

Case 4 is not solved by adding a global hook. A production implementation would need a documented vendor integration, an accessibility improvement in the app, or a user-mediated workflow such as opening the vault and explicitly copying/filling one field.

## 8. Data model

Conceptual encrypted entry:

```json
{
  "id": "uuid",
  "kind": "web | desktop",
  "label": "display label",
  "username": "user@example.com",
  "password": "secret",
  "scope": {
    "origin": "https://example.com",
    "exe_path": "C:\\...\\app.exe",
    "exe_sha256": "...",
    "window_title": "Sign in",
    "control_fingerprint": [{"automation_id": "...", "is_password": true}],
    "signer": {"thumbprint": "..."},
    "username_selector": {"automation_id": "..."},
    "password_selector": {"automation_id": "...", "is_password": true}
  },
  "created_at": 0,
  "updated_at": 0
}
```

A web entry has `origin`; a desktop entry has the executable/window/control fields.

## 9. Why no automatic desktop capture

A process-wide or system-wide observer capable of collecting arbitrary passwords must see secrets before it knows whether the target is legitimate. It creates the same high-value telemetry and privileges as a keylogger, triggers endpoint-defense concerns, and cannot reliably distinguish login, payment, recovery, and new-password fields across arbitrary custom UIs.

The prototype instead separates:

- **metadata detection**, which can be continuous in a future design if narrowly scoped and transparent
- **secret capture**, which occurs only inside LocalVault or an exact-origin browser flow
- **secret release**, which requires scope validation and an unlocked vault

## 10. Device sync

User guide: [SYNC.md](SYNC.md).

Sync keeps the local-first model: no server, no account. Devices exchange
*sealed views* (every item the device knows, encrypted under a key derived from
a shared group key) either over an authenticated LAN connection or as files in
a cloud-drive folder. Both transports carry the same record format and use the
same merge code, so an edit that arrives by both routes is idempotent.

### Modules

All under `src/localvault/sync/` unless noted.

| Module | Role |
| --- | --- |
| `engine.py` | Pure version-vector merge. No I/O, no clocks. Dominating vector wins; concurrent live edits keep a winner and emit a deterministic conflict copy; edit vs delete keeps the edit. The iOS/Mac core (`ios/LGKCore`) and the Android core (`android/lgk-core`) implement the same rules and pass the shared vectors. |
| `vault_bridge.py` | Turns the unlocked vault into engine states (`local_view`) and writes a merge outcome back in one transaction (`apply`). Defines what syncs and what is device-local. Holds `SyncGroupState` (group id, epoch, group key, device identity, peers, counters), stored inside the vault payload under `sync_group`, so nothing about sync sits in a settings file. |
| `group.py` | Group key, key derivation, and the sealed view / device file format (`LGKSYNC1`). |
| `keyring.py` | The keyring file: group key wrapped by the sync password (Argon2id) and by each member's X25519 key, with the MAC chain. Create, join, `accept_keyring`, `rotate`. |
| `folder_transport.py` | Cloud-folder transport: reads the keyring and other devices' files, merges, writes this device's own file atomically. Layout `LocalGateKeys Sync/keyring.lgkkeys` and `devices/<id>.lgksync`. |
| `runner.py` | `run_merge`: the single place peer views become vault changes. Used by both transports. |
| `lan_sync.py` | Wi-Fi sync on the group model: one-use QR enrollment, view exchange inside the authenticated channel. |
| `pairing.py` | Pairing offers, the QR text, and the enrollment request and reply formats. |
| `transport.py` | Bounded authenticated private-LAN transport: signed hellos, AES-GCM channel, literal private IPs, no discovery. |
| `state.py` | Pinned-peer store used by the transport (`SyncState`, revocation). |
| `lan_address.py` | The private and link-local address ranges a LAN endpoint may use (`LAN_NETWORKS`), an explicit list the phone apps apply too. |
| `lan_interfaces.py` | Ranks this PC's addresses a phone on the same Wi-Fi can reach, for the address suggested in the QR setup. |
| `firewall.py` | Windows Firewall status for the sync port, and the inbound rule added only from the "Allow through Windows Firewall" button (elevated `netsh`). |
| `phone_restore.py` | Restores a phone backup (`LGKMBAK1`) by passing it to `run_merge` as one peer view. |
| `install.py` | Per-installation id in the data directory, used to detect a vault copied to another PC. |
| `service.py` | Background service and the `SyncGate`: scheduling, single-flight runs, lock and lease handling, UI job queue, status. |
| `manifest.py`, `conflicts.py` | Earlier catalog-manifest and conflict-record primitives from the first LAN implementation. The group sync path does not use them for merging. |
| `src/localvault/app/sync_view.py` | Sync screen view models and all user copy for issues (no UI toolkit). |
| `src/localvault/app/sync.py` | The background service for the WebView UI and the Sync page's actions (bridge calls that submit jobs to the sync worker). |
| `webui/src/components/SyncPage.svelte` | The Sync page. |

The former `src/localvault/sync_vault.py` adapter was removed; the vault bridge
replaces it.

The iPhone and Mac apps share the sync core in `ios/LGKCore/Sources/LGKCore/Sync`
(screens in `ios/App/Sync` and `ios/Mac/Sync`); the Android app uses
`android/lgk-core` (screens in `android/app`). Phones only join: they scan or
paste a QR offer, or join a cloud folder, and connect out to a PC or Mac over
Wi-Fi without listening themselves. The Mac app can also create a group, listen
and show the QR code.

### Trust model

The cloud folder is untrusted: it can read, replace, roll back and delete files.

- **Group key `G`** is 32 random bytes with an integer `epoch`. Record and file
  keys are HKDF-SHA256 derivations from `G` (salt `group_id`, labelled info
  strings that include the epoch).
- **Keyring MAC chain.** The keyring is authenticated by knowledge of `G`, not
  by a writer signature: `mac` is HMAC-SHA256 under a key derived from `G`,
  covering the whole body including `prev_mac`. A device stores
  `(group_id, epoch, G)` in its vault and accepts a keyring only if the group
  matches and either the epoch equals its own and `mac` verifies under its
  stored `G`, or the epoch is its own plus one, `prev_mac` verifies under the old
  key and commits to the new one, its own device wrap opens, and `mac` verifies
  under the new key. Older epochs (rollback) and larger jumps are rejected. A
  keyring with a foreign group id stops sync. `prev_mac` must be null at epoch
  1 and may be null at any epoch in the first keyring of a group that existed
  before it had one (a Wi-Fi-only group adding a cloud folder,
  `create_for_existing_group`; its other devices `attach_with_password` and
  keep their identity). An epoch + 1 keyring still needs a valid `prev_mac`.
- **Rotation.** Changing the sync password and removing a device are one
  operation, `rotate`: new `G`, epoch + 1, new salt, wraps for the remaining
  members and the new password. Reusing the current password is refused.
- **Races.** Each device keeps the last keyring it accepted and writes it back
  if the folder shows a rollback or same-group tampering (`keyring-restored`).
  A competing genuine rotation or a removed device stops sync
  (`rotation-conflict`, `removed-or-conflict`). Join and rotate re-read the
  keyring immediately before writing. A device that was offline during a removal
  accepts the first valid next-epoch keyring it sees (documented in SYNC.md).
- **Device files.** One writer per file. The plain header carries a counter;
  readers remember the highest counter per device and skip a lower one as a
  rollback. Files are bounded (20,000 records, 64 MiB), and files not written
  for over 365 days are treated as stale. Tombstones are kept 365 days and are
  authenticated (empty plaintext under the same AAD scheme).
- **LAN enrollment.** The QR carries the inviter's endpoint and public keys, a
  one-use secret and a short code (120 s TTL). The new device sends the only
  message the listener accepts from an unpinned peer: an enrollment request
  encrypted to the inviter's exchange key from the QR, with an HMAC under the
  pairing secret over the transcript. A `PairingSession` allows one success and
  at most five failed attempts. The inviter pins the device and replies with
  `(group_id, epoch, G)` encrypted to the new device and bound to the
  transcript. Group keys are never delivered by "first contact", so a removed
  device never receives a newer key. Rotation drops LAN peers; they must re-pair.
- **Install binding.** The vault stores the `install_id` of the PC it joined on.
  A different id (vault copied or restored) answers `rejoin-required`.

### Formats

The byte-level authority is the docstrings of `group.py` (sealed views, device
files), `keyring.py` (keyring and "Canonical JSON"), `engine.py` (merge rules and
identifier rules) and `pairing.py` ("Format rules": offer, QR text, enrollment
request and reply), together with the committed vectors in
`tests/vectors/sync/` (its `README.md` lists each file).
`scripts/make_sync_vectors.py` regenerates them deterministically and
`tests/test_sync_vectors.py` requires byte-for-byte equality, so they change
only when a format changes on purpose. Byte rules are not restated here.

Two canonical-JSON variants exist: sealed views and keyrings use
`ensure_ascii=False`; pairing JSON uses `ensure_ascii=True`. All identifiers are
ASCII `[A-Za-z0-9._:-]`, 1 to 128 characters.

### Threading and the gate contracts

`VaultSession` is not thread-safe and the Tk thread edits it freely, so all sync
work that touches the vault goes through one `SyncGate` (the `service.py` module
docstring is the authority):

- A reentrant lock covers every `SyncGroupState` read-modify-write in the
  process: folder runs, LAN requests on listener threads, the hello-counter
  source, enrollment and reset.
- An optional UI barrier parks the Tk thread while a worker holds the gate.
  Folder I/O releases the barrier but keeps the lock. LAN round trips release
  both, so two devices syncing with each other cannot deadlock.
- Lock order is gate lock, then barrier. The Tk thread never waits for the gate:
  every entry that needs the vault (listener start, enrollment, reset, leave,
  rotate, snapshot) is a job given to `SyncService.submit`, run on the single
  worker thread, with the result posted back to Tk.
- Dialogs collect input first, then submit a job. Nothing holds a
  `session.transaction()` across a nested event loop.
- Every run checks the unlock lease before touching the vault and before each
  write. Locking mid-run aborts without a partial write. A park timeout marks
  the gate broken so later gated touches raise `SyncAborted`.
- Runs are single-flight. Triggers: unlock, a five-minute tick, ten seconds after
  a local change (the app polls a cheap write marker), and "Sync now".
- `reset` is called only after explicit user confirmation.

The contracts above are written for the classic Tk UI. In the WebView UI
(`src/localvault/app/sync.py`) the barrier is `VaultLockBarrier`: holding the
gate holds the controller's vault lock, which page calls also take, so a sync
run's vault writes exclude user saves in the same way.
