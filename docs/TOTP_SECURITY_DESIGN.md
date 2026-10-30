# 2FA (TOTP) secrets: security design, import and auto-fill

Status: phase 1 (import + guarded auto-fill) and the memory/validation/
confirmation parts of phase 2, the `totp_confirm` settings switch and the
export opt-in are implemented. The separate Hello-wrapped
TOTP key (`totp_vault`, sections 1 and 7) and the write-only editor
(section 3) are designed, **not built**.

## Problem

LocalGateKeys stores a TOTP secret inside the credential that also holds the
password. Anyone who has the vault file and the master password — or simply
sits at an unlocked PC — gets both factors. The goals below restore as much of
"two factors" as a single local app can, without making daily use painful.

## Threats considered

| # | Threat | Mitigation | Status |
|---|--------|------------|--------|
| T1 | Vault file + master password stolen (malware, shoulder-surfing, reused password) | TOTP secrets encrypted under a separate TPM-bound Windows Hello key | Planned |
| T2 | Someone uses an unlocked, unattended PC | Optional per-code confirmation (`totp_confirm`); session lock wipes the TOTP section | Confirmation implemented (desktop dialog); Hello/face prompt planned |
| T3 | Phishing page asks for the code | Codes are released only to the exact origin stored on the credential | Implemented |
| T4 | Malicious page script / other extension scrapes codes | Code only after a trusted user click; one code per grant; no clipboard by default | Implemented |
| T5 | Secret leaks through exports, logs, diagnostics, screenshots | Broker responses carry only codes; `totp`/`otp` keys redacted from logs/diagnostics; write-only UI and export opt-in | Broker, redaction and export opt-in implemented; write-only editor planned |
| T6 | Secret lingers in memory | Decode into `bytearray` → compute → wipe in `finally`; never cached | Implemented (see section 4 for residuals) |
| T7 | Lost TPM key (new PC, reinstall) | Recovery-phrase-wrapped backup of the TOTP key | Planned |
| T8 | Hostile otpauth URI / Authenticator export (oversized secrets, absurd parameters, malformed protobuf) | Strict bounds on every field; parsers raise only `TotpError` | Implemented |

Out of scope: an attacker already running code as the user while the vault is
unlocked. They can wait for the next code release; we limit and log, not prevent.

## 1. Separate TOTP key (planned, not built)

* On first TOTP enrolment create a random 256-bit **TOTP key (TK)**.
* Store TOTP secrets in a separate encrypted blob `totp_vault` (AES-256-GCM
  under TK, entry id as associated data), not in `entries[].totp`.
* Wrap TK with a Windows Hello key (`windows_hello.WindowsHello.wrap`,
  record id `totp-<profile_id>`). The Hello key is TPM-bound and non-exportable.
* The master-password-derived vault key does **not** unlock TK. Unlocking the
  vault yields passwords and TOTP *metadata* (issuer, digits, "has 2FA") only.
* Producing a code calls `unwrap` (Hello prompt, or the Hello cache window if
  the user allows it), decrypts that single secret, computes the code, wipes
  both buffers.
* Migration: on first unlock after upgrade, move existing `entries[].totp`
  secrets into `totp_vault` and replace them with `{"enrolled": true, ...meta}`.
* Machines without Hello: fall back to today's behaviour with a visible
  "2FA secrets protected by master password only" warning in Security settings.

Today the secret still lives in `entries[].totp.secret` (Base32 string) under
the master-password-derived vault key. `_release_totp_browser` is where the
Hello unwrap will be inserted; the protocol does not change.

## 2. Per-code confirmation (implemented as a boolean)

`AppSettings.totp_confirm: bool` (default `False`, persisted in
`settings.json`, non-boolean values fall back to `False`).
`totp.requires_totp_confirmation(settings)` is the single check used by the
broker.

When on, `get_totp_browser` shows the same trusted desktop `confirm` dialog
used for identity fills and password-update prompts before releasing a code.
The dialog shows profile, origin and login name only — never the secret or
the code. Declining returns `{"ok": false, "error": "user_cancelled"}` and
does **not** consume the grant, so the user can click Fill again; accepting
releases exactly one code (plus `next_code`) and consumes the grant.

The setting is the "Ask before releasing 2FA codes" switch in Settings ›
Locking (`shell/settings_sections.py`).

Still to do:

* The original design's three-way `never | every 5 minutes | every code`
  with Hello/face as the prompt. Once the Hello-wrapped key exists the
  `confirm` dialog becomes the fallback and `unwrap` the primary prompt.
* The desktop UI's own "copy code" path (`feature_ui`) does not consult
  `totp_confirm`; it is a local, visible action and currently out of scope.

## 3. Write-only secret (planned, not built)

* After saving, the editor shows the live code and countdown, never the
  secret. "Show setup key" is a separate action requiring master password
  re-entry and is logged in `activity`.
* Default export/backup excludes TOTP secrets; including them is an explicit
  checkbox with a warning. Encrypted LocalGateKeys backups always keep them.
  (Export part in place today: `include_totp` defaults to `False` in
  `export.py` / `app/import_export.py` and adds `ExportWarning.TOTP`.)
* `totp`/`otp` keys stay in the redaction list used by `next_release_ui`,
  `error_log` and `diagnostics`. (In place today.)

## 4. Memory handling (implemented)

`totp.py`:

* `decode_secret(secret) -> bytearray` validates and decodes the Base32
  secret into a mutable buffer.
* `generate_totp_from_key(key: bytearray, ..., wipe_key=True)` computes the
  HMAC straight from the bytearray (`hmac.new` accepts it; no `bytes()` copy
  is made by our code) and zeroes the buffer in a `finally`, including when
  HMAC raises. `wipe_key=False` lets the broker derive `code` and
  `next_code` from one decode; the broker then wipes the buffer itself in
  its own `finally`.
* `generate_totp(secret, ...)` is the convenience wrapper: decode → compute →
  wipe. Nothing is cached at module level.
* `wipe(buffer: bytearray)` is the module's own zeroing helper (same
  behaviour as `windows_hello.wipe`, kept local so `totp.py` has no Hello
  dependency).

Residual copies that CPython does not let us erase (documented in the
docstrings):

* `base64.b32decode` returns immutable `bytes`; we copy it into the bytearray
  and drop the reference at once, but the freed memory is not overwritten.
* `hmac.new` copies the key into the HMAC object (padded inner/outer blocks,
  or OpenSSL-owned memory). It is released with the object, not zeroed.
* The Base32 secret *string* inside the entry dict is immutable; the broker
  clears the entry dict (`entry.clear()`) but cannot overwrite the string.
  Section 1 is what removes it from the unlocked vault altogether.

This reduces, not eliminates, the secret's lifetime in memory.

## 5. Input validation (implemented)

All limits are enforced by `totp.py` and every failure is a `TotpError`
(a `ValueError` subclass); the parsers never leak `UnicodeError`,
`binascii.Error`, `struct.error`, `KeyError` or urllib's `ValueError`s.

| Field | Accepted |
|-------|----------|
| Decoded secret length | 10 … 128 bytes (`MIN_SECRET_BYTES`, `MAX_SECRET_BYTES`) |
| Base32 text | ≤ 4096 chars after whitespace/`-` removal |
| `digits` | 6, 7, 8 (ASCII digits only; `digits=` or `digits=6.0` are errors) |
| `period` | 15 … 120 seconds |
| `algorithm` | SHA1, SHA256, SHA512 (case-insensitive) |
| otpauth URI | ≤ 16 KiB, `otpauth://totp/...`, ≤ 64 query fields, no duplicate `secret`/`digits`/`period`/`algorithm`/`issuer`, label ≤ 1024, issuer ≤ 256 |
| Migration link | ≤ 64 KiB, valid Base64 protobuf, ≤ 256 accounts, `1 ≤ batch_size ≤ 256`, `0 ≤ batch_index < batch_size` |
| Migration account | secret ≤ 128 bytes, algorithm/digits/type must be varints; anything else is reported in `skipped` with a reason |

`tests/test_totp_hardening.py` fuzzes both parsers (500 mutated inputs each,
text and raw-protobuf mutations, fixed seeds) and asserts that only
`TotpError` escapes and that anything accepted produces a valid code.

## 6. Browser auto-fill (implemented)

Protocol additions (native protocol 2, new actions):

* `begin_totp_browser` — requires a trusted user gesture. Returns metadata for
  web credentials whose stored origin **equals** the page origin and which
  have TOTP configured, plus a 90-second grant bound to tab, document,
  origin and operation id (same `SessionGuard.grant` as passwords).
* `get_totp_browser` — consumes the grant once (`release=True`) and returns
  **only** `{ok, code, next_code, remaining, session_id}`. The secret never
  leaves the agent; error responses carry only `{ok, error}`. There is no
  logging on this path, and a test asserts that neither responses nor any
  log record contains the secret in Base32, hex or raw form.

Rules:

* Fill policy `never` and `require_master_password` on the credential apply
  to codes exactly as to passwords; `totp_confirm` (section 2) adds a prompt
  on top.
* Content script shows the LocalGateKeys icon on likely one-time-code fields:
  `autocomplete="one-time-code"`, or text/number/tel inputs whose
  name/id/placeholder/label matches otp/totp/2fa/mfa/verification code and
  whose `maxlength` (if set) is 6–8. Nothing is filled without a click.
* Split code inputs (6 boxes of length 1) are filled box by box.
* If fewer than 4 seconds remain, the content script waits for the period to
  roll over and types `next_code` instead (avoids codes that expire in transit
  without blocking the desktop UI thread).
* The code is typed into the field; it is not placed on the clipboard.
* Each release calls `_touch_secret` and is recorded like a password fill.

## 7. Google Authenticator import (implemented)

* Google Authenticator "Transfer accounts → Export" shows QR codes containing
  `otpauth-migration://offline?data=<base64 protobuf>`.
* `totp.parse_migration_uri` decodes the protobuf by hand (no new dependency):
  `MigrationPayload.otp_parameters[]` → secret (raw bytes → Base32), name,
  issuer, algorithm, digits, type. HOTP, unknown algorithms, oversized secrets
  and malformed entries are reported as skipped, not imported silently.
* Import is per credential: the 2FA tab of a login has an **Import…** button.
  Paste the export text (scan the QR with any QR reader). The account whose
  issuer/label matches the login's label or site is preselected only if the
  match is unambiguous; otherwise the user picks it. Nothing is saved until
  the user presses Save on the login.
* The pasted export text is cleared from the dialog as soon as it is read,
  and the decoded list is dropped when the dialog closes. Multi-batch exports
  show "Batch n of m"; paste the next QR for the remaining accounts.

### 7a. Scan sheet (Windows, implemented)

* `app/qr_import.py` decodes a pasted snip, a chosen or dropped picture file
  (PNG, JPEG or BMP, re-validated by `check_image` in Python) or webcam frames.
  Pictures exist only in memory; nothing is written to disk or logged. The app
  never captures the screen.
* `app/qr_accounts.py` keeps the decoded accounts under a random token (dropped
  on lock, on close and after use); the page gets issuer, account name and the
  logins that match (`totp.migration_match_score`), never a secret.
* One key opens a login in the editor with the key applied; the user saves.
  An export is added in bulk through `import_workflow` (plan, review, atomic
  apply), so duplicates and the free plan's item limit follow the file-import
  rules. Multi-part exports are merged code by code (same batch size only).
* Every step checks Pro (`totp`) and shows the upgrade screen on the free plan.

## 8. Backup of the TOTP key (planned, not built)

TK is additionally wrapped with a key derived from the existing recovery
phrase (`recovery.py`), so a dead TPM does not mean re-enrolling every site.

## 9. "Keep on phone" accounts

A credential may be marked `totp: {"external": true, "issuer": ...}` — the UI
shows "2FA lives on your phone" and never stores a secret. Recommended for
the primary email and banking accounts.

## Rollout

1. Phase 1 (done): migration importer, `*_totp_browser` actions,
   content-script detection and fill, tests.
2. Phase 2a (done): bytearray key handling with wipe-in-`finally`, strict
   parser bounds and fuzz tests, `totp_confirm` setting honoured by the
   broker, secret-free broker responses verified by test.
3. Phase 2b (partly done): settings switch for `totp_confirm` and export
   opt-in are in place. Remaining: `totp_vault` + Hello-wrapped TK with
   migration, Hello/face as the confirmation prompt, write-only editor,
   recovery wrap.
