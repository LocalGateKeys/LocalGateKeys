# `.lgkshare` v1: one shared item

Status: format frozen with the vectors in `tests/vectors/share/v1.json` (UX plan workstream 9).
Reference code: `src/localvault/share.py`. LGKCore and lgk-core must pass the same vectors.
LocalGateKeys to LocalGateKeys only; there is no web viewer.

## Code

- Six words from the BIP39 English list (`src/localvault/assets/bip39_english.txt`), chosen uniformly at
  random: 66 bits. Shown on the sender's screen only and never put in the package.
- Normalised before use: lower case, split on any run of spaces, `·`, `.`, `,` or `-`, exactly six words,
  each in the list, joined with one ASCII space. Anything else is `bad-code`.
- As a QR (the separate "key" QR): `lgkshare-code:` followed by the six words joined with `-`.

## Key

`key = Argon2id(password = UTF-8(normalised code), salt = 16 random bytes, t = 2, m = 19456 KiB, p = 1,
length = 32)`. The parameters are fixed for v1; a reader refuses any other values.

## Package (the file, or the QR content)

UTF-8 canonical JSON (keys sorted, no spaces, non-ASCII kept as is), at most 256 KiB:

| key | value |
|---|---|
| `format` | `"localgatekeys-share"` |
| `version` | `1` |
| `id` | random UUID v4, lower case: the package id for open-once |
| `sender` | device name shown in the pop-up, at most 64 characters |
| `kdf` | `{"name": "argon2id", "time_cost": 2, "memory_cost_kib": 19456, "parallelism": 1, "salt": base64(16 bytes)}` |
| `nonce` | base64 of 12 random bytes |
| `ciphertext` | base64 of AES-256-GCM(key, nonce, plaintext, aad) including the 16-byte tag |

`aad` is the canonical JSON of the object with `format`, `version`, `id`, `sender`, `kdf`, `nonce` (no
`ciphertext`), so changing the sender or the parameters fails decryption. Base64 is standard with padding.

QR: a package of at most 2048 bytes may be shown as one QR; larger ones go as a file by any route.

## Plaintext

Canonical JSON: `{"version": 1, "created_at": <unix s>, "expires_at": created_at + 86400, "item": {...}}`.

`item` is the item record as the vault stores it (`kind` required), in the desktop's stored shape, which is
also the synced record shape: a login (`web`, `desktop`) has `label` and `scope` (`scope.origin`, and for
`web` the `scope.urls` rows with their `match`, `starts_with` included); a typed item has `title` and
`payload`. It is never the display shape (top-level `urls` or `fields`). Every vector in `opens` is in this
shape. Packages from early builds may carry the display shape: a receiver converts them first (Python
`share.stored_form`, Kotlin `Share.storedForm`, Swift `Share.vaultForm`; vectors in `legacy`):
`title` becomes a login's `label` and `label` a typed item's `title`; a web login's `urls` become
`scope.urls` with `scope.origin` the first row's URL (`exact_origin`) or its scheme and host; `fields`
becomes `payload`.

Before sealing and again before saving, an app drops references that only mean something in its own
vault: `payload.document_ids` becomes `[]`, a card's `payload.billing_address_id` becomes `""`, and the
local trust keys leave `scope` (`sign_in_selector`, `embedded_web_fill_approved`, `browser_approval`,
`browser_approvals`, `sync_pairing`, `pairing_secret`, `pairing_state`). A phone saves only the kinds it
keeps (not `desktop`) and says the item can't be saved on this device otherwise.

The record is sent minus local-only keys: `policy`,
`password_history`, `collection_ids`, `favorite`, `usage`, `last_used_at`. Passkeys (`kind: "passkey"`)
and anything with `attachments`, `attachment_ids`, `passkeys` or `passkey` cannot be shared. A receiver
refuses an item that still holds any of these keys (`not-shareable`), and validates the item with its own
item schema before saving; credential policies are reset to the receiver's defaults (fill on click, never
auto sign in), as for an encrypted transfer.

## Opening, in order

1. Header: format, version (`unsupported` when newer), exact key set, UUID, sender length, kdf values,
   salt and nonce sizes. Otherwise `malformed`.
2. Open once: the id is in this device's opened list → `already-opened`.
3. Decrypt. A tag failure is `wrong-code` (wrong code and tampering look the same).
4. Plaintext: exact key set and version, `expires_at == created_at + 86400`, `created_at` at most 300 s
   in the future (`malformed`), `now < expires_at` (`expired`).
5. Item rules above.

Refusal codes: `bad-code`, `malformed`, `unsupported`, `already-opened`, `wrong-code`, `expired`,
`not-shareable`, `too-large` (sender side).

## App rules (not in the bytes)

The receiving app moves the delivered file into private storage and deletes the delivered copy, deletes the
package after Save or Reject, after three wrong codes, or 24 h after `created_at`, and records the id in
its opened list after a successful open, a Reject, and three wrong codes (so delivering the same package
again cannot reset the count). A QR package arrives as its text: a phone scans it, Windows takes the
pasted text or a pasted snip of the QR. The saved item counts toward the free item limit.
