# Backup key vectors (v3, step 1)

Written by `python scripts/gen_mac_backup_vectors.py backup_v3` with Windows `src/localvault/backup_key.py`.
The spec is `docs/design/backup-public-key-2026-10-31.md` sections 3.2, 3.3, 3.4 (wrap of one data key) and 3.6.
`tests/test_backup_key.py` checks every value against independent reference code; `tests/test_backup_v3_vectors.py`
regenerates the four files and compares bytes (also with `TZ` at UTC+14 and UTC-12).

TEST ONLY: every password, phrase and key in these files is published.

Encodings: byte strings are lowercase **hex** unless the field name ends in `_b64` or the field is a stored
record/header field (`salt`, `public_key`, `ephemeral_public_key`, authority fields), which are standard **base64**
with padding, canonical (no set padding bits). Passwords are JSON strings; hash their UTF-8 bytes as given (no
Unicode normalisation; `password_utf8_hex` pins them). Times are integer Unix seconds. `canon(x)` is
`json.dumps(x, ensure_ascii=False, separators=(",", ":"), sort_keys=True)` as UTF-8 (Swift `CanonicalJSON`).
"Absent" HKDF salt = 32 zero bytes.

The 2026-10-31 full backup v2 vectors (`../v2`) are unchanged by this step.

## key.json (3.2)

| field | meaning |
|---|---|
| `cases[]` | `name`, `password`, `password_utf8_hex`, `password_characters` (Python `len`, code points), `kdf` (the stored object: `name`, `time_cost`, `memory_cost_kib`, `parallelism`, `salt` b64), `seed` = Argon2id v0x13 (32 bytes), `sk_raw` = HKDF(seed, zero salt, `info`), `sk` = clamped `sk_raw`, `pk` = X25519(sk, 9), `pk_b64`, `key_id` = hex(SHA-256(`key_id_prefix` ‖ pk)[0:16]) |
| `cases` names | `ascii` (the one case at the default 3 / 262144 / 4), `composed` (é = U+00E9), `decomposed` (e + U+0301: a different key), `max_length` (4096 ASCII characters); the rest use 1 / 8192 / 1 |
| `rejected_passwords[]` | `password`, `kdf`, `error`: lengths outside 12–4096 characters |
| `rejected_kdf[]` | `kdf`, `error`: the `kdf` object must have exactly its five keys (an extra `hash_len` is refused), `name` `argon2id`, ints (not bools or strings) inside time 1–10, memory 8192–524288 KiB, parallelism 1–16, salt canonical b64 of 16 bytes |

## wrap.json (3.4, wrap of one data key)

Uses key case `key_case` (`sk`, `pk`, `password`).

| field | meaning |
|---|---|
| `esk_random` → `esk` | the 32 random bytes and their clamped value; `epk` = X25519(esk, 9) |
| `ss` | X25519(esk, pk) = X25519(sk, epk) |
| `kek_salt`, `kek` | `epk ‖ pk`; HKDF(ss, kek_salt, `info`) |
| `dk` | the data key |
| `core`, `recipient_body` | the v3 header without `recipient`, and the recipient without `wrapped_key` |
| `wrap_aad` | `aad_prefix` ‖ canon({"header": core, "recipient": recipient_body}) |
| `wrapped`, `wrapped_b64` | AES-256-GCM(kek, nonce = 12 zero bytes, dk, wrap_aad): 32 + 16 bytes |
| `wrap_to_low_order_pk[]` | `pk` (five low-order points), `error`: wrapping to them is refused (all-zero `ss`) |
| `unwrap_rejected[]` | `name`, `error`: zero / low-order `epk`, tampered or short `wrapped`, tampered AAD, other key, wrong password, other key id. One message for all: `Wrong backup password or modified full backup`. A key id mismatch fails before any GCM attempt. |

## record.json (3.3)

| field | meaning |
|---|---|
| `records.<name>.record` / `.canonical` | the stored record and its `canon` bytes as text |
| `records.<name>.inputs` | `password`, `kdf`, `now` and where the authority came from |
| names | `set` (Windows authority = `authority.json` `windows.old_snapshot`), `changed` (previous `set` → history), `reset` (previous `changed`; `reset_at = now`; Mac authority bound to this record's key id), `migrated` (no authority), `changed_history_full` (previous history of 16 → still 16, oldest dropped) |
| `previous_history` | the 16 synthetic entries used for `changed_history_full` |
| `password_proofs[]` | `record`, `password`, `matches`: re-derive with the record's kdf and compare `pk` |
| `rejected[]` | `name`, `record`, `error`: every way a record is "damaged" |

Record rules (Windows): exactly the nine keys; `v` = 1 (int); `public_key` canonical b64 of 32 bytes; `key_id`
`^[0-9a-f]{32}$` and equal to the recomputed id; `kdf` as in key.json; `set_at` int 0..2^53-1; `set_by` one of
`set`, `migrated`, `changed`, `reset`; `reset_at` an int exactly when `set_by` is `reset`, else null;
`reset_authority` null or a valid authority (below); `history` a list of at most 16 objects with exactly
`key_id` (32 hex), `set_at`, `set_by`, `replaced_at` (ints, enum as above), newest first, no public keys.
History is not checked for order. The error text is `The backup key record is damaged: <reason>`.

## authority.json (3.6)

`K(s)` = HKDF(entropy, s, `phrase_key_info`).

| field | meaning |
|---|---|
| `windows.old_phrase`, `old_entropy`, `old_snapshot` | a Windows vault with a phrase; the `recovery-wrapper-v1` snapshot of its `wrappers.recovery` (`salt`, `nonce`, `ciphertext`, `aad` = `_wrapper_aad(header, "recovery", {"kind","salt"})`, all b64) |
| `windows.new_*` | after the phrase was replaced (data-key rotation) |
| `windows.checks[]` | `snapshot`, `phrase`, `accepted`: verify = AES-256-GCM-Decrypt(K(salt), nonce, ciphertext, aad) succeeds. Old↔old and new↔new pass; the crossed pairs fail. |
| `mac.entropy`, `phrase`, `salt`, `phrase_key`, `authority` | `recovery-key-mac-v1`: `mac` = HMAC-SHA256(K(salt), `mac_prefix` ‖ key_id ASCII), bound to `record_key_id` |
| `mac.checks[]` | `phrase` (`phrase` or `other_phrase`), `key_id`, `accepted` (constant-time compare) |
| `rejected[]` | `name`, `authority`, `error`: shape errors (`The reset authority is damaged: <reason>`). Exactly the keys of its kind; salt 16, nonce 12, ciphertext 48, mac 32 bytes; `aad` 1–4096 bytes. |

### authority.json `strict_reset` (owner decision Q2, design section 16)

A reset is allowed only with the vault's **current** recovery phrase, and only if it is the phrase bound in the
record's `reset_authority`. `accepted = verify(record.reset_authority, entropy, record.key_id) and
verify(current, entropy, record.key_id)`, where `current` is an authority captured from the current state just
before the check, of the same kind (a kind mismatch, a record without an authority, or no phrase now (`null`)
→ refused). Windows `current` = the `recovery-wrapper-v1` snapshot of the current vault header; Mac `current` =
`recovery-key-mac-v1` from the current `VaultKey` (salt, key) bound to the record's key id.

| field | meaning |
|---|---|
| `entropies` | `old`/`new` (Windows phrases), `mac`/`other` (Mac phrase before and after it is replaced) |
| `records` | `set`, `reset`, `migrated` (from record.json) and `set_rebound`, `reset_rebound` |
| `currents` | `windows.old_snapshot`, `windows.new_snapshot`, `mac_before`, `mac_after`, `none` |
| `mac_replaced` | `salt`, `phrase_key` of the Mac `VaultKey` after the phrase was replaced (`mac_after`) |
| `cases[]` | `record`, `current`, `entropy`, `accepted`: a replaced phrase is refused although it matches the bound authority; the new phrase is refused until re-bound, accepted after |
| `rebound_canonical` | canon bytes of the re-bound records |
| `rebind_with_wrong_password` | re-bind needs the current backup password; `error` = `That is not the current backup password.` |

Re-bind (after the phrase is replaced): proof with the backup password (re-derive, compare the public key), then
replace `reset_authority` only; every other record field stays the same.

## full.lgkfull, relocked.lgkfull, expected.json, rejected/ (3.4, 7.2; step 2a)

Written by the same `backup_v3` section with Windows `backup.export_full_backup_to_key` and `relock_full_backup`
over the v2 fixture profile (its files are `../v2/inputs`; `expected.inputs_sha256` pins them), with every random
byte and the clock fixed. `tests/test_backup_v3.py` reads them.

**Container.** The v2 ZIP (ZIP_STORED, `_full_zip_info` metadata, members `header.json`, `manifest.bin`,
`data/00000000.bin`…, same bounds and manifest entry rules) with these differences:

* `header.json` = canon of exactly `format`, `version` = 3, `cipher` = `{"name":"aes-256-gcm","nonce_bytes":12,"tag_bytes":16}`,
  `entry_count`, `recipient`; `recipient` = exactly `scheme` (`x25519-hkdf-sha256-aes-256-gcm-v1`), `key_id`,
  `key_set_at` (the record's `set_at`), `kdf` (the record's five-key object), `ephemeral_public_key` (b64 32),
  `wrapped_key` (b64 48). The header bytes must be canonical (a non-canonical `header.json` is a modified file).
  The record's public key is never in the file.
* `core` = header without `recipient`; `core_data = canon(core)`; `wrap_aad` as in wrap.json (header = `core`,
  recipient = `recipient` without `wrapped_key`).
* `manifest.bin` = `nonce12 ‖ AES-256-GCM(dk, nonce12, canon(manifest), "localgatekeys|encrypted-full-profile-backup|v3" ‖ core_data)`;
  `manifest.version` = 3.
* member = `nonce12 ‖ AES-256-GCM(dk, nonce12, data, AAD_V3 ‖ core_data ‖ SHA-256(canon(manifest)) ‖ member name ASCII)`.

**Random stream** (`expected.random_hex`, in this order): `dk` 32, `esk_random` 32 (then clamped), manifest nonce 12,
one nonce 12 per member in member order. `expected.data_key` is `dk`; `expected.header` is the parsed header.
`created_at` (manifest) = `expected.created_at`; `key_set_at` = `expected.record.set_at`.

**Reader order** (Windows; give the same messages): ZIP member checks as v2 → strict header (`Unsupported full backup
format` for a key set or version mismatch; `Unsupported full backup encryption parameters` for the cipher or the
scheme; `Unsupported backup encryption parameters` for the kdf keys or bounds; `Malformed full backup KDF salt`;
`Full backup entry count is invalid`; `Malformed full backup recipient` for `key_id` not `^[0-9a-f]{32}$`,
`key_set_at` not an int in 0..2^53-1, or `epk`/`wrapped` not canonical b64 of 32/48 bytes) → canonical header
bytes → Argon2 (`recipient.kdf`) → key id check (no GCM attempt on a mismatch) → unwrap → manifest → members.
A wrong password, a key id mismatch, a failed unwrap, a failed manifest or member tag, and a non-canonical header
all give `Wrong backup password or modified full backup` (the v2 text). A manifest with `version` ≠ 3 gives
`Full backup manifest is malformed`.

**relocked.lgkfull** = `full.lgkfull` re-locked to `expected.relock_record` (password `expected.second_password`;
ephemeral random `expected.relock_esk_random`): `header.json` is replaced (same `core`, new recipient wrapping the
**same** `dk`), every other member is byte-identical, same names, same order. It opens only with the second password.
Re-lock touches only version 3 files under the old key id; anything else is left byte for byte, mtime included.

**rejected/** — `expected.rejected[<name>]` is the Windows message for `rejected/<name>.lgkfull` read with
`expected.backup_password`:

| name | change |
|---|---|
| `unknown_scheme` | `recipient.scheme` = `…-v2` |
| `extra_recipient_key` | `recipient.public_key` added |
| `extra_header_key` | top-level `kdf` added |
| `key_id_mismatch` | `recipient.key_id` = another valid key id |
| `tampered_recipient_kdf` | `time_cost` 1 → 2 (in bounds: fails at the key id check) |
| `kdf_out_of_range` | `time_cost` 11 |
| `wrapped_short` | `wrapped_key` 47 bytes |
| `epk_low_order` | `ephemeral_public_key` = 32 zero bytes (all-zero shared secret) |
| `tampered_core_entry_count` | `entry_count` + 1 (fails the wrap: `core` is in its AAD) |
| `version_4` | `version` 4 |
| `manifest_version_2_in_v3` | manifest re-encrypted with `version` 2 (members re-encrypted to its digest) |
| `recipient_from_other_file` | the recipient of another v3 file to the same key (a valid wrap of another `dk`) |
| `tampered_header` | canonical header + one space |
| `tampered_member` | one ciphertext bit of `data/00000000.bin` |

`full.lgkfull with a wrong password` and `relocked.lgkfull with the first password` give the v2 text too.
`from_mac_v3.lgkfull` (written by the Swift `FullBackupV3Tests`, step 5) is kept by the generator and read by
`tests/test_backup_v3.py`.
