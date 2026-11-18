# Removal notice vectors (step 1 of removal-parity-plan.md)

Files:

- `tests/vectors/sync/removal/notices.json`, `writer.json`, `watch.json` (new)
- `scripts/gen_removal_vectors.py` (new): `python scripts/gen_removal_vectors.py [OUT_DIR]`
- `tests/test_removal_vectors.py` (new): byte-compares regeneration; runs every case through Python
- `tests/vectors/sync/README.md` + its template in `scripts/make_sync_vectors.py`: row + "Removal notices" section
- `tests/test_sync_vectors.py`: `removal/` excluded from the make_sync_vectors file listing (own generator, like `mac/`)
- `src/localvault/sync/removal.py`: two small fixes (below)

Tests: `pytest tests/test_removal_vectors.py tests/test_sync_removal.py tests/test_sync_folder_transport.py
tests/test_device_removal.py` -> 257 passed; `tests/test_sync_vectors.py` passes; ruff clean.

## Conventions

- Vector files: `json.dumps(indent=2, sort_keys=True, ensure_ascii=True) + "\n"`, LF.
- Every byte string: standard padded base64 in a `*_b64` field. `*_text` / `notice_text` = same bytes
  decoded as UTF-8 for reading (null when not UTF-8). The base64 is authoritative.
- Canonical JSON (notice, watch file): `localvault.updates.canonical_json` = sorted keys, `,` `:`
  separators, no whitespace, `ensure_ascii=False` (non-ASCII written as raw UTF-8), no trailing newline.
- Group `5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64`, T0 = 1790000000, `issued_at` = T0 + 600 unless stated.
  No clock anywhere; Ed25519 (RFC 8032, pure) is deterministic.
- Removed device = C (`c3333333-0000-4000-8000-00000000000c`), trusted epoch 1; signer A
  (`a1111111-...0a`); B (`b2222222-...0b`) is the other member; D (`d4444444-0000-4000-8000-00000000000d`)
  a stranger, seed = SHA-256(`localgatekeys|test|removal-vectors|stranger`).

## Notice format (what the verifier implements)

Path `LocalGateKeys Sync/removed/<device_id>.lgkremoved`. Object with exactly the keys
`format, group_id, device_id, epoch, signer, issued_at, sig`. `sig` = base64(Ed25519(seed of signer,
`"localgatekeys|sync|removal-notice|v1|"` + canonical_json(object without `sig`))).

`verify_notice(raw, watch, folder_keyring)` order and reason codes:
1. `bad-notice`: `len(raw) > 4096`; not UTF-8 (BOM rejected); not strict JSON (no duplicate keys, no
   NaN/Infinity, nothing after the value but whitespace); not an object with exactly the 7 keys;
   `format` not the integer 1 (`true`, `1.0` rejected); `group_id`/`device_id`/`signer` not ids
   (`[A-Za-z0-9._:-]{1,128}`); `epoch`/`issued_at` not integers in 0..2^53-1 (floats such as `2.0`/`2e0`,
   bools, strings, null rejected); `sig` not a string, not strict standard base64 (no whitespace, URL-safe
   alphabet or missing padding), not exactly 64 bytes, or not re-encoding to the same text (nonzero
   padding bits rejected). Layout is NOT required to be canonical: whitespace, key order and `\uXXXX`
   escapes are accepted; the signed message is rebuilt from the parsed values.
2. `not-for-this-device`: group_id or device_id differ from the watch.
3. `stale`: signer == watch device_id, or epoch <= watch epoch.
4. `unknown-signer`: signer not a key of `watch.signers`.
5. `bad-key`: that signer's key is not strict base64 of exactly 32 bytes (same re-encode rule).
6. `bad-signature`: Ed25519 verify fails (incl. S >= L, zero signature, signature without the label).
7. `keyring`: folder keyring bytes over 256 KiB, not UTF-8/strict JSON (duplicate keys, NaN rejected;
   finite floats parse), not an object; `group_id` not an id; `epoch` not an int 0..2^53-1; `members`
   not a list; then group_id != watch group, keyring epoch < notice epoch, or watch device_id is among
   `members[*].device_id` (entries that are not objects with a string `device_id` are ignored).
   The folder keyring is NOT authenticated (no MAC/proof check) - do not add one, or the synthetic
   vectors (and the Python result) will differ.
Accept -> the notice fields.

## notices.json

```
WARNING, about: string
constants: {notice_format:1, notice_label:"localgatekeys|sync|removal-notice|v1|", max_notice_bytes:4096,
            max_keyring_bytes:262144, max_int:9007199254740991, removed_dir:"removed",
            notice_suffix:".lgkremoved", group_id, t0}
identities: {A|B|C|D: {device_id, signing_private_seed_b64 (32-byte Ed25519 seed), signing_public_b64}}
keyrings:   {name: {b64: keyring file bytes, source: string, synthetic: bool}}
            real: trusted_epoch1 (= keyring_epoch1.json), trusted_epoch1_format1 (= keyring_v1_epoch1.json),
                  folder_epoch2 (= keyring_epoch2.json)
            synthetic (edited canonical copies, MAC invalid): synthetic_epoch3_without_c, synthetic_epoch2_lists_c,
                  synthetic_other_group, synthetic_members_not_list, synthetic_epoch_float, synthetic_epoch_string,
                  synthetic_group_invalid_id, synthetic_member_bad_ids, synthetic_duplicate_key,
                  synthetic_not_json, synthetic_array, synthetic_empty
watches:    {name: watch object, same keys as the watch file: version, group_id, device_id, epoch,
             install_id, folder, signers {device_id: signing_public_b64}}
            trusted_c (signers A,B), trusted_c_format1 (signers {}), trusted_c_b_unconfirmed (signers A),
            bad_key_not_base64, bad_key_31_bytes, bad_key_noncanonical_base64 (A's key replaced)
cases: [{name, description, notice_b64, notice_text|null, watch: <watches name>,
         folder_keyring: <keyrings name>,
         expected: {accept: bool, reason: null|"bad-notice"|"not-for-this-device"|"stale"|"unknown-signer"|
                    "bad-key"|"bad-signature"|"keyring",
                    notice: {group_id, device_id, epoch, signer, issued_at} | null}}]
```
80 cases: 10 accepted (incl. non-canonical layout, trailing LF, escaped id, exactly 4096 bytes,
issued_at 0 and 2^53-1, later folder epoch, ignored bad members), and every rejection above.
Test: `verify(base64(notice_b64), watches[watch], base64(keyrings[folder_keyring].b64))` == expected.

## writer.json

```
cases: [{description, signer: "A"|"B",
         inputs: {group_id, device_id, epoch, signer, issued_at, signing_private_seed_b64},
         path: "LocalGateKeys Sync/removed/<device_id>.lgkremoved",
         body_canonical: canonical JSON of the 6 body fields (ASCII text),
         signed_message_hex: hex(label + body_canonical),
         sig_b64, notice_text: exact file content (ASCII, no newline), notice_sha256: hex}]
refusals: [{description, inputs: {group_id, device_id, epoch, signer, issued_at}, error: "bad-notice"}]
```
Writer must refuse: signer == device_id, any id invalid, epoch or issued_at outside 0..2^53-1.
Case 0 equals notices.json case `valid`. Rotation rule (folder_transport.rotate_folder_group): one
notice per member in `remove` that is in the keyring and is not this device, epoch = new epoch,
written after the keyring; members dropped only for being unconfirmed get NO notice.

## watch.json

```
constants: {watch_version:1, watch_suffix:".sync-watch.json", max_watch_bytes:16384}
paths:   [{vault, watch}]  watch file name = vault stem + ".sync-watch.json" (vault.json -> vault.sync-watch.json)
example: {watch_text: canonical JSON the writer must produce, parsed: object}
derive:  [{name, state: {group_id, device_id, epoch, install_id, keyring: <notices.json keyrings name>,
           unacked_members: [ids]}, folder, watch_text}]
         signers = members of the trusted keyring that list signing_public, minus this device, minus
         unacked_members, minus invalid ids.
parse:   [{name, description, b64, text|null, expected: watch object | null}]  null = file ignored.
         Rules: <= 16384 bytes; strict JSON (UTF-8, no BOM, no duplicates, no NaN); exactly the 7 keys;
         version integer 1 (true/1.0 rejected); group_id, device_id ids; epoch int 0..2^53-1;
         install_id, folder non-empty strings; signers an object, keys ids, values strings
         (values are NOT checked as base64 here; verify gives bad-key later).
pinned:  [{name, old: watch|null, fresh: watch, expected: watch}]  pinned(fresh, old): if old is null or
         (group_id, device_id) differ -> fresh; else fresh with each signer's key replaced by old's
         key for that signer when old has it (members only in old are dropped).
```

## Fixes made in removal.py (small, behaviour-preserving except for the bugs)

1. `_ring_members`: a folder keyring member whose `device_id` is unhashable (e.g. `[]`) raised
   `TypeError`, which escaped `verify_notice` and `check()` ("never raises"). Such entries are now ignored,
   like non-object entries already were (vector `valid-folder-keyring-ignores-bad-members`).
2. `load_watch`: `"version": true` and `1.0` were accepted (`True == 1` in Python). Now must be int 1.

## Observations, not changed

- `stale` is also the code for signer == removed device (a self-signed notice); fine but odd naming.
- The folder keyring is only corroboration and unauthenticated; the residual risk (a device removed
  earlier, still trusted by a lagging device, forging notice + next-epoch keyring) is the one
  wp-a-design.md already lists.
- Non-canonical notice layouts are accepted (signature over re-canonicalised body). Swift/Kotlin must
  parse then re-canonicalise; they must not verify the raw bytes.
- Ed25519 edge cases outside the vectors: OpenSSL (Python) accepted an all-zero (small-order) public key
  with a zero signature in a quick probe. Signer keys come from proof-checked keyrings, so not a practical
  issue, but CryptoKit/BouncyCastle may differ there; no vector pins it.
