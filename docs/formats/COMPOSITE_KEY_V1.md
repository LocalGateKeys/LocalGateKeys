# Composite key v1: key-file and YubiKey unlock factors

Status: format frozen with the vectors in `tests/vectors/composite_key/` (KeePass unlocking plan, Task 1).
Reference code: `src/localvault/composite_key.py` and `src/localvault/keyfile.py`; generator
`scripts/make_composite_vectors.py`. LGKCore (Swift) and lgk-core (Kotlin) must pass the same vectors.
Design: `docs/superpowers/specs/2026-11-03-feature-pack-design.md` §4.

A vault (Windows), the Apple `MasterKeyFile` or the Android app-password file may require a **key file**
and/or a **YubiKey** (HMAC-SHA1 challenge-response) on top of the password. Each factor gives a 32-byte
secret that is mixed into the Argon2id output before the password wrap. Factors are per device and never
sync. The recovery phrase wrapper does not use them: the phrase still opens everything without the factors.

All byte strings below are ASCII. `‖` is concatenation. Hex is lower case unless stated. Base64 is standard
with padding.

## 1. Factor secrets

### 1.1 `keyfile`: the KeePass key-file key

The secret is the key the file gives under KeePass rules, tried in this order (`keyfile.key_from_bytes`):

"Whitespace" in this section means exactly the four ASCII characters space, tab (`\t`), LF (`\n`) and
CR (`\r`): not VT, FF, NBSP or any other Unicode space.

1. **XML.** If the file with leading and trailing whitespace removed starts with `<?xml` or `<KeyFile`,
   it is parsed as XML (the trimmed bytes). A DOCTYPE or entity declaration, or malformed XML, is refused
   (no fallback to rule 4). Under the document element:
   - `Meta/Version`, whitespace-trimmed, `1.0` when absent. If it starts with `2`, the 2.0 rules apply;
     anything else gets the 1.0 rules.
   - `Key/Data` must exist; every whitespace character is removed from its text, and the rest must not be
     empty; otherwise refused. Any other character (an NBSP, say) stays and makes the hex or Base64 invalid.
   - **2.0:** the text is hex (either case, an even number of digits), decoded. If the `Data` element has
     a non-empty `Hash` attribute, it must equal, case-insensitively, the first `len(Hash)` characters of
     the hex SHA-256 of the decoded key (KeePass writes 8 upper-case digits: the first 4 bytes); otherwise
     refused.
   - **1.0:** the text is strict Base64 (standard alphabet, correct padding), decoded.
   - As an unlock factor the decoded key must be exactly 32 bytes; otherwise refused. (The KDBX importer
     uses `keyfile.key_material`, which keeps KeePass's any-length XML data.)
2. **Raw.** A file of exactly 32 bytes: the file itself.
3. **Hex.** A file of exactly 64 bytes, every byte an ASCII hex digit (`0-9a-fA-F`): the decoded 32 bytes.
   No trimming: a 64-digit file with a trailing newline is 65 bytes and falls to rule 4, as in KeePass and
   KeePassXC (`src/keys/FileKey.cpp` `loadHex`).
4. **Anything else:** SHA-256 of the whole file.

Two differences from KeePass are inherited from our importer and kept **on purpose** (ports must match):
a file that starts with `<?xml`/`<KeyFile` but is not valid XML is refused, where KeePass would fall back
to hashing it; and a file starting with a UTF-8 BOM (`EF BB BF`) misses the XML rule and is hashed (rule
4), where KeePass would read the XML. Vectors: `keyfile_rejects`, `tests/test_keyfile.py`.

A key file under rule 4 (any file) has only the entropy of its contents; anyone with a copy of the vault
can test candidate files at HMAC speed against `check` (§3). Recommend "Create key file" (32 random bytes).

"Create key file" writes a KeePass XML 2.0 file (`keyfile.new_keepass_xml_v2`), the layout KeePass and
KeePassXC write, which both open:

```
<?xml version="1.0" encoding="UTF-8"?>
<KeyFile>
    <Meta>
        <Version>2.0</Version>
    </Meta>
    <Key>
        <Data Hash="B51C3600">
            B639CAA6 546D2001 C52C9E94 01A70803
            3E25E99A 3CBB8C88 915A6417 D56FC988
        </Data>
    </Key>
</KeyFile>
```

(32 random bytes as upper-case hex in groups of 8, four groups per line; `Hash` = the first 4 bytes of
SHA-256 of the key, upper-case hex; LF line ends.) The key file itself is never copied into app storage,
logs or backups.

### 1.2 `yubikey-hmac`: HMAC-SHA1 challenge-response

- Each `yubikey-hmac` factor stores a **challenge** of 32 random bytes (§2), renewed whenever the data
  key rotates (Windows) or the password wrapper is rewritten (phones, Mac). A new challenge whose last
  byte is `0x00` or `0x20` is **drawn again** (`composite_key.new_challenge`), so the variable-mode
  stripping described below never removes challenge bytes.
- The challenge is sent **padded to 64 bytes the way KeePassXC pads it**: append `64 - 32 = 32` bytes of
  value `0x20` (PKCS#7 style). `pad_challenge(c) = c ‖ 0x20 × 32`.
  Source: KeePassXC `src/keys/drivers/YubiKeyInterfaceUSB.cpp` (`performChallenge`, lines 272-281) and
  `src/keys/drivers/YubiKeyInterfacePCSC.cpp` (lines 734-748), commit
  `5acfcc6a1fbd391cfbdf140aea063948f6297375` (develop, 2025-11-09):
  `paddedChallenge.append(QByteArray(padLen, padLen))` with `padLen = 64 - challenge.size()`.
- **Always pass the full 64-byte `pad_challenge` output to the YubiKey library; never let a library pad.**
  yubikit-android's `calculateHmacSha1` may pad a short challenge itself, and YubiKit iOS sends bytes as
  given, so handing either the bare 32 bytes would give a different response on different platforms. Each
  port has a test hook (a fake transport) asserting that the bytes on the wire equal
  `padded_challenge_hex` from the vectors.
- The command goes to slot 2 by default, or slot 1 (`slot`). USB HID: `SLOT_CHAL_HMAC1` (0x30) /
  `SLOT_CHAL_HMAC2` (0x38); NFC/CCID: select the OTP applet (AID `A0000005272001`), then the APDU
  `00 01 <P1> 00 40 ‖ padded challenge` with P1 = `0x30` (slot 1) or `0x38` (slot 2) (KeePassXC
  `YubiKeyInterfacePCSC.cpp` `getHMAC`, constants in `YubiKeyInterfacePCSC.h`; YubiKit sends the same). The
  response is 20 bytes.
- What the key computes is up to the key: a slot in **variable-input mode** (the `ykman` and Yubico
  Authenticator default) treats the last byte and every equal byte before it as padding, so it computes
  `HMAC-SHA1(slot secret, padded minus its trailing run of the last byte)`. With our padding that is the
  32-byte challenge, unless the challenge itself ends in `0x20` bytes, which are dropped too (vector
  `pad_challenge[1]`). A slot in fixed 64-byte mode HMACs all 64 bytes. Either way the key answers the same
  every time, so both work; the apps never compute the HMAC themselves. Test doubles model variable mode.
  `pad_challenge[1]` documents the edge case only; `new_challenge` never produces such a challenge.
- Secret: `yubikey_secret(response) = SHA-256(response)` (32 bytes). A response that is not 20 bytes is an
  error.
- Two YubiKeys may serve one factor only if they give the same response (programmed with the same slot
  secret); the app checks this at enrolment through `check`. We never program YubiKeys.

## 2. The factor list (public)

Each factor is described by a JSON object (`FactorSpec`). Nothing in it is secret.

| field | kinds | value |
|---|---|---|
| `kind` | all | `"keyfile"` or `"yubikey-hmac"` |
| `check` | all | 16 lower-case hex digits (§3) |
| `slot` | `yubikey-hmac` only | integer `1` or `2` (not a boolean) |
| `challenge` | `yubikey-hmac` only | 64 lower-case hex digits: the 32-byte challenge, unpadded |

A `keyfile` object has exactly `kind` and `check`; a `yubikey-hmac` object has exactly all four. Any
other field, a missing field or another value is refused.

The **factor list** holds one or two objects: at most one `keyfile` and at most one `yubikey-hmac`, and a
`keyfile` always comes first. The same order is used for the secrets in §4. An empty list is never stored:
no factors means the format without factors (§5-§7).

**Canonical JSON** of the list (`info`): a JSON array of the objects in list order, each object's keys in
byte order (`challenge`, `check`, `kind`, `slot`), no whitespace, integers in decimal, strings with no
escapes (every value is ASCII letters, digits or `-`). Example (vector `keyfile_and_yubikey`):

```
[{"check":"10ed9c05250cf31b","kind":"keyfile"},{"challenge":"c05359d74919120739f641308863507d259ab55bd6401b04098c50989be6b5fb","check":"d4cceb1d258554e0","kind":"yubikey-hmac","slot":2}]
```

Implementations build this string from the validated fields; they do not trust a JSON encoder's
defaults (Swift's `JSONEncoder` escapes `/`, for example; there is none here, but do not rely on it).

## 3. `check`

`check = hex(HMAC-SHA256(key = secret, message = "localgatekeys|factor-check|v1")[0:8])`

Before any Argon2 work, the app computes `check` for each supplied secret and compares it (constant time)
with the stored one, in list order. The first difference raises `FactorMismatch(kind)` ("This isn't the key
file used for this vault" / the YubiKey equivalent). It is not counted by the unlock throttle, because no
password was tried. The check is a 64-bit fingerprint of the secret: harmless for a random 256-bit secret ("Create key file", or a
YubiKey slot programmed with a random secret, the `ykman` default), but a weak secret can be guessed
offline at HMAC speed: a rule-4 key file (§1.1) has only its file's entropy, and a YubiKey slot secret
typed in by hand only what was typed. The UI recommends a created key file and a random slot secret.

## 4. The wrapping key

```
argon_out = Argon2id(password, salt, the format's own parameters, 32 bytes)   # unchanged per format
no factors:   wrapping_key = argon_out
with factors: wrapping_key = HKDF-SHA256(ikm  = argon_out ‖ secret_1 [‖ secret_2],
                                         salt = "localgatekeys|composite|v1",
                                         info = canonical JSON of the factor list (§2),
                                         L    = 32)
```

HKDF is RFC 5869 (extract with the salt, expand with the info). Each secret is 32 bytes. The wrapping key
replaces `argon_out` as the AES-256-GCM key of the password wrapper; nothing else changes. The info binds
the factor list, so editing a stored `check`, `slot` or `challenge` changes the key and the unwrap fails.

The order on unlock is: read the factor list → missing secret ⇒ "factor required" (offer the recovery
phrase) → `check` (§3) → Argon2id → HKDF → AES-GCM open. Python: `composite_key.derive_wrapping_key`.

## 5. Windows vault v4

A vault with factors is written as **v4**; a vault without factors stays **v3 byte for byte**. Removing the
last factor writes v3 again. Differences from v3 (`src/localvault/vault.py`):

- `"version": 4` and `"format": "localgatekeys-vault-v4"`.
- `wrappers.password` gains `"factors": [...]`, the factor list (§2) as JSON objects:
  `{"nonce": b64(12), "ciphertext": b64(48), "factors": [...]}`.
- Password wrapper key: §4 with `argon_out` = the v3 KEK (`Argon2id(master password, header.kdf)`).
- Password wrapper AAD: `"localgatekeys|vault-key-wrapper|v3|"` ‖ canonical JSON (vault `_canonical_json`:
  sorted keys, no whitespace, ASCII escapes) of the **v3 identity** plus `"wrapper": "password"` and
  `"metadata": {"kdf": header.kdf, "factors": [...]}`.
- **Every AAD uses the v3 identity, literally**: `{"version": 3, "format": "localgatekeys-vault-v3",
  "catalog", "catalog_version", "vault_id", "key_generation"}` with the header's other values. So the
  catalog AAD, the recovery wrapper AAD and the unlock context that Hello, FIDO2 and camera sidecars bind
  to (`unlock_context_for_header`) are the same as for the same header written as v3. Adding or removing a
  factor therefore rewrites only the password wrapper: the recovery wrapper and the device-bound shortcuts
  keep working, and the recovery phrase is not needed. The factors are still authenticated: they are in
  the password wrapper's AAD and HKDF info, and a v3 reader refuses a list-valued wrapper field.
- The recovery wrapper, the catalog cipher and every other field are as in v3.

Reader rules (Task 2, `_validate_v4_header`): everything `_validate_v3_header` checks, except the format
identifier is `localgatekeys-vault-v4` and `wrappers.password` may also hold `factors` (a list of 1-2
objects valid under §2, in §2 order; at most 3 fields in that wrapper). A v4 header without factors is
refused. A version above 4 gives "This vault needs a newer LocalGateKeys". Older builds refuse v4 with
their unsupported-version error and never rewrite the file. A `.lgkfull` whose inner vault is v4 asks for
the factors on restore (or the recovery phrase).

Changing the master password keeps the factors and renews each YubiKey `challenge` (the data key rotates);
the old password plus the old response no longer opens the vault.

**Adding a factor does not rotate the data key.** Adding a factor protects new copies; copies of
`vault.json` or `.lgkfull` made before it still open with the password alone. If you think the password
leaked, also change the master password, which rotates the data key. (Task 5's add-factor screen shows the
same hint.)

**"Always ask for the key file / YubiKey" deletes the Hello, FIDO2 and camera sidecars** (not just hides
them): their unlock context does not change when a factor is added (the v3 identity above), so a kept
sidecar would still open the vault without the factors.

**Future versions:** `version` and `format` are outside every AAD (the identity in the AADs is the
constant v3 one), so they are not authenticated. The factors are safe because they are in the password
wrapper's AAD and HKDF info. A future v5 must not rely on `version`/`format` for security: bind anything
new in a wrapper's AAD metadata, as v4 does with `factors`.

**Tampered vectors** (`tampered` rows of the case, expected `unwrap-fails`): `factors_removed` (list
dropped; key = plain Argon2id output, the v3 password AAD `{"kdf"}`; also as the file
`windows_v4_tampered_no_factors.json`, a v3 vault that must fail with "wrong password" and stay
unchanged), `slot_changed` (2 → 1) and `challenge_changed` (another challenge), each with the info and
AAD an attacker would recompute and the real secrets. Every port asserts that each row's key and AAD fail
to open the stored password wrapper.

Vector: `windows_v4_vault.json` (8 MiB, t = 1, p = 1; key file `keyfiles/xml_v2.keyx` + YubiKey slot 2),
details in the `windows_v4_header` case, including the recovery phrase that opens it without factors.

## 6. Apple `MasterKeyFile` v2 (LGKCore, Mac and iPhone)

v1 (`ios/LGKCore/Sources/LGKCore/Crypto/MasterKeyFile.swift`) is unchanged and still written when there are
no factors. v2 is the same JSON with `"version": 2` and a `factors` list:

```json
{"version": 2, "kdf": {"time_cost": 3, "memory_kib": 65536, "parallelism": 4},
 "salt": "<b64 16>", "nonce": "<b64 12>", "sealed_key": "<b64 48>",
 "factors": [ ...§2 objects... ], "recovery": { ...unchanged, optional... }}
```

- Key: §4 with `argon_out = Argon2id(UTF-8 password, salt, kdf)` (no Unicode normalisation, as v1).
- AAD: `"localgatekeys|mac-master|v2|t=<t>|m=<m>|p=<p>|salt=<salt as stored>|factors="` ‖ canonical JSON of
  the factor list (§2). (v1: `localgatekeys|mac-master|v1|t=..|m=..|p=..|salt=..`.)
- `factors` must be present with 1-2 entries in v2 and absent in v1. Key order in the file does not
  matter (the vector is written with sorted keys).
- The `recovery` wrapper (`RecoveryWrapper.swift`) is untouched; its AAD does not involve the version.
- `samePasswordWrapper(as:)` also compares `factors`.
- The KDF parameter limits are those of v1 (t 1-10, p 1-16, 8-512 MiB).
- `tampered` rows as in §5: `factors_removed` (key = plain Argon2id output, the v1 AAD), `slot_changed`
  (1 → 2), `challenge_changed`; each must fail to open `sealed_key`.

Vector: `apple_masterkeyfile_v2.json` (8 MiB, t = 1, p = 1; one YubiKey in slot 1), case
`apple_masterkeyfile_v2`.

## 7. Android `AppPasswordWrap` v2 (`app-password.bin`)

v1 (`android/lgk-core/.../crypto/AppPasswordWrap.kt`), 165 bytes, is unchanged and still written when
there are no factors:

| offset | size | v1 field |
|---|---|---|
| 0 | 6 | `"LGKAPW"` |
| 6 | 1 | version `0x01` |
| 7 | 4 | Argon2id memory KiB, big-endian |
| 11 | 1 | iterations |
| 12 | 1 | parallelism |
| 13 | 16 + 12 + 48 | password wrapper: salt, nonce, sealed local key |
| 89 | 16 + 12 + 48 | recovery wrapper: salt, nonce, sealed local key |

v2, `167 + L` bytes:

| offset | size | v2 field |
|---|---|---|
| 0 | 6 | `"LGKAPW"` |
| 6 | 1 | version `0x02` |
| 7 | 4 | Argon2id memory KiB, big-endian |
| 11 | 1 | iterations |
| 12 | 1 | parallelism |
| 13 | 2 | `L`, big-endian: length of the factor list, 1-1024 |
| 15 | L | the factor list, canonical JSON (§2), UTF-8 (ASCII) |
| 15 + L | 76 | password wrapper: salt 16, nonce 12, sealed 48 |
| 91 + L | 76 | recovery wrapper: salt 16, nonce 12, sealed 48 |

- The **v2 header** is the first `15 + L` bytes (offsets `0` to `14 + L`). Password wrapper AAD = v2 header ‖ `"|password"`; its key is §4
  with `argon_out = Argon2id(NFC UTF-8 password, salt, params)`.
- The recovery wrapper keeps its **v1** AAD: `"LGKAPW" ‖ 0x01 ‖ memory ‖ iterations ‖ parallelism ‖
  "|recovery"` (13 + 9 bytes). Its bytes carry over unchanged between v1 and v2, so adding or removing a
  factor never needs the phrase.
- The Argon2id parameter limits are those of v1 (`AppPasswordParams`).
- `tampered` rows as in §5: `factors_removed` (key = plain Argon2id output, AAD = the v1 header ‖
  `"|password"`), `slot_changed` (2 → 1), `challenge_changed`; each must fail to open the password wrapper.
- A reader parses the list, validates it (§2), and refuses the file unless re-encoding it canonically gives
  exactly the stored `L` bytes; the file size must be exactly `167 + L`. Any other version byte is
  `MALFORMED`.

Vector: `android_apppassword_v2.bin` (8 MiB, t = 1, p = 1; key file `keyfiles/xml_v1.key` + YubiKey slot 2), case
`android_apppassword_v2`, with the recovery phrase.

## 8. Vectors (`tests/vectors/composite_key/`)

`cases.json`:

- `argon`: the password, salt and parameters (8 MiB, t = 1, p = 1) of the shared `argon_out`.
- `yubikey`: HMAC secret `vector-hmac-secret`, slot 2, challenge, padded challenge, the message a
  variable-mode slot HMACs, the HMAC-SHA1 response, the factor secret and its `check`.
- `pad_challenge`: challenge → padded → variable-mode message (the second one ends in `0x20`).
- `keyfiles`: each file under `keyfiles/`, the rule it hits and its key and `check`.
  `keyfile_rejects`: files a factor must refuse (bad `Hash`, 16-byte XML data, DOCTYPE, no `Key/Data`).
- `cases`, generic (`no_factors`, `keyfile_xml_v2`, `keyfile_xml_v1`, `keyfile_raw32`, `keyfile_hex64`,
  `keyfile_arbitrary`, `yubikey_only`, `keyfile_and_yubikey`): factor list, secrets, `info`, `combine_hex`
  (the wrapping key from the shared `argon_out`) and `wrap`: AES-256-GCM of `data_key_hex` under that key
  with the given nonce and an empty AAD (a test-only wrap that checks the key).
- `cases`, formats (`windows_v4_header`, `apple_masterkeyfile_v2`, `android_apppassword_v2`): the file,
  its factor list, which secrets it takes (`secret_sources`), the Argon2id output, the wrapping key, the
  AADs, the expected plaintext and the `tampered` rows (§5-§7) that must fail.

The generator rebuilds every file byte for byte (`tests/test_composite_key.py`). Never edit a committed
vector; add a new case instead.
