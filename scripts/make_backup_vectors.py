"""Generate the deterministic ``LGKMBAK1`` phone backup test vectors in ``tests/vectors/backup``.

Everything here is test-only.  The salt and nonce come from fixed labels and the production
format and Argon2id parameters (128 MiB x 4 passes x 4 lanes) run unmodified through
``localvault.phone_backup``; the item content is reused from the sync vectors
(``tests/vectors/sync``) so the phones already decode it.

Usage::

    python scripts/make_backup_vectors.py [OUT_DIR]      # default: tests/vectors/backup

``tests/test_backup_vectors.py`` regenerates into a temporary directory and compares every
file byte for byte with the committed copies.
"""

# ruff: noqa: S101, S105  (generator self-checks use assert; the passwords are published test vectors)

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import phone_backup
from localvault.phone_backup import KDF, PhoneBackupError, read_phone_backup, write_phone_backup
from localvault.sync.engine import ItemState
from localvault.updates import canonical_json

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "tests" / "vectors" / "backup"
SYNC = ROOT / "tests" / "vectors" / "sync"

PASSWORD = "correct horse battery staple 42"
WRONG_PASSWORD = "wrong"
CREATED_AT = 1790000000
PLATFORM = "android"
APP_VERSION = "1.0.0"
PRO_HINT = False
LICENSE_VV_COUNTER = 1  # the licence state gets the version vector {device A: 1}

SALT = hashlib.sha256(b"lgk-backup-salt").digest()[:16]
NONCE = hashlib.sha256(b"lgk-backup-nonce").digest()[:12]

#: file name -> (password, reason) for every rejected vector.
REJECTED: dict[str, tuple[str, str]] = {
    "duplicate_ids.lgkm": (PASSWORD, "bad-payload"),
    "edited_header.lgkm": (PASSWORD, "wrong-password-or-damaged"),
    "extra_header_key.lgkm": (PASSWORD, "not-a-backup"),
    "flipped_ciphertext.lgkm": (PASSWORD, "wrong-password-or-damaged"),
    "kdf_time_11.lgkm": (PASSWORD, "bad-kdf"),
    "noncanonical_ciphertext.lgkm": (PASSWORD, "not-a-backup"),
    "noncanonical_salt.lgkm": (PASSWORD, "not-a-backup"),
    "non_ascii_app_version.lgkm": (PASSWORD, "bad-payload"),
    "truncated.lgkm": (PASSWORD, "not-a-backup"),
    "version_3.lgkm": (PASSWORD, "unsupported-version"),
    "wrong_password.lgkm": (WRONG_PASSWORD, "wrong-password-or-damaged"),
    "zero_vv_counter.lgkm": (PASSWORD, "bad-payload"),
}

#: Format 2 (document files): file name under ``format2/rejected/`` -> reason (all opened with PASSWORD).
REJECTED_V2 = {
    "empty_files.lgkm": "bad-payload",
    "file_hash_mismatch.lgkm": "bad-payload",
    "files_in_version_1.lgkm": "bad-payload",
    "payload_version_1.lgkm": "bad-payload",
    "unreferenced_file.lgkm": "bad-payload",
    "unsorted_files.lgkm": "bad-payload",
}
ATTACHMENTS = SYNC / "attachments" / "vectors.json"
#: The document of the format-2 vector: it carries the ``small`` blob of the attachment sync vectors.
DOCUMENT_ID = "88888888-aaaa-4000-8000-000000000008"
DOCUMENT_BLOB = "small"
EXTRA_BLOB = "unicode-name"  # same size as ``small``; used by the rejected files only

GENERATED_FILES = tuple(sorted(
    ["README.md", "backup.lgkm", "expected.json"] + [f"rejected/{name}" for name in REJECTED]
    + ["format2/backup.lgkm", "format2/expected.json"] + [f"format2/rejected/{name}" for name in REJECTED_V2]
))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def dumps(value: Any) -> bytes:
    """Readable, stable JSON for the descriptive files (keys sorted, 2 spaces, LF, final newline)."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def device_a_id() -> str:
    return json.loads((SYNC / "identities.json").read_text(encoding="utf-8"))["devices"]["A"]["device_id"]


def input_states() -> list[ItemState]:
    """Every stored state of ``expected_merge.json`` plus the licence state of ``license_state.json``.

    ``bridge_stored_states`` is what a device's own local view publishes (conflict copies under their
    own record id with the suffixed label); the engine form of a copy is never published.
    """
    merged = json.loads((SYNC / "expected_merge.json").read_text(encoding="utf-8"))
    states = [ItemState(s["id"], s["vv"], s["deleted"], s["deleted_at"], s["item"])
              for s in merged["bridge_stored_states"]]
    lic = json.loads((SYNC / "license_state.json").read_text(encoding="utf-8"))
    states.append(ItemState(lic["state_id"], {device_a_id(): LICENSE_VV_COUNTER}, False, None, lic["wrapper"]))
    return sorted(states, key=lambda s: s.item_id)


def attachment_blob(name: str) -> tuple[dict, bytes]:
    """(reference, sealed blob) of one entry of the attachment sync vectors."""
    entry = next(b for b in json.loads(ATTACHMENTS.read_text(encoding="utf-8"))["blobs"] if b["name"] == name)
    return entry["ref"], base64.b64decode(entry["blob"])


def document_state() -> ItemState:
    """A live document (stored form: wrapper with its ``attachment`` reference), version vector {A: 1}."""
    ref, _blob = attachment_blob(DOCUMENT_BLOB)
    record = {"created_at": 1789956800, "favorite": False, "id": DOCUMENT_ID, "kind": "document",
              "payload": {"attachment_id": ref["id"], "description": "Scan of the passport"},
              "tags": [], "title": "Passport", "updated_at": 1789956800}
    return ItemState(DOCUMENT_ID, {device_a_id(): 1}, False, None,
                     {"attachment": ref, "ns": "item", "record": record, "schema": 1, "updated_at": 1789956800})


def state_dict(s: ItemState) -> dict:
    return {"deleted": s.deleted, "deleted_at": s.deleted_at, "id": s.item_id, "item": s.item, "vv": dict(s.vv)}


def envelope(header: dict, ct: bytes) -> bytes:
    return canonical_json({"ciphertext": b64(ct), "header": header})


def seal(key: bytes, header: dict, payload: dict) -> bytes:
    return envelope(header, AESGCM(key).encrypt(NONCE, canonical_json(payload), canonical_json(header)))


_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def noncanonical(text: str) -> str:
    """Same bytes, different text: set an unused low bit of the last base64 character."""
    stripped = text.rstrip("=")
    pad = len(text) - len(stripped)
    assert pad in (1, 2), "no spare bits to make this base64 non-canonical"
    bump = 1
    value = _B64.index(stripped[-1])
    spare_mask = 0b1111 if pad == 2 else 0b11  # pad 2: 4 spare bits, pad 1: 2
    assert value & spare_mask == 0
    out = stripped[:-1] + _B64[value | bump] + "=" * pad
    assert base64.b64decode(out, validate=True) == base64.b64decode(text, validate=True) and out != text
    return out


def build() -> dict[str, bytes]:
    """All vector files (relative name -> bytes).  Two production Argon2id derivations in total
    (the vector password and ``wrong``); repeated derivations of the same inputs are memoised."""
    real_derive = phone_backup._derive
    cache: dict[tuple, bytes] = {}

    def derive(password: str, salt: bytes, kdf: Any) -> bytes:
        k = (password, salt, tuple(sorted(kdf.items())))
        if k not in cache:
            cache[k] = real_derive(password, salt, kdf)
        return cache[k]

    phone_backup._derive = derive
    try:
        return _build(derive)
    finally:
        phone_backup._derive = real_derive


def _build(derive) -> dict[str, bytes]:
    device_id = device_a_id()
    states = input_states()

    def write() -> bytes:
        return write_phone_backup(
            states, password=PASSWORD, device_id=device_id, platform=PLATFORM, app_version=APP_VERSION,
            created_at=CREATED_AT, pro_hint=PRO_HINT, _salt=SALT, _nonce=NONCE)

    backup = write()
    assert write() == backup

    key = derive(PASSWORD, SALT, KDF)
    env = json.loads(backup)
    header, ct = env["header"], base64.b64decode(env["ciphertext"])
    aad = canonical_json(header)
    plain = AESGCM(key).decrypt(NONCE, ct, aad)
    payload = json.loads(plain)
    assert plain == canonical_json(payload)
    assert header["salt"] == b64(SALT) and header["nonce"] == b64(NONCE)

    opened = read_phone_backup(backup, PASSWORD)
    assert [state_dict(s) for s in opened.states] == payload["states"] == [state_dict(s) for s in states]
    assert not any(n == 0 for s in payload["states"] for n in s["vv"].values())

    # --- rejected files --------------------------------------------------------------------
    flipped = bytearray(ct)
    flipped[0] ^= 0x01
    edited = {**header, "created_at": header["created_at"] + 1}
    duplicated = {**payload, "states": [payload["states"][0], *payload["states"]]}
    # The ciphertext base64 needs padding (spare bits) to be spelled non-canonically: when the
    # backup's own has none, re-seal with the shortest app_version suffix that gives it some.
    padded_env = env
    for suffix in ("", "b", "-b"):
        sealed = seal(key, header, {**payload, "app_version": APP_VERSION + suffix}) if suffix else backup
        if json.loads(sealed)["ciphertext"].endswith("="):
            padded_env = json.loads(sealed)
            break
    padded_app_version = json.loads(AESGCM(key).decrypt(
        NONCE, base64.b64decode(padded_env["ciphertext"]), aad))["app_version"]
    rejected: dict[str, bytes] = {
        "wrong_password.lgkm": backup,
        "flipped_ciphertext.lgkm": envelope(header, bytes(flipped)),
        "edited_header.lgkm": envelope(edited, ct),
        "version_3.lgkm": envelope({**header, "version": 3}, ct),
        "kdf_time_11.lgkm": envelope({**header, "kdf": {**header["kdf"], "time_cost": 11}}, ct),
        "extra_header_key.lgkm": envelope({**header, "extra": 1}, ct),
        "duplicate_ids.lgkm": seal(key, header, duplicated),
        "truncated.lgkm": backup[:100],
        "noncanonical_salt.lgkm": envelope({**header, "salt": noncanonical(header["salt"])}, ct),
        "noncanonical_ciphertext.lgkm": canonical_json(
            {"ciphertext": noncanonical(padded_env["ciphertext"]), "header": header}),
        "non_ascii_app_version.lgkm": seal(key, header, {**payload, "app_version": "1.0.é"}),
        "zero_vv_counter.lgkm": seal(key, header, {**payload, "states": [
            {**payload["states"][0], "vv": {**payload["states"][0]["vv"], device_id: 0}},
            *payload["states"][1:]]}),
    }
    assert set(rejected) == set(REJECTED)
    for name, data in rejected.items():
        password, reason = REJECTED[name]
        try:
            read_phone_backup(data, password)
        except PhoneBackupError as exc:
            assert exc.reason == reason, (name, exc.reason)
        else:
            raise AssertionError(f"{name} was accepted")

    expected = {
        "password": PASSWORD,
        "salt_b64": header["salt"],
        "nonce_b64": header["nonce"],
        "key_hex": key.hex(),
        "header": header,
        "aad_hex": aad.hex(),
        "payload_canonical": plain.decode("utf-8"),
        "payload_sha256": hashlib.sha256(plain).hexdigest(),
        "ciphertext_size": len(ct),
        "file_size": len(backup),
        "file_sha256": hashlib.sha256(backup).hexdigest(),
        "device_id": device_id,
        "platform": PLATFORM,
        "app_version": APP_VERSION,
        "pro_hint": PRO_HINT,
        "created_at": CREATED_AT,
        "states": payload["states"],
        "rejected": {name: {"password": pw, "reason": reason} for name, (pw, reason) in sorted(REJECTED.items())},
    }
    files = {"README.md": readme(device_id, len(states), padded_app_version).encode("utf-8"),
             "backup.lgkm": backup, "expected.json": dumps(expected)}
    files.update({f"rejected/{name}": data for name, data in rejected.items()})
    files.update(_build_v2(key, states, device_id))
    return files


def _build_v2(key: bytes, base_states: list[ItemState], device_id: str) -> dict[str, bytes]:
    """``format2/``: the same inputs plus one document and its file (header and payload version 2)."""
    from localvault.sync.vault_bridge import _documents, check_remote_state

    ref, blob = attachment_blob(DOCUMENT_BLOB)
    extra_ref, extra_blob = attachment_blob(EXTRA_BLOB)
    assert len(extra_blob) == len(blob) and extra_ref["blob"] != ref["blob"]
    doc = document_state()
    with _documents(object()):
        assert check_remote_state(doc) is None, check_remote_state(doc)
    states = sorted([*base_states, doc], key=lambda s: s.item_id)
    files_in = {ref["blob"]: blob}
    backup = write_phone_backup(
        states, password=PASSWORD, device_id=device_id, platform=PLATFORM, app_version=APP_VERSION,
        created_at=CREATED_AT, pro_hint=PRO_HINT, files=files_in, _salt=SALT, _nonce=NONCE)
    env = json.loads(backup)
    header = env["header"]
    assert header["version"] == 2
    aad = canonical_json(header)
    plain = AESGCM(key).decrypt(NONCE, base64.b64decode(env["ciphertext"]), aad)
    payload = json.loads(plain)
    assert plain == canonical_json(payload) and payload["version"] == 2
    opened = read_phone_backup(backup, PASSWORD)
    assert dict(opened.files) == files_in and [state_dict(s) for s in opened.states] == payload["states"]

    def entry(blob_id: str, data: bytes) -> dict:
        return {"blob": blob_id, "data": b64(data)}

    v1_header = {**header, "version": 1}
    both = sorted([entry(ref["blob"], blob), entry(extra_ref["blob"], extra_blob)], key=lambda e: e["blob"])
    rejected = {
        "empty_files.lgkm": seal(key, header, {**payload, "files": []}),
        "file_hash_mismatch.lgkm": seal(key, header, {**payload, "files": [entry(ref["blob"], extra_blob)]}),
        "files_in_version_1.lgkm": seal(key, v1_header, {**payload, "version": 1}),
        "payload_version_1.lgkm": seal(key, header, {**payload, "version": 1}),
        "unreferenced_file.lgkm": seal(key, header, {**payload, "files": both}),
        "unsorted_files.lgkm": seal(key, header, {**payload, "files": both[::-1]}),
    }
    assert set(rejected) == set(REJECTED_V2)
    for name, data in rejected.items():
        try:
            read_phone_backup(data, PASSWORD)
        except PhoneBackupError as exc:
            assert exc.reason == REJECTED_V2[name], (name, exc.reason)
        else:
            raise AssertionError(f"format2/{name} was accepted")
    expected = {
        "password": PASSWORD,
        "header": header,
        "aad_hex": aad.hex(),
        "payload_canonical_sha256": hashlib.sha256(plain).hexdigest(),
        "payload_size": len(plain),
        "file_size": len(backup),
        "file_sha256": hashlib.sha256(backup).hexdigest(),
        "device_id": device_id,
        "states": payload["states"],
        "document_id": DOCUMENT_ID,
        "files": [{"blob": ref["blob"], "blob_size": len(blob), "blob_sha256": hashlib.sha256(blob).hexdigest(),
                   "attachment_id": ref["id"], "source": f"tests/vectors/sync/attachments/vectors.json blobs[name={DOCUMENT_BLOB}]"}],
        "rejected": {name: {"password": PASSWORD, "reason": reason} for name, reason in sorted(REJECTED_V2.items())},
    }
    out = {"format2/backup.lgkm": backup, "format2/expected.json": dumps(expected)}
    out.update({f"format2/rejected/{name}": data for name, data in rejected.items()})
    return out


def readme(device_id: str, state_count: int, padded_app_version: str) -> str:
    return f"""# Phone backup test vectors (`LGKMBAK1`)

Generated by `scripts/make_backup_vectors.py`; `tests/test_backup_vectors.py` regenerates them and
requires byte-for-byte equality, so they only change when the format changes on purpose.
EVERY KEY HERE IS TEST ONLY: the password and everything derived from it are published in the repository.
Kotlin (Android) and Swift (iPhone) must open every file here and, when writing with the same salt, nonce
and inputs, produce `backup.lgkm` byte for byte. The reference implementation is
`src/localvault/phone_backup.py`.

## Layout

```
file    = canonical_json({{"ciphertext": b64(ct || tag), "header": header}})     # no trailing newline
header  = {{"created_at": int, "format": "LGKMBAK1",
           "kdf": {{name, time_cost, memory_cost_kib, parallelism}},
           "nonce": b64(12 bytes), "platform": "android" | "ios",
           "salt": b64(16 bytes), "version": 1}}
key     = Argon2id v1.3 (password UTF-8 exactly as typed, salt, kdf) -> 32 bytes
ct      = AES-256-GCM(key, nonce, plaintext = canonical_json(payload), aad = canonical_json(header))
payload = {{"app_version": str (printable ASCII, 1..32), "device_id": str (valid id), "pro_hint": bool,
           "states": [{{"deleted": bool, "deleted_at": int | null, "id": str,
                       "item": dict | null, "vv": {{device: int}}}} ...],     # sorted by id, unique
           "version": 1}}
```

`canonical_json` is the sync format's (sorted keys, compact, UTF-8 kept literally; see `canonical_json.json`
in the sync vectors). b64 is standard base64 with padding and must be canonical: re-encoding the decoded
bytes must give the same text (salt, nonce and ciphertext). A `vv` counter of 0 is rejected as `bad-payload`
(zero equals missing, so a writer never emits one). The device identity and the group key are never in the file.
A wrong password and any tampering give the same reason, `wrong-password-or-damaged`.

## Rules a reader enforces

Checks run in this order, and everything before the AES-GCM step needs no key derivation (no Argon2 work):

1. File larger than 64 MiB (67108864 bytes): `too-large`.
2. Parse the envelope: `not-a-backup` on any failure here (see "Strict parsing"), including a header `format` other than `LGKMBAK1`, a `platform` other than `android` or `ios`, a `created_at` that is not an integer in 0..2^53-1 (no bool, no float), or `salt`, `nonce`, `ciphertext` that are not canonical base64 (salt 16 bytes, nonce 12 bytes).
3. Header `version`: an integer greater than 1 gives `unsupported-version`; any other value that is not exactly the integer 1 (0, negative, float, bool, text) gives `not-a-backup`.
4. `kdf` (all failures `bad-kdf`): the key set is exactly `name`, `time_cost`, `memory_cost_kib`, `parallelism`; `name` is exactly `argon2id`; `time_cost` is an integer 1..10; `memory_cost_kib` is an integer 8192..524288 (8 MiB..512 MiB); `parallelism` is an integer 1..16. Bools and floats are not integers.
5. Derive the key and decrypt with AES-256-GCM, AAD = `canonical_json(header)` of the header exactly as parsed. A wrong password, a tampered header or a tampered ciphertext all give `wrong-password-or-damaged`.
6. Parse and validate the plaintext payload; any failure is `bad-payload` (see "Payload rules").

Strict parsing (envelope and payload): the bytes must be valid UTF-8 (else `not-a-backup` for the file, `bad-payload` for the plaintext); duplicate object keys, `NaN`, `Infinity` and `-Infinity` are rejected; so is any integer outside -(2^63-1)..2^63-1 anywhere in the text (`not-a-backup` in the file, even in a field checked later such as `version` or a `kdf` cost; `bad-payload` in the plaintext), because the phone parsers cannot represent it; likewise any number that overflows to infinity, such as `1e400` (`not-a-backup` in the file, before the version and kdf checks; `bad-payload` in the plaintext); the envelope has exactly the keys `ciphertext` and `header`; the header exactly `created_at`, `format`, `kdf`, `nonce`, `platform`, `salt`, `version`; the payload exactly `app_version`, `device_id`, `pro_hint`, `states`, `version`; every state exactly `deleted`, `deleted_at`, `id`, `item`, `vv`. Extra or missing keys are rejected. A leading UTF-8 byte order mark is rejected too: `not-a-backup` at the start of the file, and `bad-payload` at the start of the decrypted payload (the JSON parser refuses it in both places).

Payload rules (all `bad-payload`):

- `version` is the integer 1; `pro_hint` is a bool; `states` is a list of at most 20000 entries.
- `app_version` is printable ASCII (0x20..0x7E only), 1..32 characters.
- `device_id` is a valid id (below).
- Every state `id` is a valid id: 1..128 characters from `[A-Za-z0-9._:-]`.
- States are strictly ascending by `id`, compared as bytes (UTF-8 code units); ids are ASCII, so this equals plain string order. That also means unique: a repeated or out-of-order id is rejected.
- `deleted` is a bool, and it is true exactly when `item` is null. A live state has an object `item`.
- `deleted_at` is null or an integer in 0..2^53-1 (no bool, no float).
- `vv` is an object; every key is a valid id; every counter is an integer (no bool, no float) in 1..2^53-1. The engine accepts 0 in memory but this format rejects it: a counter of 0 is `bad-payload`.
- `item`, when present, is a JSON object: all keys are strings, nesting is limited (the `item` object itself is depth 0, each value nested one container deeper is one more, and any value, scalar or container, at depth greater than 64 is rejected, so a scalar at depth 65 is rejected), every integer is within -(2^63-1)..2^63-1, and every number is finite. The item must also be encodable as canonical JSON (for example no lone surrogates in strings).

## Fixed inputs

| Input | Value |
| --- | --- |
| password | `{PASSWORD}` (`wrong_password.lgkm` is opened with `{WRONG_PASSWORD}`) |
| KDF | `argon2id`, `time_cost` 4, `memory_cost_kib` 131072 (128 MiB), `parallelism` 4: production parameters |
| salt | first 16 bytes of SHA-256(`lgk-backup-salt`) = `{b64(SALT)}` |
| nonce | first 12 bytes of SHA-256(`lgk-backup-nonce`) = `{b64(NONCE)}` |
| `created_at` | {CREATED_AT} |
| `device_id` | `{device_id}` (device A of `tests/vectors/sync/identities.json`) |
| `platform` / `app_version` / `pro_hint` | `{PLATFORM}` / `{APP_VERSION}` / `false` |
| states | the {state_count - 1} `bridge_stored_states` of `tests/vectors/sync/expected_merge.json`, unchanged, plus the licence state of `tests/vectors/sync/license_state.json` (its `state_id` and `wrapper`) with the version vector `{{"{device_id}": {LICENSE_VV_COUNTER}}}` (device A, counter {LICENSE_VV_COUNTER}); {state_count} in all, sorted by id |

## States are the stored form

The states are what a device's own local view publishes: the stored form of `tests/vectors/sync`
(`bridge_stored_states`). A conflict copy is stored under its own id: `record.id` is the copy id, the
`label` (typed items: `title`) carries the `" (sync conflict)"` suffix, the copy keeps the loser's
version vector, and the wrapper has no top-level `id`. A phone writes its own stored states, never the
engine form of a copy (the merge result before it is stored, a wrapper with a top-level `id` and
`record.id` still the original id): the desktop refuses such a state as a bad record and skips it.

The licence state is signed with the TEST licence key of `tests/vectors/sync/license_state.json`. A
production build does not know that key, so it treats the licence as needing a newer version
(`update-needed`) and skips it; only a build whose licence keys include the test key restores it.

## Files

| File | What it is | What a phone test does with it |
| --- | --- | --- |
| `backup.lgkm` | The backup written with the fixed inputs above. | Open it with the password; the states, `device_id`, `app_version`, `pro_hint` and header must equal `expected.json`. Write the same inputs with the fixed salt and nonce and compare every byte. |
| `expected.json` | `password`, `salt_b64`, `nonce_b64`, `key_hex` (raw Argon2id output), `header`, `aad_hex` (the canonical header bytes), `payload_canonical` (the plaintext as text) and its hash, `states` (as in the payload), sizes and hashes, and `rejected`. | Compare the derived key (tells a failing KDF from a failing decrypt), the AAD and the plaintext. `rejected` maps each file name under `rejected/` to `{{"password": ..., "reason": ...}}`. |
| `rejected/wrong_password.lgkm` | The same bytes as `backup.lgkm`. | Open with password `{WRONG_PASSWORD}`: `wrong-password-or-damaged`. |
| `rejected/flipped_ciphertext.lgkm` | One bit of the first ciphertext byte flipped. | `wrong-password-or-damaged`. |
| `rejected/edited_header.lgkm` | `created_at` + 1, ciphertext unchanged, so the AAD no longer matches. | `wrong-password-or-damaged`. |
| `rejected/version_3.lgkm` | Header `version` 3 (no such format). Refused from the header, before any key derivation. | `unsupported-version`. |
| `rejected/kdf_time_11.lgkm` | Header `kdf.time_cost` 11 (above the maximum of 10). Refused before any key derivation. | `bad-kdf`. |
| `rejected/extra_header_key.lgkm` | An extra key `extra` in the header (headers must have exactly the listed keys). | `not-a-backup`. |
| `rejected/duplicate_ids.lgkm` | A correctly encrypted payload whose first state appears twice (ids must be strictly increasing). | `bad-payload`. |
| `rejected/truncated.lgkm` | The first 100 bytes of `backup.lgkm`. | `not-a-backup`. |
| `rejected/noncanonical_salt.lgkm` | The header `salt` text changed to a different base64 spelling of the same 16 bytes (a spare bit set). | `not-a-backup`. |
| `rejected/noncanonical_ciphertext.lgkm` | A correctly encrypted backup (`app_version` `{padded_app_version}`, so the ciphertext base64 ends in padding) whose `ciphertext` text is changed to a different base64 spelling of the same bytes (a spare bit set). Refused before any key derivation. | `not-a-backup`. |
| `rejected/non_ascii_app_version.lgkm` | A correctly encrypted payload whose `app_version` is `1.0.é` (not printable ASCII). | `bad-payload`. |
| `rejected/zero_vv_counter.lgkm` | A correctly encrypted payload where one state's `vv` has a counter of 0. | `bad-payload`. |

## Format 2: document files (`format2/`)

Format 2 is format 1 with header `version` 2, payload `version` 2 and one more payload key, `files`:

```
payload = {{..., "files": [{{"blob": <blob id, 64 lowercase hex>, "data": b64(sync blob)}} ...], "version": 2}}
```

`files` has 1..500 entries, strictly ascending by `blob`. Each `data` is canonical base64 of exactly one sync
blob (`LGKABLB1`, `tests/vectors/sync/attachments`), its SHA-256 is `blob`, and it is named, with the same
`blob_size`, by the `attachment` reference of at least one live document state in the same payload. A writer
emits format 2 only when it includes at least one file, and format 1 otherwise. Readers accept both. Every
failure of these rules is `bad-payload`. A reader opens a file with its reference (`open_blob`) only when it
restores it.

| File | What it is | Reason |
| --- | --- | --- |
| `format2/backup.lgkm` | The fixed inputs plus the document `{DOCUMENT_ID}` whose `attachment` is the `{DOCUMENT_BLOB}` reference of the attachment vectors, and that blob as the one file. Write it with the fixed salt and nonce and compare every byte. | opens |
| `format2/expected.json` | Header, AAD, payload hash and size, states, the file list, and `rejected`. | |
| `format2/rejected/empty_files.lgkm` | Version 2 with `files` `[]`. | `bad-payload` |
| `format2/rejected/file_hash_mismatch.lgkm` | The file entry's `data` is another blob of the same size. | `bad-payload` |
| `format2/rejected/files_in_version_1.lgkm` | Header and payload version 1 with a `files` key. | `bad-payload` |
| `format2/rejected/payload_version_1.lgkm` | Header version 2, payload version 1. | `bad-payload` |
| `format2/rejected/unreferenced_file.lgkm` | A second file no document names (the `{EXTRA_BLOB}` blob). | `bad-payload` |
| `format2/rejected/unsorted_files.lgkm` | The two files in descending order. | `bad-payload` |

Every `.lgkm` file is canonical JSON with no trailing newline and is kept byte-exact in git
(`*.lgkm binary`, `tests/vectors/** -text`); the other files use LF.
"""


def generate(out: Path) -> None:
    """Write every vector file under *out* (created if missing)."""
    out = Path(out)
    files = build()
    assert tuple(sorted(files)) == GENERATED_FILES, sorted(files)
    for rel, data in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    generate(out)
    print(f"wrote {len(GENERATED_FILES)} files to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
