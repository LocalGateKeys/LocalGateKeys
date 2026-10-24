"""Generate the deterministic format-3 vault test vectors in ``tests/vectors/vault``.

Everything here is test-only.  The password, Argon2id salt, data key, wrapper nonce, catalog
nonce, vault id and payload are fixed; the cheapest Argon2id parameters the reader accepts keep
the derivation fast.  The authenticated data is spelled out here from the format description
(it is the contract under test) and cross-checked against ``localvault.vault``:

* catalog AAD  = ``localgatekeys|vault|v3|`` + canonical JSON of the v3 identity (version,
  format, catalog, catalog_version, vault_id, key_generation) plus ``generation`` and
  ``cipher.name``.  Binding ``vault_id`` and ``generation`` is what stops a catalog being swapped
  between vaults or replayed under another write generation;
* password-wrapper AAD = ``localgatekeys|vault-key-wrapper|v3|`` + canonical JSON of the v3
  identity plus ``wrapper`` and its public ``metadata`` (the KDF).

Usage::

    python scripts/make_vault_vectors.py [OUT_DIR]      # default: tests/vectors/vault

``tests/test_vault_vectors.py`` opens the committed vault with the password and regenerates into
a temporary directory, comparing every file byte for byte with the committed copies.
"""

# ruff: noqa: S101, S105  (generator self-checks use assert; the password is a published test vector)

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import vault

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "tests" / "vectors" / "vault"

PASSWORD = "correct horse battery staple 42"
KDF = {
    "name": "argon2id",
    "time_cost": 1,
    "memory_cost_kib": 8192,
    "parallelism": 1,
    "hash_len": 32,
    "salt": base64.b64encode(hashlib.sha256(b"lgk-vault-v3-salt").digest()[:16]).decode("ascii"),
}
DATA_KEY = hashlib.sha256(b"lgk-vault-v3-data-key").digest()
WRAPPER_NONCE = hashlib.sha256(b"lgk-vault-v3-wrapper-nonce").digest()[:12]
CATALOG_NONCE = hashlib.sha256(b"lgk-vault-v3-catalog-nonce").digest()[:12]
VAULT_ID = hashlib.sha256(b"lgk-vault-v3-vault-id").hexdigest()[:32]
GENERATION = 3
CREATED_AT = 1790000000

AAD_PREFIX_V3 = b"localgatekeys|vault|v3|"
WRAPPER_AAD_PREFIX = b"localgatekeys|vault-key-wrapper|v3|"

#: rejected file name -> what was edited (each must fail to open with the right password).
REJECTED = {
    "v3_edited_generation.json": "header generation +1 (bound by the catalog AAD)",
    "v3_edited_vault_id.json": "vault_id changed (bound by the wrapper and catalog AAD)",
    "v3_edited_key_generation.json": "key_generation +1 (bound by the wrapper and catalog AAD)",
}

GENERATED_FILES = tuple(sorted(["v3_vault.json", "v3_expected.json"] + list(REJECTED)))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def canonical(value: Any) -> bytes:
    """The vault's canonical JSON: sorted keys, no whitespace, ASCII escapes."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def dumps(value: Any) -> bytes:
    """Readable, stable JSON for the descriptive file (keys sorted, 2 spaces, LF, final newline)."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def payload() -> dict[str, Any]:
    return {
        "version": 2,
        "catalog": "localgatekeys-catalog",
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
        "generation": GENERATION,
        "entries": [],
        "items": [],
        "collections": [],
        "templates": [],
        "events": [],
        "attachments": [],
        "reminders": [],
        "history": [],
        "relationships": [],
        "smart_views": [],
        "ocr_derivatives": [],
        "sync_protocol_state": {"next_counter": 1, "item_revisions": {}},
        "sync_receipts": [],
    }


def identity(header: dict[str, Any]) -> dict[str, Any]:
    return {key: header[key] for key in ("version", "format", "catalog", "catalog_version", "vault_id",
                                         "key_generation")}


def catalog_aad(header: dict[str, Any]) -> bytes:
    body = identity(header)
    body["generation"] = header["generation"]
    body["cipher"] = {"name": header["cipher"]["name"]}
    return AAD_PREFIX_V3 + canonical(body)


def wrapper_aad(header: dict[str, Any]) -> bytes:
    body = identity(header)
    body["wrapper"] = "password"
    body["metadata"] = {"kdf": header["kdf"]}
    return WRAPPER_AAD_PREFIX + canonical(body)


def seal(header: dict[str, Any], kek: bytes) -> dict[str, Any]:
    """Fill in the password wrapper and the encrypted catalog for ``header``."""
    sealed = json.loads(json.dumps(header))
    sealed["wrappers"] = {"password": {
        "nonce": b64(WRAPPER_NONCE),
        "ciphertext": b64(AESGCM(kek).encrypt(WRAPPER_NONCE, DATA_KEY, wrapper_aad(sealed))),
    }}
    sealed["cipher"] = {
        "name": "aes-256-gcm",
        "nonce": b64(CATALOG_NONCE),
        "ciphertext": b64(AESGCM(DATA_KEY).encrypt(CATALOG_NONCE, canonical(payload()), catalog_aad(sealed))),
    }
    return sealed


def build() -> dict[str, bytes]:
    header: dict[str, Any] = {
        "version": 3,
        "format": "localgatekeys-vault-v3",
        "catalog": "localgatekeys-catalog",
        "catalog_version": 2,
        "vault_id": VAULT_ID,
        "generation": GENERATION,
        "key_generation": 1,
        "kdf": KDF,
        "wrappers": {},
        "cipher": {"name": "aes-256-gcm"},
    }
    # Cross-check the spelled-out contract against the reader before writing anything.
    assert header["format"] == vault.FORMAT_V3_IDENTIFIER and header["catalog"] == vault.CATALOG_FORMAT
    assert header["catalog_version"] == vault.CATALOG_VERSION and header["version"] == vault.FORMAT_VERSION
    assert AAD_PREFIX_V3 == vault.AAD_PREFIX_V3 and WRAPPER_AAD_PREFIX == vault.WRAPPER_AAD_PREFIX
    kek = bytes(vault._derive_key(PASSWORD, KDF))
    good = seal(header, kek)
    assert vault._aad(good) == catalog_aad(good), "vault._aad no longer matches the v3 contract"
    assert vault._wrapper_aad(good, "password", {"kdf": KDF}) == wrapper_aad(good)

    files: dict[str, bytes] = {"v3_vault.json": canonical(good)}
    edits = {
        "v3_edited_generation.json": ("generation", GENERATION + 1),
        "v3_edited_vault_id.json": ("vault_id", hashlib.sha256(b"another vault").hexdigest()[:32]),
        "v3_edited_key_generation.json": ("key_generation", 2),
    }
    assert set(edits) == set(REJECTED)
    for name, (field, value) in edits.items():
        edited = json.loads(json.dumps(good))
        edited[field] = value
        files[name] = canonical(edited)

    files["v3_expected.json"] = dumps({
        "password": PASSWORD,
        "kdf": KDF,
        "kek_hex": kek.hex(),
        "data_key_hex": DATA_KEY.hex(),
        "vault_id": VAULT_ID,
        "generation": GENERATION,
        "catalog_aad_b64": b64(catalog_aad(good)),
        "wrapper_aad_b64": b64(wrapper_aad(good)),
        "payload": payload(),
        "rejected": REJECTED,
    })
    assert tuple(sorted(files)) == GENERATED_FILES
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    write(out)
    print(f"wrote {len(GENERATED_FILES)} files to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
