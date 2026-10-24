"""M-9 / L-23 (audit 2026-10-24): catalog plaintext and the data key stay in zeroable buffers."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import vault as V

LOW = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "correct horse battery staple"


class RecordingAESGCM:
    """Records what the vault hands to AES-GCM; refuses the copying ``decrypt``."""

    keys: list[type] = []
    plaintexts: list[object] = []

    def __init__(self, key):
        RecordingAESGCM.keys.append(type(key))
        self._inner = AESGCM(key)

    def encrypt(self, nonce, data, associated_data):
        RecordingAESGCM.plaintexts.append(data)
        return self._inner.encrypt(nonce, data, associated_data)

    def decrypt(self, nonce, data, associated_data):
        raise AssertionError("the catalog must be decrypted with decrypt_into")

    def decrypt_into(self, nonce, data, associated_data, buffer):
        return self._inner.decrypt_into(nonce, data, associated_data, buffer)


@pytest.fixture
def recording(monkeypatch):
    RecordingAESGCM.keys, RecordingAESGCM.plaintexts = [], []
    monkeypatch.setattr(V, "AESGCM", RecordingAESGCM)
    return RecordingAESGCM


def test_canonical_buffer_matches_canonical_json() -> None:
    value = {"b": [1, 2.5, None, True], "a": {"z": "é☃😀", "y": "\"quoted\"\n"}, "c": ""}
    buffer = V._canonical_json_buffer(value)
    assert isinstance(buffer, bytearray)
    assert bytes(buffer) == V._canonical_json(value)


def test_save_encrypts_from_a_zeroed_bytearray_and_unlock_uses_decrypt_into(tmp_path: Path, recording) -> None:
    path = tmp_path / "vault.json"
    session = V.create_vault(path, MASTER, kdf_overrides=LOW)
    session.upsert_web(origin="https://a.example", username="u", password="Catalog-Secret-123")
    session.lock()
    assert recording.plaintexts, "the catalog was not encrypted through AESGCM.encrypt"
    for plaintext in recording.plaintexts:
        if len(plaintext) == 32:
            continue  # key wrapping
        assert isinstance(plaintext, bytearray)
        assert not any(plaintext), "the plaintext catalog buffer was not zeroed after encryption"
    recording.keys.clear()
    opened = V.unlock_vault(path, MASTER)  # RecordingAESGCM.decrypt would raise
    assert opened.credential_secret(opened.summaries()[0].id) == "Catalog-Secret-123"
    opened.lock()
    # L-23: the data key / wrapping keys are handed over as bytearrays, never as bytes() copies.
    assert recording.keys and all(kind is bytearray for kind in recording.keys)


def test_saved_vault_is_unchanged_on_disk_format(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = V.create_vault(path, MASTER, kdf_overrides=LOW)
    session.upsert_web(origin="https://a.example", username="u", password="pé-☃")
    key = bytes(session._key)
    session.lock()
    header = json.loads(path.read_text())
    plain = AESGCM(key).decrypt(V._b64d(header["cipher"]["nonce"]), V._b64d(header["cipher"]["ciphertext"]),
                                V._aad(header))
    assert plain == V._canonical_json(json.loads(plain))


def test_non_ascii_catalog_from_another_writer_still_opens(tmp_path: Path) -> None:
    buffer = bytearray(json.dumps({"x": "café"}, ensure_ascii=False).encode("utf-8"))
    assert V._json_from_buffer(buffer) == {"x": "café"}


def test_transient_catalog_text_is_scrubbed() -> None:
    text = bytearray(b'{"password":"Scrub-Me-Secret"}').decode("ascii")
    V._scrub_str(text)
    assert "Scrub-Me-Secret" not in text and text.strip() == ""


def test_entry_token_is_unchanged_by_chunked_hmac(tmp_path: Path) -> None:
    session = V.create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=LOW)
    entry_id = session.upsert_web(origin="https://a.example", username="ué", password="p😀x")
    item = session.get_entry(entry_id)
    content = {k: v for k, v in item.items() if k not in V._EDIT_TOKEN_IGNORED_KEYS}
    body = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8", "surrogatepass")
    expected = hmac.new(session._edit_token_key, body, hashlib.sha256).hexdigest()
    assert session.login_edit_token(entry_id) == expected
    session.lock()
