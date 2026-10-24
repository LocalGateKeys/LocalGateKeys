"""A vault holding a stored origin that the stricter canonicalize_origin refuses must still open.

Such a row could only be written by an older release (crafted import), but it
may exist on real machines.  The entry stays loadable and visible, and it is
never offered for fill.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import vault as V
from localvault.origin import OriginError, canonicalize_origin

LOW = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "correct horse battery staple"
BAD = "https://paypal.com\\.evil.com"


def _inject_origin(path: Path, key: bytes, entry_id: str, origin: str) -> None:
    """Rewrite the encrypted catalog the way an older release would have stored it."""
    header = json.loads(path.read_text())
    plain = AESGCM(key).decrypt(V._b64d(header["cipher"]["nonce"]), V._b64d(header["cipher"]["ciphertext"]),
                                V._aad(header))
    payload = json.loads(plain)
    for entry in payload["entries"]:
        if entry["id"] == entry_id:
            entry["scope"]["origin"] = origin
            entry["scope"].pop("urls", None)
    nonce = os.urandom(12)
    header["cipher"]["nonce"] = V._b64e(nonce)
    header["cipher"]["ciphertext"] = V._b64e(AESGCM(key).encrypt(nonce, V._canonical_json(payload), V._aad(header)))
    path.write_text(json.dumps(header), encoding="utf-8")


@pytest.fixture
def legacy_vault(tmp_path: Path):
    path = tmp_path / "vault.json"
    session = V.create_vault(path, MASTER, kdf_overrides=LOW)
    bad_id = session.upsert_web(origin="https://paypal.com", username="victim", password="Legacy-Row-Secret")
    session.upsert_web(origin="https://good.example", username="u", password="Good-Row-Secret")
    key = bytes(session._key)
    session.lock()
    _inject_origin(path, key, bad_id, BAD)
    return path, bad_id


def test_stricter_origin_rules_refuse_the_row() -> None:
    with pytest.raises(OriginError):
        canonicalize_origin(BAD)


def test_vault_with_a_now_refused_origin_still_opens_and_never_fills_it(legacy_vault) -> None:
    path, bad_id = legacy_vault
    session = V.unlock_vault(path, MASTER)
    try:
        summaries = {summary.id: summary for summary in session.summaries()}
        assert len(summaries) == 2 and bad_id in summaries
        assert session.get_entry(bad_id)["scope"]["origin"] == BAD  # kept as stored, visible to the user
        assert session.credential_secret(bad_id) == "Legacy-Row-Secret"
        assert session.find_web("https://paypal.com") == []
        assert session.find_web("https://evil.com") == []
        assert all(item["id"] != bad_id for item in session.find_web("https://good.example"))
        # Saving other changes keeps the vault writable and the row unchanged.
        session.upsert_web(origin="https://other.example", username="u2", password="x")
        session.delete(bad_id)
    finally:
        session.lock()
    reopened = V.unlock_vault(path, MASTER)
    assert len(reopened.summaries()) == 2
    reopened.lock()


def test_empty_or_non_text_origin_is_still_rejected() -> None:
    with pytest.raises((OriginError, V.VaultError)):
        V._stored_origin("")
    with pytest.raises((OriginError, V.VaultError, TypeError)):
        V._stored_origin(None)
