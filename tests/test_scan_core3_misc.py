"""Scan core 3 (2026-11-15): M2 (revoke notices), L2 (imported TOTP secret), L3 (passkey outcome replies),
L5 (heir holder index bound) and the collections.delete save-failure suspicion."""
from __future__ import annotations

import base64
import json
import os
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import heir_flow, share_revoke, sss
from localvault.import_workflow import totp_dict
from localvault.importers import totp_uri_from_secret


# ------------------------------------------------------------------------------------------------ M2
def _member() -> tuple[ed25519.Ed25519PrivateKey, dict[str, str]]:
    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, {"device-a": base64.b64encode(public).decode("ascii")}


@pytest.mark.parametrize("damaged", [b'{"signer":[]}', b'{"signer":{"a":1}}', b'{"signer":null}', b"[" * 1000,
                                     b"\xff\xfe", b'"just a string"'])
def test_a_damaged_notice_never_breaks_collect(tmp_path: Path, damaged: bytes) -> None:
    key, trusted = _member()
    package = str(uuid.uuid4())
    share_revoke.publish(tmp_path, key, package, signer="device-a")
    (tmp_path / share_revoke.REVOKED_DIR_NAME / f"x{share_revoke.SUFFIX}").write_bytes(damaged)
    assert share_revoke.collect(tmp_path, trusted) == {package}


def test_newest_notices_count_when_there_are_too_many(tmp_path: Path) -> None:
    key, trusted = _member()
    folder = tmp_path / share_revoke.REVOKED_DIR_NAME
    folder.mkdir()
    old = time.time() - 3600
    for index in range(share_revoke.MAX_NOTICES + 20):
        junk = folder / f"00000000-0000-4000-8000-{index:012d}{share_revoke.SUFFIX}"
        junk.write_bytes(b"{}")
        os.utime(junk, (old, old))
    package = "ffffffff-ffff-4fff-bfff-ffffffffffff"  # sorts after every junk name
    share_revoke.publish(tmp_path, key, package, signer="device-a")
    assert share_revoke.collect(tmp_path, trusted) == {package}


def test_publish_prunes_notices_long_expired(tmp_path: Path) -> None:
    key, trusted = _member()
    stale_id, fresh_id = str(uuid.uuid4()), str(uuid.uuid4())
    stale = share_revoke.publish(tmp_path, key, stale_id, signer="device-a")
    past = time.time() - share_revoke.PRUNE_AFTER - 60
    os.utime(stale, (past, past))
    share_revoke.publish(tmp_path, key, fresh_id, signer="device-a")
    assert not stale.exists()
    assert share_revoke.collect(tmp_path, trusted) == {fresh_id}


def test_share_open_survives_a_failing_revoke_channel(monkeypatch) -> None:
    from localvault.app.share_web import ShareService

    service = object.__new__(ShareService)
    service._sync_channel = lambda: (Path("unused"), None, {})

    def boom(*_args):
        raise TypeError("cannot use 'list' as a dict key")

    monkeypatch.setattr(share_revoke, "collect", boom)
    assert service._revoked_over_sync() == set()


# ------------------------------------------------------------------------------------------------ L2
def test_a_bare_secret_cannot_inject_otpauth_parameters() -> None:
    uri = totp_uri_from_secret("JBSWY3DP&digits=8&algorithm=SHA256", label="account")
    assert uri.count("&") == 0 and "algorithm=" not in uri.lower() and "digits=" not in uri.lower()
    assert totp_dict(uri) is None, "an invalid secret is reported by the import workflow, never cut short"


def test_a_valid_secret_is_unchanged() -> None:
    uri = totp_uri_from_secret("jbsw y3dp-ehpk 3pxp", label="Example:ada", issuer="Example", digits=8)
    assert uri == "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8"
    assert totp_dict(uri) == {"secret": "JBSWY3DPEHPK3PXP", "digits": 8, "period": 30, "algorithm": "SHA1"}


# ------------------------------------------------------------------------------------------------ L3
def test_an_outcome_that_changes_nothing_is_never_reported_as_saved(tmp_path: Path) -> None:
    from test_passkey_confirm import CONTEXT, _broker

    broker = _broker(tmp_path)
    broker.create()
    [item] = broker.items()
    broker.session.item_service.update_item(item["id"], title="Edited by the user")  # confirms it
    assert broker.request("passkey_discard_browser") == {"ok": False, "error": "not_changed"}
    assert [i["title"] for i in broker.items()] == ["Edited by the user"]

    other = json.dumps([17, "document-redacted", "https://login.example.test", "pk-op-7"])
    broker.create(context=other)
    for entry in broker._passkey_pending()[other]:
        entry["stamp"] = "another session"  # locked or switched since the create
    assert broker.request("passkey_confirm_browser", context=other) == {"ok": False, "error": "not_changed"}
    assert broker.request("passkey_confirm_browser", context=CONTEXT) == {"ok": False, "error": "not_found"}


def test_a_confirm_whose_save_fails_is_not_reported_as_saved(tmp_path: Path, monkeypatch) -> None:
    from test_passkey_confirm import _broker

    from localvault.vault import VaultError

    broker = _broker(tmp_path)
    broker.create()

    def broken(self, item_id):
        raise VaultError("disk busy (test)")

    monkeypatch.setattr(type(broker.session.item_service), "confirm_passkey", broken)
    assert broker.request("passkey_confirm_browser") == {"ok": False, "error": "not_changed"}
    assert broker._passkey_pending(), "still tried again later"


def test_apply_counts_only_changed_passkeys(tmp_path: Path) -> None:
    from test_passkey_confirm import CONTEXT, _broker

    broker = _broker(tmp_path)
    broker.create()
    broker._passkey_note_outcome({"action": "passkey_confirm_browser", "context": CONTEXT})
    taken = broker._passkey_take(CONTEXT, now=None, force=False)
    assert broker._passkey_apply(taken) == 1
    assert broker._passkey_apply([{**taken[0]}]) == 0  # already confirmed


# ------------------------------------------------------------------------------------------------ L5
def test_holder_index_bound_follows_sss_max_n(tmp_path: Path, monkeypatch) -> None:
    def opened(index: int) -> SimpleNamespace:
        payload = {"plan_id": "plan", "holder_index": index, "created": 1_700_000_000,
                   "box_public": base64.b64encode(b"x" * 32).decode(), "proof": base64.b64encode(b"p" * 32).decode()}
        return SimpleNamespace(payload=payload, id="req", sender="heir", signer=b"s" * 32)

    current = {"value": None}
    monkeypatch.setattr(heir_flow, "_read_small", lambda path: b"{}")
    monkeypatch.setattr(heir_flow, "_open", lambda data, kind, fields: current["value"])
    current["value"] = opened(sss.MAX_N)
    assert heir_flow._read_request(tmp_path / "r", "plan").holder_index == sss.MAX_N
    current["value"] = opened(sss.MAX_N + 1)
    assert heir_flow._read_request(tmp_path / "r", "plan") is None
    monkeypatch.setattr(sss, "MAX_N", sss.MAX_N + 2)
    assert heir_flow._read_request(tmp_path / "r", "plan").holder_index == sss.MAX_N - 1


# ------------------------------------------------------------------- suspicion 3: collections.delete save failure
def test_a_failed_collection_delete_leaves_memory_as_on_disk(tmp_path: Path, monkeypatch) -> None:
    from localvault import vault as vault_module
    from localvault.collections import CollectionService
    from localvault.item_service import ItemService
    from localvault.vault import VaultError, create_vault

    session = create_vault(tmp_path / "v.json", "synthetic collections master",
                           kdf_overrides={"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32})
    try:
        collections = CollectionService(session)
        cid = collections.create("Family")
        note = ItemService(session).create_note("Wi-Fi", "synthetic", collection_ids=[cid])

        def failing(path, value):
            raise OSError("disk full (test)")

        monkeypatch.setattr(vault_module, "atomic_write_json", failing)
        with pytest.raises(VaultError):
            collections.delete(cid)
        monkeypatch.undo()
        assert [row["id"] for row in collections.list()] == [cid]
        item = next(i for i in session._require_typed_catalog()["items"] if i["id"] == note)
        assert item["collection_ids"] == [cid]
    finally:
        session.lock()
