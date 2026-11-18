from __future__ import annotations

import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import share, share_revoke

ITEM = {"kind": "note", "title": "n", "fields": {"text": "x"}}
NOW = 1_800_000_000


@pytest.fixture(scope="module")
def code() -> str:
    return share.generate_code()


def test_plain_package_unchanged(code) -> None:
    opened = share.open_package(share.seal(ITEM, code, sender="PC", now=NOW), code, now=NOW + 1)
    assert opened["expires_at"] == NOW + share.LIFETIME and opened["one_use"] is False


def test_earlier_expiry_wins(code) -> None:
    data = share.seal(ITEM, code, sender="PC", now=NOW, expires=NOW + 3600)
    assert share.open_package(data, code, now=NOW + 3599)["expires_at"] == NOW + 3600
    with pytest.raises(share.ShareError) as err:
        share.open_package(data, code, now=NOW + 3600)
    assert err.value.reason == "expired"


def test_later_expiry_is_capped_by_lifetime(code) -> None:
    data = share.seal(ITEM, code, sender="PC", now=NOW, expires=NOW + 7 * 86400)
    assert share.open_package(data, code, now=NOW)["expires_at"] == NOW + share.LIFETIME
    with pytest.raises(share.ShareError):
        share.open_package(data, code, now=NOW + share.LIFETIME)


def test_receiver_clock_behind_still_opens_before_expiry(code) -> None:
    data = share.seal(ITEM, code, sender="PC", now=NOW, expires=NOW + 3600)
    # Receiver's clock 4 minutes behind (inside CLOCK_SKEW): opens; the expiry is judged on its own clock.
    assert share.open_package(data, code, now=NOW - 240)["expires_at"] == NOW + 3600


def test_expiry_in_the_past_refused_at_seal(code) -> None:
    with pytest.raises(share.ShareError):
        share.seal(ITEM, code, sender="PC", now=NOW, expires=NOW)


def test_one_use_marks_used(code) -> None:
    data = share.seal(ITEM, code, sender="PC", now=NOW, one_use=True)
    opened = share.open_package(data, code, now=NOW)
    assert opened["one_use"] is True
    with pytest.raises(share.ShareError) as err:
        share.open_package(data, code, now=NOW, opened=[opened["id"]])
    assert err.value.reason == "already-opened"


def test_revoke_notice_for_this_package_only(code) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    package = str(uuid.uuid4())
    data = share.seal(ITEM, code, sender="PC", now=NOW, package_id=package)
    notice = share_revoke.make_revoke(key, package, signer="PC", now=NOW)
    revoked = share_revoke.verify_revoke(notice, key.public_key(), package)
    with pytest.raises(share.ShareError) as err:
        share.open_package(data, code, now=NOW, revoked=[revoked])
    assert err.value.reason == "revoked"
    with pytest.raises(share_revoke.RevokeError, match="other-package"):
        share_revoke.verify_revoke(notice, key.public_key(), str(uuid.uuid4()))
    with pytest.raises(share_revoke.RevokeError, match="bad-signature"):
        share_revoke.verify_revoke(notice, ed25519.Ed25519PrivateKey.generate().public_key(), package)
    with pytest.raises(share_revoke.RevokeError):
        share_revoke.verify_revoke(notice.replace(b'"format":1', b'"format":2'), key.public_key(), package)


def test_revoke_notices_travel_through_the_sync_folder(tmp_path) -> None:
    import base64

    from cryptography.hazmat.primitives import serialization

    sender = ed25519.Ed25519PrivateKey.generate()
    stranger = ed25519.Ed25519PrivateKey.generate()
    raw = sender.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    trusted = {"dev-pc": base64.b64encode(raw).decode()}
    sync_dir = tmp_path / "LocalGateKeys Sync"
    good, forged = str(uuid.uuid4()), str(uuid.uuid4())
    share_revoke.publish(sync_dir, sender, good, signer="dev-pc", now=NOW)
    share_revoke.publish(sync_dir, stranger, forged, signer="dev-pc", now=NOW)  # not the trusted key
    (sync_dir / share_revoke.REVOKED_DIR_NAME / "junk.lgkrevoke").write_bytes(b"x" * 5000)
    assert share_revoke.collect(sync_dir, trusted) == {good}
    assert share_revoke.collect(tmp_path / "missing", trusted) == set()


def test_v1_1_vectors() -> None:
    import json
    from pathlib import Path

    vectors = json.loads((Path(__file__).parent / "vectors" / "share" / "v1_1.json").read_text(encoding="utf-8"))
    for case in vectors["opens"]:
        data = case["package"].encode()
        opened = share.open_package(data, case["code"], now=case["now"])
        assert opened["expires_at"] == case["expires_at"] and opened["one_use"] is case["one_use"]
        assert opened["item"] == case["item"]
        with pytest.raises(share.ShareError):
            share.open_package(data, case["code"], now=case["expires_at"])
