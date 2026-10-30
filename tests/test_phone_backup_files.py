"""Phone backup format 2: document files inside the encrypted payload."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import phone_backup
from localvault.phone_backup import PhoneBackupError, read_phone_backup, select_files, write_phone_backup
from localvault.sync.attachment_sync import AttachmentRef, blob_id, seal_blob
from localvault.sync.engine import ItemState
from localvault.updates import canonical_json

FAST = {"name": "argon2id", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
PW = "pw"
KEY = bytes(range(32))
ATT = "00000000-0000-4000-8000-0000000000a1"
DATA = b"hello passport"


def _blob_and_ref(att=ATT, data=DATA, key=KEY):
    blob = seal_blob(key, att, data)
    ref = AttachmentRef(att, blob_id(blob), len(blob), "passport.pdf", "application/pdf", len(data),
                        hashlib.sha256(data).hexdigest(), key)
    return blob, ref


def _doc(item_id, ref):
    return ItemState(item_id, {"phone": 1}, False, None, {
        "ns": "item", "schema": 1, "updated_at": 5, "attachment": ref.to_dict(),
        "record": {"id": item_id, "kind": "document", "title": "Passport",
                   "payload": {"attachment_id": ref.attachment_id}}})


def _write(states, files=None, **kw):
    return write_phone_backup(states, password=PW, device_id="phone", platform="android", app_version="1.0",
                              created_at=1, pro_hint=False, kdf=FAST, files=files, **kw)


def _reason(data):
    with pytest.raises(PhoneBackupError) as info:
        read_phone_backup(data, PW)
    return info.value.reason


def test_files_make_version_2_and_round_trip():
    blob, ref = _blob_and_ref()
    data = _write([_doc("d1", ref)], {ref.blob: blob})
    env = json.loads(data)
    assert env["header"]["version"] == 2
    backup = read_phone_backup(data, PW)
    assert backup.header.version == 2 and dict(backup.files) == {ref.blob: blob}
    # read -> write is byte identical
    again = _write(backup.states, backup.files, _salt=backup.header.salt, _nonce=backup.header.nonce)
    assert again == data


def test_no_files_stays_version_1():
    _blob_, ref = _blob_and_ref()
    for files in (None, {}):
        data = _write([_doc("d1", ref)], files)
        assert json.loads(data)["header"]["version"] == 1
        backup = read_phone_backup(data, PW)
        assert backup.header.version == 1 and not backup.files


def _forge(payload, version=2):
    env = json.loads(_write([]))
    header = {**env["header"], "version": version}
    key = phone_backup._derive(PW, base64.b64decode(header["salt"]), header["kdf"])
    ct = AESGCM(key).encrypt(base64.b64decode(header["nonce"]), canonical_json(payload), canonical_json(header))
    return canonical_json({"ciphertext": base64.b64encode(ct).decode(), "header": header})


def _payload(states, files, version=2):
    out = {"app_version": "1.0", "device_id": "phone", "pro_hint": False, "version": version,
           "states": [{"deleted": s.deleted, "deleted_at": s.deleted_at, "id": s.item_id, "item": s.item,
                       "vv": dict(s.vv)} for s in states]}
    if files is not None:
        out["files"] = files
    return out


def _entry(blob):
    return {"blob": blob_id(blob), "data": base64.b64encode(blob).decode()}


def test_format_2_payload_rules():
    blob, ref = _blob_and_ref()
    blob2, ref2 = _blob_and_ref("00000000-0000-4000-8000-0000000000a2", b"other")
    states = [_doc("d1", ref)]
    assert read_phone_backup(_forge(_payload(states, [_entry(blob)])), PW).files == {ref.blob: blob}
    bad = {
        "empty files": _payload(states, []),
        "no files key": _payload(states, None),
        "payload version 1": _payload(states, [_entry(blob)], version=1),
        "unreferenced file": _payload(states, [_entry(blob), _entry(blob2)]),
        "wrong hash": _payload(states, [{"blob": "0" * 64, "data": _entry(blob)["data"]}]),
        "duplicate": _payload(states, [_entry(blob), _entry(blob)]),
        "extra key": _payload(states, [{**_entry(blob), "x": 1}]),
        "not a blob": _payload(states, [{"blob": hashlib.sha256(b"x").hexdigest(),
                                         "data": base64.b64encode(b"x").decode()}]),
        "file of a deleted document": _payload([ItemState("d1", {"phone": 1}, True, 3, None)], [_entry(blob)]),
    }
    for name, payload in bad.items():
        assert _reason(_forge(payload)) == "bad-payload", name
    # files in a version 1 payload are an unknown key
    assert _reason(_forge(_payload(states, [_entry(blob)], version=1), version=1)) == "bad-payload"
    assert ref2.blob != ref.blob


def test_version_3_is_unsupported():
    env = json.loads(_write([]))
    env["header"]["version"] = 3
    assert _reason(canonical_json(env)) == "unsupported-version"


def test_writer_refuses_bad_files():
    blob, ref = _blob_and_ref()
    with pytest.raises(PhoneBackupError):
        _write([], {ref.blob: blob})  # no document names it
    with pytest.raises(PhoneBackupError):
        _write([_doc("d1", ref)], {"0" * 64: blob})


def test_select_files_budget_and_missing():
    b1, r1 = _blob_and_ref()
    b2, r2 = _blob_and_ref("00000000-0000-4000-8000-0000000000a2", b"two")
    b3, r3 = _blob_and_ref("00000000-0000-4000-8000-0000000000a3", b"three")
    states = [_doc("d3", r3), _doc("d1", r1), _doc("d2", r2), _doc("d4", r1)]
    blobs = {r1.blob: b1, r2.blob: b2}
    files, left = select_files(states, lambda ref: blobs.get(ref.blob), budget=len(b1) + len(b2))
    assert files == {r1.blob: b1, r2.blob: b2} and left == (r3.attachment_id,)
    files, left = select_files(states, lambda ref: {**blobs, r3.blob: b3}.get(ref.blob), budget=len(b1))
    assert files == {r1.blob: b1} and left == (r2.attachment_id, r3.attachment_id)
