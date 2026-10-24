"""Deterministic desktop <-> iOS sync test vectors (tests/vectors/sync).

The committed files are the contract the iOS app must decode, decrypt, verify and merge.
This test pins them three ways: the generator reproduces them byte for byte, an independent
decode + merge of the committed files matches ``expected_merge.json`` in every device order,
and the keyring / LAN files verify with the public format functions.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import ipaddress
import itertools
import json
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from localvault.sync import keyring as kr
from localvault.sync.engine import ItemState, merge
from localvault.sync.group import GroupKey, decode_view
from localvault.sync.lan_address import LAN_NETWORKS, is_lan_address
from localvault.sync.lan_sync import CHUNK_BYTES, ERROR_REASONS, parse_message
from localvault.sync.pairing import (
    DeviceIdentity,
    PairedDevice,
    PairingError,
    PairingOffer,
    PairingSession,
    build_enrollment_request,
    create_pairing_offer,
    offer_qr_payload,
    open_enrollment_reply,
    parse_qr_payload,
)
from localvault.sync.transport import (
    AuthenticationError,
    SecureChannel,
    SessionHello,
    verify_session_hello,
)
from localvault.updates import canonical_json

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "sync"
SCRIPT = ROOT / "scripts" / "make_sync_vectors.py"
DEVICES = ("A", "B", "C")
#: Production-KDF Argon2id evaluations one full generation performs: create, join B, join C,
#: and rotate (reuse check against the old wrap + wrap of the new password) = 5; the two
#: existing-group keyrings and the attach = 3; the NFC / NFD password pair = 2.
EXPECTED_ARGON2_CALLS = 10


def _load_generator():
    spec = importlib.util.spec_from_file_location("make_sync_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["make_sync_vectors"] = module
    spec.loader.exec_module(module)
    return module


def _json(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _identity(name: str) -> DeviceIdentity:
    return DeviceIdentity.from_protected_dict(_json("identities.json")["devices"][name]["private"])


def _group_key(epoch: int) -> GroupKey:
    expected = _json("expected.json")
    entry = expected["epochs"][str(epoch)]
    return GroupKey(expected["group_id"], epoch, bytes.fromhex(entry["group_key_hex"]))


def _view_states(name: str) -> list[ItemState]:
    raw = (VECTORS / "devices" / f"{name}.lgksync").read_bytes()
    identity_id = _json("identities.json")["devices"][name]["device_id"]
    return list(decode_view(_group_key(1), raw, expected_device_id=identity_id).states)


def _dump(states) -> list[dict]:
    return [
        {
            "id": s.item_id,
            "vv": s.vv,
            "deleted": s.deleted,
            "deleted_at": s.deleted_at,
            "item": s.item,
            "canonical_sha256": None if s.item is None else hashlib.sha256(canonical_json(s.item)).hexdigest(),
        }
        for s in sorted(states, key=lambda s: s.item_id)
    ]


def _fold(order: tuple[str, ...], views: dict[str, list[ItemState]]) -> dict[str, ItemState]:
    local = {s.item_id: s for s in views[order[0]]}
    for name in order[1:]:
        out = merge(local, views[name])
        for state in (*out.upserts, *out.deletes, *out.copies):
            local[state.item_id] = state
    return local


def test_generator_reproduces_committed_files_byte_for_byte(tmp_path, monkeypatch):
    generator = _load_generator()
    calls = []
    real = kr._argon2

    def counting(password, salt, profile):
        calls.append(profile)
        return real(password, salt, profile)

    monkeypatch.setattr(kr, "_argon2", counting)
    started = time.monotonic()
    out = tmp_path / "sync"
    generator.generate(out)
    elapsed = time.monotonic() - started

    assert elapsed < 30
    assert len(calls) == EXPECTED_ARGON2_CALLS
    assert set(calls) == {(131072, 4, 4)}, "vectors must use the production Argon2id parameters"

    fresh = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    # from_ios/ and from_android/ are written by the phone cores (LGK_WRITE_FROM_IOS=1 swift test,
    # LGK_WRITE_FROM_ANDROID=1 gradlew :lgk-core:test), not by this generator.
    committed = sorted(
        rel for rel in (p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*") if p.is_file())
        if not rel.startswith(("from_ios/", "from_android/"))
    )
    assert fresh == committed
    for rel in committed:
        assert (out / rel).read_bytes() == (VECTORS / rel).read_bytes(), rel
    # regeneration into a second directory is stable too (no hidden clock or randomness)
    assert generator.GENERATED_FILES == tuple(committed)


def test_committed_files_are_byte_exact_in_git_and_use_lf():
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    for line in ("*.lgksync binary", "*.bin binary", "tests/vectors/** -text"):
        assert line in attributes
    for rel in ("README.md", "identities.json", "expected.json", "expected_merge.json",
                "keyring_epoch1.json", "keyring_epoch2.json", "lan/expected_lan.json",
                "lan/session.json", "lan/messages.json", "lan/lan_ranges.json"):
        assert b"\r" not in (VECTORS / rel).read_bytes(), rel


@pytest.mark.parametrize("order", list(itertools.permutations(DEVICES)))
def test_decode_and_merge_in_every_order_matches_expected(order):
    views = {name: _view_states(name) for name in DEVICES}
    local = _fold(order, views)
    expected = _json("expected_merge.json")
    assert _dump(local.values()) == expected["engine_states"]


def test_expected_merge_describes_the_conflict_copies_in_both_forms():
    from localvault.sync.engine import conflict_copy_id
    from localvault.sync.vault_bridge import CONFLICT_SUFFIX

    expected = _json("expected_merge.json")
    engine = {s["id"]: s for s in expected["engine_states"]}
    stored = {s["id"]: s for s in expected["bridge_stored_states"]}
    assert set(engine) == set(stored)
    copies = expected["conflict_copies"]
    assert {c["original_id"] for c in copies} == {
        "11111111-aaaa-4000-8000-000000000001",  # newest updated_at wins
        "77777777-aaaa-4000-8000-000000000007",  # equal updated_at: digest tie-break
    }
    for state in (*engine.values(), *stored.values()):
        item = state["item"]
        digest = None if item is None else hashlib.sha256(canonical_json(item)).hexdigest()
        assert state["canonical_sha256"] == digest
    for copy in copies:
        cid = copy["copy_id"]
        loser = copy["loser_wrapper"]
        assert copy["content_digest"] == hashlib.sha256(canonical_json(loser)).hexdigest()
        assert cid == conflict_copy_id(copy["original_id"], copy["content_digest"])
        # engine form: loser wrapper with the top-level id set to the copy id, label untouched
        assert engine[cid]["item"] == {**loser, "id": cid}
        assert not engine[cid]["item"]["record"]["label"].endswith(CONFLICT_SUFFIX)
        # stored form: no top-level id, record id = copy id, suffix on the label (entry namespace)
        wrapper = stored[cid]["item"]
        assert set(wrapper) == {"ns", "schema", "updated_at", "record"}
        assert wrapper["schema"] == 1
        assert wrapper["record"]["id"] == cid
        assert wrapper["record"]["label"] == loser["record"]["label"] + CONFLICT_SUFFIX
        assert stored[cid]["vv"] == engine[cid]["vv"]
    copy_ids = {c["copy_id"] for c in copies}
    for item_id, state in stored.items():
        if item_id not in copy_ids:
            assert state == engine[item_id]


def test_tie_item_exercises_equal_updated_at_and_canonical_edge_cases():
    views = {name: {s.item_id: s for s in _view_states(name)} for name in DEVICES}
    tie = "77777777-aaaa-4000-8000-000000000007"
    a, b = views["A"][tie].item, views["B"][tie].item
    assert a["updated_at"] == b["updated_at"] and a != b
    row = a["record"]["custom_fields"][0]
    assert row["f_neg_zero"] == 0.0 and str(row["f_neg_zero"]) == "-0.0"
    assert row["f_100"] == 100 and isinstance(row["f_100"], float) and row["i_2p62"] == 2**62
    text = canonical_json(a).decode("utf-8")
    for token in ('"f_0_1":0.1', '"f_1e-07":1e-07', '"f_1e+16":1e+16', '"f_100":100.0', '"f_neg_zero":-0.0',
                  '"i_2p62":4611686018427387904'):
        assert token in text, token
    # keys sort by code point: U+FF5A before U+1F511 (UTF-16 order would put the emoji first)
    assert text.index('"ｚ"') < text.index('"\U0001f511"')


class _Lease:
    def check(self) -> None:
        return None


@pytest.mark.parametrize("order", list(itertools.permutations(DEVICES)))
def test_real_vault_apply_in_every_order_equals_bridge_stored_states(tmp_path, order):
    """Drive the real bridge (local_view / merge / apply) over a real vault in each device order."""
    from localvault.sync.vault_bridge import apply, local_view
    from localvault.vault import create_vault

    views = {name: _view_states(name) for name in DEVICES}
    device = _json("identities.json")["devices"]["A"]["device_id"]
    now = 1790000000 + 1000
    kdf = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
    session = create_vault(tmp_path / "vault.json", "synthetic master", kdf_overrides=kdf)
    lease = _Lease()
    for name in order:
        outcome = merge(local_view(session, lease, device_id=device, now=now), views[name])
        apply(session, lease, outcome, device_id=device, now=now)
    final = local_view(session, lease, device_id=device, now=now)
    assert _dump(final.values()) == _json("expected_merge.json")["bridge_stored_states"]
    # a second pass over every file changes nothing (idempotent, no new copies)
    for name in order:
        outcome = merge(local_view(session, lease, device_id=device, now=now), views[name])
        assert not (outcome.upserts or outcome.deletes or outcome.copies)


def test_keyrings_verify_and_chain_from_epoch_1_to_epoch_2():
    ring1, ring2 = _json("keyring_epoch1.json"), _json("keyring_epoch2.json")
    expected = _json("expected.json")
    a, b = _identity("A"), _identity("B")
    gk1, gk2 = _group_key(1), _group_key(2)
    assert expected["password_epoch1"] == "correct horse battery staple 42"
    assert expected["password_epoch2"] == "violet tram sundial 1987 pebble"
    assert ring1["group_id"] == ring2["group_id"] == expected["group_id"]
    assert [m["device_id"] for m in ring1["members"]] == [
        _json("identities.json")["devices"][n]["device_id"] for n in DEVICES
    ]
    assert [m["device_id"] for m in ring2["members"]] == [a.device_id, b.device_id]
    for ring in (ring1, ring2):
        kr.verify_keyring_structure(ring)
    assert kr.accept_keyring(ring1, gk1, a) == gk1
    chained = kr.accept_keyring(ring2, gk1, a)
    assert chained == gk2
    assert kr.accept_keyring(ring2, gk1, b) == gk2
    assert kr.accept_keyring(ring2, gk2, a) == gk2
    with pytest.raises(kr.KeyringError) as caught:
        kr.accept_keyring(ring2, gk1, _identity("C"))
    assert caught.value.reason == "not-member"
    with pytest.raises(kr.KeyringError) as caught:
        kr.accept_keyring(ring1, gk2, a)
    assert caught.value.reason == "rollback"
    assert kr.open_with_device_wrap(ring1, _identity("C")) == gk1
    # the A+B intermediate keyring is a prefix of epoch 1 (join history)
    ring_ab = _json("keyring_epoch1_ab.json")
    assert [m["device_id"] for m in ring_ab["members"]] == [a.device_id, b.device_id]
    assert ring_ab["password_wrap"] == ring1["password_wrap"] and ring_ab["kdf"] == ring1["kdf"]


def test_expected_group_keys_derive_the_documented_subkeys():
    expected = _json("expected.json")
    for epoch in ("1", "2"):
        entry = expected["epochs"][epoch]
        gk = _group_key(int(epoch))
        assert gk.record_key().hex() == entry["record_key_hex"]
        assert gk.file_key().hex() == entry["file_key_hex"]
        assert kr._mac_key(gk.key, gk.group_id, gk.epoch).hex() == entry["keyring_mac_key_hex"]
        assert len(entry["password_wrap_key_hex"]) == 64


def test_member_names_decrypt_independently():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    expected = _json("expected.json")
    devices = _json("identities.json")["devices"]
    plain = {devices[n]["device_id"]: devices[n]["name"] for n in DEVICES}
    for epoch, ring in ((1, _json("keyring_epoch1.json")), (2, _json("keyring_epoch2.json"))):
        gk = _group_key(epoch)
        key = HKDF(hashes.SHA256(), 32, gk.group_id.encode(),
                   b"localgatekeys|sync|member-name|v1|" + str(epoch).encode()).derive(gk.key)
        assert key.hex() == expected["epochs"][str(epoch)]["member_name_key_hex"]
        names = {}
        for m in ring["members"]:
            assert "name" not in m
            raw = base64.b64decode(m["name_ct"])
            aad = (b"lgk-keyring-member-name-v1|" + gk.group_id.encode() + b"|" + str(epoch).encode() + b"|"
                   + m["device_id"].encode())
            names[m["device_id"]] = AESGCM(key).decrypt(raw[:12], raw[12:], aad).decode("utf-8")
        assert names == expected["epochs"][str(epoch)]["member_names"] == kr.member_names(ring, gk)
        assert names == {d: plain[d] for d in names}


def test_device_files_carry_the_scenario_the_readme_promises():
    views = {name: {s.item_id: s for s in _view_states(name)} for name in DEVICES}
    headers = {}
    for name in DEVICES:
        raw = (VECTORS / "devices" / f"{name}.lgksync").read_bytes()
        headers[name] = decode_view(_group_key(1), raw).header
        assert headers[name]["epoch"] == 1
    assert [headers[n]["counter"] for n in DEVICES] == [7, 4, 3]
    tombstones = [s for s in views["C"].values() if s.deleted]
    assert tombstones, "C must publish a tombstone"
    kinds = {(s.item["ns"], s.item["record"]["kind"]) for v in views.values() for s in v.values() if not s.deleted}
    assert {("entry", "web"), ("entry", "desktop"), ("item", "note")} <= kinds
    edited = [i for i in views["A"] if i in views["B"] and not views["A"][i].deleted
              and views["A"][i].item != views["B"][i].item]
    tie = "77777777-aaaa-4000-8000-000000000007"
    assert edited and all(
        views["A"][i].item["updated_at"] != views["B"][i].item["updated_at"] for i in edited if i != tie
    )


def test_lan_files_decode_and_match_expected_lan():
    expected = _json("lan/expected_lan.json")
    qr = (VECTORS / "lan" / "qr_payload.txt").read_text(encoding="ascii")
    assert qr == expected["qr_payload"] and "\n" not in qr
    bundle = parse_qr_payload(qr)
    assert bundle == expected["offer_bundle"]
    assert type(bundle["expires_at"]) is int and bundle["expires_at"] == 1790000120

    offer = PairingOffer.from_bundle_dict(bundle)
    inviter, invitee = _identity("A"), _identity("B")
    framing = expected["framing"]
    assert framing["request_magic_hex"] == b"LGKENROLL1\n".hex()
    assert framing["reply_magic_hex"] == b"LGKENROLLOK1\n".hex()
    assert framing["refused_magic_hex"] == b"LGKENROLLNO1\n".hex()
    assert _json("expected.json")["view_magic_hex"] == b"LGKSYNC1\n".hex()
    for suffix, req_key, rep_key in (("", "request", "reply"),
                                      ("_no_endpoint", "request_no_endpoint", "reply_no_endpoint")):
        request_raw = (VECTORS / "lan" / f"enroll_request{suffix}.bin").read_bytes()
        reply_raw = (VECTORS / "lan" / f"enroll_reply{suffix}.bin").read_bytes()
        assert request_raw.startswith(bytes.fromhex(framing["request_magic_hex"]))
        assert reply_raw.startswith(bytes.fromhex(framing["reply_magic_hex"]))
        want_req, want_rep = expected[req_key], expected[rep_key]
        peer, request = PairingSession(offer).accept_enrollment(inviter, request_raw, now=expected["now"])
        assert request.device_id == invitee.device_id == want_req["device_id"]
        if suffix:
            assert request.endpoint is None and want_req["invitee_endpoint"] is None
            assert '"invitee_endpoint":null' in want_req["transcript"]
        else:
            assert list(request.endpoint) == want_req["endpoint_list"]
        assert request.transcript.decode("ascii") == want_req["transcript"]
        assert hashlib.sha256(request.transcript).hexdigest() == want_req["transcript_sha256_hex"]
        assert peer.fingerprint == invitee.fingerprint
        body = json.loads(want_req["plaintext"])
        assert set(body) == {"version", "offer_id", "device_id", "signing_public", "exchange_public",
                             "endpoint", "signature", "mac"}
        group_id, epoch, key = open_enrollment_reply(offer, invitee, reply_raw, endpoint=request.endpoint)
        assert (group_id, epoch) == (want_rep["group_id"], want_rep["epoch"])
        assert key == _group_key(1).key and key.hex() == want_rep["key_hex"]
        assert base64.b64encode(key).decode() == want_rep["key_b64"]
        assert json.loads(want_rep["plaintext"]) == {
            "group_id": group_id, "epoch": epoch, "key": want_rep["key_b64"],
            "device_id": invitee.device_id, "signing_public": b64(invitee.signing_public_key),
        }
        assert len(bytes.fromhex(want_req["hkdf_key_hex"])) == len(bytes.fromhex(want_rep["hkdf_key_hex"])) == 32


def _paired(name: str) -> PairedDevice:
    ident = _identity(name)
    return PairedDevice(ident.device_id, _json("expected.json")["group_id"], ident.signing_public_key,
                        ident.exchange_public_key, ident.fingerprint, 0.0, bytes(64))


def _lan_bin(name: str) -> bytes:
    """A frame .bin file: the 4-byte big-endian length prefix is part of the file."""
    raw = (VECTORS / "lan" / name).read_bytes()
    assert int.from_bytes(raw[:4], "big") == len(raw) - 4, name
    return raw


def _check_session(session: dict, group_id: str) -> tuple[bytes, SessionHello, SessionHello]:
    """Verify both hellos with the pinned identities and re-derive the session key independently."""
    roles = {"initiator": (session["initiator_device"], session["responder_device"]),
             "responder": (session["responder_device"], session["initiator_device"])}
    hellos = {}
    for role, (device, other) in roles.items():
        entry = session["hello"][role]
        hello = SessionHello.from_bytes(entry["text"].encode("ascii"))
        assert entry["device"] == device and hello.device_id == _identity(device).device_id
        assert hello.to_bytes().decode("ascii") == entry["text"]
        assert hello.signing_bytes().hex() == entry["signing_input_hex"]
        assert hello.nonce.hex() == entry["nonce_hex"] and len(hello.nonce) == 32
        assert hello.counter == entry["counter"]
        assert hello.session_id.hex() == session["session_id"]
        # the signature, checked with the raw Ed25519 public key over the published signing input
        ed25519.Ed25519PublicKey.from_public_bytes(hello.signing_public).verify(
            hello.signature, bytes.fromhex(entry["signing_input_hex"]))
        verify_session_hello(hello, group_id, _paired(device))
        with pytest.raises(AuthenticationError):  # the other device's pin must not accept it
            verify_session_hello(hello, group_id, _paired(other))
        hellos[role] = hello
    texts = [hellos["initiator"].to_bytes(), hellos["responder"].to_bytes()]
    transcript = b"".join(sorted(texts))
    assert transcript.hex() == session["transcript_sorted_hex"]
    first = "initiator" if sorted(texts)[0] == texts[0] else "responder"
    assert first == session["sorted_first"]
    salt = hashlib.sha256(b"localgatekeys|sync|session-salt|" + transcript).digest()
    assert salt.hex() == session["salt"]
    shared = _identity(session["initiator_device"]).exchange_key.exchange(
        x25519.X25519PublicKey.from_public_bytes(_identity(session["responder_device"]).exchange_public_key))
    assert shared.hex() == session["shared_secret_hex"]
    sid = bytes.fromhex(session["session_id"])
    info = b"localgatekeys|sync|session-key|" + sid
    assert info.hex() == session["info_hex"]
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)
    assert key.hex() == session["key"]
    for role in ("initiator", "responder"):
        assert hashlib.sha256(key + b"send|" + role.encode()).digest()[:4].hex() == session["prefix_" + role]
    return key, hellos["initiator"], hellos["responder"]


def _open_frame(session: dict, frame: bytes, expected: dict) -> bytes:
    key, sid = bytes.fromhex(session["key"]), bytes.fromhex(session["session_id"])
    assert int.from_bytes(frame[:4], "big") == len(frame) - 4
    outer = json.loads(frame[4:])
    nonce = base64.b64decode(outer["nonce"])
    assert nonce.hex() == expected["nonce"] and outer["counter"] == expected["counter"] == 1
    assert nonce[:4].hex() == session["prefix_" + expected["sender"]]
    assert int.from_bytes(nonce[4:], "big") == outer["counter"]
    metadata = {k: v for k, v in outer.items() if k != "ciphertext"}
    aad = json.dumps(metadata, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    assert aad.decode("ascii") == expected["aad"] and metadata["session_id"] == b64(sid)
    plain = AESGCM(key).decrypt(nonce, base64.b64decode(outer["ciphertext"]), aad)
    assert len(plain) == expected["plaintext_size"] and len(frame) == expected["frame_size"]
    assert hashlib.sha256(plain).hexdigest() == expected["plaintext_sha256"]
    assert hashlib.sha256(frame).hexdigest() == expected["frame_sha256"]
    return plain


def _channel(role: str, sid: bytes, group_id: str, hello_i: SessionHello, hello_r: SessionHello,
             session: dict) -> SecureChannel:
    device = session[role + "_device"]
    other = session[("responder" if role == "initiator" else "initiator") + "_device"]
    local, remote = (hello_i, hello_r) if role == "initiator" else (hello_r, hello_i)
    return SecureChannel.from_paired_identities(
        _identity(device), _paired(other), group_id=group_id, session_id=sid, role=role,
        local_hello=local, remote_hello=remote)


def _open_both(session: dict, group_id: str, frames: dict[str, bytes]) -> dict[str, bytes]:
    """Check a connection: key re-derivation, both frames decrypt independently and through the channels."""
    key, hello_i, hello_r = _check_session(session, group_id)
    sid = bytes.fromhex(session["session_id"])
    out = {}
    for role, receiver in (("request", "responder"), ("response", "initiator")):
        entry = session[role]
        plain = _open_frame(session, frames[role], {**entry, "sender": "initiator" if role == "request" else "responder"})
        channel = _channel(receiver, sid, group_id, hello_i, hello_r, session)
        assert channel.open(frames[role]) == plain
        message = parse_message(plain)
        if "plaintext" in entry:
            assert plain.decode("ascii") == entry["plaintext"]
        out[role] = message
        out[role + "_raw"] = plain
    return out


def test_lan_session_vectors_verify_and_decrypt():
    vector = _json("lan/session.json")
    group_id = _json("expected.json")["group_id"]
    by_name = {s["name"]: s for s in vector["sessions"]}
    assert set(by_name) == {"a-initiates", "b-initiates", "counters-9-10"}
    for session in vector["sessions"]:
        frames = {role: bytes.fromhex(session[role]["frame_hex"]) for role in ("request", "response")}
        opened = _open_both(session, group_id, frames)
        assert opened["request"]["type"] == "next" and opened["response"] == {"type": "error", "reason": "bad-chunk"}
    # the transcript is sorted bytewise: never initiator-then-responder, never by counter
    assert by_name["a-initiates"]["sorted_first"] == "initiator"
    assert by_name["b-initiates"]["initiator_device"] == "B" and by_name["b-initiates"]["sorted_first"] == "responder"
    nine_ten = by_name["counters-9-10"]
    assert [nine_ten["hello"][r]["counter"] for r in ("initiator", "responder")] == [9, 10]
    assert nine_ten["sorted_first"] == "responder"
    assert nine_ten["hello"]["responder"]["text"].startswith('{"counter":10,')
    assert nine_ten["hello"]["initiator"]["text"].startswith('{"counter":9,')
    # the first connection is also available as raw files
    first = by_name["a-initiates"]
    assert _lan_bin("hello_initiator.bin")[4:].decode("ascii") == first["hello"]["initiator"]["text"]
    assert _lan_bin("hello_responder.bin")[4:].decode("ascii") == first["hello"]["responder"]["text"]
    assert _lan_bin("frame_initiator.bin").hex() == first["request"]["frame_hex"]
    assert _lan_bin("frame_responder.bin").hex() == first["response"]["frame_hex"]


def test_lan_message_vectors_two_chunk_exchange():
    messages = _json("lan/messages.json")
    group_id = _json("expected.json")["group_id"]
    assert messages["chunk_bytes"] == CHUNK_BYTES == 524288
    conns = messages["connections"]
    assert len(conns) == 3 and len({c["session_id"] for c in conns}) == 3 and len({c["key"] for c in conns}) == 3
    shapes = [((c["request"]["type"], c["request"]["seq"]), (c["response"]["type"], c["response"]["seq"])) for c in conns]
    assert shapes == [(("view", 0), ("ack", 0)), (("view", 1), ("view", 0)), (("next", 1), ("view", 1))]
    chunks: dict[str, list[bytes]] = {}
    for conn in conns:
        assert conn["initiator_device"] == "A" and conn["responder_device"] == "B"
        frames = {role: _lan_bin(conn[role]["file"]) for role in ("request", "response")}
        assert all(conn[role]["file"].startswith("messages/") for role in frames)
        opened = _open_both(conn, group_id, frames)
        for role in ("request", "response"):
            message = opened[role]
            assert message["type"] == conn[role]["type"] and message["seq"] == conn[role]["seq"]
            assert message["transfer"] == conn[role]["transfer"] and len(message["transfer"]) == 32
            assert ("plaintext" in conn[role]) == (conn[role]["plaintext_size"] < 4096)
            if message["type"] == "view":
                assert message["group_id"] == group_id and message["epoch"] == messages["epoch"]
                assert message["total"] == 2
                chunks.setdefault(message["transfer"], []).append(base64.b64decode(message["view"]))
    devices = _json("identities.json")["devices"]
    for role, device in (("initiator", "A"), ("responder", "B")):
        info = messages["views"][role]
        parts = chunks[info["transfer"]]
        assert len(parts) == info["total"] == 2
        assert len(parts[0]) == CHUNK_BYTES and len(parts[1]) == info["size"] - CHUNK_BYTES > 0
        raw = b"".join(parts)
        assert len(raw) == info["size"] and hashlib.sha256(raw).hexdigest() == info["sha256"]
        assert 0 <= info["size"] - CHUNK_BYTES - 1000 < 8
        view = decode_view(_group_key(1), raw, expected_device_id=devices[device]["device_id"])
        assert len(view.states) == info["items"]
    # the committed vector directory holds exactly the listed frame files
    listed = {c[r]["file"] for c in conns for r in ("request", "response")}
    on_disk = {p.relative_to(VECTORS / "lan").as_posix() for p in (VECTORS / "lan" / "messages").glob("*")}
    assert listed == on_disk


def test_lan_error_message_vectors_cover_every_reason():
    errors = _json("lan/messages.json")["errors"]
    assert [e["reason"] for e in errors] == list(ERROR_REASONS) and len(set(ERROR_REASONS)) == len(ERROR_REASONS)
    for entry in errors:
        assert parse_message(entry["plaintext"].encode("ascii")) == {"type": "error", "reason": entry["reason"]}


def test_error_reasons_match_the_reasons_lan_sync_can_send():
    """ERROR_REASONS = the literals of every ``_error("...")`` call, the reasons of the LanSyncError
    values that are passed on as ``exc.reason``, and the two computed in ``_serve``."""
    path = ROOT / "src" / "localvault" / "sync" / "lan_sync.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_error"
                and node.args and isinstance(node.args[0], ast.Constant)):
            found.add(node.args[0].value)
    passed_on = {"parse_message", "_receive_chunk", "_prepare_view"}  # raise LanSyncError, _serve sends exc.reason
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in passed_on:
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and getattr(call.func, "id", "") == "LanSyncError"
                        and isinstance(call.args[0], ast.Constant)):
                    found.add(call.args[0].value)
    found |= {"device-mismatch", "bad-view"}  # the computed ``reason`` in _serve
    assert found == set(ERROR_REASONS)


def test_lan_ranges_vector_matches_the_table_and_the_code():
    ranges = _json("lan/lan_ranges.json")
    assert ranges["networks"] == [str(n) for n in LAN_NETWORKS]
    cases = _load_generator().LAN_RANGE_CASES
    assert [[c["address"], c["lan"]] for c in ranges["cases"]] == [list(c) for c in cases]
    assert {"address": "fe80::1%eth0", "lan": False} in ranges["cases"]
    for case in ranges["cases"]:
        assert is_lan_address(ipaddress.ip_address(case["address"])) is case["lan"]


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _offer_bundle() -> dict:
    return dict(json.loads(json.dumps(_json("lan/expected_lan.json")["offer_bundle"])))


@pytest.mark.parametrize("bad", [1790000120.0, 1790000120.5, True, "1790000120", None, 0, -5, 2**53])
def test_offer_expiry_must_be_a_strict_positive_int(bad):
    bundle = _offer_bundle()
    bundle["expires_at"] = bad
    with pytest.raises(PairingError):
        PairingOffer.from_bundle_dict(bundle)


def test_offer_code_and_offer_id_are_ascii_only():
    for code in ("٤٨١٧٣٥٢٠", "1234567", "123456789", "abcdefgh"):
        bundle = _offer_bundle()
        bundle["code"] = code
        with pytest.raises(PairingError):
            PairingOffer.from_bundle_dict(bundle)
    for offer_id in ("café", "a b", "x" * 129, ""):
        bundle = _offer_bundle()
        bundle["offer_id"] = offer_id
        with pytest.raises(PairingError):
            PairingOffer.from_bundle_dict(bundle)


def test_integer_expiry_round_trips_and_verifies_python_to_python():
    inviter, invitee = _identity("A"), _identity("B")
    offer = create_pairing_offer(inviter, "group-1", "192.168.1.20", 48201, now=1790000000.25)
    assert type(offer.expires_at) is int and offer.expires_at == 1790000001 + 120  # ceil(created) + ttl
    qr_offer = PairingOffer.from_bundle_dict(parse_qr_payload(offer_qr_payload(offer)))
    assert qr_offer == offer and qr_offer.public_dict() == offer.public_dict()
    request = build_enrollment_request(qr_offer, invitee, now=1790000010)
    _peer, verified = PairingSession(offer).accept_enrollment(inviter, request, now=1790000010)
    assert verified.device_id == invitee.device_id


def test_production_code_never_passes_the_test_hooks():
    """Only the defining modules may mention the hooks, and only to forward their own parameters."""
    hooks = {"_rand", "_now", "_group_id", "_eph_seed", "_nonce", "nonce_source"}
    hooked_functions = {"create_group", "join_with_password", "rotate", "build_enrollment_request",
                        "seal_enrollment_reply", "encode_view", "seal_item"}
    allowed_names = {  # parameter names a defining module may forward (keyword -> accepted Name ids)
        "_rand": {"_rand", "rand"},
        "_now": {"_now", "now"},
        "_group_id": {"_group_id"},
        "_eph_seed": {"_eph_seed"},
        "_nonce": {"_nonce"},
        "nonce_source": {"nonce_source", "unique_nonces"},
    }
    defining = {"sync/keyring.py", "sync/pairing.py", "sync/group.py", "sync/transport.py"}
    src = ROOT / "src" / "localvault"
    for path in sorted(src.rglob("*.py")):
        rel = path.relative_to(src).as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            for kw in node.keywords:
                if kw.arg is None:
                    assert func not in hooked_functions, (rel, node.lineno, "** splat into a hooked function")
                    continue
                if kw.arg not in hooks:
                    continue
                assert rel in defining, (rel, node.lineno, kw.arg)
                assert isinstance(kw.value, ast.Name) and kw.value.id in allowed_names[kw.arg], (
                    rel, node.lineno, kw.arg)
            if func in hooked_functions and rel not in defining:
                assert not any(isinstance(a, ast.Starred) for a in node.args), (rel, node.lineno)


def test_without_hooks_keyrings_and_enrollment_stay_random():
    cheap = (1024, 1, 1)
    password = "correct horse battery staple 42"
    ident = DeviceIdentity.generate()
    one, gk_one = kr.create_group(password, ident, "A", _kdf_override=cheap)
    two, gk_two = kr.create_group(password, ident, "A", _kdf_override=cheap)
    assert one["group_id"] != two["group_id"] and gk_one.key != gk_two.key
    assert one["kdf"]["salt"] != two["kdf"]["salt"] and one["password_wrap"] != two["password_wrap"]
    with pytest.raises(kr.KeyringError) as caught:
        kr.create_group(password, ident, "A", _kdf_override=cheap, _rand=lambda n: b"\x00")
    assert caught.value.reason == "bad-random"


# --- normalisation vectors ---------------------------------------------------------------------

_NORM_REQUIRED_ENTRY_CASES = {
    "origin_upper_case_scheme_and_host", "origin_default_https_port", "origin_trailing_dot",
    "origin_ipv6_upper_case_with_port", "origin_localhost_http_with_port",
    "origin_plain_http_rejected", "origin_with_path_rejected", "origin_idna_umlaut",
    "origin_idna_sharp_s_non_transitional", "origin_idna_japanese", "urls_bare_string_row",
    "urls_each_match_mode", "urls_duplicate_row_dropped", "urls_bad_match_mode", "totp_minimal",
    "totp_all_fields", "totp_digits_7", "totp_period_15", "totp_period_120", "totp_extra_scalar_key",
    "totp_digits_5_rejected", "totp_digits_9_rejected", "totp_period_14_rejected",
    "totp_period_121_rejected", "totp_algorithm_not_text_rejected", "totp_secret_not_text_rejected",
    "totp_empty_secret_kept", "custom_fields_name_value_hidden", "custom_fields_int_float_null",
    "custom_fields_16_keys", "custom_fields_17_keys_rejected", "policy_missing", "policy_full_dict",
    "policy_unknown_key", "policy_is_a_list", "policy_fill_auto", "policy_fill_unknown_value",
    "tags_plain", "password_history_replaced_at", "desktop_exe_sha256_upper_case",
    "desktop_exe_sha256_lower_case",
}
_NORM_REQUIRED_ITEM_CASES = {
    "note_minimal", "note_already_normal", "card_minimal", "identity_minimal", "identity_populated",
    "identity_template_id_null",
    "tags_case_fold_dedup", "id_upper_case_uuid",
}
_DEFAULT_POLICY = {"fill": "click", "require_master_password": False, "save_prompts": True}


def _norm_cases(name: str) -> list[dict]:
    return json.loads((VECTORS / "normalise" / name).read_text(encoding="utf-8"))["cases"]


_NORM_PARAMS = [
    pytest.param(ns, case, id=f"{ns}-{case['name']}")
    for ns, name in (("entry", "entries.json"), ("item", "items.json"))
    for case in _norm_cases(name)
]


@pytest.mark.parametrize(("ns", "case"), _NORM_PARAMS)
def test_normalisation_vector_matches_normal_form(ns, case):
    from localvault.item_schema import ItemSchemaError
    from localvault.origin import OriginError
    from localvault.sync.vault_bridge import normal_form
    from localvault.totp import TotpError
    from localvault.vault import VaultError

    assert set(case) - {"detail"} == {"name", "ns", "input", "output", "error", "already_normal"}
    assert case["ns"] == ns
    assert case["error"] in (None, "rejected")
    wire = json.loads(json.dumps(case["input"]))
    if case["error"] is None:
        assert "detail" not in case
        output = normal_form(ns, wire)
        assert canonical_json(output) == canonical_json(case["output"])
        assert case["already_normal"] is (canonical_json(case["input"]) == canonical_json(case["output"]))
    else:
        assert case["output"] is None and case["already_normal"] is False
        with pytest.raises((VaultError, ItemSchemaError, TotpError, OriginError)):
            normal_form(ns, wire)


@pytest.mark.parametrize(("name", "required"), [
    ("entries.json", _NORM_REQUIRED_ENTRY_CASES),
    ("items.json", _NORM_REQUIRED_ITEM_CASES),
])
def test_normalisation_vectors_list_the_required_cases(name, required):
    names = [c["name"] for c in _norm_cases(name)]
    assert required <= set(names)
    assert len(set(names)) == len(names)


def test_normalisation_vectors_have_hard_anchors():
    by_name = {c["name"]: c for c in _norm_cases("entries.json")}
    assert by_name["origin_plain_http_rejected"]["error"] == "rejected"
    assert by_name["policy_is_a_list"]["output"]["policy"] == _DEFAULT_POLICY
    assert by_name["origin_idna_umlaut"]["output"]["scope"]["origin"] == "https://xn--bcher-kva.example"
    assert by_name["desktop_exe_sha256_lower_case"]["output"]["scope"]["exe_sha256"] == "CD" * 32
    assert by_name["custom_fields_int_float_null"]["output"]["custom_fields"][0]["whole"] == 100.0
    assert by_name["plain_web_login"]["already_normal"] is True
    items = {c["name"]: c for c in _norm_cases("items.json")}
    assert items["note_already_normal"]["already_normal"] is True
    assert items["note_minimal"]["already_normal"] is False
    assert items["identity_populated"]["error"] is None
    assert items["identity_populated"]["output"]["payload"]["middle_name"] == ""
    assert items["identity_populated"]["output"]["payload"]["city"] == "Zurich"
    assert items["identity_template_id_null"]["error"] is None
    assert items["identity_template_id_null"]["output"]["payload"]["template_id"] is None


def test_normalisation_vectors_cover_both_outcomes_and_changes():
    cases = _norm_cases("entries.json") + _norm_cases("items.json")
    assert any(c["error"] for c in cases)
    assert any(c["error"] is None and c["already_normal"] for c in cases)
    assert any(c["error"] is None and not c["already_normal"] for c in cases)


# --- canonical JSON known answers, existing-group keyrings, licence and schema cases -----------


def _utf8_canonical(value) -> bytes:
    return canonical_json(value)


def _ascii_canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


@pytest.mark.parametrize(("dialect", "encode"), [("utf8", _utf8_canonical), ("ascii", _ascii_canonical)])
def test_canonical_json_known_answers(dialect, encode):
    cases = _json("canonical_json.json")[dialect]
    assert cases
    for case in cases:
        assert set(case) == {"value_json", "canonical_hex"}
        value = json.loads(case["value_json"])
        raw = encode(value)
        assert raw.hex() == case["canonical_hex"], case["value_json"]
        assert encode(json.loads(raw.decode("utf-8"))) == raw, case["value_json"]
        if dialect == "ascii":
            assert raw.isascii()


def test_canonical_json_cases_cover_the_documented_edges():
    data = _json("canonical_json.json")
    by_json = {dialect: {c["value_json"]: bytes.fromhex(c["canonical_hex"]) for c in data[dialect]}
               for dialect in ("utf8", "ascii")}
    assert [c["value_json"] for c in data["utf8"]] == [c["value_json"] for c in data["ascii"]]
    for value_json, expected_utf8, expected_ascii in [
        ('"\\u2028"', b'"\xe2\x80\xa8"', b'"\\u2028"'),
        ('"\\u2029"', b'"\xe2\x80\xa9"', b'"\\u2029"'),
        ('"\\u007f"', b'"\x7f"', b'"\\u007f"'),
        ('"\\u0000"', b'"\\u0000"', b'"\\u0000"'),
        ('"\\u001f"', b'"\\u001f"', b'"\\u001f"'),
        ('"\\/"', b'"/"', b'"/"'),
        ('"\\ud83d\\udd11"', '"\U0001f511"'.encode(), b'"\\ud83d\\udd11"'),
        ("1e15", b"1000000000000000.0", b"1000000000000000.0"),
        ("1e16", b"1e+16", b"1e+16"),
        ("0.1", b"0.1", b"0.1"),
        ("-0.0", b"-0.0", b"-0.0"),
        ("1e-07", b"1e-07", b"1e-07"),
        ("9007199254740992", b"9007199254740992", b"9007199254740992"),
        ("9223372036854775807", b"9223372036854775807", b"9223372036854775807"),
    ]:
        assert by_json["utf8"][value_json] == expected_utf8, value_json
        assert by_json["ascii"][value_json] == expected_ascii, value_json


def test_canonical_json_rejected_cases_name_the_decoder_that_rejects_them():
    from localvault.sync.engine import EngineError

    rejected = _json("canonical_json.json")["rejected"]
    by_text = {c["text"]: c for c in rejected}
    assert len(by_text) == len(rejected) == 5
    for case in rejected:
        assert set(case) == {"text", "reason", "rejected_by"}
        assert case["reason"] and case["rejected_by"]
        assert set(case["rejected_by"]) <= {"engine_item_state", "canonical_encoder", "strict_parser"}

    def rejects(case, decoder) -> bool:
        text = case["text"]
        try:
            if decoder == "strict_parser":
                kr.parse_keyring(text.encode("utf-8"))
            elif decoder == "canonical_encoder":
                canonical_json(json.loads(text))
            else:
                ItemState("x", {"A": 1}, False, None, json.loads(text))
        except (kr.KeyringError, ValueError, EngineError):
            return True
        return False

    for case in rejected:
        for decoder in ("engine_item_state", "canonical_encoder", "strict_parser"):
            assert rejects(case, decoder) is (decoder in case["rejected_by"]), (case["text"], decoder)
    assert by_text['{"n":9223372036854775808}']["rejected_by"] == ["engine_item_state"]
    assert by_text['{"a":1,"a":2}']["rejected_by"] == ["strict_parser"]
    assert by_text['{"x":NaN}']["rejected_by"] == ["canonical_encoder", "engine_item_state", "strict_parser"]
    assert by_text['{"x":Infinity}']["rejected_by"] == ["canonical_encoder", "engine_item_state", "strict_parser"]
    assert by_text['{"s":"\\ud800"}']["rejected_by"] == ["canonical_encoder", "engine_item_state"]


def _existing_key(epoch: int) -> GroupKey:
    entry = _json("expected.json")["existing_group"]
    return GroupKey(entry["group_id"], epoch, bytes.fromhex(entry["epochs"][str(epoch)]["group_key_hex"]))


def test_existing_group_keyrings_verify_open_and_name_their_members():
    expected = _json("expected.json")["existing_group"]
    a, b = _identity("A"), _identity("B")
    ring1 = _json("keyring_existing_epoch1.json")
    ring3 = _json("keyring_existing_epoch3.json")
    attach = _json("keyring_attach.json")
    for ring in (ring1, ring3, attach):
        kr.verify_keyring_structure(ring)
        assert ring["group_id"] == expected["group_id"]
        assert ring["prev_mac"] is None
    assert (ring1["epoch"], ring3["epoch"], attach["epoch"]) == (1, 3, 1)
    gk1, gk3 = _existing_key(1), _existing_key(3)
    assert gk1.key != gk3.key
    assert kr.accept_keyring(ring1, gk1, a) == gk1
    assert kr.accept_keyring(ring3, gk3, a) == gk3
    assert kr.accept_keyring(attach, gk1, a) == gk1
    assert kr.accept_keyring(attach, gk1, b) == gk1
    assert kr.open_with_device_wrap(ring1, a) == gk1
    assert kr.open_with_device_wrap(ring3, a) == gk3
    assert kr.open_with_device_wrap(attach, b) == gk1
    with pytest.raises(kr.KeyringError) as caught:
        kr.open_with_device_wrap(ring1, b)
    assert caught.value.reason == "not-member"
    assert [m["device_id"] for m in ring1["members"]] == [a.device_id]
    assert [m["device_id"] for m in ring3["members"]] == [a.device_id]
    assert [m["device_id"] for m in attach["members"]] == [a.device_id, b.device_id]
    # attach extends the epoch-1 keyring: same password wrap, KDF and salt, A's entry unchanged
    assert attach["password_wrap"] == ring1["password_wrap"] and attach["kdf"] == ring1["kdf"]
    assert attach["members"][0] == ring1["members"][0]
    assert attach["device_wraps"][a.device_id] == ring1["device_wraps"][a.device_id]
    assert attach["mac"] != ring1["mac"]
    plain = {a.device_id: "Desk PC (Windows)", b.device_id: "Laptop (Windows)"}
    assert kr.member_names(ring1, gk1) == {a.device_id: plain[a.device_id]}
    assert kr.member_names(ring3, gk3) == {a.device_id: plain[a.device_id]}
    assert kr.member_names(attach, gk1) == plain
    assert expected["epochs"]["1"]["member_names"] == {a.device_id: plain[a.device_id]}
    assert expected["epochs"]["3"]["member_names"] == {a.device_id: plain[a.device_id]}
    assert expected["attach"]["member_names"] == plain
    for epoch, gk in ((1, gk1), (3, gk3)):
        entry = expected["epochs"][str(epoch)]
        assert gk.record_key().hex() == entry["record_key_hex"]
        assert gk.file_key().hex() == entry["file_key_hex"]
        assert kr._mac_key(gk.key, gk.group_id, gk.epoch).hex() == entry["keyring_mac_key_hex"]
        assert kr._name_key(gk).hex() == entry["member_name_key_hex"]
        assert len(entry["password_wrap_key_hex"]) == 64


def test_existing_group_password_wraps_open_with_the_published_keys():
    expected = _json("expected.json")["existing_group"]
    for epoch, name in ((1, "keyring_existing_epoch1.json"), (3, "keyring_existing_epoch3.json")):
        ring = _json(name)
        entry = expected["epochs"][str(epoch)]
        gk = _existing_key(epoch)
        wrap = ring["password_wrap"]
        aad = b"lgk-keyring-password-wrap-v1|" + gk.group_id.encode() + b"|" + str(epoch).encode()
        opened = AESGCM(bytes.fromhex(entry["password_wrap_key_hex"])).decrypt(
            base64.b64decode(wrap["nonce"]), base64.b64decode(wrap["ct"]), aad)
        assert opened == gk.key
        assert entry["password"] in ("correct horse battery staple 42", "violet tram sundial 1987 pebble")
    assert expected["attach"]["password"] == expected["epochs"]["1"]["password"]
    assert expected["attach"]["password_wrap_key_hex"] == expected["epochs"]["1"]["password_wrap_key_hex"]


def test_nfc_and_nfd_passwords_give_different_argon2_outputs():
    import unicodedata

    entry = _json("expected.json")["unicode_password"]
    nfc, nfd = entry["password_nfc"], entry["password_nfd"]
    assert nfc == unicodedata.normalize("NFC", nfc) and nfd == unicodedata.normalize("NFD", nfd)
    assert nfc != nfd and unicodedata.normalize("NFC", nfd) == nfc == "café sync password 42"
    assert entry["password_nfc_utf8_hex"] == nfc.encode("utf-8").hex()
    assert entry["password_nfd_utf8_hex"] == nfd.encode("utf-8").hex()
    assert entry["kdf"] == {"name": "argon2id", "memory_kib": 131072, "iterations": 4, "parallelism": 4}
    assert entry["argon2id_nfc_hex"] != entry["argon2id_nfd_hex"]
    salt = bytes.fromhex(entry["salt_hex"])
    assert len(salt) == 16
    assert kr._argon2(nfc, salt, (131072, 4, 4)).hex() == entry["argon2id_nfc_hex"]
    assert kr._argon2(nfd, salt, (131072, 4, 4)).hex() == entry["argon2id_nfd_hex"]


def test_licence_state_verifies_with_the_published_test_key(monkeypatch):
    from localvault import licensing
    from localvault.sync import vault_bridge

    state = _json("license_state.json")
    raw_key = base64.b64decode(state["public_key_b64"], validate=True)
    assert len(raw_key) == 32
    assert state["key_id"] == hashlib.sha256(raw_key).digest()[:8].hex()
    keys = {state["key_id"]: state["public_key_b64"]}
    bundle = state["bundle"]
    lic = licensing.verify_bundle(bundle, keys=keys)
    assert bundle["signature"]["key_id"] == state["key_id"]
    assert state["license"] == {
        "license_id": lic.license_id, "edition": lic.edition, "name": lic.name, "email": lic.email,
        "issued_at": lic.issued_at.isoformat(), "updates_until": lic.updates_until.isoformat(),
    }
    assert state["state_id"] == licensing.sync_state_id(lic.license_id)
    assert state["state_id"] == "lic:" + hashlib.sha256(lic.license_id.encode()).hexdigest()[:32]
    assert state["wrapper"] == {"ns": "license", "schema": 1, "updated_at": 0, "record": bundle}
    assert state["wrapper"] == vault_bridge._license_wrapper(bundle)
    assert state["wrapper_canonical_hex"] == canonical_json(state["wrapper"]).hex()
    # the production key set does not know the test key: the same bundle is refused there
    with pytest.raises(licensing.LicenseError):
        licensing.verify_bundle(bundle)
    tampered = json.loads(json.dumps(bundle))
    tampered["license"]["name"] = "Someone Else"
    with pytest.raises(licensing.LicenseError) as caught:
        licensing.verify_bundle(tampered, keys=keys)
    assert caught.value.reason == "bad-signature"
    # and the bridge accepts the wrapper as a licence state once the test key is installed
    monkeypatch.setattr(licensing, "LICENSE_KEYS", keys)
    item = ItemState(state["state_id"], {"A": 1}, False, None, state["wrapper"])
    assert vault_bridge._unwrap(item, is_copy=False) == ("license", bundle)


def test_schema_cases_go_through_the_bridge_unwrap_path():
    from localvault.sync import vault_bridge

    cases = _json("schema_cases.json")["cases"]
    assert {c["expect"] for c in cases} == {"accepted", "update-needed", "bad-remote"}
    names = [c["name"] for c in cases]
    assert len(set(names)) == len(names)
    by_name = {c["name"]: c for c in cases}
    assert by_name["entry_schema_1"]["expect"] == "accepted"
    assert by_name["entry_schema_2"]["expect"] == "update-needed"
    for bad in ("entry_schema_missing", "entry_schema_0", "entry_schema_string_1"):
        assert by_name[bad]["expect"] == "bad-remote"
    assert "schema" not in by_name["entry_schema_missing"]["wrapper"]
    assert by_name["entry_schema_string_1"]["wrapper"]["schema"] == "1"
    assert by_name["entry_schema_0"]["wrapper"]["schema"] == 0
    # the schema is checked before the wrapper key set: a newer schema may add wrapper fields
    extra = by_name["entry_schema_2_extra_wrapper_key"]
    assert extra["expect"] == "update-needed" and extra["wrapper"]["schema"] == 2
    assert set(extra["wrapper"]) - {"ns", "schema", "updated_at", "record"}
    for case in cases:
        assert set(case) == {"name", "item_id", "wrapper", "expect"}
        state = ItemState(case["item_id"], {"A": 1}, False, None, case["wrapper"])
        try:
            with vault_bridge._blame(case["item_id"]):
                ns, record = vault_bridge._unwrap(state, is_copy=False)
        except vault_bridge.BridgeError as exc:
            outcome = exc.reason
        else:
            outcome = "accepted"
            assert ns == case["wrapper"]["ns"] and record["id"] == case["item_id"]
        assert outcome == case["expect"], case["name"]


def test_licence_state_cases_go_through_the_real_bridge(tmp_path, monkeypatch):
    """Every licence case of license_state.json, applied to a real vault with the TEST key installed."""
    from localvault import licensing
    from localvault.sync.engine import MergeOutcome
    from localvault.sync.vault_bridge import BridgeError, apply, local_view
    from localvault.vault import create_vault

    state = _json("license_state.json")
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {state["key_id"]: state["public_key_b64"]})
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset())
    cases = state["cases"]
    names = [c["name"] for c in cases]
    assert len(set(names)) == len(names)
    assert {c["expect"] for c in cases} == {"accepted", "update-needed", "bad-remote", "dropped"}
    for required in ("valid", "bad_signature", "id_mismatch", "unknown_key_id", "malformed_key_id",
                     "format_2_signed", "updated_at_1", "conflict_copy"):
        assert required in names, required
    device = "device-b"
    now = 1790000000
    kdf = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
    for n, case in enumerate(cases):
        assert set(case) == {"name", "state_id", "copy", "wrapper", "expect"}
        session = create_vault(tmp_path / f"vault-{n}.json", "synthetic master", kdf_overrides=kdf)
        local_view(session, _Lease(), device_id=device, now=now)
        item = ItemState(case["state_id"], {"device-a": 1}, False, None, case["wrapper"])
        outcome = MergeOutcome((), (), (), (item,)) if case["copy"] else MergeOutcome((item,), (), ())
        try:
            report = apply(session, _Lease(), outcome, device_id=device, now=now)
        except BridgeError as exc:
            got = exc.reason
            assert exc.item_id == case["state_id"], case["name"]
            assert "sync_licenses" not in session._payload, case["name"]
        else:
            stored = session._payload.get("sync_licenses", {})
            got = "accepted" if stored else "dropped"
            if got == "accepted":
                assert stored == {case["state_id"]: case["wrapper"]["record"]}, case["name"]
                assert report.licenses == (case["wrapper"]["record"],), case["name"]
            else:
                assert report.licenses == (), case["name"]
        assert got == case["expect"], case["name"]


def test_identity_accepts_null_template_id_like_other_kinds():
    from localvault.item_schema import validate_item
    base = {"id": "0f8fad5b-d9cb-469f-a165-70867728950e", "title": "x", "created_at": 1, "updated_at": 1}
    for kind in ("identity", "note"):
        out = validate_item({**base, "kind": kind, "payload": {"template_id": None}})
        assert out["payload"]["template_id"] is None


# --- passkey vectors ----------------------------------------------------------------------------


def test_passkey_vectors_regenerate_identically():
    generator = _load_generator()
    for rel, raw in generator.passkey_files().items():
        assert (VECTORS / rel).read_bytes() == raw, rel
    assert {p.name for p in (VECTORS / "passkeys").iterdir()} == {"assertion.json", "records.json", "registration.json"}


def test_passkey_vectors_match_desktop_authenticator():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: F401

    from localvault import passkeys

    for row in json.loads((VECTORS / "passkeys" / "assertion.json").read_text(encoding="utf-8")):
        key = serialization.load_der_private_key(passkeys.b64u_decode(row["private_key_b64u"], max_bytes=4096), None)
        auth = passkeys.authenticator_data(row["rp_id"], user_verified=row["user_verified"])
        assert auth.hex() == row["authenticator_data_hex"]
        assert auth[32] == (0x19 | (0x04 if row["user_verified"] else 0)) and auth[33:37] == bytes(4)
        numbers = key.public_key().public_numbers()
        assert (numbers.x.to_bytes(32, "big").hex(), numbers.y.to_bytes(32, "big").hex()) == (
            row["public_key_x_hex"], row["public_key_y_hex"])
        sig = key.sign(auth + bytes.fromhex(row["client_data_hash_hex"]), ec.ECDSA(hashes.SHA256()))
        key.public_key().verify(sig, auth + bytes.fromhex(row["client_data_hash_hex"]), ec.ECDSA(hashes.SHA256()))

    for row in json.loads((VECTORS / "passkeys" / "registration.json").read_text(encoding="utf-8")):
        key = serialization.load_der_private_key(passkeys.b64u_decode(row["private_key_b64u"], max_bytes=4096), None)
        cose = passkeys.cose_es256_public_key(key.public_key())
        assert cose.hex() == row["cose_key_hex"]
        auth = passkeys.authenticator_data(
            row["rp_id"], user_verified=True, attested=(bytes.fromhex(row["credential_id_hex"]), cose))
        assert auth.hex() == row["authenticator_data_hex"]
        assert passkeys.cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth}).hex() == row["attestation_object_hex"]


def test_passkey_vector_records_match_validator():
    from localvault import passkeys
    from localvault.item_schema import ItemSchemaError, validate_passkey_fields

    rows = json.loads((VECTORS / "passkeys" / "records.json").read_text(encoding="utf-8"))
    assert [r["name"] for r in rows] == [
        "desktop-made", "rs256-import", "garbage-key", "uppercase-rp-id", "missing-discoverable",
        "bad-b64url-credential-id"]
    for row in rows:
        try:
            normalised = validate_passkey_fields(row["input"])
        except ItemSchemaError:
            assert row["valid"] is False and "normalised" not in row, row["name"]
        else:
            assert row["valid"] is True and row["normalised"] == normalised, row["name"]
        assert row["usable"] is passkeys.usable_record(row["input"]), row["name"]
    by_name = {r["name"]: r for r in rows}
    assert by_name["uppercase-rp-id"]["normalised"]["relying_party_id"] == "example.com"
    assert by_name["missing-discoverable"]["normalised"]["discoverable"] is True
