"""LAN sync over the group model with one-use QR enrollment (loopback only, no Tk, no discovery)."""
from __future__ import annotations

import base64
import dataclasses
import json
import os
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from localvault.session_guard import StaleSession
from localvault.sync import folder_transport as ft
from localvault.sync import lan_sync as lan
from localvault.sync import pairing
from localvault.sync.group import GroupKey, encode_view
from localvault.sync.state import SyncState
from localvault.sync.transport import (
    MAX_MESSAGE_BYTES,
    FrameTooLarge,
    LANEndpoint,
    PeerNotAnswering,
    SecureChannel,
    SyncTransport,
    TransportError,
)
from localvault.sync.vault_bridge import load_sync_state, save_sync_state
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "synthetic master"
NOW = int(time.time())
CHEAP = (1024, 1, 1)
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"


class FakeLease:
    def __init__(self) -> None:
        self.valid = True

    def check(self) -> None:
        if not self.valid:
            raise StaleSession("Vault is locked")


def _free_endpoint() -> tuple[LANEndpoint, socket.socket]:
    """A loopback port bound now and held until the device's transport binds it (no TOCTOU).

    The probe binds port 0 and the OS hands back a free port; the returned
    socket keeps that port reserved (bound, not listening) until ``Dev.listen``
    closes it right before ``SyncTransport.start`` binds the same port.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    probe.bind(("127.0.0.1", 0))
    return LANEndpoint("127.0.0.1", int(probe.getsockname()[1])), probe


@dataclass
class Dev:
    name: str
    session: object
    lease: FakeLease
    install: str
    endpoint: LANEndpoint
    transport: SyncTransport | None = None
    responder: lan.LanResponder | None = None
    port_hold: socket.socket | None = None

    @property
    def state(self):
        return load_sync_state(self.session)

    @property
    def device_id(self) -> str:
        return self.state.device_id

    def entry(self, entry_id: str) -> dict:
        return next(e for e in self.session._payload["entries"] if e["id"] == entry_id)

    def ids(self) -> set[str]:
        return {e["id"] for e in self.session._payload["entries"]}

    def labels(self) -> list[str]:
        return sorted(e["label"] for e in self.session._payload["entries"])

    def listen(self, state: SyncState, clock=lambda: NOW) -> None:
        if self.transport is not None:
            self.transport.stop()
        self.responder = lan.LanResponder(self.session, self.lease, install_id=self.install, clock=clock)
        self.transport = SyncTransport(state)
        self.transport.set_peer_request_handler(self.responder)
        self._release_port()
        self.transport.start(self.endpoint)

    def _release_port(self) -> None:
        if self.port_hold is not None:
            self.port_hold.close()
            self.port_hold = None

    def relisten(self, *, hello_clock=None, clock=lambda: NOW) -> None:
        self.listen(lan.transport_state(self.state, self.session, self.lease, clock=hello_clock), clock)

    def sync_with(self, other: Dev, *, install: str | None = None) -> lan.RunReport:
        return lan.sync_with(self.transport, other.device_id, self.session, self.lease,
                             install_id=install or self.install, now=NOW)

    def stop(self) -> None:
        if self.transport is not None:
            self.transport.stop()
        self._release_port()


def _web(dev: Dev, label: str) -> str:
    return dev.session.upsert_web(origin=f"https://{label}.example.com", username="me", password="pw-123456",
                                  label=label)


def kinds(report) -> list[str]:
    return [i.kind for i in report.issues]


def _offer_for(inviter: Dev) -> tuple[pairing.PairingOffer, str]:
    """The inviter shows a QR code and arms its listener for one enrollment."""
    offer = lan.begin_pairing(inviter.session, inviter.lease, inviter.endpoint.host, inviter.endpoint.port,
                              install_id=inviter.install, now=NOW)
    inviter.responder.start_enrollment(offer, inviter.transport)
    return offer, pairing.offer_qr_payload(offer)


def _pair(inviter: Dev, invitee: Dev, *, listen: bool = True) -> None:
    """Real network enrollment: the invitee scans the QR text and talks to the inviter's listener."""
    _offer, text = _offer_for(inviter)
    lan.enroll_from_qr(text, invitee.session, invitee.lease, install_id=invitee.install,
                       endpoint=invitee.endpoint if listen else None, now=NOW)
    if listen:
        invitee.relisten()


@pytest.fixture
def devs(tmp_path: Path):
    made: list[Dev] = []

    def make(name: str, *, group: bool = False) -> Dev:
        session = create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)
        endpoint, hold = _free_endpoint()
        d = Dev(name, session, FakeLease(), f"install-{name}", endpoint, port_hold=hold)
        made.append(d)
        if group:
            lan.create_lan_group(d.session, d.lease, install_id=d.install)
            d.relisten()
        return d

    yield make
    for d in made:
        d.stop()


def _group_ab(devs) -> tuple[Dev, Dev]:
    a, b = devs("a", group=True), devs("b")
    _pair(a, b)
    return a, b


def _peer_record(sender: Dev, receiver: Dev) -> pairing.PairedDevice:
    """The pinned record *receiver*'s transport holds for *sender* (what the handler receives)."""
    return receiver.transport.state.trusted_peers[sender.device_id]


def _msg(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _view_msg(sender: Dev, claimed_device: str) -> bytes:
    st = sender.state
    raw = encode_view(GroupKey(st.group_id, st.epoch, st.key), claimed_device, 99, [], NOW)
    return _msg({"type": "view", "group_id": st.group_id, "epoch": st.epoch, "transfer": "ab" * 16,
                 "seq": 0, "total": 1, "size": len(raw), "view": base64.b64encode(raw).decode()})


def _serve(receiver: Dev, peer: pairing.PairedDevice, payload: bytes, inbox=None) -> dict:
    return json.loads(lan.serve_request(receiver.session, receiver.lease, peer, payload,
                                        install_id=receiver.install, now=NOW, inbox=inbox))


# --- QR payload ---------------------------------------------------------------------------


def _offer() -> pairing.PairingOffer:
    ident = pairing.DeviceIdentity.generate()
    return pairing.create_pairing_offer(ident, "0f8b8c1e-4c1e-4a57-9d43-5b0b2d1f0a11", "192.168.100.200",
                                        65000, now=NOW)


def test_qr_round_trip_and_png() -> None:
    import segno

    offer = _offer()
    text = pairing.offer_qr_payload(offer)
    assert text.startswith("lgk-pair:") and "=" not in text
    assert len(text) <= pairing.MAX_QR_PAYLOAD
    parsed = pairing.parse_qr_payload(text)
    assert parsed == offer.bundle_dict()
    assert pairing.PairingOffer.from_bundle_dict(parsed) == offer
    assert segno.make(text, error="m", micro=False, boost_error=False).version <= 25
    assert pairing.render_qr_png(text, scale=6).startswith(b"\x89PNG\r\n\x1a\n")
    ident = pairing.DeviceIdentity.generate()
    v6 = pairing.create_pairing_offer(ident, str(offer.group_id), "fd12:3456:789a:1::ffff", 65000, now=NOW)
    assert segno.make(pairing.offer_qr_payload(v6), error="m", micro=False, boost_error=False).version <= 25


def _qr(raw: bytes) -> str:
    return "lgk-pair:" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _canon(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def test_qr_rejections() -> None:
    offer = _offer()
    text = pairing.offer_qr_payload(offer)
    body = json.dumps(offer.bundle_dict(), ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    assert '"code":' in body
    bad = [
        "LGK-PAIR:" + text[len("lgk-pair:"):],
        "lgk-pairing:" + text[len("lgk-pair:"):],
        " " + text,
        text + "=",
        text[:-1] + "+",
        text + "A" * (pairing.MAX_QR_PAYLOAD - len(text) + 1),
        _qr(body.replace('"code":', '"code":"00000000","code":', 1).encode()),  # duplicate key
        _qr(b"[1,2,3]"),
        _qr(body.encode() + b" "),
        _qr(_canon(dict(offer.bundle_dict(), inviter_device_id="dévice"))),
        _qr(_canon(dict(offer.bundle_dict(), group_id="a group"))),
        b"lgk-pair:abc",
    ]
    for value in bad:
        with pytest.raises(pairing.PairingError):
            pairing.parse_qr_payload(value)


def test_pairing_ids_follow_the_ascii_identifier_rule() -> None:
    ident = pairing.DeviceIdentity.generate()
    with pytest.raises(pairing.PairingError):
        pairing.create_pairing_offer(ident, "grüppe", "10.0.0.1", 4000, now=NOW)
    with pytest.raises(pairing.PairingError):
        pairing.create_pairing_offer(ident, "group 1", "10.0.0.1", 4000, now=NOW)
    with pytest.raises(pairing.PairingError):
        pairing.DeviceIdentity.generate("bad id")
    bad = dataclasses.replace(ident, device_id="dévice")
    with pytest.raises(pairing.PairingError):
        bad.protected_dict()
    with pytest.raises(pairing.PairingError):
        pairing.create_pairing_offer(bad, "group-1", "10.0.0.1", 4000, now=NOW)


# --- enrollment over the network -------------------------------------------------------------


def test_qr_enrollment_delivers_key_then_views_merge_both_ways(devs) -> None:
    a = devs("a", group=True)
    on_a = _web(a, "mail")
    b = devs("b")
    _pair(a, b)
    sa, sb = a.state, b.state
    assert (sb.group_id, sb.epoch, sb.key) == (sa.group_id, sa.epoch, sa.key)
    assert sb.install_id == b.install and sb.device_id != sa.device_id
    assert lan.peer_endpoint(sa, sb.device_id) == b.endpoint
    assert lan.peer_endpoint(sb, sa.device_id) == a.endpoint
    assert a.responder.enrolled.device_id == sb.device_id and a.responder.pairing.exhausted
    assert "key_pending" not in lan.peer_entry(sa, sb.device_id)

    report = a.sync_with(b)  # A's running transport already trusts B
    assert kinds(report) == [] and report.wrote
    assert b.entry(on_a)["password"] == "pw-123456"
    on_b = _web(b, "bank")
    a.session.update_entry_fields(on_a, password="edited-on-a")
    assert kinds(b.sync_with(a)) == []
    for d in (a, b):
        assert d.entry(on_a)["password"] == "edited-on-a"
        assert d.entry(on_b)["label"] == "bank"
    assert a.state.own_counter == 0 and b.state.own_counter == 0  # LAN reserves no view counters


def test_phone_without_endpoint_always_initiates(devs) -> None:
    a = devs("a", group=True)
    phone = devs("phone")
    _pair(a, phone, listen=False)
    assert lan.peer_endpoint(a.state, phone.device_id) is None
    phone.relisten()
    _web(phone, "from-phone")
    assert kinds(phone.sync_with(a)) == []
    assert "from-phone" in a.labels()
    assert kinds(a.sync_with(phone)) == ["no-endpoint"]


def test_second_enrollment_on_the_same_offer_is_rejected(devs) -> None:
    a = devs("a", group=True)
    b, c = devs("b"), devs("c")
    offer, text = _offer_for(a)
    session = a.responder.pairing
    lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert session.exhausted
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, c.session, c.lease, install_id=c.install, now=NOW)
    assert err.value.reason == "offer-used-or-expired"
    assert str(err.value).endswith(lan.USED_OR_EXPIRED_MESSAGE)
    assert c.state is None and len(a.state.lan_peers) == 1
    # Even replayed directly into the consumed session, a request is refused.
    raw = pairing.build_enrollment_request(offer, pairing.DeviceIdentity.generate(), now=NOW)
    with pytest.raises(pairing.PairingReplayError):
        session.accept_enrollment(a.state.identity(), raw, now=NOW)


def _custom_request(offer: pairing.PairingOffer, body: dict) -> bytes:
    """Encrypt an arbitrary body to the inviter exactly as a real client would."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(offer.inviter_exchange_public))
    key = pairing._hkdf(shared, offer.transcript_nonce, pairing._REQUEST_INFO + offer.offer_id.encode())
    header = {"offer_id": offer.offer_id, "eph": pairing._b64e(pairing._public_bytes(eph.public_key()))}
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, pairing._canonical(body), pairing._canonical(header))
    return pairing.ENROLL_REQUEST_MAGIC + pairing._canonical(
        {**header, "nonce": pairing._b64e(nonce), "ct": pairing._b64e(ct)})


def test_forged_or_missing_mac_is_rejected_and_counted(devs) -> None:
    a = devs("a", group=True)
    offer, text = _offer_for(a)
    session = a.responder.pairing
    sender = SyncTransport()
    # Forged from the public fields only: the attacker does not know the secret (nor the code).
    forged_offer = dataclasses.replace(offer, pairing_secret=os.urandom(32), code="00000000")
    reply = sender.enroll(a.endpoint, pairing.build_enrollment_request(forged_offer,
                                                                       pairing.DeviceIdentity.generate(), now=NOW))
    assert reply.startswith(pairing.ENROLL_REFUSED_MAGIC)
    assert session.attempts == 1
    # A body without the MAC field.
    ident = pairing.DeviceIdentity.generate()
    transcript = pairing.enrollment_transcript(offer, ident.device_id, ident.signing_public_key,
                                               ident.exchange_public_key, None)
    body = {"version": 1, "offer_id": offer.offer_id, "device_id": ident.device_id,
            "signing_public": pairing._b64e(ident.signing_public_key),
            "exchange_public": pairing._b64e(ident.exchange_public_key), "endpoint": None,
            "signature": pairing._b64e(ident.sign(pairing._SIG_LABEL + transcript))}
    assert sender.enroll(a.endpoint, _custom_request(offer, body)).startswith(pairing.ENROLL_REFUSED_MAGIC)
    # A valid MAC over a different transcript (endpoint swapped after MACing).
    good = dict(body, mac=pairing._b64e(pairing._mac(offer, transcript)),
                endpoint={"host": "127.0.0.1", "port": 9})
    assert sender.enroll(a.endpoint, _custom_request(offer, good)).startswith(pairing.ENROLL_REFUSED_MAGIC)
    assert session.attempts == 3 and a.state.lan_peers == ()
    # Frames that do not decrypt (no QR: wrong key, junk, another offer) are refused without counting.
    stranger = dataclasses.replace(
        offer, inviter_exchange_public=pairing.DeviceIdentity.generate().exchange_public_key)
    junk = [pairing.build_enrollment_request(stranger, pairing.DeviceIdentity.generate(), now=NOW),
            pairing.ENROLL_REQUEST_MAGIC + b"{}", pairing.ENROLL_REQUEST_MAGIC + b"not json",
            pairing.build_enrollment_request(_offer(), pairing.DeviceIdentity.generate(), now=NOW)]
    for raw in junk * 2:
        assert sender.enroll(a.endpoint, raw).startswith(pairing.ENROLL_REFUSED_MAGIC)
    assert session.attempts == 3 and not session.exhausted
    # The real device still enrolls with the remaining attempts.
    b = devs("b")
    lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert b.state.key == a.state.key


def test_attempts_are_exhausted_after_five_failures(devs) -> None:
    a = devs("a", group=True)
    offer, text = _offer_for(a)
    forged = dataclasses.replace(offer, pairing_secret=os.urandom(32))
    sender = SyncTransport()
    for _ in range(pairing.PAIRING_MAX_ATTEMPTS):
        reply = sender.enroll(a.endpoint, pairing.build_enrollment_request(
            forged, pairing.DeviceIdentity.generate(), now=NOW))
        assert reply.startswith(pairing.ENROLL_REFUSED_MAGIC)
    assert a.responder.pairing.exhausted
    b = devs("b")
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "offer-used-or-expired"
    assert b.state is None and a.state.lan_peers == ()


def test_expired_offer_is_refused(devs) -> None:
    a = devs("a", group=True)
    _offer, text = _offer_for(a)
    a.responder.clock = lambda: NOW + pairing.PAIRING_TTL_SECONDS + 1
    a.responder.pairing._clock = a.responder.clock
    b = devs("b")
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "offer-used-or-expired"
    assert b.state is None and a.state.lan_peers == () and a.responder.pairing.attempts == 0
    with pytest.raises(lan.LanSyncError) as err:  # the client refuses an expired offer itself
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install,
                           now=NOW + pairing.PAIRING_TTL_SECONDS + 1)
    assert err.value.reason == "offer-used-or-expired"
    # Well after expiry the listener stops answering enrollments at all.
    a.responder.clock = lambda: NOW + pairing.PAIRING_TTL_SECONDS + lan.ENROLL_GRACE_SECONDS + 1
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "unreachable" and a.responder.pairing is None


def test_reply_must_pin_this_device(devs) -> None:
    a = devs("a", group=True)
    offer, _text = _offer_for(a)
    me, other = pairing.DeviceIdentity.generate(), pairing.DeviceIdentity.generate()
    session = a.responder.pairing
    _peer, req = session.accept_enrollment(a.state.identity(),
                                           pairing.build_enrollment_request(offer, other, now=NOW), now=NOW)
    st = a.state
    reply = pairing.seal_enrollment_reply(st.identity(), offer, req, st.group_id, st.epoch, st.key)
    assert pairing.open_enrollment_reply(offer, other, reply)[2] == st.key
    with pytest.raises(pairing.PairingError):
        pairing.open_enrollment_reply(offer, me, reply)
    forged = pairing.seal_enrollment_reply(pairing.DeviceIdentity.generate(), offer, req, st.group_id,
                                           st.epoch, st.key)
    with pytest.raises(pairing.PairingAuthenticationError):  # not signed by the QR-pinned inviter
        pairing.open_enrollment_reply(offer, other, forged)


# --- refusals -------------------------------------------------------------------------------


def test_unpinned_device_gets_nothing_but_enrollment(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    c = devs("c", group=True)
    # C pins A (as if from an old QR) but A never pinned C.
    st = dataclasses.replace(c.state, group_id=a.state.group_id,
                             lan_peers=(lan.peer_to_entry(_peer_record(a, b), endpoint=a.endpoint),))
    save_sync_state(c.session, st)
    c.relisten()
    _web(c, "evil")
    before = a.labels()
    assert kinds(c.sync_with(a)) == ["unreachable"]
    assert a.labels() == before
    # The used offer only yields a refusal; with no offer armed, enrollment frames get no reply.
    assert (SyncTransport().enroll(a.endpoint, pairing.ENROLL_REQUEST_MAGIC + b"{}")
            == pairing.enrollment_refusal("used-or-expired"))
    a.responder.stop_enrollment()
    with pytest.raises(TransportError):
        SyncTransport().enroll(a.endpoint, pairing.ENROLL_REQUEST_MAGIC + b"{}")


def test_unlisted_or_mismatched_peer_is_refused_by_the_vault(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    record = _peer_record(a, b)
    impostor = dataclasses.replace(record, signing_public=os.urandom(32))
    assert _serve(b, impostor, _view_msg(a, a.device_id)) == {"type": "error", "reason": "unknown-peer"}
    save_sync_state(b.session, dataclasses.replace(b.state, lan_peers=()))
    assert _serve(b, record, _view_msg(a, a.device_id)) == {"type": "error", "reason": "unknown-peer"}


def test_view_under_another_device_id_is_refused(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    c = devs("c")
    _pair(a, c)
    _web(a, "fresh")
    before = b.labels()
    assert _serve(b, _peer_record(a, b), _view_msg(a, c.device_id)) == {"type": "error",
                                                                         "reason": "device-mismatch"}
    assert b.labels() == before


def test_removed_lan_peer_is_refused(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    record = _peer_record(b, a)
    assert lan.remove_lan_peer(a.session, a.lease, b.device_id, install_id=a.install, transport=a.transport)
    assert lan.peer_entry(a.state, b.device_id) is None
    assert kinds(b.sync_with(a)) == ["unreachable"]
    assert _serve(a, record, _view_msg(b, b.device_id)) == {"type": "error", "reason": "unknown-peer"}
    assert kinds(a.sync_with(b)) == ["unknown-peer"]


def test_rotated_out_peer_is_dropped_and_never_gets_the_new_key(devs, tmp_path: Path) -> None:
    root = tmp_path / "OneDrive"
    root.mkdir()
    a = devs("a")
    ft.create_folder_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    a.relisten()
    b = devs("b")
    _pair(a, b)  # B is a LAN-only peer
    old_key = b.state.key
    assert kinds(a.sync_with(b)) == []
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[b.device_id], install_id=a.install,
                           now=NOW, _kdf_override=CHEAP)
    assert a.state.epoch == 2 and lan.peer_entry(a.state, b.device_id) is None
    a.relisten()
    assert kinds(b.sync_with(a)) == ["unreachable"]
    assert b.state.epoch == 1 and b.state.key == old_key


def test_revoked_peer_is_refused(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    record = _peer_record(b, a)
    st = a.state
    entry = dict(lan.peer_entry(st, b.device_id), revoked=True)
    save_sync_state(a.session, dataclasses.replace(st, lan_peers=(entry,)))
    assert _serve(a, record, _view_msg(b, b.device_id)) == {"type": "error", "reason": "revoked"}
    assert kinds(a.sync_with(b)) == ["peer-revoked"]
    a.relisten()  # a rebuilt transport does not trust a revoked peer at all
    assert b.device_id not in a.transport.state.trusted_peers
    assert kinds(b.sync_with(a)) == ["unreachable"]


def test_oversized_frames_are_refused(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    peer = _peer_record(a, b)

    def serve(payload: bytes) -> dict:
        return _serve(b, peer, payload)

    assert serve(b"{" + b" " * MAX_MESSAGE_BYTES + b"}") == {"type": "error", "reason": "too-large"}
    st = b.state
    huge = {"type": "view", "group_id": st.group_id, "epoch": st.epoch, "transfer": "cd" * 16, "seq": 0,
            "total": 2, "size": lan.MAX_VIEW_BYTES + 1, "view": base64.b64encode(b"x").decode()}
    assert serve(_msg(huge)) == {"type": "error", "reason": "too-large"}
    chunk = dict(huge, size=lan.CHUNK_LIMIT * 2, view=base64.b64encode(b"x" * (lan.CHUNK_LIMIT + 1)).decode())
    assert serve(_msg(chunk)) == {"type": "error", "reason": "too-large"}
    with pytest.raises(FrameTooLarge):
        a.transport.request(b.endpoint, b"x" * (MAX_MESSAGE_BYTES + 1), peer_id=b.device_id)
    with pytest.raises(TransportError):  # an oversized enrollment is not even sent
        SyncTransport().enroll(a.endpoint, pairing.ENROLL_REQUEST_MAGIC + b"x" * pairing.MAX_ENROLL_BYTES)
    assert kinds(a.sync_with(b)) == []


def test_largest_accepted_chunk_still_seals_into_one_frame() -> None:
    gid = "0f8b8c1e-4c1e-4a57-9d43-5b0b2d1f0a11"
    message = _msg({"type": "view", "group_id": gid, "epoch": 2**53 - 1, "transfer": "ab" * 16,
                    "seq": lan.MAX_CHUNKS - 2, "total": lan.MAX_CHUNKS - 1, "size": lan.MAX_VIEW_BYTES,
                    "view": base64.b64encode(b"x" * lan.CHUNK_LIMIT).decode()})
    assert len(message) <= MAX_MESSAGE_BYTES
    channel = SecureChannel(os.urandom(32), session_id=os.urandom(16), role="initiator")
    channel.seal(message)
    assert lan.CHUNK_BYTES <= lan.CHUNK_LIMIT


def test_malformed_messages_get_an_error(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    peer = _peer_record(a, b)
    for payload in (b"not json", b"[]", b'{"type":"view","type":"view"}', b'{"type":"nope"}',
                    b'{"type":"view"}', b'{"epoch":NaN,"type":"view"}',
                    b'{"epoch":1,"group_id":"g","key":"AA==","type":"group-key"}'):
        reply = _serve(b, peer, payload)
        assert reply == {"type": "error", "reason": "bad-message"}


# --- epochs, installation binding, hello counters ------------------------------------------------


def test_epoch_behind_does_not_merge(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    save_sync_state(a.session, dataclasses.replace(a.state, epoch=2, key=os.urandom(32)))
    on_a, on_b = _web(a, "after-rotation"), _web(b, "old-epoch")

    assert kinds(b.sync_with(a)) == ["epoch-behind"]
    assert kinds(a.responder.last_report) == ["peer-epoch-behind"]
    assert kinds(a.sync_with(b)) == ["peer-epoch-behind"]
    assert kinds(b.responder.last_report) == ["epoch-behind"]
    assert on_b not in a.ids() and on_a not in b.ids()


def test_install_mismatch_requires_rejoin(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    _web(a, "x")
    before = b.labels()
    report = a.sync_with(b, install="install-elsewhere")
    assert kinds(report) == ["rejoin-required"] and not report.wrote
    save_sync_state(b.session, dataclasses.replace(b.state, install_id="copied-from-other-pc"))
    assert kinds(a.sync_with(b)) == ["peer-rejoin-required"]
    assert kinds(b.responder.last_report) == ["rejoin-required"]
    assert b.labels() == before
    for bad in ("", None, 5):
        with pytest.raises(ValueError):
            lan.sync_with(a.transport, b.device_id, a.session, a.lease, install_id=bad, now=NOW)


def test_hello_counter_is_persisted_and_survives_a_clock_set_backwards(devs) -> None:
    a, b = _group_ab(devs)
    far = 10**15
    a.relisten(hello_clock=lambda: far)
    assert kinds(a.sync_with(b)) == []
    used = a.state.hello_counter
    assert used == far + lan.HELLO_COUNTER_BLOCK - 1  # one block reserved and saved
    assert kinds(a.sync_with(b)) == [] and kinds(a.sync_with(b)) == []
    assert a.state.hello_counter == used  # handed out from memory, no save per connection
    a.relisten(hello_clock=lambda: 5)  # restart with the clock far in the past
    assert kinds(a.sync_with(b)) == []
    assert a.state.hello_counter == used + lan.HELLO_COUNTER_BLOCK


def test_lock_during_serve_propagates(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    b.lease.valid = False
    with pytest.raises(StaleSession):
        _serve(b, _peer_record(a, b), _view_msg(a, a.device_id))


# --- chunking and relay ----------------------------------------------------------------------


def test_views_larger_than_one_message_are_chunked(devs, monkeypatch) -> None:
    monkeypatch.setattr(lan, "CHUNK_BYTES", 1500)
    a, b = _group_ab(devs)
    on_a = [_web(a, f"a-site-{i}") for i in range(12)]
    types: list[str] = []
    real = SyncTransport.request

    def spy(self, endpoint, payload, **kw):
        types.append(json.loads(payload)["type"])
        return real(self, endpoint, payload, **kw)

    monkeypatch.setattr(SyncTransport, "request", spy)
    assert kinds(a.sync_with(b)) == []
    assert types.count("view") > 2
    on_b = [_web(b, f"b-site-{i}") for i in range(12)]
    types.clear()
    assert kinds(b.sync_with(a)) == []
    assert types.count("view") > 2 and types.count("next") > 2
    for d in (a, b):
        assert set(on_a) | set(on_b) <= d.ids()


def test_chunks_survive_a_slow_slot_release(devs, monkeypatch) -> None:
    """The responder's handler thread is preempted for 20 ms after replying (I1).

    The initiator's next chunk connection then arrives while the responder's one
    connection slot is still taken; the listener waits for the slot instead of
    dropping the connection.
    """
    monkeypatch.setattr(lan, "CHUNK_BYTES", 1500)
    a, b = _group_ab(devs)
    real_release = SyncTransport._release_socket

    def slow_release(self, sock):
        if threading.current_thread().name == "localvault-sync-peer":
            time.sleep(0.02)
        return real_release(self, sock)

    monkeypatch.setattr(SyncTransport, "_release_socket", slow_release)
    on_a = [_web(a, f"a-site-{i}") for i in range(12)]
    for _ in range(3):
        assert kinds(a.sync_with(b)) == []
    on_b = [_web(b, f"b-site-{i}") for i in range(12)]
    assert kinds(b.sync_with(a)) == []
    for d in (a, b):
        assert set(on_a) | set(on_b) <= d.ids()


def test_chunk_request_is_retried_once_when_the_peer_never_answered(devs, monkeypatch) -> None:
    """A dropped chunk connection (old listener behaviour) is retried once; the first request is not."""
    monkeypatch.setattr(lan, "CHUNK_BYTES", 1500)
    monkeypatch.setattr(lan, "CHUNK_RETRY_DELAY", 0.0)
    a, b = _group_ab(devs)
    [_web(a, f"a-site-{i}") for i in range(12)]
    real = SyncTransport.request
    calls = {"n": 0}

    def flaky(self, endpoint, payload, **kw):
        calls["n"] += 1
        if calls["n"] == 2:  # the second chunk: dropped before the hello
            raise PeerNotAnswering("dropped")
        return real(self, endpoint, payload, **kw)

    monkeypatch.setattr(SyncTransport, "request", flaky)
    assert kinds(a.sync_with(b)) == []
    assert "a-site-11" in b.labels()

    calls["n"] = 1  # the next call is the first view of a new exchange
    monkeypatch.setattr(SyncTransport, "request", lambda self, *a_, **k: (_ for _ in ()).throw(
        PeerNotAnswering("down")))
    assert kinds(a.sync_with(b)) == ["unreachable"]


def test_chunk_sequence_is_enforced(devs, monkeypatch) -> None:
    monkeypatch.setattr(lan, "CHUNK_BYTES", 64)
    a, b = _group_ab(devs)
    a.sync_with(b)
    peer = _peer_record(a, b)
    st = a.state
    raw = encode_view(GroupKey(st.group_id, st.epoch, st.key), st.device_id, 500, [], NOW)
    parts = [raw[i:i + 64] for i in range(0, len(raw), 64)]
    assert len(parts) >= 3

    def chunk(seq: int) -> bytes:
        return _msg({"type": "view", "group_id": st.group_id, "epoch": st.epoch, "transfer": "ef" * 16,
                     "seq": seq, "total": len(parts), "size": len(raw),
                     "view": base64.b64encode(parts[seq]).decode()})

    inbox = lan.LanInbox()
    assert _serve(b, peer, chunk(0), inbox)["type"] == "ack"
    assert _serve(b, peer, chunk(2), inbox) == {"type": "error", "reason": "bad-chunk"}
    assert _serve(b, peer, chunk(1), lan.LanInbox()) == {"type": "error", "reason": "bad-chunk"}
    inbox = lan.LanInbox()
    for seq in range(len(parts) - 1):
        assert _serve(b, peer, chunk(seq), inbox)["type"] == "ack"
    assert _serve(b, peer, chunk(len(parts) - 1), inbox)["type"] == "view"


def test_in_flight_transfers_are_capped() -> None:
    inbox = lan.LanInbox()
    msg = {"transfer": "ab" * 16, "seq": 0, "total": 2, "size": 2, "view": base64.b64encode(b"x").decode()}
    for i, peer in enumerate(("p1", "p2", "p3")):
        assert lan._receive_chunk(inbox, peer, msg, NOW + i) is None
    assert set(inbox.incoming) == {"p2", "p3"} and lan.MAX_TRANSFERS == 2
    assert lan._receive_chunk(inbox, "p3", msg, NOW) is None  # a new transfer replaces the peer's old one
    assert len(inbox.incoming) == 2


def test_three_device_relay(devs) -> None:
    a, b = _group_ab(devs)
    a.sync_with(b)
    c = devs("c")
    _pair(b, c)
    assert kinds(b.sync_with(c)) == []
    assert c.state.group_id == a.state.group_id and c.state.key == a.state.key
    on_a = _web(a, "relayed")
    assert kinds(a.sync_with(b)) == []
    assert kinds(b.sync_with(c)) == []
    assert c.entry(on_a)["label"] == "relayed"


# --- round 2: id takeover, capacity, rotation observed by the folder transport ---------------------


def test_enrollment_cannot_take_over_an_existing_device_id(devs) -> None:
    a, b = _group_ab(devs)
    assert kinds(a.sync_with(b)) == []
    pinned = lan.peer_entry(a.state, b.device_id)
    offer, _text = _offer_for(a)
    session = a.responder.pairing
    sender = SyncTransport()
    st = a.state
    save_sync_state(a.session, dataclasses.replace(st, members_epoch=st.epoch, members=("folder-member-1",)))
    for taken in (b.device_id, a.device_id, "folder-member-1"):
        thief = pairing.DeviceIdentity.generate(taken)
        if taken == a.device_id:
            raw = _custom_request(offer, _body(offer, thief))  # the client library refuses this itself
        else:
            raw = pairing.build_enrollment_request(offer, thief, now=NOW)
        assert sender.enroll(a.endpoint, raw) == pairing.enrollment_refusal()
    assert session.attempts == 3 and not session.exhausted
    assert lan.peer_entry(a.state, b.device_id) == pinned
    assert a.transport.state.trusted_peers[b.device_id].fingerprint == pinned["fingerprint"]
    assert kinds(b.sync_with(a)) == []  # the real B is not locked out


def _body(offer: pairing.PairingOffer, ident: pairing.DeviceIdentity) -> dict:
    transcript = pairing.enrollment_transcript(offer, ident.device_id, ident.signing_public_key,
                                               ident.exchange_public_key, None)
    return {"version": 1, "offer_id": offer.offer_id, "device_id": ident.device_id,
            "signing_public": pairing._b64e(ident.signing_public_key),
            "exchange_public": pairing._b64e(ident.exchange_public_key), "endpoint": None,
            "signature": pairing._b64e(ident.sign(pairing._SIG_LABEL + transcript)),
            "mac": pairing._b64e(pairing._mac(offer, transcript))}


def test_full_peer_list_refuses_before_consuming_the_offer(devs) -> None:
    a = devs("a", group=True)
    fakes = []
    for i in range(lan.MAX_LAN_PEERS):
        ident = pairing.DeviceIdentity.generate(f"fake-{i}")
        fakes.append(lan.peer_to_entry(pairing.PairedDevice(
            ident.device_id, a.state.group_id, ident.signing_public_key, ident.exchange_public_key,
            ident.fingerprint, NOW, ident.sign(b"x"))))
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=tuple(fakes)))
    _offer, text = _offer_for(a)
    b = devs("b")
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "too-many-peers"
    assert a.responder.pairing.attempts == 0 and not a.responder.pairing.exhausted
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=tuple(fakes[:-1])))
    lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)  # same offer still works
    assert len(a.state.lan_peers) == lan.MAX_LAN_PEERS


def test_folder_run_drops_lan_peers_removed_by_another_devices_rotation(devs, tmp_path: Path) -> None:
    root = tmp_path / "OneDrive"
    root.mkdir()
    a, b, c = devs("a"), devs("b"), devs("c")
    ft.create_folder_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    for d in (b, c):
        ft.join_folder_group(root, d.session, d.lease, PW, d.name, install_id=d.install, now=NOW,
                             _kdf_override=CHEAP)
    fs_a = ft.FolderSync(root, install_id=a.install, _kdf_override=CHEAP)
    fs_a.run_once(a.session, a.lease, now=NOW)
    ident_c = c.state.identity()
    record = pairing.PairedDevice(ident_c.device_id, a.state.group_id, ident_c.signing_public_key,
                                  ident_c.exchange_public_key, ident_c.fingerprint, NOW, ident_c.sign(b"x"))
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=(lan.peer_to_entry(record),)))
    assert c.device_id in a.state.members
    ft.FolderSync(root, install_id=b.install, _kdf_override=CHEAP).run_once(b.session, b.lease, now=NOW)
    ft.rotate_folder_group(root, b.session, b.lease, PW2, remove=[c.device_id], install_id=b.install,
                           now=NOW, _kdf_override=CHEAP)
    fs_a.run_once(a.session, a.lease, now=NOW)
    assert a.state.epoch == 2 and lan.peer_entry(a.state, c.device_id) is None


@pytest.mark.skipif(not hasattr(socket, "SO_EXCLUSIVEADDRUSE"), reason="Windows-only socket option")
def test_listener_port_cannot_be_shared_on_windows(devs) -> None:
    """M4: the listener uses SO_EXCLUSIVEADDRUSE, so a SO_REUSEADDR socket cannot bind over it."""
    a = devs("a", group=True)
    intruder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        intruder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with pytest.raises(OSError):
            intruder.bind((a.endpoint.host, a.endpoint.port))
    finally:
        intruder.close()


# --- strict transport parsing ------------------------------------------------------------------


def _hello_pair():
    from localvault.sync.transport import create_session_hello

    a = pairing.DeviceIdentity.generate("device-a")
    b = pairing.DeviceIdentity.generate("device-b")
    peer_a = pairing.PairedDevice(a.device_id, "group-1", a.signing_public_key, a.exchange_public_key,
                                  a.fingerprint, 1000.0, a.sign(b"enrollment"))
    peer_b = pairing.PairedDevice(b.device_id, "group-1", b.signing_public_key, b.exchange_public_key,
                                  b.fingerprint, 1000.0, b.sign(b"enrollment"))
    sid = b"s" * 16
    return a, b, peer_a, peer_b, create_session_hello(a, "group-1", sid), create_session_hello(b, "group-1", sid)


def test_hello_with_duplicate_keys_rejected() -> None:
    from localvault.sync.transport import SessionHello

    *_, hello_a, _hello_b = _hello_pair()
    text = hello_a.to_bytes().decode()
    assert '"counter":1' in text
    dup = text.replace('"counter":1', '"counter":2,"counter":1', 1).encode()
    with pytest.raises(TransportError):
        SessionHello.from_bytes(dup)
    with pytest.raises(TransportError):
        SessionHello.from_bytes(text.replace('"counter":1', '"counter":NaN', 1).encode())


def test_hello_noncanonical_base64_rejected() -> None:
    from localvault.sync.transport import SessionHello

    *_, hello_a, _hello_b = _hello_pair()
    raw = json.loads(hello_a.to_bytes())
    assert SessionHello.from_bytes(json.dumps(raw).encode()) == hello_a
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    sid = raw["session_id"]  # 16 bytes: 22 chars + "==", last char carries 2 zero pad bits
    assert sid.endswith("==")
    raw["session_id"] = sid[:21] + alphabet[alphabet.index(sid[21]) + 1] + "=="
    assert base64.b64decode(raw["session_id"], validate=True) == base64.b64decode(sid)
    with pytest.raises(TransportError):
        SessionHello.from_bytes(json.dumps(raw).encode())


def test_hello_exchange_key_must_match_pinned() -> None:
    from localvault.sync.transport import AuthenticationError, verify_session_hello

    a, _b, peer_a, _peer_b, hello_a, _hello_b = _hello_pair()
    verify_session_hello(hello_a, "group-1", peer_a)
    other = pairing.DeviceIdentity.generate("device-a")
    pinned_elsewhere = pairing.PairedDevice(a.device_id, "group-1", a.signing_public_key,
                                            other.exchange_public_key, a.fingerprint, 1000.0,
                                            a.sign(b"enrollment"))
    with pytest.raises(AuthenticationError):
        verify_session_hello(hello_a, "group-1", pinned_elsewhere)


def test_sealed_frame_duplicate_keys_rejected() -> None:
    from localvault.sync.transport import encode_frame

    a, b, peer_a, peer_b, hello_a, hello_b = _hello_pair()
    chan_a = SecureChannel.from_paired_identities(a, peer_b, group_id="group-1", session_id=b"s" * 16,
                                                  role="initiator", local_hello=hello_a, remote_hello=hello_b)
    chan_b = SecureChannel.from_paired_identities(b, peer_a, group_id="group-1", session_id=b"s" * 16,
                                                  role="responder", local_hello=hello_b, remote_hello=hello_a)
    frame = chan_a.seal(b"payload")
    payload = frame[4:].decode()
    assert '"counter":1' in payload
    dup = encode_frame(payload.replace('"counter":1', '"counter":2,"counter":1', 1).encode())
    with pytest.raises(TransportError):
        chan_b.open(dup)
    assert chan_b.open(frame) == b"payload"


def _hello_variant(hello, **change) -> bytes:
    raw = json.loads(hello.to_bytes())
    for key, value in change.items():
        if value is ...:
            del raw[key]
        else:
            raw[key] = value
    return json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()


@pytest.mark.parametrize("change", [
    {"extra": 1}, {"version": True}, {"version": 1.0}, {"version": "1"}, {"version": 2},
    {"version": ...}, {"nonce": ...}, {"signature": ...}])
def test_hello_requires_the_exact_field_set_and_integer_version(change) -> None:
    from localvault.sync.transport import SessionHello

    *_, hello_a, _hello_b = _hello_pair()
    assert SessionHello.from_bytes(_hello_variant(hello_a)) == hello_a
    with pytest.raises(TransportError):
        SessionHello.from_bytes(_hello_variant(hello_a, **change))


@pytest.mark.parametrize("change", [
    {"extra": 1}, {"version": True}, {"version": 1.0}, {"version": "1"}, {"version": ...}])
def test_sealed_frame_requires_the_exact_field_set_and_integer_version(change) -> None:
    from localvault.sync.transport import encode_frame

    a, b, peer_a, peer_b, hello_a, hello_b = _hello_pair()
    chan_a = SecureChannel.from_paired_identities(a, peer_b, group_id="group-1", session_id=b"s" * 16,
                                                  role="initiator", local_hello=hello_a, remote_hello=hello_b)
    chan_b = SecureChannel.from_paired_identities(b, peer_a, group_id="group-1", session_id=b"s" * 16,
                                                  role="responder", local_hello=hello_b, remote_hello=hello_a)
    frame = chan_a.seal(b"payload")
    raw = json.loads(frame[4:])
    for key, value in change.items():
        if value is ...:
            del raw[key]
        else:
            raw[key] = value
    with pytest.raises(TransportError):
        chan_b.open(encode_frame(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()))
    assert chan_b.open(frame) == b"payload"


def test_attach_keeps_identity_and_lan_peers(devs, tmp_path: Path) -> None:
    """A Wi-Fi group A+B (QR) adds a cloud folder on A; B attaches: same devices, same pairings."""
    a, b = _group_ab(devs)
    root = tmp_path / "Cloud"
    root.mkdir()
    a_id, b_id = a.device_id, b.device_id
    a_peers, b_peers = a.state.lan_peers, b.state.lan_peers
    kept = {d.name: (d.state.hello_counter, d.state.own_counter, d.state.last_seen) for d in (a, b)}
    ft.add_folder_to_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW, _kdf_override=CHEAP,
                           run=False)  # no folder run yet: nothing but the folder fields may change
    ft.attach_folder(root, b.session, b.lease, PW, "PC B", install_id=b.install, now=NOW, _kdf_override=CHEAP,
                     run=False)
    for dev, own, peers in ((a, a_id, a_peers), (b, b_id, b_peers)):
        assert dev.device_id == own and dev.state.lan_peers == peers
        assert dev.state.folder_path == str(root)
    assert {d.name: (d.state.hello_counter, d.state.own_counter, d.state.last_seen) for d in (a, b)} == kept
    # both sync through the folder
    folder = {d.name: ft.FolderSync(root, install_id=d.install, _kdf_override=CHEAP) for d in (a, b)}
    entry = _web(a, "alpha")
    assert kinds(folder["a"].run_once(a.session, a.lease, now=NOW)) == ["member-added"]  # B attached (M10)
    ft.acknowledge_members(a.session, a.lease, [b_id], install_id=a.install)
    assert kinds(folder["b"].run_once(b.session, b.lease, now=NOW)) == []
    assert b.entry(entry)["label"] == "alpha"
    assert kinds(folder["a"].run_once(a.session, a.lease, now=NOW)) == []
    assert a.state.members == b.state.members == tuple(sorted((a_id, b_id)))
    # and still over Wi-Fi with the same pairing
    other = _web(b, "bravo")
    assert kinds(b.sync_with(a)) == []
    assert a.entry(other)["label"] == "bravo"
