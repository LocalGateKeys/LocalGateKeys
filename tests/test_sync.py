"""Pure M8 sync contract tests; no socket, GUI, or live LAN is used."""
from __future__ import annotations

import hashlib
import json

import pytest

from localvault.sync import (
    AttachmentDelta,
    AuthenticationError,
    DeviceIdentity,
    FrameError,
    FrameTooLarge,
    LANEndpoint,
    ManifestError,
    PairedDevice,
    PairingCodeError,
    PairingExpired,
    PairingSession,
    PeerRevoked,
    ReplayError,
    Revision,
    SecureChannel,
    SyncDisabled,
    SyncRecord,
    SyncState,
    SyncTransport,
    apply_delta,
    build_manifest,
    complete_pairing,
    confirm_pairing_offer,
    create_pairing_offer,
    create_session_hello,
    decode_frame,
    encode_frame,
    encrypt_catalog_record,
    make_attachment_delta,
    merge_records,
    resolve_conflict,
)


def _pair(now: float = 1000.0):
    inviter = DeviceIdentity.generate("device-a")
    invitee = DeviceIdentity.generate("device-b")
    offer = create_pairing_offer(inviter, "group-1", "192.168.10.5", 43125, now=now)
    confirmation = confirm_pairing_offer(
        offer, invitee, code=offer.code, pairing_secret=offer.pairing_secret,
        expected_fingerprint=offer.certificate_fingerprint, now=now + 1,
    )
    paired = complete_pairing(
        offer, inviter, confirmation, code=offer.code,
        pairing_secret=offer.pairing_secret, now=now + 2,
    )
    return inviter, invitee, offer, confirmation, paired


def _paired_inviter(inviter: DeviceIdentity, group_id: str) -> PairedDevice:
    return PairedDevice(
        inviter.device_id, group_id, inviter.signing_public_key, inviter.exchange_public_key,
        inviter.fingerprint, 1000.0, inviter.sign(b"enrollment"),
    )


def test_pairing_requires_both_confirmation_and_rejects_wrong_code_and_expiry():
    inviter = DeviceIdentity.generate("a")
    invitee = DeviceIdentity.generate("b")
    offer = create_pairing_offer(inviter, "g", "10.0.0.10", 40000, now=10.0)
    session = PairingSession(offer, clock=lambda: 11.0)
    with pytest.raises(PairingCodeError):
        session.confirm(invitee, code="00000000", pairing_secret=offer.pairing_secret)
    confirmation = session.confirm(invitee, code=offer.code, pairing_secret=offer.pairing_secret)
    assert confirmation.explicit
    with pytest.raises(Exception):
        # The inviter's explicit confirmation is a separate step and the
        # session itself cannot be consumed twice.
        session.confirm(invitee, code=offer.code, pairing_secret=offer.pairing_secret)
    expired = create_pairing_offer(inviter, "g", "10.0.0.10", 40000, now=10.0)
    with pytest.raises(PairingExpired):
        confirm_pairing_offer(expired, invitee, code=expired.code,
                              pairing_secret=expired.pairing_secret, now=expired.expires_at)


def test_pairing_authentication_and_session_auth_failure():
    inviter, invitee, offer, confirmation, paired = _pair()
    bad = bytearray(confirmation.signature)
    bad[0] ^= 1
    forged = type(confirmation)(
        confirmation.offer_id, confirmation.group_id, confirmation.device_id,
        confirmation.signing_public, confirmation.exchange_public,
        confirmation.inviter_fingerprint, confirmation.confirmed_at,
        confirmation.explicit, bytes(bad), confirmation.version,
    )
    with pytest.raises(Exception):
        complete_pairing(offer, inviter, forged, code=offer.code,
                         pairing_secret=offer.pairing_secret, now=1003.0)

    session_id = b"s" * 16
    hello_a = create_session_hello(inviter, "group-1", session_id)
    hello_b = create_session_hello(invitee, "group-1", session_id)
    channel_a = SecureChannel.from_paired_identities(
        inviter, paired, group_id="group-1", session_id=session_id, role="initiator",
        local_hello=hello_a, remote_hello=hello_b,
    )
    channel_b = SecureChannel.from_paired_identities(
        invitee, _paired_inviter(inviter, "group-1"), group_id="group-1",
        session_id=session_id, role="responder", local_hello=hello_b, remote_hello=hello_a,
    )
    frame = channel_a.seal(b"opaque delta")
    assert channel_b.open(frame) == b"opaque delta"
    with pytest.raises(ReplayError):
        channel_b.open(frame)

    frame_two = channel_a.seal(b"another")
    frame_three = channel_a.seal(b"third")
    assert channel_b.open(frame_three) == b"third"
    with pytest.raises(ReplayError):
        channel_b.open(frame_two)

    malformed = bytearray(channel_a.seal(b"malformed envelope"))
    malformed[-1] ^= 1
    with pytest.raises(FrameError):
        channel_b.open(bytes(malformed))

    authenticated = channel_a.seal(b"authenticated tamper")
    authenticated_payload = json.loads(authenticated[4:])
    ciphertext = authenticated_payload["ciphertext"]
    authenticated_payload["ciphertext"] = (
        ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    )
    tampered_payload = json.dumps(
        authenticated_payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    with pytest.raises(AuthenticationError):
        channel_b.open(encode_frame(tampered_payload))


def test_state_is_off_by_default_encrypted_and_revocation_blocks_counters():
    inviter, invitee, _, _, paired = _pair()
    state = SyncState(identity=inviter, group_id="group-1")
    assert not state.enabled
    with pytest.raises(SyncDisabled):
        state.next_counter()
    state.enable()
    state.trust_peer(paired)
    assert state.next_counter() == 1
    state.accept_inbound_counter(paired.device_id, 1)
    with pytest.raises(Exception):
        state.accept_inbound_counter(paired.device_id, 1)
    blob = state.to_encrypted_bytes(b"k" * 32)
    assert b"group-1" not in blob and b"device-b" not in blob
    restored = SyncState.from_encrypted_bytes(blob, b"k" * 32)
    assert restored.enabled and restored.is_trusted("device-b")
    state.revoke_peer(paired.device_id)
    with pytest.raises(Exception):
        state.require_trusted("device-b")


def test_existing_channel_rejects_exchange_after_peer_revocation():
    inviter, invitee, _, _, paired = _pair()
    state = SyncState(identity=inviter, group_id="group-1")
    state.enable()
    state.trust_peer(paired)
    session_id = b"r" * 16
    hello_a = create_session_hello(inviter, "group-1", session_id)
    hello_b = create_session_hello(invitee, "group-1", session_id)
    channel_a = SecureChannel.from_paired_identities(
        inviter, paired, group_id="group-1", session_id=session_id, role="initiator",
        local_hello=hello_a, remote_hello=hello_b, state=state,
    )
    channel_b = SecureChannel.from_paired_identities(
        invitee, _paired_inviter(inviter, "group-1"), group_id="group-1",
        session_id=session_id, role="responder", local_hello=hello_b, remote_hello=hello_a,
    )
    frame = channel_b.seal(b"before revoke")
    assert channel_a.open(frame) == b"before revoke"

    state.revoke_peer(paired.device_id)
    with pytest.raises(PeerRevoked):
        channel_a.seal(b"after revoke")
    with pytest.raises(PeerRevoked):
        channel_a.open(frame)


def test_existing_channel_rejects_exchange_after_sync_disable_and_reenable():
    inviter, invitee, _, _, paired = _pair()
    state = SyncState(identity=inviter, group_id="group-1")
    state.enable()
    state.trust_peer(paired)
    session_id = b"d" * 16
    hello_a = create_session_hello(inviter, "group-1", session_id)
    hello_b = create_session_hello(invitee, "group-1", session_id)
    channel_a = SecureChannel.from_paired_identities(
        inviter, paired, group_id="group-1", session_id=session_id, role="initiator",
        local_hello=hello_a, remote_hello=hello_b, state=state,
    )
    channel_b = SecureChannel.from_paired_identities(
        invitee, _paired_inviter(inviter, "group-1"), group_id="group-1",
        session_id=session_id, role="responder", local_hello=hello_b, remote_hello=hello_a,
    )
    frame = channel_b.seal(b"before disable")
    assert channel_a.open(frame) == b"before disable"

    state.disable()
    with pytest.raises(SyncDisabled):
        channel_a.seal(b"after disable")
    with pytest.raises(SyncDisabled):
        channel_a.open(frame)

    state.enable()
    with pytest.raises(SyncDisabled):
        channel_a.seal(b"stale after reenable")


def test_manifest_delta_tombstone_conflicts_and_attachment_integrity():
    key = b"z" * 32
    encrypted = encrypt_catalog_record(b'{"secret":"value"}', key, record_id="item-1")
    revision_a = Revision("device-a", 1)
    revision_a2 = Revision("device-a", 2, (revision_a.key,))
    live = SyncRecord("item-1", encrypted, revision_a)
    tombstone = SyncRecord("item-2", b"", Revision("device-a", 3), deleted=True)
    attachment_bytes = b"LGKATT1\x00encrypted-sidecar"
    attachment_delta = make_attachment_delta("att-1", attachment_bytes, revision_a)
    base = build_manifest("group-1", "device-a", 1, [live], attachments=[{
        "id": "att-1", "size": len(attachment_bytes),
        "sha256": hashlib.sha256(attachment_bytes).hexdigest(), "revision": revision_a,
    }])
    changed = build_manifest("group-1", "device-a", 3, [
        SyncRecord("item-1", encrypt_catalog_record(b"changed", key, record_id="item-1"), revision_a2),
        tombstone,
    ], attachments=base.attachments)
    delta = changed.delta_since(base)
    applied = apply_delta(base, delta)
    assert applied.digest == changed.digest
    assert any(row.deleted for row in applied.records)
    assert attachment_delta.size == len(attachment_bytes)
    with pytest.raises(ManifestError):
        AttachmentDelta("att-1", attachment_bytes + b"tampered",
                         hashlib.sha256(attachment_bytes).hexdigest(), revision_a)

    concurrent = SyncRecord("item-1", encrypt_catalog_record(b"remote", key, record_id="item-1"),
                            Revision("device-b", 1))
    result = merge_records([live], [concurrent])
    assert result.has_conflicts and len(result.records) == 2
    resolved = resolve_conflict(result, result.conflicts[0].conflict_id, choice="remote")
    assert not resolved.has_conflicts
    assert resolved.records[0].record_id == "item-1"


def test_bounded_frames_endpoint_allowlist_and_explicit_transport_lifecycle():
    payload = b"x" * 128
    assert decode_frame(encode_frame(payload)) == payload
    with pytest.raises(FrameTooLarge):
        encode_frame(b"x" * (1024 * 1024 + 1))
    with pytest.raises(Exception):
        LANEndpoint("8.8.8.8", 443)
    state = SyncState()
    transport = SyncTransport(state, endpoint_allowlist=(LANEndpoint("127.0.0.1", 45000),))
    assert not transport.running and not state.enabled
    transport.start(LANEndpoint("127.0.0.1", 45000))
    assert transport.running and state.enabled
    transport.stop()
    assert not transport.running
