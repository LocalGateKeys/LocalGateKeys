"""F-02: the LAN hello is sealed to the pinned responder (protocol version 3) and pinned per peer.

Loopback only.  docs/formats/LAN_SYNC_V3.md has the byte rules; tests/vectors/sync/lan/v3 the vectors.
"""
from __future__ import annotations

import base64
import json
import socket
import threading
import time

import pytest

from localvault.sync import (
    DeviceIdentity,
    LANEndpoint,
    PairedDevice,
    SyncState,
    SyncTransport,
)
from localvault.sync import transport as tr
from localvault.sync.transport import PeerVersionMismatch, TransportError

GROUP = "sealed-hello-group"


def _record(identity: DeviceIdentity) -> PairedDevice:
    return PairedDevice(identity.device_id, GROUP, identity.signing_public_key, identity.exchange_public_key,
                        identity.fingerprint, 3, identity.sign(b"enrollment"))


def _state(identity: DeviceIdentity, *peers: DeviceIdentity, sealed: set[str] | None = None) -> SyncState:
    state = SyncState(identity=identity, group_id=GROUP, sealed_peers=set(sealed or ()))
    state.enable()
    for peer in peers:
        state.trust_peer(_record(peer))
    return state


def _pair():
    a, b = DeviceIdentity.generate("sealed-a"), DeviceIdentity.generate("sealed-b")
    return a, b, SyncTransport(_state(a, b)), SyncTransport(_state(b, a))


def _free_endpoint() -> LANEndpoint:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return LANEndpoint("127.0.0.1", int(probe.getsockname()[1]))
    finally:
        probe.close()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    out = b""
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            return out
        out += chunk
    return out


def _read_frame(sock: socket.socket) -> bytes | None:
    """One length-prefixed frame payload, or None when the peer closed first."""
    header = _recv_exact(sock, 4)
    if len(header) < 4:
        return None
    return _recv_exact(sock, int.from_bytes(header, "big"))


class _FakePeer:
    """A loopback listener that records the first frame of each connection and answers with *reply*."""

    def __init__(self, reply: bytes | None = None) -> None:
        self.reply = reply
        self.frames: list[bytes] = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(5)
        self.endpoint = LANEndpoint("127.0.0.1", int(self.listener.getsockname()[1]))
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                frame = _read_frame(conn)
                if frame is not None:
                    self.frames.append(frame)
                if self.reply is not None:
                    conn.sendall(tr.encode_frame(self.reply))

    def close(self) -> None:
        self.listener.close()
        self.thread.join(timeout=5)


def _exchange_raw(endpoint: LANEndpoint, payload: bytes) -> bytes | None:
    """Send one first frame on a new connection; the answer frame, or None for a silent close."""
    with socket.create_connection((endpoint.host, endpoint.port), timeout=5) as raw:
        raw.settimeout(5)
        raw.sendall(tr.encode_frame(payload))
        try:
            return _read_frame(raw)
        except (ConnectionResetError, ConnectionAbortedError):
            return None


def _wait_until(check, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.02)
    return check()


def _common_window(left: bytes, right: bytes, size: int = 8) -> bool:
    windows = {left[i:i + size] for i in range(len(left) - size + 1)}
    return any(right[i:i + size] in windows for i in range(len(right) - size + 1))


# --- tracking ---------------------------------------------------------------------------------


def test_two_first_frames_carry_no_identifier_and_share_no_linkable_bytes():
    a, b, client, _server = _pair()
    fake = _FakePeer()  # closes after reading: request() fails, but its first frame is recorded
    client.start(_free_endpoint())
    try:
        for _ in range(2):
            with pytest.raises(TransportError):
                client.request(fake.endpoint, b"x", peer_id=b.device_id, timeout=5)
    finally:
        client.stop()
        fake.close()
    first, second = fake.frames
    assert len(first) == len(second)
    for frame in (first, second):
        value = json.loads(frame)
        assert set(value) == {"box", "eph", "signature", "version"} and value["signature"] == ""
        assert value["version"] == 3
        for ident in (a, b):
            for marker in (ident.device_id.encode(), ident.fingerprint.encode(),
                           base64.b64encode(ident.signing_public_key), base64.b64encode(ident.exchange_public_key),
                           ident.signing_public_key, ident.exchange_public_key):
                assert marker not in frame
        assert GROUP.encode() not in frame
    raw = [{k: base64.b64decode(json.loads(f)[k]) for k in ("box", "eph")} for f in (first, second)]
    assert len(raw[0]["box"]) == tr.SEALED_HELLO_PLAINTEXT_BYTES + 16
    # the only bytes the two sessions have in common are the fixed JSON skeleton
    assert not _common_window(raw[0]["eph"] + raw[0]["box"], raw[1]["eph"] + raw[1]["box"])


def test_a_clear_text_hello_is_never_sent_and_an_old_peer_is_reported():
    _a, b, client, _server = _pair()
    old = _FakePeer(reply=b'{"refused":"version","version":2}')  # what a released version-2 build answers
    client.start(_free_endpoint())
    try:
        with pytest.raises(PeerVersionMismatch) as caught:
            client.request(old.endpoint, b"x", peer_id=b.device_id, timeout=5)
    finally:
        client.stop()
        old.close()
    assert caught.value.peer_version == 2 and caught.value.peer_older
    assert len(old.frames) == 1 and json.loads(old.frames[0])["version"] == 3  # sealed, never clear text
    assert not client.state.is_sealed(b.device_id)


def test_request_requires_the_expected_peer():
    _a, _b, client, _server = _pair()
    client.start(_free_endpoint())
    try:
        with pytest.raises(tr.AuthenticationError):
            client.request(_free_endpoint(), b"x")
    finally:
        client.stop()


# --- non-members ------------------------------------------------------------------------------


def test_a_non_member_or_a_wrong_key_gets_no_answer_at_all():
    a, b, _client, server = _pair()
    outsider = DeviceIdentity.generate("sealed-outsider")
    endpoint = _free_endpoint()
    server.set_request_handler(lambda payload: payload)
    server.start(endpoint)
    try:
        # sealed to B's real key, but the inner hello is from a device B does not trust
        hello = tr.create_session_hello(outsider, GROUP, b"\x01" * 16, version=3)
        first, ctx = tr.seal_initiator_hello(hello, b.exchange_public_key)
        ctx.wipe()
        assert _exchange_raw(endpoint, first) is None
        # A's genuine hello sealed to a key that is not B's: B cannot open it
        hello = tr.create_session_hello(a, GROUP, b"\x02" * 16, counter=50, version=3)
        first, ctx = tr.seal_initiator_hello(hello, DeviceIdentity.generate().exchange_public_key)
        ctx.wipe()
        assert _exchange_raw(endpoint, first) is None
        # a clear-text hello of a non-member
        hello = tr.create_session_hello(outsider, GROUP, b"\x03" * 16)
        assert _exchange_raw(endpoint, hello.to_bytes()) is None
        # random bytes in the sealed shape
        junk = json.dumps({"box": base64.b64encode(bytes(1040)).decode(),
                           "eph": base64.b64encode(bytes([9]) * 32).decode(),
                           "signature": "", "version": 3}, separators=(",", ":"), sort_keys=True).encode()
        assert _exchange_raw(endpoint, junk) is None
    finally:
        server.stop()
    assert server._verified == {}


# --- pinning and downgrade --------------------------------------------------------------------


def test_a_sealed_session_pins_both_sides_and_then_a_clear_hello_is_refused():
    a, b, client, server = _pair()
    endpoint = _free_endpoint()
    saved: list[str] = []
    server.state.on_sealed = saved.append
    server.set_request_handler(lambda payload: payload.upper())
    server.start(endpoint)
    client.start(_free_endpoint())
    try:
        # before the pin: an older initiator's clear-text hello is still answered with a hello
        hello = client._local_hello(b"\x04" * 16)
        try:
            answer = _exchange_raw(endpoint, hello.to_bytes())
        finally:
            hello.ephemeral_secret.wipe()
        assert answer is not None and json.loads(answer)["version"] == 2
        assert _wait_until(lambda: not server._inbound)
        assert client.request(endpoint, b"sealed", peer_id=b.device_id) == b"SEALED"
        assert client.state.is_sealed(b.device_id)
        assert _wait_until(lambda: server.state.is_sealed(a.device_id))
        assert saved == [a.device_id]
        # after the pin: A's (valid, fresh) clear-text hello gets only the version refusal
        hello = client._local_hello(b"\x05" * 16)
        try:
            answer = _exchange_raw(endpoint, hello.to_bytes())
        finally:
            hello.ephemeral_secret.wipe()
        assert answer == tr.version_refusal() == b'{"refused":"version","version":3}'
        # a second sealed session still works and is not saved again
        assert client.request(endpoint, b"again", peer_id=b.device_id) == b"AGAIN"
        assert saved == [a.device_id]
    finally:
        client.stop()
        server.stop()


def test_a_pin_loaded_at_start_refuses_the_clear_hello_from_the_first_connection():
    a, b = DeviceIdentity.generate("pinned-a"), DeviceIdentity.generate("pinned-b")
    client = SyncTransport(_state(a, b))
    server = SyncTransport(_state(b, a, sealed={a.device_id}))
    endpoint = _free_endpoint()
    server.set_request_handler(lambda payload: payload)
    server.start(endpoint)
    try:
        hello = client._local_hello(b"\x06" * 16)
        try:
            assert _exchange_raw(endpoint, hello.to_bytes()) == tr.version_refusal()
        finally:
            hello.ephemeral_secret.wipe()
        assert _wait_until(lambda: not server._inbound)
        client.start(_free_endpoint())
        assert client.request(endpoint, b"ok", peer_id=b.device_id) == b"ok"
    finally:
        client.stop()
        server.stop()


def test_the_pin_survives_the_encrypted_state():
    a, b = DeviceIdentity.generate("persist-a"), DeviceIdentity.generate("persist-b")
    state = _state(a, b)
    state.mark_sealed(b.device_id)
    key = b"\x11" * 32
    restored = SyncState.from_encrypted_bytes(state.to_encrypted_bytes(key), key)
    assert restored.is_sealed(b.device_id)
