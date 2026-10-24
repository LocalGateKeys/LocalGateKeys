"""Focused live-loopback checks for the explicit private-LAN sync transport."""
from __future__ import annotations

import queue
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
    TransportCancelled,
    TransportError,
    complete_pairing,
    confirm_pairing_offer,
    create_pairing_offer,
)
from localvault.sync import transport as tr
from localvault.sync.transport import MAX_FRAME_PAYLOAD


def _paired_transports():
    inviter = DeviceIdentity.generate("transport-a")
    invitee = DeviceIdentity.generate("transport-b")
    offer = create_pairing_offer(inviter, "transport-group", "127.0.0.1", 1, now=1)
    confirmation = confirm_pairing_offer(
        offer, invitee, code=offer.code, pairing_secret=offer.pairing_secret,
        expected_fingerprint=offer.certificate_fingerprint, now=2,
    )
    invitee_record = complete_pairing(
        offer, inviter, confirmation, code=offer.code,
        pairing_secret=offer.pairing_secret, now=3,
    )
    inviter_record = PairedDevice(
        inviter.device_id, "transport-group", inviter.signing_public_key,
        inviter.exchange_public_key, inviter.fingerprint, 3, inviter.sign(b"enrollment"),
    )
    left_state = SyncState(identity=inviter, group_id="transport-group")
    right_state = SyncState(identity=invitee, group_id="transport-group")
    left_state.enable()
    right_state.enable()
    left_state.trust_peer(invitee_record)
    right_state.trust_peer(inviter_record)
    return SyncTransport(left_state), SyncTransport(right_state)


def _free_endpoints(count: int = 1) -> tuple[LANEndpoint, ...]:
    probes = []
    try:
        for _ in range(count):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", 0))
            probes.append(probe)
        return tuple(LANEndpoint("127.0.0.1", int(probe.getsockname()[1])) for probe in probes)
    finally:
        for probe in probes:
            probe.close()


def test_two_paired_states_exchange_one_authenticated_request_response():
    client, server = _paired_transports()
    server_endpoint, client_endpoint = _free_endpoints(2)
    server.set_request_handler(lambda payload: payload.upper())
    server.start(server_endpoint)
    client.start(client_endpoint)
    try:
        assert client.connect(server_endpoint, b"opaque request", peer_id="transport-b") == b"OPAQUE REQUEST"
    finally:
        client.stop()
        server.stop()


def test_oversized_socket_frame_is_rejected_without_killing_listener():
    _client, server = _paired_transports()
    endpoint, = _free_endpoints()
    server.set_request_handler(lambda payload: payload)
    server.start(endpoint)
    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=1) as raw:
            raw.sendall((MAX_FRAME_PAYLOAD + 1).to_bytes(4, "big"))
            raw.settimeout(0.1)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    assert raw.recv(1) == b""
                    break
                except TimeoutError:
                    continue
        assert server.running
    finally:
        server.stop()


@pytest.mark.parametrize("close_operation", ["cancel", "stop"])
def test_cancel_or_stop_closes_active_request_and_unblocks_waiting_client(close_operation: str):
    client, server = _paired_transports()
    server_endpoint, client_endpoint = _free_endpoints(2)
    entered = threading.Event()
    release = threading.Event()

    def blocked_handler(_payload: bytes) -> bytes:
        entered.set()
        release.wait(5)
        return b"done"

    server.set_request_handler(blocked_handler)
    server.start(server_endpoint)
    client.start(client_endpoint)
    result: queue.Queue[BaseException | bytes] = queue.Queue()

    def run_request() -> None:
        try:
            result.put(client.request(server_endpoint, b"wait", peer_id="transport-b", timeout=10))
        except BaseException as exc:  # noqa: BLE001 - assert the worker outcome below
            result.put(exc)

    worker = threading.Thread(target=run_request, daemon=True)
    worker.start()
    assert entered.wait(3)
    getattr(client, close_operation)()
    worker.join(3)
    release.set()
    assert not worker.is_alive()
    assert isinstance(result.get_nowait(), (TransportCancelled, TransportError))
    assert not client.running
    client.stop()
    server.stop()


def test_private_literal_and_endpoint_allowlist_are_enforced_before_connect():
    endpoint = LANEndpoint("127.0.0.1", 45199)
    transport = SyncTransport(SyncState(), endpoint_allowlist=(endpoint,))
    with pytest.raises(TransportError):
        transport.start(LANEndpoint("127.0.0.1", 45200))
    with pytest.raises(TransportError):
        LANEndpoint("8.8.8.8", 443)
    with pytest.raises(TransportError):
        LANEndpoint("localhost", 443)
    transport.stop()


def test_constructor_does_not_create_network_socket(monkeypatch):
    calls = []

    def forbidden_socket(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("constructor created a socket")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    SyncTransport(SyncState())
    assert calls == []


class _FakeSocket:
    def shutdown(self, how) -> None:
        pass

    def close(self) -> None:
        pass


def test_one_network_holds_at_most_two_unauthenticated_inbound_slots():
    transport = SyncTransport(SyncState())
    socks = [_FakeSocket() for _ in range(5)]
    assert tr.MAX_PRE_AUTH_PER_PREFIX == 2 and tr.MAX_INBOUND_CONNECTIONS == 4
    # One host with two addresses in the same /24 can no longer take all four slots.
    assert transport._reserve_inbound(socks[0], "192.168.1.10")
    assert transport._reserve_inbound(socks[1], "192.168.1.11")
    assert not transport._reserve_inbound(socks[2], "192.168.1.12")
    # Another network still gets in; the total cap is unchanged.
    assert transport._reserve_inbound(socks[2], "192.168.2.10")
    assert transport._reserve_inbound(socks[3], "10.0.0.1")
    assert not transport._reserve_inbound(socks[4], "172.16.0.1")
    # An authenticated connection no longer counts against its network.
    transport._release_inbound(socks[3])
    transport._inbound_authenticated(socks[0])
    assert transport._reserve_inbound(socks[4], "192.168.1.12")
    transport._release_inbound(socks[4])
    transport._release_inbound(socks[1])
    assert transport._pre_auth == {socks[2]: "192.168.2.0/24"}
    # IPv6: one /64 (with or without a scope id); an IPv4-mapped address counts as its IPv4 network.
    assert transport._reserve_inbound(socks[1], "fe80::1%3")
    assert transport._reserve_inbound(socks[3], "fe80::2")
    transport._release_inbound(socks[0])
    assert not transport._reserve_inbound(socks[4], "fe80::3")
    transport._release_inbound(socks[1])
    transport._release_inbound(socks[3])
    assert transport._reserve_inbound(socks[1], "::ffff:192.168.2.11")
    assert not transport._reserve_inbound(socks[3], "192.168.2.12")
    assert transport._reserve_inbound(socks[3], "fd00:1:2:3::9")
    transport.stop()
    assert transport._inbound == {} and transport._pre_auth == {}
