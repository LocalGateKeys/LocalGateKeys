"""Regression tests for the 2026-11-10 audit (sync transport, native host)."""
from __future__ import annotations

import io
import struct

import pytest

from localvault import native_host
from localvault.sync import transport


def test_deeply_nested_sync_json_is_a_malformed_frame_not_a_crash():
    with pytest.raises(ValueError):
        transport._strict_json(b"[" * 200000)


def test_deeply_nested_hello_is_rejected_as_a_frame_error():
    with pytest.raises(transport.TransportError):
        transport.SessionHello.from_bytes(b"[" * 200000)


def _frame(payload: bytes) -> io.BytesIO:
    return io.BytesIO(struct.pack("=I", len(payload)) + payload)


@pytest.mark.parametrize("payload", [b'{"n": ' + b"9" * 4400 + b"}", b"[" * 100000, b"\xff\xfe"],
                         ids=["huge-integer", "deep-nesting", "bad-utf8"])
def test_native_host_reports_bad_json_as_a_protocol_error(payload):
    with pytest.raises(native_host.NativeBridgeError):
        native_host._read_native_message(_frame(payload))


def test_lan_run_stops_at_sync_aborted_instead_of_trying_the_next_peer(monkeypatch):
    """A vault lock or service stop mid-sync (SyncAborted) ends the LAN run; it is not one peer's error."""
    from types import SimpleNamespace

    from localvault.sync import service as svc

    peers = [{"device_id": "peer-a", "endpoint": "10.0.0.2:1"}, {"device_id": "peer-b", "endpoint": "10.0.0.3:1"}]
    monkeypatch.setattr(svc, "load_sync_state", lambda session: SimpleNamespace(lan_peers=peers))
    tried: list[str] = []

    def aborted(transport, peer_id, *args, **kwargs):
        tried.append(peer_id)
        raise svc.SyncAborted("vault locked")

    monkeypatch.setattr(svc, "sync_with", aborted)
    adapter = svc.LanAdapter(install_id="install", endpoint=lambda: None)
    adapter.transport = object()
    with pytest.raises(svc.SyncAborted):
        adapter.run(object(), object(), now=0, gate=svc.SyncGate())
    assert tried == ["peer-a"]
