"""Small disposable Windows-VM probe for the authenticated private-LAN transport.

The two guests run this script with the same deterministic public test identities.
It creates no vault data and sends one opaque request after the normal pinned-peer
hello exchange.  It is intentionally separate from product startup code.
"""
from __future__ import annotations

import argparse
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from localvault.sync import DeviceIdentity, LANEndpoint, PairedDevice, SyncState, SyncTransport

GROUP = "vm-lan-probe"


def identity(label: str) -> DeviceIdentity:
    seed = hashlib.sha256(("localgatekeys-vm|" + label).encode()).digest()
    exchange = hashlib.sha256(("localgatekeys-vm-x25519|" + label).encode()).digest()
    return DeviceIdentity(
        label,
        ed25519.Ed25519PrivateKey.from_private_bytes(seed),
        x25519.X25519PrivateKey.from_private_bytes(exchange),
    )


def peer_record(peer: DeviceIdentity) -> PairedDevice:
    return PairedDevice(
        peer.device_id,
        GROUP,
        peer.signing_public_key,
        peer.exchange_public_key,
        peer.fingerprint,
        1.0,
        b"\x00" * 64,
    )


def state(local: DeviceIdentity, peer: DeviceIdentity) -> SyncState:
    result = SyncState(identity=local, group_id=GROUP)
    result.enable()
    result.trust_peer(peer_record(peer))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("server", "client"))
    parser.add_argument("--local", required=True, help="literal host-only guest address")
    parser.add_argument("--remote", default="192.168.56.101")
    parser.add_argument("--port", type=int, default=45555)
    parser.add_argument("--seconds", type=float, default=30.0)
    args = parser.parse_args()

    local = identity("vm-peer-a" if args.role == "server" else "vm-peer-b")
    peer = identity("vm-peer-b" if args.role == "server" else "vm-peer-a")
    transport = SyncTransport(
        state(local, peer),
        request_handler=(lambda payload: b"vm-ack:" + payload),
        socket_timeout=8,
    )
    local_endpoint = LANEndpoint(args.local, args.port + (0 if args.role == "server" else 1))
    remote_endpoint = LANEndpoint(args.remote, args.port)
    transport.start(local_endpoint)
    try:
        if args.role == "server":
            print(f"VM_PROBE_SERVER_READY {local_endpoint.host}:{local_endpoint.port}", flush=True)
            time.sleep(args.seconds)
            return 0
        response = transport.request(
            remote_endpoint,
            b"authenticated-lan-probe",
            peer_id=peer.device_id,
        )
        print(f"VM_PROBE_CLIENT_RESPONSE {response.decode('ascii')}", flush=True)
        return 0 if response == b"vm-ack:authenticated-lan-probe" else 2
    finally:
        transport.stop()


if __name__ == "__main__":
    raise SystemExit(main())
