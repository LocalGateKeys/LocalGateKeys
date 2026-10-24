"""Protected local sync state, trust, counters, and opt-in lifecycle."""
from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .pairing import DeviceIdentity, PairedDevice

STATE_MAGIC = b"LGKSYNCSTATE1"
STATE_VERSION = 1
MAX_STATE_BYTES = 512 * 1024
MAX_TRUSTED_PEERS = 32
MAX_COUNTER = 2**63 - 1


class SyncStateError(ValueError):
    pass


class SyncDisabled(SyncStateError):
    pass


class PeerRevoked(SyncStateError):
    pass


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: Any, length: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise SyncStateError(f"{field} is malformed")
    try:
        data = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - stable parser boundary
        raise SyncStateError(f"{field} is malformed") from exc
    if len(data) != length:
        raise SyncStateError(f"{field} has an invalid length")
    return data


def _canonical(value: Any) -> bytes:
    try:
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    except (TypeError, ValueError) as exc:
        raise SyncStateError("Sync state is not serializable") from exc
    if len(data) > MAX_STATE_BYTES:
        raise SyncStateError("Sync state is too large")
    return data


def _bounded_counter(value: Any, field: str = "counter") -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise SyncStateError(f"{field} is malformed")
    return value


@dataclass
class SyncState:
    """In-memory state that is disabled until the user explicitly enables it.

    ``to_encrypted_bytes`` is the only persistence representation.  There is
    intentionally no plain JSON/settings writer for this object.
    """

    identity: DeviceIdentity = field(default_factory=DeviceIdentity.generate)
    group_id: str = field(default_factory=lambda: __import__("uuid").uuid4().__str__())
    enabled: bool = False
    trusted_peers: dict[str, PairedDevice] = field(default_factory=dict)
    disabled_devices: set[str] = field(default_factory=set)
    revoked_devices: set[str] = field(default_factory=set)
    outbound_counter: int = 0
    inbound_counters: dict[str, int] = field(default_factory=dict)
    acknowledgements: dict[str, int] = field(default_factory=dict)
    tombstones: dict[str, dict[str, Any]] = field(default_factory=dict)
    selected_item_ids: set[str] = field(default_factory=set)
    retry_attempt: int = 0
    #: Optional persistent source of hello counters (called once per hello; must return a
    #: value it has already persisted, strictly above every earlier one).
    counter_source: Callable[[], int] | None = field(default=None, repr=False, compare=False)
    _authorization_epoch: int = field(default=0, init=False, repr=False, compare=False)
    #: Guards the outbound and inbound counters: the transport runs several
    #: connection handlers (and an outbound run) at once.
    _counter_lock: Any = field(default_factory=threading.RLock, init=False, repr=False, compare=False)
    _counters_in_flight: int = field(default=0, init=False, repr=False, compare=False)
    _issued_in_flight: set[int] = field(default_factory=set, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.identity, DeviceIdentity) or not self.identity.device_id:
            raise SyncStateError("Device identity is required")
        if not isinstance(self.group_id, str) or not self.group_id or len(self.group_id) > 128:
            raise SyncStateError("Sync group identity is malformed")
        self.outbound_counter = _bounded_counter(self.outbound_counter, "outbound counter")
        if len(self.trusted_peers) > MAX_TRUSTED_PEERS:
            raise SyncStateError("Too many trusted sync peers")
        for peer_id, peer in self.trusted_peers.items():
            if peer_id != peer.device_id or peer.group_id != self.group_id:
                raise SyncStateError("Trusted peer is not bound to this group")
        if any(not isinstance(peer_id, str) or not peer_id for peer_id in self.disabled_devices):
            raise SyncStateError("Disabled peer identity is malformed")
        for peer_id, counter in self.inbound_counters.items():
            if not isinstance(peer_id, str):
                raise SyncStateError("Inbound peer identity is malformed")
            _bounded_counter(counter, "inbound counter")
        for peer_id, counter in self.acknowledgements.items():
            if not isinstance(peer_id, str):
                raise SyncStateError("Acknowledgement peer identity is malformed")
            _bounded_counter(counter, "acknowledgement counter")

    @property
    def opted_in(self) -> bool:
        return self.enabled

    def enable(self) -> None:
        """Explicit user opt-in; no constructor or import enables sync."""

        self.enabled = True

    def disable(self) -> None:
        """Opt out and invalidate active channels and counter acceptance."""

        self.enabled = False
        self._authorization_epoch += 1

    def require_enabled(self) -> None:
        if not self.enabled:
            raise SyncDisabled("LAN sync is disabled; explicit opt-in is required")

    def next_counter(self) -> int:
        """Hand out the next hello counter; safe to call from several threads at once.

        ``counter_source`` is deliberately called *outside* ``_counter_lock``:
        the LAN source may enter the sync gate for a block refill, and an
        outbound run calls this while already holding that gate, so holding our
        lock across the call would order the two locks both ways (deadlock).
        Instead each call notes the high-water mark when it starts and must get
        a value above it (a source that repeats or goes backwards is still
        caught), concurrent calls must get distinct values, and the mark only
        moves forward.
        """
        with self._counter_lock:
            self.require_enabled()
            if self.outbound_counter >= MAX_COUNTER:
                raise SyncStateError("Outbound sync counter is exhausted")
            source = self.counter_source
            if source is None:
                self.outbound_counter += 1
                return self.outbound_counter
            floor = self.outbound_counter
            self._counters_in_flight += 1
        counter: int | None = None
        try:
            counter = _bounded_counter(source(), "outbound counter")
        finally:
            with self._counter_lock:
                self._counters_in_flight -= 1
                duplicate = counter is not None and counter in self._issued_in_flight
                if counter is not None and self._counters_in_flight:
                    self._issued_in_flight.add(counter)
                else:
                    self._issued_in_flight.clear()
                if counter is not None and counter > floor and not duplicate:
                    self.outbound_counter = max(self.outbound_counter, counter)
        if counter <= floor or duplicate:
            raise SyncStateError("Persistent hello counter did not increase")
        return counter

    def trust_peer(self, peer: PairedDevice) -> None:
        self.require_enabled()
        if not isinstance(peer, PairedDevice) or peer.group_id != self.group_id:
            raise SyncStateError("Peer trust record is malformed or from another group")
        if peer.device_id == self.identity.device_id or peer.device_id in self.revoked_devices:
            raise PeerRevoked("This device identity is revoked")
        if len(self.trusted_peers) >= MAX_TRUSTED_PEERS and peer.device_id not in self.trusted_peers:
            raise SyncStateError("Trusted peer limit exceeded")
        self.trusted_peers[peer.device_id] = peer
        self.disabled_devices.discard(peer.device_id)

    def disable_peer(self, device_id: str) -> None:
        """Disable a trusted peer and invalidate channels bound to it."""

        self.require_trusted(device_id)
        self.disabled_devices.add(device_id)
        self._authorization_epoch += 1

    def enable_peer(self, device_id: str) -> None:
        """Re-enable a still-trusted peer after an explicit user action."""

        self.require_enabled()
        if device_id not in self.trusted_peers:
            raise SyncStateError("Peer is not explicitly paired")
        self.disabled_devices.discard(device_id)
        self._authorization_epoch += 1

    def invalidate_channels(self) -> None:
        """Invalidate every channel without changing the trust list."""

        self._authorization_epoch += 1

    def forget_peer(self, device_id: str) -> None:
        """Remove local trust without adding a permanent revocation marker."""

        if not isinstance(device_id, str) or not device_id:
            raise SyncStateError("Peer device identity is malformed")
        if device_id not in self.trusted_peers:
            raise SyncStateError("Peer is not explicitly paired")
        self._authorization_epoch += 1
        self.trusted_peers.pop(device_id, None)
        self.disabled_devices.discard(device_id)
        self.inbound_counters.pop(device_id, None)
        self.acknowledgements.pop(device_id, None)

    def revoke_peer(self, device_id: str) -> None:
        if not isinstance(device_id, str) or not device_id:
            raise SyncStateError("Peer device identity is malformed")
        self._authorization_epoch += 1
        self.revoked_devices.add(device_id)
        self.trusted_peers.pop(device_id, None)
        self.disabled_devices.discard(device_id)

    def require_channel_authorized(self, peer_id: str, authorization_epoch: int) -> None:
        """Reject a channel after disable, revocation, or trust invalidation."""

        self.require_enabled()
        if peer_id in self.revoked_devices:
            raise PeerRevoked("Peer device has been revoked")
        if peer_id in self.disabled_devices:
            raise SyncDisabled("Peer sync is disabled")
        if authorization_epoch != self._authorization_epoch:
            raise SyncDisabled("Sync channel authorization has expired")
        self.require_trusted(peer_id)

    def channel_authorizer(self, peer_id: str) -> Callable[[], None]:
        """Return a guard bound to this peer and the current authorization epoch."""

        self.require_enabled()
        self.require_trusted(peer_id)
        authorization_epoch = self._authorization_epoch

        def check() -> None:
            self.require_channel_authorized(peer_id, authorization_epoch)

        return check

    def is_trusted(self, device_id: str) -> bool:
        return (self.enabled and device_id not in self.revoked_devices
                and device_id not in self.disabled_devices
                and device_id in self.trusted_peers)

    def require_trusted(self, device_id: str) -> PairedDevice:
        self.require_enabled()
        if device_id in self.revoked_devices:
            raise PeerRevoked("Peer device has been revoked")
        if device_id in self.disabled_devices:
            raise SyncDisabled("Peer sync is disabled")
        peer = self.trusted_peers.get(device_id)
        if peer is None:
            raise SyncStateError("Peer is not explicitly paired")
        return peer

    def accept_inbound_counter(self, peer_id: str, counter: int) -> None:
        with self._counter_lock:  # check and record as one step (concurrent handlers)
            self.require_trusted(peer_id)
            counter = _bounded_counter(counter)
            previous = self.inbound_counters.get(peer_id, 0)
            # Strict monotonicity rejects duplicates and out-of-order frames.
            if counter <= previous:
                raise SyncStateError("Replay or out-of-order sync message")
            self.inbound_counters[peer_id] = counter

    def acknowledge(self, peer_id: str, counter: int) -> None:
        self.require_trusted(peer_id)
        counter = _bounded_counter(counter)
        self.acknowledgements[peer_id] = max(self.acknowledgements.get(peer_id, 0), counter)

    def retain_tombstone(self, item_id: str, *, device_id: str, counter: int,
                         parents: tuple[str, ...] = ()) -> None:
        self.require_enabled()
        if not isinstance(item_id, str) or not item_id or len(item_id) > 128:
            raise SyncStateError("Tombstone item identity is malformed")
        self.tombstones[item_id] = {
            "device_id": device_id, "counter": _bounded_counter(counter),
            "parents": list(parents), "created_at": int(time.time()),
        }

    def retry_delay(self, *, base_seconds: float = 1.0, max_seconds: float = 300.0) -> float:
        if not 0 < base_seconds <= max_seconds or max_seconds > 3600:
            raise SyncStateError("Retry bounds are malformed")
        delay = min(max_seconds, base_seconds * (2 ** min(self.retry_attempt, 10)))
        self.retry_attempt = min(self.retry_attempt + 1, 31)
        return delay

    def reset_retry(self) -> None:
        self.retry_attempt = 0

    def _protected_dict(self) -> dict[str, Any]:
        return {
            "version": STATE_VERSION, "group_id": self.group_id, "enabled": self.enabled,
            "identity": self.identity.protected_dict(),
            "trusted_peers": [peer.to_dict() for peer in self.trusted_peers.values()],
            "disabled_devices": sorted(self.disabled_devices),
            "revoked_devices": sorted(self.revoked_devices),
            "outbound_counter": self.outbound_counter,
            "inbound_counters": dict(self.inbound_counters),
            "acknowledgements": dict(self.acknowledgements),
            "tombstones": self.tombstones,
            "selected_item_ids": sorted(self.selected_item_ids),
            "retry_attempt": self.retry_attempt,
        }

    def to_encrypted_bytes(self, key: bytes) -> bytes:
        if not isinstance(key, bytes) or len(key) != 32:
            raise SyncStateError("Protected state key must be 32 bytes")
        payload = _canonical(self._protected_dict())
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, payload, STATE_MAGIC)
        result = STATE_MAGIC + nonce + ciphertext
        if len(result) > MAX_STATE_BYTES:
            raise SyncStateError("Protected sync state is too large")
        return result

    @classmethod
    def from_encrypted_bytes(cls, blob: bytes, key: bytes) -> SyncState:
        if not isinstance(key, bytes) or len(key) != 32:
            raise SyncStateError("Protected state key must be 32 bytes")
        if not isinstance(blob, bytes) or not (len(STATE_MAGIC) + 12 + 16 <= len(blob) <= MAX_STATE_BYTES):
            raise SyncStateError("Protected sync state is malformed")
        if blob[:len(STATE_MAGIC)] != STATE_MAGIC:
            raise SyncStateError("Protected sync state has an invalid header")
        nonce_start = len(STATE_MAGIC)
        try:
            payload = AESGCM(key).decrypt(blob[nonce_start:nonce_start + 12],
                                         blob[nonce_start + 12:], STATE_MAGIC)
            raw = json.loads(payload)
        except (InvalidTag, ValueError, TypeError, json.JSONDecodeError):
            raise SyncStateError("Protected sync state authentication failed") from None
        if not isinstance(raw, Mapping) or raw.get("version") != STATE_VERSION:
            raise SyncStateError("Unsupported protected sync state")
        peers: dict[str, PairedDevice] = {}
        for value in raw.get("trusted_peers", []):
            if not isinstance(value, Mapping):
                raise SyncStateError("Trusted peer state is malformed")
            try:
                peer = PairedDevice(
                    device_id=value["device_id"], group_id=value["group_id"],
                    signing_public=_b64d(value["signing_public"], 32, "peer signing key"),
                    exchange_public=_b64d(value["exchange_public"], 32, "peer exchange key"),
                    fingerprint=value["fingerprint"], enrolled_at=float(value["enrolled_at"]),
                    enrollment_signature=_b64d(value["enrollment_signature"], 64,
                                                "enrollment signature"),
                    revoked=value.get("revoked") is True,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise SyncStateError("Trusted peer state is malformed") from exc
            peers[peer.device_id] = peer
        identity = DeviceIdentity.from_protected_dict(raw.get("identity", {}))
        result = cls(
            identity=identity, group_id=raw.get("group_id", ""), enabled=raw.get("enabled") is True,
            trusted_peers=peers, disabled_devices=set(raw.get("disabled_devices", [])),
            revoked_devices=set(raw.get("revoked_devices", [])),
            outbound_counter=raw.get("outbound_counter", 0),
            inbound_counters=dict(raw.get("inbound_counters", {})),
            acknowledgements=dict(raw.get("acknowledgements", {})),
            tombstones=dict(raw.get("tombstones", {})),
            selected_item_ids=set(raw.get("selected_item_ids", [])),
            retry_attempt=raw.get("retry_attempt", 0),
        )
        return result

    def save_encrypted(self, path: Path, key: bytes) -> None:
        """Persist only the authenticated encrypted representation."""

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_encrypted_bytes(key)
        fd, name = tempfile.mkstemp(prefix=".lgk-sync-", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @classmethod
    def load_encrypted(cls, path: Path, key: bytes) -> SyncState:
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            raise SyncStateError("Protected sync state is unavailable") from exc
        return cls.from_encrypted_bytes(data, key)


__all__ = ["SyncState", "SyncStateError", "SyncDisabled", "PeerRevoked",
           "STATE_MAGIC", "MAX_STATE_BYTES"]
