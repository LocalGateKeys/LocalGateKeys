"""Wi-Fi LAN sync on the group model, with one-use QR enrollment.

Two devices that trust each other talk over the authenticated
:class:`~localvault.sync.transport.SyncTransport` (signed hellos, AES-GCM
channel, literal private IPs, no discovery).  Inside that channel they exchange
the same sealed views as the cloud folder (:func:`localvault.sync.group.encode_view`)
and merge them with the shared :func:`localvault.sync.runner.run_merge`, so an
edit that arrives over LAN and through the folder is merged by the same code.

Enrollment (spec "LAN enrollment")
----------------------------------
1. A device that has a group calls :func:`begin_pairing`, shows
   ``pairing.offer_qr_payload(offer)`` as a QR code and arms its listener with
   ``LanResponder.start_enrollment(offer, transport)``.
2. The new device scans it and calls :func:`enroll_from_qr`: it sends the one
   pre-authentication request the listener accepts (encrypted to the inviter's
   exchange key from the QR, MAC under the pairing secret, signed by the new
   identity; see :func:`localvault.sync.pairing.build_enrollment_request`).
3. The inviter verifies it inside a ``PairingSession`` (one success consumes the
   offer, at most 5 failures counted only for requests that decrypt, 120 s TTL;
   a device id already in ``lan_peers``, the keyring members or the inviter's own
   is refused as a failure; a full peer list is refused before anything is
   consumed; a used or expired offer gets a clear refusal), pins the new device in its
   ``lan_peers`` (with the optional listening endpoint) and answers with
   (group_id, epoch, G) sealed to the new device and signed by the inviter.  The
   reply goes out at once: the iPhone app waits only about 5 seconds for it and the
   request carries no device name, so there is no "Accept" step before it; the
   inviter's screen names the device (id and key fingerprint) with an Undo, which
   removes it again (``remove_lan_peer``, or a rotation in a cloud-folder group).
   Frames for no armed offer, an expired one or another offer id are answered by
   :meth:`LanResponder.enroll_prefilter` without the sync gate.
4. The new device verifies the reply against the QR-pinned inviter key, checks it
   pinned its own identity, and stores the group with its identity, install id
   and the inviter as its LAN peer.

There is no other key delivery: a device removed or rotated out never gets a
newer key over LAN.  LAN-only peers cannot follow a rotation and re-pair; until
then the device with the lower epoch reports ``epoch-behind`` and does not merge.

Messages (inside the authenticated channel)
-------------------------------------------
Every message is canonical JSON (sorted keys, compact, ASCII).  Duplicate keys
and non-finite numbers are rejected; requests over ``transport.MAX_MESSAGE_BYTES``
get ``too-large``.

* ``{"type":"view","group_id","epoch","transfer","seq","total","size","view"}``:
  ``view`` is standard base64 of chunk ``seq`` (0-based) of ``total`` chunks of
  one encoded view of ``size`` bytes.  The transport carries one request and one
  response per connection and one frame is about 1 MiB, so a view is split into
  chunks of ``CHUNK_BYTES``.  The responder acknowledges every chunk but the
  last with ``{"type":"ack","transfer","seq"}``; it answers the last with the
  first chunk of its own view, and the initiator fetches the others with
  ``{"type":"next","transfer","seq"}``.  Chunks must arrive in order; a view is
  at most 64 MiB; a responder keeps at most one transfer per peer and two in
  total in each direction.
* ``{"type":"error","reason"}``.

Every incoming view is decoded with ``expected_device_id`` = the authenticated
peer; the peer must be listed in this vault's ``lan_peers``, not revoked, and
with the same pinned key as the transport's record.  A LAN view carries the
current ``own_counter`` unchanged: nothing on LAN checks view counters (they
order folder files), so a LAN exchange reserves nothing and an exchange that
changes no item writes nothing to the vault.  LAN
does not touch ``last_seen``: replay protection on LAN is the transport's
per-peer hello counters, which this device reserves in blocks persisted in
``hello_counter`` (a block starts at ``max(persisted + 1, clock)`` and is saved
before any of it is used).

Installation binding is the folder rule: a stored ``install_id`` different from
the caller's gives ``rejoin-required`` and nothing is read or sent.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import dataclasses
import json
import math
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .group import MAX_BYTES, GroupKey, SyncFormatError, View, decode_view, encode_view
from .pairing import (
    ENROLL_REQUEST_MAGIC,
    MAX_ENROLL_BYTES,
    PAIRING_TTL_SECONDS,
    DeviceIdentity,
    EnrollmentRefused,
    PairedDevice,
    PairingError,
    PairingExpired,
    PairingOffer,
    PairingReplayError,
    PairingSession,
    build_enrollment_request,
    create_pairing_offer,
    enrollment_refusal,
    enrollment_transcript,
    open_enrollment_reply,
    parse_qr_payload,
    seal_enrollment_reply,
)
from .runner import RunReport, SyncIssue, run_merge
from .state import SyncState, SyncStateError
from .transport import (
    MAX_MESSAGE_BYTES,
    LANEndpoint,
    PeerNotAnswering,
    SyncTransport,
    TransportError,
)
from .vault_bridge import (
    MAX_INSTALL_ID,
    MAX_LAN_PEERS,
    BridgeError,
    SyncGroupState,
    _check_lease,
    load_sync_state,
    local_view,
    save_sync_state,
)

#: Raw view bytes per message when sending.
CHUNK_BYTES = 512 * 1024
#: Largest chunk accepted; base64 plus the envelope still seals into one transport frame.
CHUNK_LIMIT = 560 * 1024
MAX_VIEW_BYTES = MAX_BYTES
MAX_CHUNKS = 65536
TRANSFER_TTL_SECONDS = 300
#: In-flight chunked transfers a responder keeps per direction (one per peer at most).
MAX_TRANSFERS = 2
#: Pause before the one retry of a chunk request the peer did not answer.
CHUNK_RETRY_DELAY = 0.05
#: Hello counters reserved per vault save.
HELLO_COUNTER_BLOCK = 64

_FIELDS = {
    "view": frozenset({"type", "group_id", "epoch", "transfer", "seq", "total", "size", "view"}),
    "next": frozenset({"type", "transfer", "seq"}),
    "ack": frozenset({"type", "transfer", "seq"}),
    "error": frozenset({"type", "reason"}),
}
_MAX_INT = 2**53 - 1
_HEX = frozenset("0123456789abcdef")
#: Every reason a responder can send in an ``error`` message (the iOS app and the test vectors use this list).
ERROR_REASONS = (
    "bad-chunk", "bad-message", "bad-view", "device-mismatch", "epoch-behind", "group-mismatch",
    "local-data", "not-joined", "peer-epoch-behind", "rejoin-required", "revoked", "too-large",
    "unknown-peer",
)
# Responder error reasons as the initiator reports them.
_REPLY_ISSUES = {
    "epoch-behind": "epoch-behind",
    "peer-epoch-behind": "peer-epoch-behind",
    "rejoin-required": "peer-rejoin-required",
    "not-joined": "peer-not-joined",
}


USED_OR_EXPIRED_MESSAGE = "This pairing code was used up or expired. Show a new code."


class LanSyncError(ValueError):
    """A LAN pairing step or message was refused; ``reason`` is a stable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


# --- small helpers ------------------------------------------------------------------------


def _check_install(install_id: object) -> str:
    if (not isinstance(install_id, str) or not install_id or len(install_id) > MAX_INSTALL_ID
            or "\x00" in install_id):
        raise ValueError("install id must be a non-empty bounded string")
    return install_id


def encode_message(message: Mapping[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("ascii")


def _error(reason: str) -> dict[str, Any]:
    return {"type": "error", "reason": reason}


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _is_int(value: object, low: int = 0, high: int = _MAX_INT) -> bool:
    return type(value) is int and low <= value <= high


def parse_message(raw: bytes) -> dict[str, Any]:
    """Parse and shape-check one message; raises ``LanSyncError`` (too-large / bad-message)."""
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES:
        raise LanSyncError("too-large")
    try:
        msg = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                         parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise LanSyncError("bad-message") from None
    if not isinstance(msg, dict) or msg.get("type") not in _FIELDS or set(msg) != _FIELDS[msg["type"]]:
        raise LanSyncError("bad-message")
    kind = msg["type"]
    if kind in ("view", "next", "ack"):
        transfer = msg["transfer"]
        if (not isinstance(transfer, str) or len(transfer) != 32 or not set(transfer) <= _HEX
                or not _is_int(msg["seq"], 0, MAX_CHUNKS - 1)):
            raise LanSyncError("bad-message")
    if kind == "view":
        if not isinstance(msg["group_id"], str) or not _is_int(msg["epoch"], 1):
            raise LanSyncError("bad-message")
        if not _is_int(msg["total"], 1) or not _is_int(msg["size"], 1) or not isinstance(msg["view"], str):
            raise LanSyncError("bad-message")
        if msg["size"] > MAX_VIEW_BYTES or msg["total"] > MAX_CHUNKS:
            raise LanSyncError("too-large")
        if msg["seq"] >= msg["total"] or msg["total"] > msg["size"]:
            raise LanSyncError("bad-message")
        if len(msg["view"]) > 4 * math.ceil(CHUNK_LIMIT / 3):
            raise LanSyncError("too-large")
    if kind == "error" and (not isinstance(msg["reason"], str) or not 1 <= len(msg["reason"]) <= 64):
        raise LanSyncError("bad-message")
    return msg


def _b64d(value: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise LanSyncError("bad-message") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise LanSyncError("bad-message")
    return raw


def split_view(raw: bytes) -> list[bytes]:
    size = max(1, min(CHUNK_BYTES, CHUNK_LIMIT))
    return [raw[i:i + size] for i in range(0, len(raw), size)]


def _view_message(gk: GroupKey, transfer: str, seq: int, parts: list[bytes], size: int) -> dict[str, Any]:
    return {"type": "view", "group_id": gk.group_id, "epoch": gk.epoch, "transfer": transfer, "seq": seq,
            "total": len(parts), "size": size, "view": base64.b64encode(parts[seq]).decode("ascii")}


def _group_key(state: SyncGroupState) -> GroupKey:
    return GroupKey(state.group_id, state.epoch, state.key)


# --- stored LAN peers ---------------------------------------------------------------------------


def peer_to_entry(peer: PairedDevice, *, endpoint: LANEndpoint | tuple[str, int] | None = None) -> dict[str, Any]:
    """The ``SyncGroupState.lan_peers`` entry for *peer* (``endpoint`` None: the peer always initiates)."""
    if isinstance(endpoint, tuple):
        endpoint = LANEndpoint(*endpoint)
    where = None if endpoint is None else {"host": endpoint.host, "port": endpoint.port}
    return {**peer.to_dict(), "endpoint": where}


def peer_from_entry(entry: Mapping[str, Any]) -> PairedDevice:
    if not isinstance(entry, Mapping):
        raise LanSyncError("bad-peer", "stored LAN peer is malformed")
    try:
        return PairedDevice.from_dict({k: v for k, v in entry.items() if k != "endpoint"})
    except PairingError as exc:
        raise LanSyncError("bad-peer", str(exc)) from exc


def peer_entry(state: SyncGroupState, device_id: str) -> dict[str, Any] | None:
    """The stored entry for *device_id*, or None when this vault does not list it."""
    for entry in state.lan_peers:
        if entry.get("device_id") == device_id:
            return dict(entry)
    return None


def peer_endpoint(state: SyncGroupState, device_id: str) -> LANEndpoint | None:
    """The stored listening endpoint of a peer, or None (unknown peer, or one that never listens)."""
    entry = peer_entry(state, device_id)
    where = entry.get("endpoint") if entry is not None else None
    if not isinstance(where, Mapping):
        return None
    try:
        return LANEndpoint(where.get("host"), where.get("port"))
    except TransportError:
        return None


def _matches(entry: Mapping[str, Any] | None, peer: PairedDevice) -> bool:
    """The stored entry pins the same key as the transport's record for *peer*."""
    return (entry is not None and entry.get("fingerprint") == peer.fingerprint
            and entry.get("signing_public") == base64.b64encode(peer.signing_public).decode("ascii")
            and entry.get("group_id") == peer.group_id)


def _with_peer(state: SyncGroupState, entry: Mapping[str, Any]) -> SyncGroupState:
    others = [p for p in state.lan_peers if p.get("device_id") != entry["device_id"]]
    if len(others) >= MAX_LAN_PEERS:
        raise LanSyncError("too-many-peers", f"at most {MAX_LAN_PEERS} LAN peers")
    return dataclasses.replace(state, lan_peers=(*others, dict(entry)))


def remove_lan_peer(session: Any, lease: Any, device_id: str, *, install_id: str,
                    transport: SyncTransport | None = None) -> bool:
    """Forget a LAN peer (and revoke it on a running *transport*); returns whether it was listed.

    The peer keeps the key it already has; rotate the group (cloud folder) to cut it off.
    Removing a listed peer sets ``SyncGroupState.lan_removed`` (until the next key
    change), so a cloud folder added later gets a fresh key instead of this one
    (``folder_transport.add_folder_to_group``, audit M9).
    """
    state = _joined_state(session, lease, _check_install(install_id))
    kept = tuple(p for p in state.lan_peers if p.get("device_id") != device_id)
    tstate = getattr(transport, "state", None)
    if isinstance(tstate, SyncState) and isinstance(device_id, str) and device_id:
        tstate.revoke_peer(device_id)
    if len(kept) == len(state.lan_peers):
        return False
    _check_lease(session, lease)
    save_sync_state(session, dataclasses.replace(state, lan_peers=kept, lan_removed=True))
    return True


def _clock_us() -> int:
    return time.time_ns() // 1000


def transport_state(state: SyncGroupState, session: Any, lease: Any, *,
                    clock: Callable[[], int] | None = None,
                    gate: Callable[[], contextlib.AbstractContextManager[Any]] | None = None) -> SyncState:
    """An enabled transport state for this vault's identity and stored, unrevoked LAN peers.

    Session-hello counters come from ``SyncGroupState.hello_counter`` in blocks of
    ``HELLO_COUNTER_BLOCK``: a new block starts at ``max(persisted + 1, clock in
    microseconds)``, its last value is saved before any of it is used, and the
    rest is handed out from memory.  Counters therefore strictly increase across
    restarts and clock changes, with one vault save per block.

    *gate* (the sync service's ``SyncGate.hold``) is entered only for a block
    refill, the one step that reads and writes the vault; counters handed out
    from memory do not wait for it.  Order: gate, then this source's own lock.
    """
    result = SyncState(identity=state.identity(), group_id=state.group_id)
    result.enable()
    for entry in state.lan_peers:
        peer = peer_from_entry(entry)
        if peer.group_id == state.group_id and not peer.revoked:
            result.trust_peer(peer)
    now_us = clock or _clock_us
    device_id = state.device_id
    block = {"next": 1, "last": 0}
    lock = threading.Lock()

    def take() -> int | None:
        if block["next"] > block["last"]:
            return None
        counter = block["next"]
        block["next"] += 1
        return counter

    def next_hello() -> int:
        with lock:
            counter = take()
        if counter is not None:
            return counter
        with gate() if gate is not None else contextlib.nullcontext(), lock:
            counter = take()  # another thread may have refilled meanwhile
            if counter is not None:
                return counter
            _check_lease(session, lease)
            current = load_sync_state(session)
            if current is None or current.device_id != device_id:
                raise SyncStateError("The sync group of this vault changed")
            start = max(current.hello_counter + 1, int(now_us()), block["last"] + 1)
            last = start + HELLO_COUNTER_BLOCK - 1
            save_sync_state(session, dataclasses.replace(current, hello_counter=last))
            block["next"], block["last"] = start, last
            return take()

    result.counter_source = next_hello
    return result


# --- group and enrollment steps ------------------------------------------------------------------


def _joined_state(session: Any, lease: Any, install_id: str) -> SyncGroupState:
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        raise LanSyncError("not-joined", "this vault is not in a sync group")
    if state.install_id != install_id:
        raise LanSyncError("rejoin-required", "this vault was joined on another installation")
    return state


def create_lan_group(session: Any, lease: Any, *, install_id: str) -> SyncGroupState:
    """Start a new group for LAN sync with this vault as its only device."""
    _check_install(install_id)
    _check_lease(session, lease)
    if load_sync_state(session) is not None:
        raise LanSyncError("already-joined", "leave the current sync group first")
    identity = DeviceIdentity.generate()
    state = SyncGroupState(str(uuid.uuid4()), 1, secrets.token_bytes(32), identity.protected_dict(),
                           install_id=install_id)
    save_sync_state(session, state)
    return state


def begin_pairing(session: Any, lease: Any, host: str, port: int, *, install_id: str,
                  now: float | None = None, ttl_seconds: int = PAIRING_TTL_SECONDS) -> PairingOffer:
    """Create the offer this device shows as a QR code; *host*/*port* is its LAN listener."""
    state = _joined_state(session, lease, _check_install(install_id))
    return create_pairing_offer(state.identity(), state.group_id, host, port,
                                now=time.time() if now is None else now, ttl_seconds=ttl_seconds)


def enroll_from_qr(qr: str | Mapping[str, Any], session: Any, lease: Any, *, install_id: str,
                   endpoint: LANEndpoint | None = None, now: float | None = None,
                   timeout: float | None = None, transport: SyncTransport | None = None) -> SyncGroupState:
    """New-device side: enroll with a scanned offer and store the delivered group.

    *endpoint* is this device's own listening endpoint, if it has one (a phone
    passes None and always initiates).  Raises ``LanSyncError`` with reason
    ``already-joined``, ``bad-offer``, ``unreachable``, ``offer-used-or-expired``
    (message ``USED_OR_EXPIRED_MESSAGE``), ``too-many-peers`` or ``refused``.
    """
    _check_install(install_id)
    _check_lease(session, lease)
    if load_sync_state(session) is not None:
        raise LanSyncError("already-joined", "leave the current sync group first")
    try:
        bundle = parse_qr_payload(qr) if isinstance(qr, str) else qr
        offer = PairingOffer.from_bundle_dict(bundle)
    except PairingError as exc:
        raise LanSyncError("bad-offer", str(exc)) from exc
    when = time.time() if now is None else now
    identity = DeviceIdentity.generate()
    own = None if endpoint is None else (endpoint.host, endpoint.port)
    try:
        request = build_enrollment_request(offer, identity, endpoint=own, now=when)
    except PairingExpired as exc:
        raise LanSyncError("offer-used-or-expired", USED_OR_EXPIRED_MESSAGE) from exc
    except PairingError as exc:
        raise LanSyncError("bad-offer", str(exc)) from exc
    sender = transport if transport is not None else SyncTransport()
    try:
        reply = sender.enroll(LANEndpoint(offer.endpoint_host, offer.endpoint_port), request, timeout=timeout)
    except (TransportError, OSError) as exc:
        raise LanSyncError("unreachable", f"{type(exc).__name__}: {exc}") from exc
    try:
        group_id, epoch, key = open_enrollment_reply(offer, identity, reply, endpoint=own)
    except EnrollmentRefused as exc:
        if exc.reason == "used-or-expired":
            raise LanSyncError("offer-used-or-expired", USED_OR_EXPIRED_MESSAGE) from exc
        if exc.reason == "full":
            raise LanSyncError("too-many-peers", "The other device already has the most paired devices.") from exc
        raise LanSyncError("refused", str(exc)) from exc
    except PairingError as exc:
        raise LanSyncError("refused", str(exc)) from exc
    pinned = enrollment_transcript(offer, identity.device_id, identity.signing_public_key,
                                   identity.exchange_public_key, own)
    inviter = PairedDevice(offer.inviter_device_id, offer.group_id, offer.inviter_signing_public,
                           offer.inviter_exchange_public, offer.certificate_fingerprint, when,
                           identity.sign(pinned))
    state = SyncGroupState(group_id, epoch, key, identity.protected_dict(), install_id=install_id,
                           lan_peers=(peer_to_entry(inviter, endpoint=offer.endpoint),))
    _check_lease(session, lease)
    if load_sync_state(session) is not None:
        raise LanSyncError("already-joined", "the vault joined a group meanwhile")
    save_sync_state(session, state)
    return state


# --- responder ------------------------------------------------------------------------------------


@dataclass
class _Incoming:
    transfer: str
    total: int
    size: int
    started: float
    parts: list[bytes] = field(default_factory=list)
    received: int = 0


@dataclass
class _Outgoing:
    transfer: str
    parts: list[bytes]
    size: int
    gk: GroupKey
    started: float
    sent: int = 1


class LanInbox:
    """Chunk buffers of one responder, keyed by peer device id (one transfer per peer, two in total)."""

    def __init__(self) -> None:
        self.incoming: dict[str, _Incoming] = {}
        self.outgoing: dict[str, _Outgoing] = {}

    def expire(self, now: float) -> None:
        for table in (self.incoming, self.outgoing):
            for key in [k for k, v in table.items() if v.started < now - TRANSFER_TTL_SECONDS]:
                del table[key]

    @staticmethod
    def _bounded(table: dict[str, Any]) -> None:
        while len(table) > MAX_TRANSFERS:
            del table[min(table, key=lambda k: table[k].started)]


def _serve(session: Any, lease: Any, peer: PairedDevice, request: bytes, *,
           install_id: str, now: int, inbox: LanInbox) -> tuple[dict[str, Any], RunReport | None]:
    _check_install(install_id)
    if not isinstance(peer, PairedDevice):
        raise ValueError("an authenticated peer record is required")
    _check_lease(session, lease)
    inbox.expire(now)
    try:
        msg = parse_message(request)
    except LanSyncError as exc:
        return _error(exc.reason), None
    state = load_sync_state(session)
    if state is None:
        return _error("not-joined"), None
    if state.install_id != install_id:
        return _error("rejoin-required"), RunReport(issues=(SyncIssue("rejoin-required", "install-mismatch"),))
    entry = peer_entry(state, peer.device_id)
    if entry is not None and entry.get("revoked") is True:
        return _error("revoked"), RunReport(issues=(SyncIssue("peer-revoked", peer.device_id),))
    if not _matches(entry, peer) or peer.revoked or peer.group_id != state.group_id:
        return _error("unknown-peer"), RunReport(issues=(SyncIssue("unknown-peer", peer.device_id),))
    if msg["type"] == "next":
        return _next_chunk(inbox, peer.device_id, msg), None
    if msg["type"] != "view":
        return _error("bad-message"), None
    if msg["group_id"] != state.group_id:
        return _error("group-mismatch"), RunReport(issues=(SyncIssue("group-mismatch", peer.device_id),))
    if msg["epoch"] < state.epoch:
        return _error("epoch-behind"), RunReport(issues=(SyncIssue("peer-epoch-behind", peer.device_id),))
    if msg["epoch"] > state.epoch:
        return _error("peer-epoch-behind"), RunReport(issues=(SyncIssue("epoch-behind", peer.device_id),))

    try:
        raw = _receive_chunk(inbox, peer.device_id, msg, now)
    except LanSyncError as exc:
        return _error(exc.reason), None
    if raw is None:
        return {"type": "ack", "transfer": msg["transfer"], "seq": msg["seq"]}, None
    try:
        view = decode_view(_group_key(state), raw, expected_device_id=peer.device_id)
    except SyncFormatError as exc:
        reason = "device-mismatch" if exc.reason == "device-mismatch" else "bad-view"
        kind = "device-mismatch" if reason == "device-mismatch" else "bad-peer-data"
        return _error(reason), RunReport(issues=(SyncIssue(kind, f"{peer.device_id}: {exc.reason}"),))

    report = run_merge(session, lease, device_id=state.device_id, views=[view], now=now)
    if report.own_states is None:
        return _error("local-data"), report
    try:
        reply, out = _prepare_view(session, lease, report.own_states, now)
    except LanSyncError as exc:
        return _error(exc.reason), dataclasses.replace(
            report, issues=(*report.issues, SyncIssue(exc.reason, str(exc))))
    if out is not None:
        inbox.outgoing[peer.device_id] = out
        LanInbox._bounded(inbox.outgoing)
    else:
        inbox.outgoing.pop(peer.device_id, None)
    return reply, dataclasses.replace(report, wrote=True)


def _receive_chunk(inbox: LanInbox, peer_id: str, msg: Mapping[str, Any], now: float) -> bytes | None:
    """Buffer one chunk; returns the whole view after the last chunk, else None."""
    data = _b64d(msg["view"])
    if not data:
        raise LanSyncError("bad-chunk")
    if len(data) > CHUNK_LIMIT:
        inbox.incoming.pop(peer_id, None)
        raise LanSyncError("too-large")
    seq, total, size = msg["seq"], msg["total"], msg["size"]
    current = inbox.incoming.get(peer_id)
    if seq == 0:
        current = _Incoming(msg["transfer"], total, size, now)
        inbox.incoming[peer_id] = current
        LanInbox._bounded(inbox.incoming)
    elif (current is None or current.transfer != msg["transfer"] or len(current.parts) != seq
          or current.total != total or current.size != size):
        inbox.incoming.pop(peer_id, None)
        raise LanSyncError("bad-chunk")
    current.parts.append(data)
    current.received += len(data)
    if current.received > size:
        inbox.incoming.pop(peer_id, None)
        raise LanSyncError("bad-chunk")
    if seq < total - 1:
        return None
    inbox.incoming.pop(peer_id, None)
    if current.received != size:
        raise LanSyncError("bad-chunk")
    return b"".join(current.parts)


def _next_chunk(inbox: LanInbox, peer_id: str, msg: Mapping[str, Any]) -> dict[str, Any]:
    out = inbox.outgoing.get(peer_id)
    if out is None or out.transfer != msg["transfer"] or msg["seq"] != out.sent:
        inbox.outgoing.pop(peer_id, None)
        return _error("bad-chunk")
    reply = _view_message(out.gk, out.transfer, out.sent, out.parts, out.size)
    out.sent += 1
    if out.sent >= len(out.parts):
        del inbox.outgoing[peer_id]
    return reply


def _prepare_view(session: Any, lease: Any, own_states: Any, now: int) -> tuple[dict[str, Any], _Outgoing | None]:
    """Encode this device's view; first chunk + the rest.

    The header carries the stored ``own_counter`` as is: LAN never checks view
    counters, so no counter is reserved and nothing is saved here (saving on
    every exchange made each run look like a local edit, see C1).
    """
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        raise LanSyncError("not-joined")
    gk = _group_key(state)
    counter = state.own_counter
    try:
        raw = encode_view(gk, state.device_id, counter, own_states, now)
    except SyncFormatError as exc:
        raise LanSyncError("too-large", exc.reason) from exc
    if len(raw) > MAX_VIEW_BYTES or math.ceil(len(raw) / max(1, CHUNK_BYTES)) > MAX_CHUNKS:
        raise LanSyncError("too-large", "view exceeds the LAN bound")
    parts = split_view(raw)
    transfer = secrets.token_hex(16)
    first = _view_message(gk, transfer, 0, parts, len(raw))
    out = _Outgoing(transfer, parts, len(raw), gk, float(now)) if len(parts) > 1 else None
    return first, out


def serve_request(session: Any, lease: Any, peer: PairedDevice, request: bytes, *,
                  install_id: str, now: int, inbox: LanInbox | None = None) -> bytes:
    """Answer one authenticated request from *peer* (see the module docstring).

    *inbox* keeps chunk buffers between requests; without one only single-chunk
    views can be exchanged.  Lock and lease errors propagate (the transport then
    closes the connection without a reply).
    """
    reply, _report = _serve(session, lease, peer, request, install_id=install_id, now=now,
                            inbox=inbox if inbox is not None else LanInbox())
    return encode_message(reply)


#: How long after an offer expires a late enrollment still gets a clear refusal.
ENROLL_GRACE_SECONDS = 600


def _outer_offer_id(raw: object) -> str | None:
    """The plain ``offer_id`` of an enrollment request (``pairing.build_enrollment_request``), or None."""
    if (not isinstance(raw, bytes) or len(raw) > MAX_ENROLL_BYTES
            or not raw.startswith(ENROLL_REQUEST_MAGIC)):
        return None
    try:
        outer = json.loads(raw[len(ENROLL_REQUEST_MAGIC):].decode("utf-8"),
                           object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(outer, dict) or set(outer) != {"offer_id", "eph", "nonce", "ct"}:
        return None
    offer_id = outer["offer_id"]
    return offer_id if isinstance(offer_id, str) else None


class LanResponder:
    """Peer-aware transport handler: ``SyncTransport.set_peer_request_handler(responder)``.

    ``last_report`` is the report of the last request that merged or refused a
    view (issues such as ``epoch-behind`` or ``rejoin-required`` on this side).
    :meth:`start_enrollment` arms the transport for one QR enrollment.

    An offer's lifetime is also measured on *monotonic* (seconds), so setting
    the wall clock back cannot extend it; :meth:`expire_enrollment` (called by
    the sync service's timers) drops an expired or used-up offer without waiting
    for another request and removes the handler after the grace period.
    """

    def __init__(self, session: Any, lease: Any, *, install_id: str,
                 clock: Callable[[], int] | None = None,
                 monotonic: Callable[[], float] | None = None) -> None:
        self.session = session
        self.lease = lease
        self.install_id = _check_install(install_id)
        self.clock = clock or (lambda: int(time.time()))
        self.monotonic = monotonic or time.monotonic
        self.inbox = LanInbox()
        self.last_report: RunReport | None = None
        self.pairing: PairingSession | None = None
        self.enrolled: PairedDevice | None = None
        self._transport: SyncTransport | None = None
        self._deadline = 0.0  # monotonic expiry of the armed offer
        self._refuse_until = 0.0  # monotonic end of the "used up or expired" grace period

    def __call__(self, peer: PairedDevice, request: bytes) -> bytes:
        reply, report = _serve(self.session, self.lease, peer, request,
                               install_id=self.install_id, now=self.clock(), inbox=self.inbox)
        if report is not None:
            self.last_report = report
        return encode_message(reply)

    # enrollment ------------------------------------------------------------------------------

    def start_enrollment(self, offer: PairingOffer, transport: SyncTransport) -> PairingSession:
        """Accept one enrollment for *offer* on *transport* (until success, 5 failures or expiry).

        The handler stays installed until ``ENROLL_GRACE_SECONDS`` after the offer
        expires so a late device gets a clear "used up or expired" refusal.
        """
        state = _joined_state(self.session, self.lease, self.install_id)
        if offer.group_id != state.group_id or offer.inviter_device_id != state.device_id:
            raise LanSyncError("not-our-offer", "the offer belongs to another group or device")
        self.pairing = PairingSession(offer, clock=self.clock)
        self.enrolled = None
        self._transport = transport
        mono = self.monotonic()
        self._deadline = mono + max(0.0, float(offer.expires_at) - float(self.clock()))
        self._refuse_until = self._deadline + ENROLL_GRACE_SECONDS
        transport.set_enrollment_handler(self.enroll)
        return self.pairing

    def stop_enrollment(self) -> None:
        if self._transport is not None:
            self._transport.set_enrollment_handler(None)
        self.pairing = None
        self._transport = None
        self._deadline = self._refuse_until = 0.0

    def _offer_expired(self, pairing: PairingSession, now: int) -> bool:
        return now >= pairing.offer.expires_at or self.monotonic() >= self._deadline

    def expire_enrollment(self) -> None:
        """Disarm an offer that expired or was used up; remove the handler after the grace period.

        Between disarming and the end of the grace period a late device still
        gets a clear "used up or expired" refusal.
        """
        if self._transport is None:
            return
        mono = self.monotonic()
        if mono >= self._refuse_until:
            self.stop_enrollment()
            return
        pairing = self.pairing
        if pairing is not None and (pairing.exhausted or self._offer_expired(pairing, self.clock())):
            self.pairing = None

    def enroll_prefilter(self, raw: bytes) -> tuple[bool, bytes | None]:
        """Cheap checks that need no vault and no sync gate; ``(True, reply)`` answers at once.

        Reads only this responder's armed offer and the request's plain outer
        fields, so a stray or hostile enrollment frame is refused without taking
        the gate (it no longer waits behind, or delays, a sync run).  The answers
        are the ones :meth:`enroll` would give: no offer armed (``None``: close, or
        "used up or expired" during the grace period), an expired or exhausted
        offer ("used up or expired"), and a malformed request or one for another
        offer id (the generic refusal, counted as no attempt, as in
        ``PairingSession.accept_enrollment``).  ``(False, None)``: go on to
        :meth:`enroll` inside the gate, which checks everything again.
        """
        pairing = self.pairing
        if pairing is None:
            if self._transport is not None and self.monotonic() < self._refuse_until:
                return True, enrollment_refusal("used-or-expired")
            return True, None
        now = self.clock()
        if now >= pairing.offer.expires_at + ENROLL_GRACE_SECONDS or self.monotonic() >= self._refuse_until:
            return False, None  # enroll() disarms the offer (needs no vault either)
        if pairing.exhausted or self._offer_expired(pairing, now):
            return True, enrollment_refusal("used-or-expired")
        offer_id = _outer_offer_id(raw)
        if offer_id is None or offer_id != pairing.offer.offer_id:
            return True, enrollment_refusal()
        return False, None

    def enroll(self, raw: bytes) -> bytes | None:
        """Transport enrollment handler: verify, pin the new device, reply with the sealed group key.

        The reply goes out at once (the iPhone app waits only about 5 seconds for
        it, and the request carries no device name), so there is no "Accept" step
        before it.  Instead the screen shows the enrolled device with an Undo
        (``enrolled``; see ``app/sync.py`` ``qr_poll``) that removes it again.
        """
        pairing = self.pairing
        if pairing is None:
            if self._transport is not None and self.monotonic() < self._refuse_until:
                return enrollment_refusal("used-or-expired")  # disarmed, still in the grace period
            return None
        now = self.clock()
        offer = pairing.offer
        if now >= offer.expires_at + ENROLL_GRACE_SECONDS or self.monotonic() >= self._refuse_until:
            self.stop_enrollment()
            return None
        if pairing.exhausted or self._offer_expired(pairing, now):
            return enrollment_refusal("used-or-expired")
        state = _joined_state(self.session, self.lease, self.install_id)
        if offer.group_id != state.group_id or offer.inviter_device_id != state.device_id:
            self.stop_enrollment()
            return enrollment_refusal()
        if len(state.lan_peers) >= MAX_LAN_PEERS:
            return enrollment_refusal("full")  # checked before anything is consumed
        reserved = ({p.get("device_id") for p in state.lan_peers} | set(state.members)
                    | {state.device_id}) - {None}
        tstate = getattr(self._transport, "state", None)
        if isinstance(tstate, SyncState):
            reserved |= set(tstate.revoked_devices)  # a removed peer cannot come back under its old id
        identity = state.identity()
        try:
            peer, request = pairing.accept_enrollment(identity, raw, now=now, reserved_ids=reserved)
        except (PairingReplayError, PairingExpired):
            return enrollment_refusal("used-or-expired")
        except PairingError:
            return enrollment_refusal()
        endpoint = None if request.endpoint is None else LANEndpoint(*request.endpoint)
        new_state = _with_peer(state, peer_to_entry(peer, endpoint=endpoint))
        _check_lease(self.session, self.lease)
        save_sync_state(self.session, new_state)
        if isinstance(tstate, SyncState):
            tstate.trust_peer(peer)  # the new device can open sessions right away
        self.enrolled = peer
        return seal_enrollment_reply(identity, offer, request, state.group_id, state.epoch, state.key)


# --- initiator ------------------------------------------------------------------------------------


def _reply_issue(reply: Mapping[str, Any]) -> SyncIssue:
    if reply.get("type") == "error":
        reason = reply["reason"]
        kind = _REPLY_ISSUES.get(reason)
        return SyncIssue(kind) if kind else SyncIssue("peer-refused", reason)
    return SyncIssue("bad-reply", str(reply.get("type")))


def sync_with(transport: SyncTransport, peer_id: str, session: Any, lease: Any, *,
              install_id: str, now: int, endpoint: LANEndpoint | None = None,
              timeout: float | None = None) -> RunReport:
    """One LAN sync with *peer_id*: exchange views both ways and merge.

    *endpoint* defaults to the peer's stored endpoint.  Network failures and
    refusals become issues; lock and lease errors propagate.
    """
    _check_install(install_id)
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        return RunReport(issues=(SyncIssue("not-joined"),))
    if state.install_id != install_id:
        return RunReport(issues=(SyncIssue("rejoin-required", "install-mismatch"),))
    entry = peer_entry(state, peer_id)
    if entry is None:
        return RunReport(issues=(SyncIssue("unknown-peer", str(peer_id)),))
    if entry.get("revoked") is True:
        return RunReport(issues=(SyncIssue("peer-revoked", peer_id),))
    tstate = getattr(transport, "state", None)
    if not isinstance(tstate, SyncState) or tstate.identity.device_id != state.device_id:
        return RunReport(issues=(SyncIssue("identity-mismatch"),))
    pinned = tstate.trusted_peers.get(peer_id)
    if pinned is None or not _matches(entry, pinned):
        return RunReport(issues=(SyncIssue("peer-mismatch", peer_id),))
    target = endpoint if endpoint is not None else peer_endpoint(state, peer_id)
    if target is None:
        return RunReport(issues=(SyncIssue("no-endpoint", peer_id),))

    def call(message: Mapping[str, Any], *, retry: bool = True) -> dict[str, Any]:
        """One request; a chunk request (*retry*) is sent again once if the peer never answered.

        ``PeerNotAnswering`` means nothing was sent, so repeating is safe.  It
        covers the peer's listener still busy with the previous chunk's handler.
        """
        try:
            raw = transport.request(target, encode_message(message), peer_id=peer_id, timeout=timeout)
        except PeerNotAnswering:
            if not retry:
                raise
            time.sleep(CHUNK_RETRY_DELAY)
            raw = transport.request(target, encode_message(message), peer_id=peer_id, timeout=timeout)
        return parse_message(raw)

    try:
        try:
            local = local_view(session, lease, device_id=state.device_id, now=now)
        except BridgeError as exc:
            return RunReport(issues=(SyncIssue("local-data", str(exc)),))
        own = tuple(local[k] for k in sorted(local))
        first, out = _prepare_view(session, lease, own, now)
        reply = call(first, retry=False)  # an unreachable peer is reported at once
        if out is not None:
            for seq in range(1, len(out.parts)):
                if reply != {"type": "ack", "transfer": out.transfer, "seq": seq - 1}:
                    return RunReport(issues=(_reply_issue(reply),))
                reply = call(_view_message(out.gk, out.transfer, seq, out.parts, out.size))
        view = _receive_reply_view(call, reply, state, peer_id, now)
        if isinstance(view, SyncIssue):
            return RunReport(issues=(view,))
    except LanSyncError as exc:
        return RunReport(issues=(SyncIssue("bad-reply" if exc.reason == "bad-message" else exc.reason,
                                           str(exc)),))
    except (TransportError, SyncStateError, OSError) as exc:
        return RunReport(issues=(SyncIssue("unreachable", f"{type(exc).__name__}: {exc}"),))

    report = run_merge(session, lease, device_id=state.device_id, views=[view], now=now)
    return dataclasses.replace(report, wrote=True)


def _receive_reply_view(call: Callable[[Mapping[str, Any]], dict[str, Any]], reply: dict[str, Any],
                        state: SyncGroupState, peer_id: str, now: int) -> View | SyncIssue:
    if reply.get("type") != "view":
        return _reply_issue(reply)
    if reply["group_id"] != state.group_id:
        return SyncIssue("group-mismatch", peer_id)
    if reply["epoch"] != state.epoch:
        return SyncIssue("epoch-behind" if reply["epoch"] > state.epoch else "peer-epoch-behind", peer_id)
    inbox = LanInbox()
    raw = _receive_chunk(inbox, peer_id, reply, now)
    transfer = reply["transfer"]
    while raw is None:
        seq = len(inbox.incoming[peer_id].parts)
        nxt = call({"type": "next", "transfer": transfer, "seq": seq})
        if nxt.get("type") != "view" or nxt["transfer"] != transfer or nxt["seq"] != seq:
            return _reply_issue(nxt) if nxt.get("type") != "view" else SyncIssue("bad-reply", "chunk order")
        if nxt["group_id"] != state.group_id or nxt["epoch"] != state.epoch:
            return SyncIssue("bad-reply", "chunk group")
        raw = _receive_chunk(inbox, peer_id, nxt, now)
    try:
        return decode_view(_group_key(state), raw, expected_device_id=peer_id)
    except SyncFormatError as exc:
        kind = "device-mismatch" if exc.reason == "device-mismatch" else "bad-peer-data"
        return SyncIssue(kind, f"{peer_id}: {exc.reason}")


__all__ = [
    "CHUNK_BYTES", "CHUNK_LIMIT", "ERROR_REASONS", "MAX_CHUNKS", "MAX_TRANSFERS", "MAX_VIEW_BYTES", "LanInbox", "LanResponder",
    "LanSyncError", "RunReport", "begin_pairing", "create_lan_group", "encode_message", "enroll_from_qr",
    "parse_message", "peer_endpoint", "peer_entry", "peer_from_entry", "peer_to_entry", "remove_lan_peer",
    "serve_request", "split_view", "sync_with", "transport_state",
]
