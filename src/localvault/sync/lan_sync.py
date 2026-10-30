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
   consumed; a used or expired offer gets a clear refusal).  Then it asks: the
   screen shows the new device's name and the 6-digit verification code
   (``pairing.verification_code``) that the new device shows too, with Accept and
   Decline (``LanResponder.pending``, ``LanResponder.decide``).  Only Accept pins
   the new device in ``lan_peers`` (with the optional listening endpoint) and
   answers with (group_id, epoch, G) sealed to the new device and signed by the
   inviter; Decline, or no answer within ``ACCEPT_TIMEOUT_SECONDS``, answers
   ``declined`` and the offer stays used up.  The new device waits up to
   ``ENROLL_REPLY_SECONDS`` for the answer.  The wait holds no sync gate.  After
   Accept the screen still offers Undo, which removes the device again
   (``remove_lan_peer``, or a rotation in a cloud-folder group).  A version-1
   request (an app without the Accept step) gets ``update-needed``.
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
* ``{"type":"witness","group_id","epoch","view"}`` (2026-10-29): ``view`` is
  standard base64 of a witness file (``group.py`` format 2, zero records, at
  most ``MAX_WITNESS_BYTES``) carrying the sender's vault generation and its
  witness of its peers.  After a view exchange in format 1 the initiator sends
  one; a responder of this version checks it (``witness.check``) and answers
  with its own, and a responder from before answers ``bad-message`` (ignored:
  nothing is reported, the next exchange tries again).  A device that sent or
  answered a witness is recorded in ``witness_peers``.

* ``{"type":"blob-get","blob","seq"}`` and ``{"type":"blob","blob","seq","total","size","data"}``
  (attachment sync, 2026-10-29, ``attachment_sync.py``): after the view exchange the initiator
  fetches, chunk by chunk, the file of each document in the responder's view that it lacks.  A
  responder serves only blobs of its own live documents and answers ``{"type":"error",
  "reason":"no-blob"}`` otherwise.  A responder that gets a ``blob-get`` records the initiator in
  ``attachment_peers``; an initiator that needed no file sends one probe ``blob-get`` (blob id of 64
  zeros) to a peer not yet listed, and records it when the answer is ``no-blob`` or a chunk (an
  older app answers ``bad-message``, which removes it).  Documents are only sent in views to peers in
  ``attachment_peers``.  A responder cannot fetch: a document it receives waits
  (``attachment-missing``) until it syncs as initiator, or gets the file through the folder.

Format gating (2026-10-29): the initiator sends its view as format 2 (the
generation and witness inline, no witness message) only to a peer listed in
``witness_peers``; the responder answers in the format the request used.  A
``bad-view`` refusal of a format-2 view (the peer went back to an older app)
counts; two in a row remove the peer from ``witness_peers`` so the next
exchange uses format 1 (an older app cannot say why it refused, and one bad
transfer must not switch a capable peer back).
Witness state (``witness_memory``): the highest generation checked from each
peer is kept in memory for the unlock session and is what every check and
every published witness uses, so no checked value is ever thrown away.  It is
saved when it matters (a new peer, a new capability, a new suspicion), when a
peer's generation rose and that peer was not saved in the last
``witness_memory.SAVE_INTERVAL_SECONDS`` (a LAN exchange otherwise saves
nothing, see C1), with every folder run's state, and by :func:`flush_witness`
at the end of the service.  ``LAN_GENERATION_SLACK`` is kept for the vectors'
constants table only; nothing uses it any more.

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
import hmac
import ipaddress
import json
import math
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from . import attachment_sync
from .attachment_flow import import_missing, own_blob
from .group import MAX_BYTES, GroupKey, SyncFormatError, View, decode_view, encode_view
from .lan_address import is_lan_address
from .pairing import (
    DEFAULT_ENROLL_NAME,
    ENROLL_REQUEST_MAGIC,
    MAX_ENROLL_BYTES,
    PAIRING_TTL_SECONDS,
    DeviceIdentity,
    EnrollmentOutdated,
    EnrollmentRefused,
    EnrollmentRequest,
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
    verification_code,
)
from .runner import RunReport, SyncIssue, run_merge
from .state import SyncState, SyncStateError
from .transport import (
    MAX_MESSAGE_BYTES,
    LANEndpoint,
    PeerNotAnswering,
    PeerVersionMismatch,
    SyncTransport,
    TransportError,
)
from .vault_bridge import (
    MAX_INSTALL_ID,
    MAX_LAN_PEERS,
    BridgeError,
    SyncGroupState,
    _check_lease,
    licenses_in_views,
    load_sync_state,
    document_refs,
    local_view,
    publishable,
    save_sync_state,
)
from .witness import Observation, observation, own_witness, prune, session_generation
from .witness import check as witness_check
from . import witness_memory

#: Raw view bytes per message when sending.
CHUNK_BYTES = 512 * 1024
#: Largest chunk accepted; base64 plus the envelope still seals into one transport frame.
CHUNK_LIMIT = 560 * 1024
MAX_VIEW_BYTES = MAX_BYTES
MAX_CHUNKS = 65536
TRANSFER_TTL_SECONDS = 300
#: Licences a responder keeps between runs (several peers, each at most ``MAX_SYNC_LICENSES``).
MAX_KEPT_LICENSES = 64
#: In-flight chunked transfers a responder keeps per direction (one per peer at most).
MAX_TRANSFERS = 2
#: Pause before the one retry of a chunk request the peer did not answer.
CHUNK_RETRY_DELAY = 0.05
#: Hello counters reserved per vault save.
HELLO_COUNTER_BLOCK = 64
#: How long the inviting device waits for Accept or Decline before it declines on its own.
ACCEPT_TIMEOUT_SECONDS = 60.0
#: How long the new device waits for the inviter's answer (the Accept prompt plus the network).
ENROLL_REPLY_SECONDS = ACCEPT_TIMEOUT_SECONDS + 15.0

_FIELDS = {
    "view": frozenset({"type", "group_id", "epoch", "transfer", "seq", "total", "size", "view"}),
    "next": frozenset({"type", "transfer", "seq"}),
    "ack": frozenset({"type", "transfer", "seq"}),
    "error": frozenset({"type", "reason"}),
    "witness": frozenset({"type", "group_id", "epoch", "view"}),
    "blob-get": frozenset({"type", "blob", "seq"}),
    "blob": frozenset({"type", "blob", "seq", "total", "size", "data"}),
}
#: Error reasons of the attachment messages (kept apart from ``ERROR_REASONS``, which the vectors pin).
ATTACHMENT_ERROR_REASONS = ("no-blob",)
#: Blob id of the capability probe (never a real blob).
PROBE_BLOB = "0" * 64
#: Largest witness file accepted in a ``witness`` message.
MAX_WITNESS_BYTES = 16 * 1024
#: A peer generation is saved once it is this far above the stored one (see the module docstring).
LAN_GENERATION_SLACK = 32
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
DECLINED_MESSAGE = ("The other device declined, or nobody chose Accept there in time. "
                    "Show a new code and choose Accept when the codes match.")


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
    if kind in ("blob-get", "blob"):
        try:
            attachment_sync.parse_message(msg)
        except attachment_sync.AttachmentSyncError as exc:
            raise LanSyncError("too-large" if exc.reason == "too-large" else "bad-message") from None
    if kind == "witness":
        if not isinstance(msg["group_id"], str) or not _is_int(msg["epoch"], 1) or not isinstance(msg["view"], str):
            raise LanSyncError("bad-message")
        if len(msg["view"]) > 4 * math.ceil(MAX_WITNESS_BYTES / 3):
            raise LanSyncError("too-large")
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


def peer_to_entry(peer: PairedDevice, *, endpoint: LANEndpoint | tuple[str, int] | None = None,
                  name: str | None = None) -> dict[str, Any]:
    """The ``SyncGroupState.lan_peers`` entry for *peer* (``endpoint`` None: the peer always initiates).

    *name* is the name the device gave when it enrolled (display only, not authenticated by a key).
    """
    if isinstance(endpoint, tuple):
        endpoint = LANEndpoint(*endpoint)
    where = None if endpoint is None else {"host": endpoint.host, "port": endpoint.port}
    entry = {**peer.to_dict(), "endpoint": where}
    if name is not None:
        entry["name"] = name
    return entry


#: Fields of a ``lan_peers`` entry that are not part of the ``PairedDevice`` record.
_ENTRY_EXTRAS = frozenset({"endpoint", "name"})


def peer_from_entry(entry: Mapping[str, Any]) -> PairedDevice:
    if not isinstance(entry, Mapping):
        raise LanSyncError("bad-peer", "stored LAN peer is malformed")
    try:
        return PairedDevice.from_dict({k: v for k, v in entry.items() if k not in _ENTRY_EXTRAS})
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


def save_peer_endpoint(session: Any, lease: Any, device_id: str, endpoint: LANEndpoint, *,
                       install_id: str) -> bool:
    """Store *endpoint* as the listening address of the paired *device_id*; whether it changed.

    Call it only after an authenticated exchange with *device_id* at *endpoint* completed (the
    discovery client) or after a QR of that same device was checked (:func:`refind_from_qr`):
    the address is a hint, identity stays the pinned keys.  A LAN address only.
    """
    if not isinstance(endpoint, LANEndpoint):
        raise LanSyncError("bad-offer", "a validated LAN endpoint is required")
    try:
        lan_ok = is_lan_address(ipaddress.ip_address(endpoint.host))
    except ValueError:
        lan_ok = False
    if not lan_ok:
        raise LanSyncError("bad-offer", "only a local network address is stored")
    state = _joined_state(session, lease, _check_install(install_id))
    entry = peer_entry(state, device_id)
    if entry is None or entry.get("revoked") is True:
        return False
    where = {"host": endpoint.host, "port": endpoint.port}
    if entry.get("endpoint") == where:
        return False
    entry["endpoint"] = where
    _check_lease(session, lease)
    save_sync_state(session, _with_peer(state, entry))
    return True


def refind_from_qr(qr: str | Mapping[str, Any], session: Any, lease: Any, *, install_id: str,
                   now: float | None = None) -> str:
    """"Find again": take only the address from a QR of an ALREADY paired host; its device id.

    The offer must name this vault's group and the pinned device, with the same signing and
    exchange keys and certificate fingerprint as pinned; anything else is refused with
    ``LanSyncError("not-this-device")``.  Nothing is enrolled and no secret of the offer is used.
    """
    _check_install(install_id)
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        raise LanSyncError("not-joined", "this PC is not in a sync group")
    try:
        bundle = parse_qr_payload(qr) if isinstance(qr, str) else qr
        offer = PairingOffer.from_bundle_dict(bundle)
    except PairingError as exc:
        raise LanSyncError("bad-offer", str(exc)) from exc
    if offer.expires_at < int(time.time() if now is None else now):
        raise LanSyncError("offer-used-or-expired", USED_OR_EXPIRED_MESSAGE)
    entry = peer_entry(state, offer.inviter_device_id)

    def same(pinned: Any, offered: str) -> bool:
        return isinstance(pinned, str) and hmac.compare_digest(pinned.encode("utf-8"), offered.encode("utf-8"))

    if (entry is None or entry.get("revoked") is True or offer.group_id != state.group_id
            or entry.get("group_id") != state.group_id
            # Every pinned key must match, compared in constant time (``&`` so no early exit).
            or not (same(entry.get("signing_public"), base64.b64encode(offer.inviter_signing_public).decode("ascii"))
                    & same(entry.get("exchange_public"),
                           base64.b64encode(offer.inviter_exchange_public).decode("ascii"))
                    & same(entry.get("fingerprint"), offer.certificate_fingerprint))):
        raise LanSyncError("not-this-device", "This code is from a device this PC is not paired with.")
    save_peer_endpoint(session, lease, offer.inviter_device_id,
                       LANEndpoint(offer.endpoint_host, offer.endpoint_port), install_id=install_id)
    return offer.inviter_device_id


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
                   timeout: float | None = None, transport: SyncTransport | None = None,
                   name: str = DEFAULT_ENROLL_NAME,
                   on_code: Callable[[str], None] | None = None) -> SyncGroupState:
    """New-device side: enroll with a scanned offer and store the delivered group.

    *endpoint* is this device's own listening endpoint, if it has one (a phone
    passes None and always initiates).  *name* is shown on the inviting device's
    Accept prompt; *on_code* receives the 6-digit verification code before the
    request is sent (show it: the inviting device shows the same code next to
    Accept).  *timeout* defaults to ``ENROLL_REPLY_SECONDS``.  Raises
    ``LanSyncError`` with reason ``already-joined``, ``bad-offer``,
    ``unreachable``, ``offer-used-or-expired`` (message
    ``USED_OR_EXPIRED_MESSAGE``), ``too-many-peers``, ``declined``,
    ``update-needed`` or ``refused``.
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
        request = build_enrollment_request(offer, identity, endpoint=own, name=name, now=when)
    except PairingExpired as exc:
        raise LanSyncError("offer-used-or-expired", USED_OR_EXPIRED_MESSAGE) from exc
    except PairingError as exc:
        raise LanSyncError("bad-offer", str(exc)) from exc
    pinned = enrollment_transcript(offer, identity.device_id, identity.signing_public_key,
                                   identity.exchange_public_key, own, name)
    if on_code is not None:
        on_code(verification_code(pinned))
    sender = transport if transport is not None else SyncTransport()
    try:
        reply = sender.enroll(LANEndpoint(offer.endpoint_host, offer.endpoint_port), request,
                              timeout=ENROLL_REPLY_SECONDS if timeout is None else timeout)
    except (TransportError, OSError) as exc:
        raise LanSyncError("unreachable", f"{type(exc).__name__}: {exc}") from exc
    try:
        group_id, epoch, key = open_enrollment_reply(offer, identity, reply, endpoint=own, name=name)
    except EnrollmentRefused as exc:
        if exc.reason == "used-or-expired":
            raise LanSyncError("offer-used-or-expired", USED_OR_EXPIRED_MESSAGE) from exc
        if exc.reason == "full":
            raise LanSyncError("too-many-peers", "The other device already has the most paired devices.") from exc
        if exc.reason == "declined":
            raise LanSyncError("declined", DECLINED_MESSAGE) from exc
        if exc.reason == "update-needed":
            raise LanSyncError("update-needed", "Update LocalGateKeys on this device to pair with the other one.") from exc
        raise LanSyncError("refused", str(exc)) from exc
    except PairingError as exc:
        raise LanSyncError("refused", str(exc)) from exc
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
        self.blobs: dict[str, tuple[str, bytes]] = {}  # peer -> (blob id, blob) being served
        #: (store revision key, {blob id: ref}) of this device's live documents, so a run of
        #: ``blob-get seq 0`` requests does not rebuild ``local_view`` for every file.
        self.live_documents: tuple[tuple[Any, ...], dict[str, Any]] | None = None

    def expire(self, now: float) -> None:
        for table in (self.incoming, self.outgoing):
            for key in [k for k, v in table.items() if v.started < now - TRANSFER_TTL_SECONDS]:
                del table[key]

    @staticmethod
    def _bounded(table: dict[str, Any]) -> None:
        while len(table) > MAX_TRANSFERS:
            del table[min(table, key=lambda k: table[k].started)]


def _serve(session: Any, lease: Any, peer: PairedDevice, request: bytes, *,
           install_id: str, now: int, inbox: LanInbox,
           licence_only: bool = False) -> tuple[dict[str, Any], RunReport | None]:
    """One request.  *licence_only* (a free PC): a peer's view gives only its licences and is
    answered with an empty view; witness and document requests are refused; nothing is written."""
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
    if licence_only and msg["type"] in ("witness", "blob-get"):
        return _error("bad-message"), None  # what an older app answers: the peer carries on quietly
    if msg["type"] == "witness":
        return _serve_witness(session, lease, state, peer.device_id, msg, now)
    if msg["type"] == "blob-get":
        return _serve_blob(session, lease, peer.device_id, msg, inbox, now), None
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

    if licence_only:
        report = RunReport(own_states=(), licenses=licenses_in_views([view]))
        try:
            reply, _out = _prepare_view(session, lease, (), now)
        except LanSyncError as exc:
            return _error(exc.reason), None
        inbox.outgoing.pop(peer.device_id, None)  # an empty view is always one chunk
        return reply, report

    report = run_merge(session, lease, device_id=state.device_id, views=[view], now=now)
    note_peer_synced(session, lease, peer.device_id, report, now)
    inline = view.format == 2
    obs = observation(view)
    if obs is not None:
        report = dataclasses.replace(report, issues=(*report.issues, *apply_witness(session, lease, [obs])))
    if report.own_states is None:
        return _error("local-data"), report
    report = dataclasses.replace(report, own_states=publishable(
        report.own_states, documents=peer.device_id in state.attachment_peers))
    try:
        reply, out = _prepare_view(session, lease, report.own_states, now, inline=inline)
    except LanSyncError as exc:
        return _error(exc.reason), dataclasses.replace(
            report, issues=(*report.issues, SyncIssue(exc.reason, str(exc))))
    if out is not None:
        inbox.outgoing[peer.device_id] = out
        LanInbox._bounded(inbox.outgoing)
    else:
        inbox.outgoing.pop(peer.device_id, None)
    return reply, dataclasses.replace(report, wrote=True)


def apply_witness(session: Any, lease: Any, observations: list[Observation], *,
                  drop_capable: str | None = None) -> tuple[SyncIssue, ...]:
    """Check *observations* against this vault and save the witness state when it matters.

    The check runs against the session's in-memory generations (``witness_memory``), never
    against a stale stored value.  Saved: a new peer, a change of ``witness_peers`` or
    ``rollback_suspected``, or a risen generation of a peer not saved in the last
    ``SAVE_INTERVAL_SECONDS``.  *drop_capable* removes that peer from ``witness_peers``.
    """
    _check_lease(session, lease)
    state = load_sync_state(session)
    own_generation = session_generation(session)
    if state is None or own_generation is None:
        return ()
    mem = witness_memory.memory(session, state.group_id, state.device_id)
    known = witness_memory.merged(state.peer_generations, mem)
    checked = witness_check(state.device_id, own_generation, observations, known, state.rollback_suspected)
    keep = _witness_ids(state)
    generations = prune(checked.peer_generations, keep)
    capable = set(state.witness_peers) | set(checked.capable)
    capable.discard(drop_capable)
    capable_t = tuple(prune(dict.fromkeys(capable, 0), keep))
    stored = state.peer_generations
    now = witness_memory.monotonic()
    if mem is not None:
        mem.generations = dict(generations)
    risen = [d for d, g in generations.items() if d in stored and g > stored[d]]
    due = mem is None or any(now - mem.saved_at.get(d, -math.inf) >= witness_memory.SAVE_INTERVAL_SECONDS
                             for d in risen)
    worth = (checked.rollback_suspected != state.rollback_suspected or capable_t != state.witness_peers
             or any(d not in stored for d in generations) or (bool(risen) and due))
    if worth:
        new_state = dataclasses.replace(state, peer_generations=generations,
                                        rollback_suspected=checked.rollback_suspected, witness_peers=capable_t)
        _check_lease(session, lease)
        save_sync_state(session, new_state)
        if mem is not None:
            for d in generations:
                mem.saved_at[d] = now
    return checked.issues


def flush_witness(session: Any, lease: Any) -> bool:
    """Save the session's in-memory peer generations that are above the stored ones.

    Call it at the end of the sync service (before the vault locks) so a rise that the
    save throttle held back is not lost.  Returns True when it saved.
    """
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        return False
    mem = witness_memory.memory(session, state.group_id, state.device_id)
    generations = prune(witness_memory.merged(state.peer_generations, mem), _witness_ids(state))
    if generations == dict(state.peer_generations):
        return False
    _check_lease(session, lease)
    save_sync_state(session, dataclasses.replace(state, peer_generations=generations))
    if mem is not None:
        now = witness_memory.monotonic()
        for d in generations:
            mem.saved_at[d] = now
    return True


def _known_generations(session: Any, state: SyncGroupState) -> dict[str, int]:
    """Stored peer generations raised to the session's in-memory ones (what this device publishes)."""
    return witness_memory.merged(state.peer_generations,
                                 witness_memory.memory(session, state.group_id, state.device_id))


def _witness_ids(state: SyncGroupState) -> set[str]:
    """Peers whose generations this device keeps and publishes: keyring members and LAN peers."""
    ids = set(state.members) | {p.get("device_id") for p in state.lan_peers}
    ids.discard(state.device_id)
    return {i for i in ids if isinstance(i, str)}


def witness_file(session: Any, state: SyncGroupState, now: int) -> bytes | None:
    """This device's witness file for a LAN exchange (counter = the stored own counter), or None."""
    generation = session_generation(session)
    if generation is None:
        return None
    return encode_view(_group_key(state), state.device_id, state.own_counter, (), now,
                       vault_generation=generation,
                       witness=own_witness(_known_generations(session, state), _witness_ids(state),
                                           state.device_id))


def _witness_message(state: SyncGroupState, raw: bytes) -> dict[str, Any]:
    return {"type": "witness", "group_id": state.group_id, "epoch": state.epoch,
            "view": base64.b64encode(raw).decode("ascii")}


def _open_witness(state: SyncGroupState, peer_id: str, msg: Mapping[str, Any]) -> Observation | SyncIssue:
    """The observation of a ``witness`` message from *peer_id*, or the issue it raises."""
    if msg["group_id"] != state.group_id:
        return SyncIssue("group-mismatch", peer_id)
    if msg["epoch"] != state.epoch:
        return SyncIssue("epoch-behind" if msg["epoch"] > state.epoch else "peer-epoch-behind", peer_id)
    try:
        raw = _b64d(msg["view"])
        view = decode_view(_group_key(state), raw, expected_device_id=peer_id, max_bytes=MAX_WITNESS_BYTES,
                           max_records=0)
    except LanSyncError:
        return SyncIssue("bad-peer-data", f"{peer_id}: witness")
    except SyncFormatError as exc:
        kind = "device-mismatch" if exc.reason == "device-mismatch" else "bad-peer-data"
        return SyncIssue(kind, f"{peer_id}: witness {exc.reason}")
    if view.format != 2:
        return SyncIssue("bad-peer-data", f"{peer_id}: witness format")
    return Observation(peer_id, view.vault_generation, view.witness)


def _serve_witness(session: Any, lease: Any, state: SyncGroupState, peer_id: str,
                   msg: Mapping[str, Any], now: int) -> tuple[dict[str, Any], RunReport | None]:
    obs = _open_witness(state, peer_id, msg)
    if isinstance(obs, SyncIssue):
        reason = {"group-mismatch": "group-mismatch", "device-mismatch": "device-mismatch",
                  "epoch-behind": "peer-epoch-behind", "peer-epoch-behind": "epoch-behind"}.get(obs.kind, "bad-view")
        return _error(reason), RunReport(issues=(obs,))
    issues = apply_witness(session, lease, [obs])
    state = load_sync_state(session) or state
    raw = witness_file(session, state, now)
    if raw is None:
        return _error("local-data"), RunReport(issues=issues) if issues else None
    return _witness_message(state, raw), RunReport(issues=issues) if issues else None


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


def note_peer_synced(session: Any, lease: Any, peer_id: str, report: RunReport, now: float) -> bool:
    """Record ``peer_synced_at[peer_id] = now`` when a Wi-Fi merge changed records (local only).

    Same rule as Android's ``PeerSyncedAt``: an exchange that changed nothing leaves the time
    (and the vault) as they were.  Whether the state was saved.
    """
    if not (report.applied or report.deleted or report.conflicts):
        return False
    state = load_sync_state(session)
    if state is None or peer_id == state.device_id:
        return False
    new_state = state.synced_with([peer_id], int(now))
    if new_state == state:
        return False
    _check_lease(session, lease)
    save_sync_state(session, new_state)
    return True


def set_attachment_peer(session: Any, lease: Any, peer_id: str, capable: bool) -> bool:
    """Add *peer_id* to (or remove it from) ``attachment_peers``; whether the state changed."""
    state = load_sync_state(session)
    if state is None:
        return False
    peers = set(state.attachment_peers)
    peers = peers | {peer_id} if capable else peers - {peer_id}
    if peers == set(state.attachment_peers) or (capable and len(peers) > MAX_LAN_PEERS):
        return False
    _check_lease(session, lease)
    save_sync_state(session, dataclasses.replace(state, attachment_peers=tuple(sorted(peers))))
    return True


def _attachment_error(reason: str) -> dict[str, Any]:
    """An error of the attachment messages (``ATTACHMENT_ERROR_REASONS``, outside the pinned ``ERROR_REASONS``)."""
    assert reason in ATTACHMENT_ERROR_REASONS
    return {"type": "error", "reason": reason}


def _live_documents(session: Any, lease: Any, inbox: LanInbox, now: int) -> dict[str, Any] | None:
    """{blob id: ref} of this device's live documents, cached per store revision.

    The revision key is the session object, the sync device id and the committed vault
    generation (it grows with every save), so any saved change (a document added, edited or
    deleted, a group change) rebuilds the map.  None when the local view cannot be built.
    """
    state = load_sync_state(session)
    if state is None:
        return None
    generation = session_generation(session)
    key = (id(session), state.device_id, generation)
    cached = inbox.live_documents
    if generation is not None and cached is not None and cached[0] == key:
        return cached[1]
    try:
        local = local_view(session, lease, device_id=state.device_id, now=now)
    except BridgeError:
        return None
    live = {r.blob: r for r in document_refs(local.values())}
    inbox.live_documents = (key, live) if generation is not None else None
    return live


def _serve_blob(session: Any, lease: Any, peer_id: str, msg: Mapping[str, Any], inbox: LanInbox,
                now: int) -> dict[str, Any]:
    """One chunk of the blob of one of this device's own live documents, else ``no-blob``."""
    set_attachment_peer(session, lease, peer_id, True)
    blob_id = msg["blob"]
    cached = inbox.blobs.get(peer_id)
    if cached is None or cached[0] != blob_id or msg["seq"] == 0:
        inbox.blobs.pop(peer_id, None)
        if blob_id == PROBE_BLOB:
            return _attachment_error("no-blob")
        live = _live_documents(session, lease, inbox, now)
        ref = live.get(blob_id) if live is not None else None
        blob = own_blob(session, ref) if ref is not None else None
        if blob is None:
            return _attachment_error("no-blob")
        cached = inbox.blobs[peer_id] = (blob_id, blob)
        while len(inbox.blobs) > MAX_TRANSFERS:
            del inbox.blobs[next(iter(inbox.blobs))]
    try:
        reply = attachment_sync.blob_chunk(cached[1], msg["seq"])
    except attachment_sync.AttachmentSyncError:
        inbox.blobs.pop(peer_id, None)
        return _error("bad-chunk")
    if msg["seq"] == reply["total"] - 1:
        inbox.blobs.pop(peer_id, None)
    return reply


def _note_support(answered: list[bool], reply: Mapping[str, Any]) -> None:
    """Only a chunk or ``no-blob`` shows support and only ``bad-message`` shows an older app; any other
    error (revoked, busy, ...) says nothing about the peer's support."""
    if reply.get("type") == "blob" or reply.get("reason") == "no-blob":
        answered.append(True)
    elif reply.get("reason") == "bad-message":
        answered.append(False)


def _fetch_blobs(call: Callable[..., dict[str, Any]], session: Any, lease: Any, peer_id: str,
                 view: View) -> list[SyncIssue]:
    """Fetch the files of the peer's documents this vault lacks; probe once to learn the peer's support."""
    answered: list[bool] = []  # True: the peer knows blob-get; False: an older app

    def fetch(ref: attachment_sync.AttachmentRef) -> bytes | None:
        download = attachment_sync.BlobDownload(ref)
        seq = 0
        while True:
            reply = call(attachment_sync.blob_get(ref.blob, seq))
            if reply.get("type") == "error":
                _note_support(answered, reply)
                return None
            answered.append(True)
            try:
                blob = download.add(reply)
            except attachment_sync.AttachmentSyncError:
                return None
            if blob is not None:
                return blob
            seq += 1

    issues = import_missing(session, lease, view.states, fetch)
    state = load_sync_state(session)
    if not answered and state is not None and peer_id not in state.attachment_peers:
        _note_support(answered, call(attachment_sync.blob_get(PROBE_BLOB)))
    if answered:
        set_attachment_peer(session, lease, peer_id, answered[-1])
    return issues


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


def _prepare_view(session: Any, lease: Any, own_states: Any, now: int, *,
                  inline: bool = False) -> tuple[dict[str, Any], _Outgoing | None]:
    """Encode this device's view; first chunk + the rest.  *inline*: format 2 (generation and witness).

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
    generation = session_generation(session) if inline else None
    witness = (own_witness(_known_generations(session, state), _witness_ids(state), state.device_id)
               if inline else None)
    try:
        raw = encode_view(gk, state.device_id, counter, own_states, now, vault_generation=generation,
                          witness=witness if generation is not None else None)
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


@dataclass
class PendingEnrollment:
    """A verified enrollment request waiting for the user's Accept or Decline on the inviting device.

    ``name`` and ``code`` are what the screen shows (the new device shows the same
    code); ``deadline`` is the ``time.monotonic()`` at which it declines on its own.
    """

    offer: PairingOffer
    peer: PairedDevice
    request: EnrollmentRequest
    deadline: float
    accepted: bool | None = None
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def offer_id(self) -> str:
        return self.offer.offer_id

    @property
    def name(self) -> str:
        return self.request.name

    @property
    def code(self) -> str:
        return self.request.code

    @property
    def fingerprint(self) -> str:
        return self.peer.fingerprint

    def seconds_left(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def decide(self, accept: bool) -> bool:
        """Record the user's answer once; False when it was already decided (or timed out)."""
        if self._event.is_set():
            return False
        self.accepted = bool(accept)
        self._event.set()
        return True


class LanResponder:
    """Peer-aware transport handler: ``SyncTransport.set_peer_request_handler(responder)``.

    ``last_report`` is the report of the last request that merged or refused a
    view (issues such as ``epoch-behind`` or ``rejoin-required`` on this side).
    :meth:`start_enrollment` arms the transport for one QR enrollment; a verified
    request waits in ``pending`` for :meth:`decide` (Accept or Decline).

    An offer's lifetime is also measured on *monotonic* (seconds), so setting
    the wall clock back cannot extend it; :meth:`expire_enrollment` (called by
    the sync service's timers) drops an expired or used-up offer without waiting
    for another request and removes the handler after the grace period.
    """

    def __init__(self, session: Any, lease: Any, *, install_id: str,
                 clock: Callable[[], int] | None = None,
                 monotonic: Callable[[], float] | None = None,
                 accept_timeout: float = ACCEPT_TIMEOUT_SECONDS,
                 on_pending: Callable[[PendingEnrollment], None] | None = None) -> None:
        self.session = session
        self.lease = lease
        self.install_id = _check_install(install_id)
        self.clock = clock or (lambda: int(time.time()))
        self.monotonic = monotonic or time.monotonic
        self.inbox = LanInbox()
        self.last_report: RunReport | None = None
        self.pairing: PairingSession | None = None
        self.enrolled: PairedDevice | None = None
        #: Offer id of the last enrollment accepted (``enrolled``) and of the last one declined.
        self.enrolled_offer: str | None = None
        self.declined_offer: str | None = None
        self.pending: PendingEnrollment | None = None
        self.accept_timeout = float(accept_timeout)
        #: Called (on the transport thread) when a request starts waiting for Accept, e.g. to refresh the screen.
        self.on_pending = on_pending
        #: Called (on the transport thread) after a peer's request reached the merge step: a phone
        #: connects to this PC, so this is the only sign on this side that a sync with it happened.
        self.on_served: Callable[[RunReport], None] | None = None
        #: A free PC: serve views licence-only (``_serve``); set by ``service.LanAdapter``.
        self.licence_only = False
        self._transport: SyncTransport | None = None
        self._deadline = 0.0  # monotonic expiry of the armed offer
        self._refuse_until = 0.0  # monotonic end of the "used up or expired" grace period

    def __call__(self, peer: PairedDevice, request: bytes) -> bytes:
        reply, report = _serve(self.session, self.lease, peer, request,
                               install_id=self.install_id, now=self.clock(), inbox=self.inbox,
                               licence_only=self.licence_only)
        if report is not None:
            earlier = self.last_report
            if earlier is not None and earlier.licenses:
                # A licence-only PC stores nothing: keep licences already received until the next
                # run collects them, so a later refused request does not drop them.
                kept = (earlier.licenses + report.licenses)[-MAX_KEPT_LICENSES:]
                report = dataclasses.replace(report, licenses=kept)
            self.last_report = report
            on_served = self.on_served
            if report.own_states is not None and on_served is not None:
                with contextlib.suppress(Exception):  # the status update must not cost the peer its reply
                    on_served(report)
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
        self._decline_pending()
        self.pairing = PairingSession(offer, clock=self.clock)
        self.enrolled = None
        self.enrolled_offer = self.declined_offer = None
        self._transport = transport
        mono = self.monotonic()
        self._deadline = mono + max(0.0, float(offer.expires_at) - float(self.clock()))
        self._refuse_until = self._deadline + ENROLL_GRACE_SECONDS
        transport.set_enrollment_handler(self.enroll)
        return self.pairing

    def stop_enrollment(self) -> None:
        """Disarm the offer; a request waiting for Accept is declined."""
        self._decline_pending()
        if self._transport is not None:
            self._transport.set_enrollment_handler(None)
        self.pairing = None
        self._transport = None
        self._deadline = self._refuse_until = 0.0

    def _decline_pending(self) -> None:
        pending = self.pending
        if pending is not None:
            pending.decide(False)

    def decide(self, offer_id: str, accept: bool) -> bool:
        """The user's Accept (True) or Decline (False) for the request waiting on *offer_id*.

        Returns False when no request waits for that offer (already answered or timed out).
        Needs no gate: it only wakes the waiting transport thread.
        """
        pending = self.pending
        if pending is None or pending.offer_id != offer_id:
            return False
        return pending.decide(accept)

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
        """Transport enrollment handler: verify, ask Accept/Decline, then pin and reply (or decline).

        The three steps are :meth:`enroll_verify`, :meth:`await_decision` and
        :meth:`enroll_finish`; the sync service runs the first and the last inside
        its gate and the wait outside it (``service._GatedEnrollment``).
        """
        first = self.enroll_verify(raw)
        if not isinstance(first, PendingEnrollment):
            return first
        return self.enroll_finish(first, self.await_decision(first))

    def enroll_verify(self, raw: bytes) -> bytes | PendingEnrollment | None:
        """Verify one request; returns the reply for a refusal, or the ``PendingEnrollment`` to ask about.

        A request that verifies consumes the offer (``PairingSession``) but pins
        nothing yet: the device is admitted only by :meth:`enroll_finish` after Accept.
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
        try:
            peer, request = pairing.accept_enrollment(state.identity(), raw, now=now,
                                                      reserved_ids=self._reserved_ids(state))
        except EnrollmentOutdated:
            return enrollment_refusal("update-needed")
        except (PairingReplayError, PairingExpired):
            return enrollment_refusal("used-or-expired")
        except PairingError:
            return enrollment_refusal()
        pending = PendingEnrollment(offer, peer, request, time.monotonic() + self.accept_timeout)
        self._decline_pending()
        self.pending = pending
        if self.on_pending is not None:
            with contextlib.suppress(Exception):
                self.on_pending(pending)
        return pending

    def await_decision(self, pending: PendingEnrollment) -> bool:
        """Wait (no gate held) for Accept or Decline; False on Decline, timeout or a disarmed offer."""
        pending._event.wait(max(0.0, pending.deadline - time.monotonic()))
        pending.decide(False)  # a timeout declines (no effect once answered)
        return pending.accepted is True

    def enroll_finish(self, pending: PendingEnrollment, accepted: bool) -> bytes:
        """After the decision: pin the device and seal the group key to it, or answer ``declined``."""
        if self.pending is pending:
            self.pending = None
        if not accepted:
            self.declined_offer = pending.offer_id
            return enrollment_refusal("declined")
        offer, peer, request = pending.offer, pending.peer, pending.request
        try:
            state = _joined_state(self.session, self.lease, self.install_id)
        except LanSyncError:
            return enrollment_refusal()
        if offer.group_id != state.group_id or offer.inviter_device_id != state.device_id:
            return enrollment_refusal()
        if len(state.lan_peers) >= MAX_LAN_PEERS:
            return enrollment_refusal("full")
        if peer.device_id in self._reserved_ids(state):
            return enrollment_refusal()  # the id was taken while the prompt was open
        endpoint = None if request.endpoint is None else LANEndpoint(*request.endpoint)
        new_state = _with_peer(state, peer_to_entry(peer, endpoint=endpoint, name=request.name))
        _check_lease(self.session, self.lease)
        save_sync_state(self.session, new_state)
        tstate = getattr(self._transport, "state", None)
        if isinstance(tstate, SyncState):
            tstate.trust_peer(peer)  # the new device can open sessions right away
        self.enrolled = peer
        self.enrolled_offer = pending.offer_id
        return seal_enrollment_reply(state.identity(), offer, request, state.group_id, state.epoch, state.key)

    def _reserved_ids(self, state: SyncGroupState) -> set[str]:
        """Device ids a new device may not take: listed peers, keyring members, this device, revoked ids."""
        reserved = ({p.get("device_id") for p in state.lan_peers} | set(state.members)
                    | {state.device_id}) - {None}
        tstate = getattr(self._transport, "state", None)
        if isinstance(tstate, SyncState):
            reserved |= set(tstate.revoked_devices)  # a removed peer cannot come back under its old id
        return reserved


# --- initiator ------------------------------------------------------------------------------------


def _reply_issue(reply: Mapping[str, Any]) -> SyncIssue:
    if reply.get("type") == "error":
        reason = reply["reason"]
        kind = _REPLY_ISSUES.get(reason)
        return SyncIssue(kind) if kind else SyncIssue("peer-refused", reason)
    return SyncIssue("bad-reply", str(reply.get("type")))


def sync_with(transport: SyncTransport, peer_id: str, session: Any, lease: Any, *,
              install_id: str, now: int, endpoint: LANEndpoint | None = None,
              timeout: float | None = None, licence_only: bool = False) -> RunReport:
    """One LAN sync with *peer_id*: exchange views both ways and merge.

    *endpoint* defaults to the peer's stored endpoint.  Network failures and
    refusals become issues; lock and lease errors propagate.

    *licence_only* (a free PC): send an empty view, keep only the licences of
    the reply (``RunReport.licenses``) and write nothing: no merge, no document
    files, no witness, no peer bookkeeping.
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
        The first request is repeated only when the connection was made and then
        dropped (a listener refusing a slot); a peer that cannot be reached at all
        is reported at once.
        """
        try:
            raw = transport.request(target, encode_message(message), peer_id=peer_id, timeout=timeout)
        except PeerNotAnswering as exc:
            if not retry and not exc.connected:
                raise
            time.sleep(CHUNK_RETRY_DELAY)
            raw = transport.request(target, encode_message(message), peer_id=peer_id, timeout=timeout)
        return parse_message(raw)

    try:
        if licence_only:
            own: tuple[Any, ...] = ()  # publishes nothing
            inline = False
        else:
            try:
                local = local_view(session, lease, device_id=state.device_id, now=now)
            except BridgeError as exc:
                return RunReport(issues=(SyncIssue("local-data", str(exc)),))
            own = publishable(tuple(local[k] for k in sorted(local)), documents=peer_id in state.attachment_peers)
            inline = peer_id in state.witness_peers and session_generation(session) is not None
        first, out = _prepare_view(session, lease, own, now, inline=inline)
        reply = call(first, retry=False)  # an unreachable peer is reported at once
        if out is not None:
            for seq in range(1, len(out.parts)):
                if reply != {"type": "ack", "transfer": out.transfer, "seq": seq - 1}:
                    return _refused(session, lease, reply, peer_id, inline)
                reply = call(_view_message(out.gk, out.transfer, seq, out.parts, out.size))
        view = _receive_reply_view(call, reply, state, peer_id, now)
        if isinstance(view, SyncIssue):
            if inline and reply.get("type") == "error":
                return _refused(session, lease, reply, peer_id, inline)
            return RunReport(issues=(view,))
        if licence_only:
            _check_lease(session, lease)
            return RunReport(licenses=licenses_in_views([view]))
        file_issues = _fetch_blobs(call, session, lease, peer_id, view)
    except LanSyncError as exc:
        return RunReport(issues=(SyncIssue("bad-reply" if exc.reason == "bad-message" else exc.reason,
                                           str(exc)),))
    except PeerVersionMismatch as exc:
        # Never a fallback to the older protocol: the user updates the older device.
        return RunReport(issues=(SyncIssue("peer-update-needed" if exc.peer_older else "lan-update-needed",
                                           f"{peer_id}: {exc}"),))
    except (TransportError, SyncStateError, OSError) as exc:
        return RunReport(issues=(SyncIssue("unreachable", f"{type(exc).__name__}: {exc}"),))

    report = run_merge(session, lease, device_id=state.device_id, views=[view], now=now)
    note_peer_synced(session, lease, peer_id, report, now)
    report = dataclasses.replace(report, issues=(*file_issues, *report.issues))
    extra: tuple[SyncIssue, ...] = ()
    if inline:
        mem = witness_memory.memory(session, state.group_id, state.device_id)
        if mem is not None:
            mem.refusals.pop(peer_id, None)  # a format-2 exchange went through
    obs = observation(view)
    if obs is not None:
        extra = apply_witness(session, lease, [obs])
    elif not inline:
        extra = _exchange_witness(call, session, lease, peer_id, now)
    return dataclasses.replace(report, issues=(*report.issues, *extra), wrote=True)


#: Consecutive ``bad-view`` refusals of a format-2 view that drop a peer's format-2 support.
FORMAT_REFUSALS_TO_DROP = 2


def _refused(session: Any, lease: Any, reply: Mapping[str, Any], peer_id: str, inline: bool) -> RunReport:
    """A refused exchange; repeated ``bad-view`` refusals of a format-2 view drop the peer's support.

    The refusal carries no detail (an older app answers ``bad-view`` for any view it cannot
    read), so a single one may be a damaged transfer: only ``FORMAT_REFUSALS_TO_DROP`` in a
    row (no successful format-2 exchange in between) count as "the peer went back to an older app".
    """
    if inline and reply.get("type") == "error" and reply.get("reason") == "bad-view":
        state = load_sync_state(session)
        mem = witness_memory.memory(session, state.group_id, state.device_id) if state is not None else None
        count = FORMAT_REFUSALS_TO_DROP
        if mem is not None:
            count = mem.refusals[peer_id] = mem.refusals.get(peer_id, 0) + 1
        if count >= FORMAT_REFUSALS_TO_DROP:
            if mem is not None:
                mem.refusals.pop(peer_id, None)
            apply_witness(session, lease, [], drop_capable=peer_id)
    return RunReport(issues=(_reply_issue(reply),))


def _exchange_witness(call: Callable[..., dict[str, Any]], session: Any, lease: Any, peer_id: str,
                      now: int) -> tuple[SyncIssue, ...]:
    """Send this device's witness after a format-1 exchange; check the peer's answer.

    A peer from before 2026-10-29 answers ``bad-message``, a lost connection gives nothing: both
    are silent (the views were merged already; the next exchange tries again).
    """
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        return ()
    raw = witness_file(session, state, now)
    if raw is None:
        return ()
    try:
        reply = call(_witness_message(state, raw))
    except (LanSyncError, TransportError, SyncStateError, OSError):
        return ()
    if reply.get("type") != "witness":
        return ()
    obs = _open_witness(state, peer_id, reply)
    if isinstance(obs, SyncIssue):
        return (obs,)
    return apply_witness(session, lease, [obs])


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
    "ACCEPT_TIMEOUT_SECONDS", "CHUNK_BYTES", "CHUNK_LIMIT", "ENROLL_REPLY_SECONDS", "ERROR_REASONS", "MAX_CHUNKS",
    "MAX_TRANSFERS", "MAX_VIEW_BYTES", "LanInbox", "LanResponder", "LanSyncError", "PendingEnrollment", "RunReport", "begin_pairing", "create_lan_group", "encode_message", "enroll_from_qr",
    "MAX_WITNESS_BYTES", "LAN_GENERATION_SLACK", "FORMAT_REFUSALS_TO_DROP", "apply_witness", "flush_witness",
    "witness_file",
    "parse_message", "peer_endpoint", "peer_entry", "peer_from_entry", "peer_to_entry", "remove_lan_peer", "save_peer_endpoint", "refind_from_qr",
    "serve_request", "split_view", "sync_with", "transport_state",
]
