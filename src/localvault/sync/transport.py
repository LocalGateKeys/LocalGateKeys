"""Bounded authenticated private-LAN transport primitives.

Importing this module, constructing :class:`SyncTransport`, and constructing
the UI controller never create a socket or perform network activity.  A
caller must explicitly call ``start(LANEndpoint(...))`` to arm a listener.
The optional ``request_handler`` receives an authenticated opaque request and
returns an opaque response.  A caller can use ``request(endpoint, payload)``
or its ``connect`` alias to perform one authenticated request/response on a
single TCP connection.  There is no discovery, DNS lookup, relay, Internet
fallback, or connection pool.

Connection slots: outbound (``request``/``enroll``) and inbound connections
have separate slots, so a peer connecting in never blocks this device's own
sync or pairing and vice versa.  At most one outbound connection runs at a
time.  The listener serves up to ``MAX_INBOUND_CONNECTIONS`` connections at
once and at most ``MAX_INBOUND_PER_ADDRESS`` from one source address.  Of the
connections not yet authenticated (no verified session hello), at most
``MAX_PRE_AUTH_PER_ADDRESS`` come from one address and ``MAX_PRE_AUTH_PER_PREFIX``
from one /24 (IPv4) or /64 (IPv6) network, and ``RESERVED_FOR_VERIFIED`` of the
slots are kept for addresses that completed a verified hello in the last
``VERIFIED_ADDRESS_SECONDS``: one host on the home network holding idle
connections cannot lock out a paired peer on the same network (audit R-1).  A
connection whose first frame (session hello or enrollment request, at most
``MAX_FIRST_FRAME_BYTES``) has not arrived within ``FIRST_FRAME_SECONDS`` is
dropped, so an idle unauthenticated connection holds a slot for about two
seconds.

Session keys (protocol version 2): each hello carries a fresh X25519
``ephemeral_public``.  The key is HKDF over the ephemeral-ephemeral X25519
output followed by the static-static one, so recorded traffic stays sealed
after a device's long-term exchange key leaks (forward secrecy); the signed
hellos and the pinned static keys still authenticate both ends.  An ephemeral
private key is used for exactly one derivation and dropped.  A hello of
another version is never used to derive a key: the responder answers with a
plain ``{"refused":"version","version":2}`` frame (and remembers a paired
device whose signed version-1 hello verified, ``outdated_peers``), and an
initiator that receives that frame raises :class:`PeerVersionMismatch`.

Every socket operation is bounded by a timeout and checks the transport's
cancellation token.  ``stop()`` and ``cancel()`` close the listener and any
active connection, which unblocks a pending read or connect.  Endpoints are
literal loopback/private/link-local IP addresses and, when supplied, must be
in the explicit endpoint allowlist.  Before any encrypted application bytes
are exchanged, both peers send signed :class:`SessionHello` values and pin
the peer to a :class:`~localvault.sync.pairing.PairedDevice` in
:class:`~localvault.sync.state.SyncState`.
"""
from __future__ import annotations

import base64
import dataclasses
import errno
import hashlib
import ipaddress
import json
import secrets
import select
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .lan_address import is_lan_address
from .pairing import ENROLL_REQUEST_MAGIC, MAX_ENROLL_BYTES, DeviceIdentity, PairedDevice
from .state import SyncDisabled, SyncState

#: Version 2 added the per-session ephemeral key (forward secrecy); a version-1 peer gets "update needed".
TRANSPORT_VERSION = 2
MAX_FRAME_PAYLOAD = 1024 * 1024
MAX_FRAME_BYTES = MAX_FRAME_PAYLOAD + 4
MAX_MESSAGE_BYTES = MAX_FRAME_PAYLOAD - 256
FRAME_HEADER = struct.Struct(">I")
SESSION_ID_BYTES = 16
NONCE_BYTES = 12


class TransportError(ValueError):
    pass


class FrameTooLarge(TransportError):
    pass


class FrameError(TransportError):
    pass


class AuthenticationError(TransportError):
    pass


class ReplayError(TransportError):
    pass


class TransportCancelled(TransportError):
    pass


class TransportTimeout(TransportError):
    """A bounded socket operation exceeded its deadline."""


class PeerNotAnswering(TransportError):
    """``request`` failed before the peer's session hello arrived: the request was never sent.

    The peer processed nothing, so the caller may safely retry.  The original
    error is the ``__cause__``.  ``connected`` is True when the TCP connection
    was made and the peer then closed or stayed silent (a busy listener refusing
    a slot), False when the connection itself failed.
    """

    def __init__(self, message: str, *, connected: bool = False) -> None:
        super().__init__(message)
        self.connected = connected


class PeerVersionMismatch(TransportError):
    """The peer speaks another LAN protocol version; nothing was derived or sent.

    ``peer_version`` is the version it announced; ``peer_older`` is True when the
    other device needs the update, False when this one does.
    """

    def __init__(self, peer_version: int) -> None:
        self.peer_version = peer_version
        self.peer_older = peer_version < TRANSPORT_VERSION
        who = "the other device" if self.peer_older else "this device"
        super().__init__(f"update needed: {who} runs an older LocalGateKeys (Wi-Fi sync version "
                         f"{min(peer_version, TRANSPORT_VERSION)} instead of {max(peer_version, TRANSPORT_VERSION)})")


DEFAULT_SOCKET_TIMEOUT = 5.0
MAX_SOCKET_TIMEOUT = 300.0
SOCKET_POLL_SECONDS = 0.10
#: Kept for callers of the earlier single-slot listener; inbound connections no
#: longer wait for the outbound slot (see the module docstring).
SLOT_WAIT_SECONDS = 2.0
#: Inbound connections served at the same time (pre-authentication included).
MAX_INBOUND_CONNECTIONS = 4
#: Inbound connections served at the same time from one source address.  Two cover
#: a peer whose next LAN chunk arrives while the previous handler is finishing.
MAX_INBOUND_PER_ADDRESS = 2
#: Inbound connections not yet authenticated (no verified session hello) held at the same
#: time from one source address.
MAX_PRE_AUTH_PER_ADDRESS = 1
#: Inbound connections not yet authenticated held at the same time from one /24 (IPv4) or
#: /64 (IPv6) network: a host with several addresses cannot take every slot before
#: authenticating, and one address leaves room for the other devices of its network.
MAX_PRE_AUTH_PER_PREFIX = 3
#: Slots only an address that completed a verified session hello in the last
#: ``VERIFIED_ADDRESS_SECONDS`` may take (such an address is not held to the
#: pre-authentication caps either), so unauthenticated connections never fill the listener.
RESERVED_FOR_VERIFIED = 1
VERIFIED_ADDRESS_SECONDS = 15 * 60.0
#: Recently verified addresses remembered (the oldest is forgotten first).
MAX_VERIFIED_ADDRESSES = 64
#: Longest wait for the TCP connection to a peer (Wi-Fi power saving can delay the first packets).
CONNECT_SECONDS = 3.0
#: Deadline for the first frame of an inbound connection (a hello or enrollment request
#: is sent right after connecting; the iPhone app does the same).
FIRST_FRAME_SECONDS = 2.0
#: Largest first frame accepted: an enrollment request (``MAX_ENROLL_BYTES``) or a
#: session hello (well under 1 KiB).
MAX_FIRST_FRAME_BYTES = 64 * 1024
#: Listen backlog (connections the OS queues before ``accept``).
LISTEN_BACKLOG = 8


def _source_prefix(address: str) -> str:
    """The /24 (IPv4) or /64 (IPv6) network of *address*; the address itself when it does not parse."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return address
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False))


def _canonical(value: Any, limit: int = MAX_FRAME_PAYLOAD) -> bytes:
    try:
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    except (TypeError, ValueError) as exc:
        raise FrameError("Transport message is not serializable") from exc
    if len(data) > limit:
        raise FrameTooLarge("Transport message exceeds the frame bound")
    return data


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError("non-finite number")


def _strict_json(value: bytes) -> Any:
    return json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)


def _b64d(value: Any, length: int | None, field: str, *, max_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise FrameError(f"{field} is malformed")
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise FrameError(f"{field} is malformed") from exc
    if base64.b64encode(result).decode("ascii") != value:
        raise FrameError(f"{field} is not canonical base64")
    if length is not None and len(result) != length:
        raise FrameError(f"{field} has an invalid length")
    if max_length is not None and len(result) > max_length:
        raise FrameTooLarge(f"{field} exceeds the size bound")
    return result


def encode_frame(payload: bytes) -> bytes:
    """Encode exactly one bounded length-prefixed frame."""

    if not isinstance(payload, bytes):
        raise FrameError("Frame payload must be bytes")
    if not 1 <= len(payload) <= MAX_FRAME_PAYLOAD:
        raise FrameTooLarge("Frame payload is empty or exceeds the bound")
    return FRAME_HEADER.pack(len(payload)) + payload


def decode_frame(frame: bytes) -> bytes:
    if not isinstance(frame, bytes) or len(frame) < FRAME_HEADER.size:
        raise FrameError("Frame is truncated")
    (length,) = FRAME_HEADER.unpack(frame[:FRAME_HEADER.size])
    if not 1 <= length <= MAX_FRAME_PAYLOAD:
        raise FrameTooLarge("Frame length is outside the bound")
    if len(frame) != FRAME_HEADER.size + length:
        raise FrameError("Frame contains trailing or missing bytes")
    return frame[FRAME_HEADER.size:]


@dataclass(frozen=True)
class LANEndpoint:
    host: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.host, str) or len(self.host) > 255:
            raise TransportError("LAN endpoint host is malformed")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError:
            raise TransportError("LAN endpoint must be a literal IP address") from None
        if not is_lan_address(address):
            raise TransportError("LAN endpoint must be a specific private address")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise TransportError("LAN endpoint port is malformed")


#: The exact field sets of a session hello and of a sealed frame; anything else is malformed.
_HELLO_FIELDS = frozenset({"counter", "device_id", "ephemeral_public", "exchange_public", "group_id", "nonce",
                           "session_id", "signature", "signing_public", "version"})
_FRAME_FIELDS = frozenset({"ciphertext", "counter", "nonce", "session_id", "version"})
#: A version-1 hello (no ephemeral key): recognised only to report "update needed".
_LEGACY_HELLO_FIELDS = _HELLO_FIELDS - {"ephemeral_public"}
#: The plain answer of a responder to a hello of another version.
_VERSION_REFUSAL_FIELDS = frozenset({"refused", "version"})
_HELLO_LABEL = b"localgatekeys|sync|session-hello|v2|"
_LEGACY_HELLO_LABEL = b"localgatekeys|sync|session-hello|v1|"
_SALT_LABEL = b"localgatekeys|sync|session-salt|v2|"
_KEY_LABEL = b"localgatekeys|sync|session-key|v2|"


def _is_version(value: Any) -> bool:
    """True only for the JSON integer TRANSPORT_VERSION (not ``true`` or ``1.0``)."""
    return type(value) is int and value == TRANSPORT_VERSION


class EphemeralSecret:
    """The X25519 ephemeral private key of one session hello, usable for exactly one derivation.

    :meth:`take` hands it out once and forgets it; :meth:`wipe` forgets it unused
    (a failed handshake).  Python cannot overwrite the key's memory, but no
    reference to it survives the derivation.
    """

    __slots__ = ("_key",)

    def __init__(self, key: x25519.X25519PrivateKey) -> None:
        self._key: x25519.X25519PrivateKey | None = key

    def take(self) -> x25519.X25519PrivateKey:
        key, self._key = self._key, None
        if key is None:
            raise AuthenticationError("Session ephemeral key was already used or wiped")
        return key

    def wipe(self) -> None:
        self._key = None

    @property
    def used(self) -> bool:
        return self._key is None

    def __repr__(self) -> str:
        return "EphemeralSecret(<redacted>)"


@dataclass(frozen=True)
class SessionHello:
    session_id: bytes
    group_id: str
    device_id: str
    signing_public: bytes
    exchange_public: bytes
    ephemeral_public: bytes
    nonce: bytes
    counter: int
    signature: bytes
    version: int = TRANSPORT_VERSION
    #: Set only on a hello this device created (never parsed or serialised).
    ephemeral_secret: EphemeralSecret | None = field(default=None, repr=False, compare=False)

    def unsigned_dict(self) -> dict[str, Any]:
        return {"version": self.version, "session_id": _b64e(self.session_id),
                "group_id": self.group_id, "device_id": self.device_id,
                "signing_public": _b64e(self.signing_public),
                "exchange_public": _b64e(self.exchange_public),
                "ephemeral_public": _b64e(self.ephemeral_public),
                "nonce": _b64e(self.nonce), "counter": self.counter}

    def signing_bytes(self) -> bytes:
        return _HELLO_LABEL + _canonical(self.unsigned_dict())

    def to_bytes(self) -> bytes:
        result = dict(self.unsigned_dict())
        result["signature"] = _b64e(self.signature)
        return _canonical(result)

    @classmethod
    def from_bytes(cls, value: bytes) -> SessionHello:
        """Parse a version-2 hello; a hello of another version raises :class:`HelloVersionError`."""
        if not isinstance(value, bytes) or len(value) > MAX_MESSAGE_BYTES:
            raise FrameTooLarge("Session hello exceeds the bound")
        try:
            raw = _strict_json(value)
        except (ValueError, TypeError):
            raise FrameError("Session hello is malformed") from None
        if (isinstance(raw, Mapping) and type(raw.get("version")) is int and raw["version"] != TRANSPORT_VERSION
                and "signature" in raw):
            raise HelloVersionError(raw["version"], raw)
        if not isinstance(raw, Mapping) or set(raw) != _HELLO_FIELDS:
            raise FrameError("Session hello is malformed")
        if not _is_version(raw["version"]):
            raise FrameError("Unsupported session hello")
        counter = raw.get("counter")
        if type(counter) is not int or not 0 <= counter <= 2**63 - 1:
            raise FrameError("Session hello counter is malformed")
        return cls(
            session_id=_b64d(raw.get("session_id"), SESSION_ID_BYTES, "session id"),
            group_id=raw.get("group_id"), device_id=raw.get("device_id"),
            signing_public=_b64d(raw.get("signing_public"), 32, "signing public key"),
            exchange_public=_b64d(raw.get("exchange_public"), 32, "exchange public key"),
            ephemeral_public=_b64d(raw.get("ephemeral_public"), 32, "ephemeral public key"),
            nonce=_b64d(raw.get("nonce"), 32, "session nonce"), counter=counter,
            signature=_b64d(raw.get("signature"), 64, "session signature"),
        )


class HelloVersionError(FrameError):
    """A first frame that is a signed hello of another protocol ``version``; never used for a key."""

    def __init__(self, version: int, raw: Mapping[str, Any]) -> None:
        super().__init__(f"Session hello version {version} is not supported")
        self.version = version
        self.raw = raw


def version_refusal() -> bytes:
    """The plain frame payload a responder sends for a hello of another version."""
    return _canonical({"refused": "version", "version": TRANSPORT_VERSION})


def parse_version_refusal(value: bytes) -> int | None:
    """The version a peer announced in a version refusal, or None when *value* is not one."""
    if not isinstance(value, bytes) or len(value) > 256:
        return None
    try:
        raw = _strict_json(value)
    except (ValueError, TypeError):
        return None
    if (isinstance(raw, Mapping) and set(raw) == _VERSION_REFUSAL_FIELDS and raw["refused"] == "version"
            and type(raw["version"]) is int and 1 <= raw["version"] <= 2**31 - 1
            and raw["version"] != TRANSPORT_VERSION):
        return raw["version"]
    return None


def verify_legacy_hello(raw: Mapping[str, Any], expected_group_id: str, trusted_peer: PairedDevice) -> str:
    """The device id of a version-1 hello whose signature verifies under *trusted_peer*'s pinned key.

    Used ONLY to tell the user that a paired device needs an update: nothing is
    derived from a version-1 hello and it never gets a session.
    """
    if not isinstance(raw, Mapping) or set(raw) != _LEGACY_HELLO_FIELDS or raw.get("version") != 1:
        raise FrameError("Session hello is malformed")
    if (raw.get("group_id") != expected_group_id or raw.get("device_id") != trusted_peer.device_id
            or raw.get("signing_public") != _b64e(trusted_peer.signing_public)):
        raise AuthenticationError("Session device key is not pinned")
    unsigned = {k: v for k, v in raw.items() if k != "signature"}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(trusted_peer.signing_public).verify(
            _b64d(raw.get("signature"), 64, "session signature"), _LEGACY_HELLO_LABEL + _canonical(unsigned))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise AuthenticationError("Session hello signature is invalid") from exc
    return trusted_peer.device_id


def create_session_hello(identity: DeviceIdentity, group_id: str, session_id: bytes,
                         *, counter: int = 1, _nonce: bytes | None = None,
                         _ephemeral: bytes | None = None) -> SessionHello:
    """A signed hello with a fresh ephemeral key (``ephemeral_secret``, good for one derivation).

    ``_nonce`` and ``_ephemeral`` (a 32-byte X25519 private key) exist only for the test vectors.
    """
    if not isinstance(identity, DeviceIdentity) or not isinstance(group_id, str) or not group_id:
        raise AuthenticationError("Session identity or group is malformed")
    if not isinstance(session_id, bytes) or len(session_id) != SESSION_ID_BYTES:
        raise AuthenticationError("Session ID is malformed")
    if type(counter) is not int or not 0 <= counter <= 2**63 - 1:
        raise AuthenticationError("Session counter is malformed")
    if _ephemeral is None:
        eph = x25519.X25519PrivateKey.generate()
    elif isinstance(_ephemeral, bytes) and len(_ephemeral) == 32:
        eph = x25519.X25519PrivateKey.from_private_bytes(_ephemeral)
    else:
        raise AuthenticationError("Session ephemeral key is malformed")
    eph_public = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    hello = SessionHello(session_id, group_id, identity.device_id, identity.signing_public_key,
                         identity.exchange_public_key, eph_public, _nonce or secrets.token_bytes(32), counter, b"")
    return dataclasses.replace(hello, signature=identity.sign(hello.signing_bytes()),
                               ephemeral_secret=EphemeralSecret(eph))


def verify_session_hello(hello: SessionHello, expected_group_id: str,
                         trusted_peer: PairedDevice) -> None:
    if not isinstance(hello, SessionHello) or not isinstance(trusted_peer, PairedDevice):
        raise AuthenticationError("Session hello or trust record is malformed")
    if hello.group_id != expected_group_id or hello.group_id != trusted_peer.group_id:
        raise AuthenticationError("Session group mismatch")
    if hello.device_id != trusted_peer.device_id or hello.signing_public != trusted_peer.signing_public:
        raise AuthenticationError("Session device key is not pinned")
    if hashlib.sha256(hello.signing_public).hexdigest() != trusted_peer.fingerprint:
        raise AuthenticationError("Session device fingerprint is not pinned")
    if hello.exchange_public != trusted_peer.exchange_public:
        raise AuthenticationError("Session exchange key is not pinned")
    if hello.ephemeral_public in (hello.exchange_public, bytes(32)):
        raise AuthenticationError("Session ephemeral key is malformed")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(hello.signing_public).verify(
            hello.signature, hello.signing_bytes())
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise AuthenticationError("Session hello signature is invalid") from exc


def _exchange(private: x25519.X25519PrivateKey, public: bytes, what: str) -> bytes:
    """X25519; an all-zero result (a low-order peer key) is refused like a malformed key."""
    try:
        shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(public))
    except (ValueError, TypeError) as exc:
        raise AuthenticationError(f"Peer {what} key is malformed") from exc
    if shared == bytes(32):
        raise AuthenticationError(f"Peer {what} key is malformed")
    return shared


def _derive_key(local: DeviceIdentity, remote: PairedDevice, session_id: bytes, transcript: bytes,
                local_hello: SessionHello, remote_hello: SessionHello) -> bytes:
    """Session key: HKDF-SHA256 over ``X25519(own eph, peer eph) || X25519(own static, peer static)``.

    Consumes *local_hello*'s ephemeral secret: a second derivation from the same
    hello fails, and nothing keeps the ephemeral private key afterwards.
    """
    if len(session_id) != SESSION_ID_BYTES or len(transcript) > MAX_MESSAGE_BYTES:
        raise AuthenticationError("Session transcript is malformed")
    secret = local_hello.ephemeral_secret
    if not isinstance(secret, EphemeralSecret):
        raise AuthenticationError("Local session hello has no ephemeral key")
    eph = secret.take()
    try:
        own_public = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if own_public != local_hello.ephemeral_public:
            raise AuthenticationError("Local session hello does not carry its ephemeral key")
        ephemeral = _exchange(eph, remote_hello.ephemeral_public, "ephemeral")
    finally:
        del eph
    static = _exchange(local.exchange_key, remote.exchange_public, "exchange")
    salt = hashlib.sha256(_SALT_LABEL + transcript).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=_KEY_LABEL + session_id).derive(ephemeral + static)


class SecureChannel:
    """AEAD channel with strict counters and an optional lifecycle guard."""

    def __init__(self, key: bytes, *, session_id: bytes, role: str,
                 max_payload: int = MAX_MESSAGE_BYTES,
                 authorization: Callable[[], None] | None = None) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise AuthenticationError("Session key must be 32 bytes")
        if not isinstance(session_id, bytes) or len(session_id) != SESSION_ID_BYTES:
            raise AuthenticationError("Session ID is malformed")
        if role not in {"initiator", "responder"}:
            raise AuthenticationError("Session role is malformed")
        if type(max_payload) is not int or not 1 <= max_payload <= MAX_MESSAGE_BYTES:
            raise AuthenticationError("Session payload bound is malformed")
        if authorization is not None and not callable(authorization):
            raise AuthenticationError("Session authorization guard is malformed")
        self._key = key
        self.session_id = session_id
        self.role = role
        self.max_payload = max_payload
        self._send_counter = 0
        self._last_received = 0
        self._authorization = authorization
        self._send_prefix = hashlib.sha256(key + b"send|" + role.encode()).digest()[:4]
        peer_role = "responder" if role == "initiator" else "initiator"
        self._receive_prefix = hashlib.sha256(key + b"send|" + peer_role.encode()).digest()[:4]

    @classmethod
    def from_paired_identities(cls, local: DeviceIdentity, remote: PairedDevice,
                               *, group_id: str, session_id: bytes, role: str,
                               local_hello: SessionHello, remote_hello: SessionHello,
                               state: SyncState | None = None) -> SecureChannel:
        verify_session_hello(remote_hello, group_id, remote)
        if (local_hello.group_id != group_id or local_hello.device_id != local.device_id
                or local_hello.session_id != session_id or remote_hello.session_id != session_id):
            raise AuthenticationError("Session hello binding is invalid")
        if state is not None and not isinstance(state, SyncState):
            raise AuthenticationError("Sync state is malformed")
        if local_hello.signing_public != local.signing_public_key:
            raise AuthenticationError("Local session hello belongs to another identity")
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(local.signing_public_key).verify(
                local_hello.signature, local_hello.signing_bytes())
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise AuthenticationError("Local session hello signature is invalid") from exc
        # Both directions derive the same transcript while retaining the
        # explicit device binding.  Sorting by encoded hello avoids a role-
        # dependent key while the signed hellos still prevent substitution.
        transcript = b"".join(sorted((local_hello.to_bytes(), remote_hello.to_bytes())))
        authorization = state.channel_authorizer(remote.device_id) if state is not None else None
        return cls(_derive_key(local, remote, session_id, transcript, local_hello, remote_hello),
                   session_id=session_id, role=role, authorization=authorization)

    def _check_authorized(self) -> None:
        if self._authorization is not None:
            self._authorization()

    def seal(self, payload: bytes) -> bytes:
        self._check_authorized()
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= self.max_payload:
            raise FrameTooLarge("Encrypted message exceeds the bound")
        if self._send_counter >= 2**63 - 1:
            raise ReplayError("Session counter exhausted")
        self._send_counter += 1
        counter = self._send_counter
        nonce = self._send_prefix + counter.to_bytes(8, "big")
        metadata = {"version": TRANSPORT_VERSION, "session_id": _b64e(self.session_id),
                    "counter": counter, "nonce": _b64e(nonce)}
        aad = _canonical(metadata)
        ciphertext = AESGCM(self._key).encrypt(nonce, payload, aad)
        return encode_frame(_canonical({**metadata, "ciphertext": _b64e(ciphertext)}))

    def open(self, frame: bytes) -> bytes:
        self._check_authorized()
        payload = decode_frame(frame)
        if len(payload) > self.max_payload + 4096:
            raise FrameTooLarge("Encrypted frame exceeds the bound")
        try:
            raw = _strict_json(payload)
        except (ValueError, TypeError):
            raise FrameError("Encrypted frame is malformed") from None
        if not isinstance(raw, Mapping) or set(raw) != _FRAME_FIELDS:
            raise FrameError("Encrypted frame is malformed")
        if not _is_version(raw["version"]):
            raise FrameError("Unsupported encrypted frame")
        if raw.get("session_id") != _b64e(self.session_id):
            raise AuthenticationError("Encrypted frame belongs to another session")
        counter = raw.get("counter")
        if type(counter) is not int or not 1 <= counter <= 2**63 - 1:
            raise FrameError("Encrypted frame counter is malformed")
        if counter <= self._last_received:
            raise ReplayError("Duplicate or out-of-order encrypted frame")
        nonce = _b64d(raw.get("nonce"), NONCE_BYTES, "encrypted nonce")
        if nonce[:4] != self._receive_prefix or int.from_bytes(nonce[4:], "big") != counter:
            raise AuthenticationError("Encrypted nonce is not bound to the session direction")
        ciphertext = _b64d(raw.get("ciphertext"), None, "encrypted payload",
                            max_length=self.max_payload + 16)
        metadata = {"version": TRANSPORT_VERSION, "session_id": _b64e(self.session_id),
                    "counter": counter, "nonce": _b64e(nonce)}
        try:
            result = AESGCM(self._key).decrypt(nonce, ciphertext, _canonical(metadata))
        except (InvalidTag, ValueError):
            raise AuthenticationError("Encrypted frame authentication failed") from None
        if len(result) > self.max_payload:
            raise FrameTooLarge("Decrypted message exceeds the bound")
        self._last_received = counter
        return result


def establish_channel(local: DeviceIdentity, remote: PairedDevice, *, group_id: str,
                      session_id: bytes, role: str,
                      local_hello: SessionHello, remote_hello: SessionHello,
                      state: SyncState | None = None) -> SecureChannel:
    return SecureChannel.from_paired_identities(local, remote, group_id=group_id,
                                                session_id=session_id, role=role,
                                                local_hello=local_hello, remote_hello=remote_hello,
                                                state=state)


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self.cancelled:
            raise TransportCancelled("Sync operation was cancelled")


@dataclass
class RetryBackoff:
    base_seconds: float = 1.0
    max_seconds: float = 300.0
    attempts: int = 0

    def next_delay(self) -> float:
        if not 0 < self.base_seconds <= self.max_seconds <= 3600:
            raise TransportError("Retry bounds are malformed")
        result = min(self.max_seconds, self.base_seconds * (2 ** min(self.attempts, 10)))
        self.attempts = min(self.attempts + 1, 31)
        return result

    def reset(self) -> None:
        self.attempts = 0


class SyncTransport:
    """Explicit, authenticated one-connection private-LAN transport.

    ``request_handler`` is deliberately a small bytes-in/bytes-out seam.  It
    lets the sync adapter own the application protocol while this class owns
    endpoint validation, framing, session authentication, cancellation, and
    socket lifetime.  A handler is optional so existing lifecycle callers can
    arm a transport before pairing; a transport without a handler rejects
    inbound requests.
    """

    def __init__(self, state: SyncState | None = None,
                 *, endpoint_allowlist: tuple[LANEndpoint, ...] = (),
                 request_handler: Callable[[bytes], bytes] | None = None,
                 handler: Callable[[bytes], bytes] | None = None,
                 socket_timeout: float = DEFAULT_SOCKET_TIMEOUT) -> None:
        if state is not None and not isinstance(state, SyncState):
            raise TransportError("A protected sync state is required")
        if request_handler is not None and not callable(request_handler):
            raise TransportError("Transport request handler is malformed")
        if handler is not None and not callable(handler):
            raise TransportError("Transport request handler is malformed")
        if request_handler is not None and handler is not None and request_handler is not handler:
            raise TransportError("Specify only one transport request handler")
        if type(socket_timeout) not in (int, float) or not (
                0 < float(socket_timeout) <= MAX_SOCKET_TIMEOUT):
            raise TransportError("Transport socket timeout is malformed")
        allowed = tuple(endpoint_allowlist)
        if any(not isinstance(endpoint, LANEndpoint) for endpoint in allowed):
            raise TransportError("Transport endpoint allowlist is malformed")
        self.state = state
        self.endpoint_allowlist = allowed
        self.endpoint: LANEndpoint | None = None
        self.running = False
        self.socket_timeout = float(socket_timeout)
        self._request_handler = request_handler if request_handler is not None else handler
        self._peer_request_handler: Callable[[PairedDevice, bytes], bytes] | None = None
        self._enrollment_handler: Callable[[bytes], bytes | None] | None = None
        self._cancel = CancellationToken()
        self._listener: socket.socket | None = None
        self._listener_thread: threading.Thread | None = None
        self._active_socket: socket.socket | None = None  # the one outbound connection
        self._inbound: dict[socket.socket, str] = {}  # inbound connection -> source address
        self._pre_auth: dict[socket.socket, str] = {}  # not yet authenticated -> source network
        self._verified: dict[str, float] = {}  # source address -> monotonic time of its last verified hello
        #: Paired device id -> monotonic time its signed hello of an older protocol version was refused.
        self.outdated_peers: dict[str, float] = {}
        self._socket_lock = threading.RLock()
        self._slot_free = threading.Condition(self._socket_lock)
        self._connection_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.state and self.state.enabled) if self.state is not None else self.running

    @property
    def request_handler(self) -> Callable[[bytes], bytes] | None:
        return self._request_handler

    def set_request_handler(self, handler: Callable[[bytes], bytes] | None) -> None:
        """Set the handler used for future authenticated inbound requests."""

        if handler is not None and not callable(handler):
            raise TransportError("Transport request handler is malformed")
        self._request_handler = handler

    set_handler = set_request_handler

    def set_peer_request_handler(self, handler: Callable[[PairedDevice, bytes], bytes] | None) -> None:
        """Set a handler that also receives the authenticated peer's pinned record.

        When set it takes precedence over the bytes-only request handler; the
        group-model LAN sync uses it to bind each message to the peer device id.
        """

        if handler is not None and not callable(handler):
            raise TransportError("Transport request handler is malformed")
        self._peer_request_handler = handler

    def set_enrollment_handler(self, handler: Callable[[bytes], bytes | None] | None) -> None:
        """Accept one-frame enrollment requests from unpinned devices while *handler* is set.

        Install it only while a pairing offer is active and remove it afterwards.
        The handler receives the raw request (``ENROLL_REQUEST_MAGIC`` prefix, at
        most ``MAX_ENROLL_BYTES``) and returns the reply bytes, or None to close
        without a reply.
        """

        if handler is not None and not callable(handler):
            raise TransportError("Transport enrollment handler is malformed")
        self._enrollment_handler = handler

    def enroll(self, endpoint: LANEndpoint, payload: bytes, *, timeout: float | None = None) -> bytes:
        """Send one enrollment request to *endpoint* and return the one-frame reply.

        Needs no started listener or pinned peer: the payload is protected by the
        pairing offer (see :func:`localvault.sync.pairing.build_enrollment_request`).
        """

        self._check_endpoint(endpoint)
        self._cancel.check()
        if (not isinstance(payload, bytes) or not payload.startswith(ENROLL_REQUEST_MAGIC)
                or len(payload) > MAX_ENROLL_BYTES):
            raise FrameError("Enrollment request is malformed")
        deadline = self._deadline(timeout)
        sock = socket.socket(self._socket_family(endpoint), socket.SOCK_STREAM)
        if not self._reserve_socket(sock):
            self._close_socket(sock)
            raise TransportError("Sync transport already has an active connection")
        try:
            self._connect(sock, endpoint, deadline)
            self._send_all(sock, encode_frame(payload), deadline)
            reply = self._read_socket_frame(sock, deadline)[FRAME_HEADER.size:]
            if len(reply) > MAX_ENROLL_BYTES:
                raise FrameTooLarge("Enrollment reply exceeds the bound")
            return reply
        finally:
            self._release_socket(sock)
            self._close_socket(sock)

    _CONNECT_PENDING = frozenset({0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                                  getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK)})

    def _connect(self, sock: socket.socket, endpoint: LANEndpoint, deadline: float) -> None:
        """Connect *sock*, waiting up to ``CONNECT_SECONDS`` (and *deadline*) in cancellable steps.

        A single short ``connect`` timeout made a busy or power-saving peer (and a
        loaded test machine) look unreachable.
        """
        limit = min(deadline, time.monotonic() + CONNECT_SECONDS)
        try:
            sock.setblocking(False)
            code = sock.connect_ex(self._socket_address(endpoint))
        except OSError as exc:
            raise TransportError("Transport connect failed") from exc
        if code not in self._CONNECT_PENDING:
            raise TransportError(f"Transport connect failed ({code})")
        while code != 0:
            if self._cancel.cancelled:
                raise TransportCancelled("Sync operation was cancelled")
            remaining = limit - time.monotonic()
            if remaining <= 0:
                raise TransportTimeout("Transport connect timed out")
            try:
                _r, writable, failed = select.select([], [sock], [sock], min(SOCKET_POLL_SECONDS, remaining))
            except (OSError, ValueError) as exc:
                if self._cancel.cancelled:
                    raise TransportCancelled("Sync operation was cancelled") from exc
                raise TransportError("Transport connect failed") from exc
            if writable or failed:
                code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if code != 0 or failed:
                    raise TransportError(f"Transport connect failed ({code})")
        sock.setblocking(True)

    def _check_endpoint(self, endpoint: LANEndpoint) -> None:
        if not isinstance(endpoint, LANEndpoint):
            raise TransportError("A validated LAN endpoint is required")
        if self.endpoint_allowlist and endpoint not in self.endpoint_allowlist:
            raise TransportError("LAN endpoint is not explicitly allowlisted")

    @staticmethod
    def _socket_address(endpoint: LANEndpoint) -> tuple[Any, ...]:
        address = ipaddress.ip_address(endpoint.host)
        return ((endpoint.host, endpoint.port, 0, 0)
                if address.version == 6 else (endpoint.host, endpoint.port))

    @staticmethod
    def _socket_family(endpoint: LANEndpoint) -> int:
        return socket.AF_INET6 if ipaddress.ip_address(endpoint.host).version == 6 else socket.AF_INET

    @staticmethod
    def _close_socket(sock: socket.socket | None) -> None:
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _recently_verified(self, address: str, now: float) -> bool:
        """*address* completed a verified hello within ``VERIFIED_ADDRESS_SECONDS`` (call under the lock)."""
        for stale in [a for a, t in self._verified.items() if now - t > VERIFIED_ADDRESS_SECONDS]:
            del self._verified[stale]
        return address in self._verified

    def _reserve_inbound(self, sock: socket.socket, address: str) -> bool:
        """Take an inbound slot for *sock* from *address*; False when a cap is reached.

        Every address: at most ``MAX_INBOUND_CONNECTIONS`` in total and
        ``MAX_INBOUND_PER_ADDRESS`` from it.  An address without a recent
        verified hello also leaves ``RESERVED_FOR_VERIFIED`` slots free and holds
        at most ``MAX_PRE_AUTH_PER_ADDRESS`` unauthenticated connections itself and
        ``MAX_PRE_AUTH_PER_PREFIX`` together with its /24 or /64 network.
        """
        prefix = _source_prefix(address)
        with self._socket_lock:
            if len(self._inbound) >= MAX_INBOUND_CONNECTIONS:
                return False
            if sum(1 for a in self._inbound.values() if a == address) >= MAX_INBOUND_PER_ADDRESS:
                return False
            if not self._recently_verified(address, time.monotonic()):
                if len(self._inbound) >= MAX_INBOUND_CONNECTIONS - RESERVED_FOR_VERIFIED:
                    return False
                pending = [s for s in self._pre_auth if self._inbound.get(s) == address]
                if len(pending) >= MAX_PRE_AUTH_PER_ADDRESS:
                    return False
                if sum(1 for p in self._pre_auth.values() if p == prefix) >= MAX_PRE_AUTH_PER_PREFIX:
                    return False
            self._inbound[sock] = address
            self._pre_auth[sock] = prefix
            return True

    def _inbound_authenticated(self, sock: socket.socket) -> None:
        """*sock*'s peer sent a verified session hello: it no longer counts against the pre-authentication
        caps, and its address may use the reserved slots for ``VERIFIED_ADDRESS_SECONDS``."""
        with self._socket_lock:
            self._pre_auth.pop(sock, None)
            address = self._inbound.get(sock)
            if address is not None:
                self._verified.pop(address, None)
                self._verified[address] = time.monotonic()
                while len(self._verified) > MAX_VERIFIED_ADDRESSES:
                    del self._verified[next(iter(self._verified))]

    def _release_inbound(self, sock: socket.socket) -> None:
        with self._socket_lock:
            self._inbound.pop(sock, None)
            self._pre_auth.pop(sock, None)

    def _take_all_sockets(self) -> list[socket.socket]:
        """Detach the outbound and every inbound socket (stop/cancel closes them)."""
        with self._socket_lock:
            taken = [s for s in (self._active_socket, *self._inbound) if s is not None]
            self._active_socket = None
            self._inbound.clear()
            self._pre_auth.clear()
            self._slot_free.notify_all()
        return taken

    def _reserve_socket(self, sock: socket.socket, wait: float = 0.0) -> bool:
        """Take the one outbound connection slot; wait up to *wait* seconds for it (stops on cancel)."""
        deadline = time.monotonic() + max(0.0, wait)
        with self._slot_free:
            while self._active_socket is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._cancel.cancelled:
                    return False
                self._slot_free.wait(min(SOCKET_POLL_SECONDS, remaining))
            self._active_socket = sock
            return True

    def _release_socket(self, sock: socket.socket) -> None:
        with self._slot_free:
            if self._active_socket is sock:
                self._active_socket = None
                self._slot_free.notify_all()

    @staticmethod
    def _validate_timeout(timeout: float | None, default: float) -> float:
        value = default if timeout is None else timeout
        if type(value) not in (int, float) or not (0 < float(value) <= MAX_SOCKET_TIMEOUT):
            raise TransportError("Transport timeout is malformed")
        return float(value)

    def _new_listener(self, endpoint: LANEndpoint) -> socket.socket:
        listener = socket.socket(self._socket_family(endpoint), socket.SOCK_STREAM)
        try:
            if sys.platform == "win32":
                # Windows SO_REUSEADDR lets another socket bind the same port and
                # steal connections; exclusive use refuses that instead.
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if listener.family == socket.AF_INET6:
                try:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except OSError:
                    pass
            listener.bind(self._socket_address(endpoint))
            listener.listen(LISTEN_BACKLOG)
            listener.settimeout(SOCKET_POLL_SECONDS)
            return listener
        except OSError as exc:
            self._close_socket(listener)
            raise TransportError("LAN listener could not be started") from exc

    def start(self, endpoint: LANEndpoint,
              request_handler: Callable[[bytes], bytes] | None = None, *,
              handler: Callable[[bytes], bytes] | None = None) -> None:
        """Bind an explicitly selected private endpoint and start its listener."""

        if not isinstance(endpoint, LANEndpoint):
            raise TransportError("A validated LAN endpoint is required")
        if self.running:
            raise TransportError("Sync transport is already running")
        self._check_endpoint(endpoint)
        if request_handler is not None and handler is not None and request_handler is not handler:
            raise TransportError("Specify only one transport request handler")
        selected_handler = request_handler if request_handler is not None else handler
        if selected_handler is not None:
            self.set_request_handler(selected_handler)
        listener = self._new_listener(endpoint)
        if self.state is not None:
            self.state.enable()
        self.endpoint = endpoint
        self.running = True
        self._cancel = CancellationToken()
        with self._socket_lock:
            self._listener = listener
        self._listener_thread = threading.Thread(
            target=self._listen_loop, name="localvault-sync-listener", daemon=True)
        self._listener_thread.start()

    def _listen_loop(self) -> None:
        listener: socket.socket | None = None
        while self.running and not self._cancel.cancelled:
            with self._socket_lock:
                listener = self._listener
            if listener is None:
                break
            try:
                client, address = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            source = str(address[0]) if isinstance(address, tuple) and address else ""
            if not self._reserve_inbound(client, source):
                self._close_socket(client)  # cheap: nothing was read
                continue
            threading.Thread(target=self._handle_inbound, args=(client,),
                             name="localvault-sync-peer", daemon=True).start()
        with self._socket_lock:
            if listener is not None and self._listener is listener:
                self._listener = None

    def _deadline(self, timeout: float | None = None) -> float:
        return time.monotonic() + self._validate_timeout(timeout, self.socket_timeout)

    def _recv_exact(self, sock: socket.socket, length: int, deadline: float) -> bytes:
        result = bytearray()
        while len(result) < length:
            self._cancel.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportTimeout("Transport read timed out")
            try:
                sock.settimeout(min(SOCKET_POLL_SECONDS, remaining))
                chunk = sock.recv(length - len(result))
            except TimeoutError:
                continue
            except OSError as exc:
                if self._cancel.cancelled:
                    raise TransportCancelled("Sync operation was cancelled") from exc
                raise TransportError("Transport read failed") from exc
            if not chunk:
                raise FrameError("Peer closed the transport before the frame completed")
            result.extend(chunk)
        return bytes(result)

    def _read_socket_frame(self, sock: socket.socket, deadline: float,
                           limit: int = MAX_FRAME_PAYLOAD) -> bytes:
        header = self._recv_exact(sock, FRAME_HEADER.size, deadline)
        (length,) = FRAME_HEADER.unpack(header)
        if not 1 <= length <= min(limit, MAX_FRAME_PAYLOAD):
            raise FrameTooLarge("Frame length is outside the bound")
        return header + self._recv_exact(sock, length, deadline)

    def _send_all(self, sock: socket.socket, data: bytes, deadline: float) -> None:
        if not isinstance(data, bytes) or len(data) > MAX_FRAME_BYTES:
            raise FrameTooLarge("Transport frame exceeds the bound")
        offset = 0
        while offset < len(data):
            self._cancel.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportTimeout("Transport write timed out")
            try:
                sock.settimeout(min(SOCKET_POLL_SECONDS, remaining))
                sent = sock.send(data[offset:])
            except TimeoutError:
                continue
            except OSError as exc:
                if self._cancel.cancelled:
                    raise TransportCancelled("Sync operation was cancelled") from exc
                raise TransportError("Transport write failed") from exc
            if sent <= 0:
                raise TransportError("Transport write failed")
            offset += sent

    def _local_hello(self, session_id: bytes) -> SessionHello:
        if self.state is None:
            raise AuthenticationError("A protected paired-device state is required")
        return create_session_hello(self.state.identity, self.state.group_id, session_id,
                                    counter=self.state.next_counter())

    def _peer_for_hello(self, hello: SessionHello, expected_peer: str | None = None) -> PairedDevice:
        if self.state is None:
            raise AuthenticationError("A protected paired-device state is required")
        if expected_peer is not None and hello.device_id != expected_peer:
            raise AuthenticationError("Session peer is not the expected paired device")
        peer = self.state.require_trusted(hello.device_id)
        verify_session_hello(hello, self.state.group_id, peer)
        self.state.accept_inbound_counter(peer.device_id, hello.counter)
        return peer

    def _refuse_version(self, client: socket.socket, exc: HelloVersionError, deadline: float) -> None:
        """Answer a hello of another version with the plain version refusal; never derive a key.

        A version-1 hello whose signature verifies under a pinned peer's key marks
        that peer in ``outdated_peers`` (the sync status asks the user to update it).
        """
        if exc.version == 1 and self.state is not None:
            device_id = exc.raw.get("device_id")
            peer = self.state.trusted_peers.get(device_id) if isinstance(device_id, str) else None
            if peer is not None and not peer.revoked:
                try:
                    verify_legacy_hello(exc.raw, self.state.group_id, peer)
                except TransportError:
                    pass
                else:
                    with self._socket_lock:
                        self.outdated_peers[peer.device_id] = time.monotonic()
        self._send_all(client, encode_frame(version_refusal()), deadline)

    def take_outdated_peers(self) -> list[str]:
        """The paired device ids refused for an older protocol version since the last call (sorted)."""
        with self._socket_lock:
            taken = sorted(self.outdated_peers)
            self.outdated_peers.clear()
        return taken

    def _handle_inbound(self, client: socket.socket) -> None:
        deadline = self._deadline()
        try:
            first_deadline = min(deadline, time.monotonic() + FIRST_FRAME_SECONDS)
            first = self._read_socket_frame(client, first_deadline, MAX_FIRST_FRAME_BYTES)[FRAME_HEADER.size:]
            if first.startswith(ENROLL_REQUEST_MAGIC):
                # The only message accepted from an unpinned device, and only while an
                # enrollment handler (an active pairing offer) is installed.
                enroll = self._enrollment_handler
                if enroll is None or len(first) > MAX_ENROLL_BYTES:
                    return
                reply = enroll(first)  # may wait for the user's Accept (lan_sync.ACCEPT_TIMEOUT_SECONDS)
                if isinstance(reply, bytes) and 1 <= len(reply) <= MAX_ENROLL_BYTES:
                    self._send_all(client, encode_frame(reply), self._deadline())
                return
            try:
                remote_hello = SessionHello.from_bytes(first)
            except HelloVersionError as exc:
                self._refuse_version(client, exc, deadline)
                return
            peer = self._peer_for_hello(remote_hello)
            self._inbound_authenticated(client)
            local_hello = self._local_hello(remote_hello.session_id)
            try:
                self._send_all(client, encode_frame(local_hello.to_bytes()), deadline)
                channel = establish_channel(
                    self.state.identity, peer, group_id=self.state.group_id,
                    session_id=remote_hello.session_id, role="responder",
                    local_hello=local_hello, remote_hello=remote_hello, state=self.state,
                )
            finally:
                local_hello.ephemeral_secret.wipe()
            request = channel.open(self._read_socket_frame(client, deadline))
            self._cancel.check()
            peer_handler = self._peer_request_handler
            handler = self._request_handler
            if peer_handler is not None:
                response = peer_handler(peer, request)
            elif handler is not None:
                response = handler(request)
            else:
                raise TransportError("No transport request handler is configured")
            if not isinstance(response, bytes):
                raise FrameError("Transport request handler must return bytes")
            self._send_all(client, channel.seal(response), deadline)
        except (TransportCancelled, TransportError, SyncDisabled, OSError):
            pass
        except Exception:  # noqa: BLE001 - isolate malformed peer/handler failures
            # A malformed or unauthorised peer gets no unauthenticated error
            # response.  The connection is closed after the bounded attempt.
            return
        finally:
            self._release_inbound(client)
            self._close_socket(client)

    def request(self, endpoint: LANEndpoint, payload: bytes, *,
                peer_id: str | None = None, timeout: float | None = None) -> bytes:
        """Connect to one pinned peer, exchange one request, and close.

        ``start()`` must have been called first.  The target is validated
        against the same private literal endpoint and allowlist rules as the
        listener.  The remote signed hello supplies the pinned device identity
        before any request payload is sent.
        """

        self.require_running()
        self._check_endpoint(endpoint)
        self._cancel.check()
        if self.state is None:
            raise AuthenticationError("A protected paired-device state is required")
        deadline = self._deadline(timeout)
        sock = socket.socket(self._socket_family(endpoint), socket.SOCK_STREAM)
        if not self._reserve_socket(sock):
            self._close_socket(sock)
            raise TransportError("Sync transport already has an active connection")
        local_hello: SessionHello | None = None
        try:
            connected = False
            try:
                self._connect(sock, endpoint, deadline)
                connected = True
                session_id = secrets.token_bytes(SESSION_ID_BYTES)
                local_hello = self._local_hello(session_id)
                self._send_all(sock, encode_frame(local_hello.to_bytes()), deadline)
                hello_frame = self._read_socket_frame(sock, deadline)
            except (TransportCancelled, AuthenticationError, SyncDisabled):
                raise
            except (TransportError, OSError) as exc:
                # Nothing of the request was sent: the peer dropped or never took the connection.
                raise PeerNotAnswering(f"Peer did not answer: {exc}", connected=connected) from exc
            refused = parse_version_refusal(hello_frame[FRAME_HEADER.size:])
            if refused is not None:
                raise PeerVersionMismatch(refused)
            try:
                remote_hello = SessionHello.from_bytes(hello_frame[FRAME_HEADER.size:])
            except HelloVersionError as exc:
                raise PeerVersionMismatch(exc.version) from exc
            peer = self._peer_for_hello(remote_hello, peer_id)
            if remote_hello.session_id != session_id:
                raise AuthenticationError("Session hello is bound to another session")
            channel = establish_channel(
                self.state.identity, peer, group_id=self.state.group_id,
                session_id=session_id, role="initiator",
                local_hello=local_hello, remote_hello=remote_hello, state=self.state,
            )
            if not isinstance(payload, bytes):
                raise FrameError("Transport request must be bytes")
            self._send_all(sock, channel.seal(payload), deadline)
            return channel.open(self._read_socket_frame(sock, deadline))
        finally:
            if local_hello is not None and local_hello.ephemeral_secret is not None:
                local_hello.ephemeral_secret.wipe()
            self._release_socket(sock)
            self._close_socket(sock)

    connect = request
    request_response = request

    def stop(self) -> None:
        self._cancel.cancel()
        self.running = False
        with self._socket_lock:
            listener = self._listener
            listener_thread = self._listener_thread
            self._listener = None
        for sock in self._take_all_sockets():
            self._close_socket(sock)
        self._close_socket(listener)
        if listener_thread is not None and listener_thread is not threading.current_thread():
            listener_thread.join(timeout=1.0)
        self.endpoint = None

    def disable(self) -> None:
        self.stop()
        if self.state is not None:
            self.state.disable()

    def require_running(self) -> None:
        if not self.running:
            raise SyncDisabled("Sync transport is not explicitly started")

    def authorize_peer(self, device_id: str) -> PairedDevice | None:
        self.require_running()
        if self.state is None:
            raise AuthenticationError("A protected paired-device state is required")
        return self.state.require_trusted(device_id)

    def cancel(self) -> None:
        self._cancel.cancel()
        self.running = False
        self.endpoint = None
        with self._socket_lock:
            listener = self._listener
            listener_thread = self._listener_thread
            self._listener = None
        for sock in self._take_all_sockets():
            self._close_socket(sock)
        self._close_socket(listener)
        if listener_thread is not None and listener_thread is not threading.current_thread():
            listener_thread.join(timeout=1.0)

    def cancellation(self) -> CancellationToken:
        return self._cancel


# Friendly spelling aliases for callers and tests.
LANTransport = SyncTransport
LanTransport = SyncTransport


__all__ = [
    "MAX_FRAME_BYTES", "MAX_FRAME_PAYLOAD", "MAX_MESSAGE_BYTES",
    "AuthenticationError", "CancellationToken", "EphemeralSecret", "FrameError", "FrameTooLarge",
    "HelloVersionError", "LANEndpoint", "LANTransport", "LanTransport", "PeerNotAnswering", "PeerVersionMismatch",
    "ReplayError", "RetryBackoff", "SecureChannel", "SessionHello", "SyncTransport", "TRANSPORT_VERSION",
    "TransportCancelled", "TransportError", "TransportTimeout", "create_session_hello", "decode_frame",
    "encode_frame", "establish_channel", "parse_version_refusal", "verify_legacy_hello", "verify_session_hello",
    "version_refusal",
]
