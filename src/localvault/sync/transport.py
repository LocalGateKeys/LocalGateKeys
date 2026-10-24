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
once, at most ``MAX_INBOUND_PER_ADDRESS`` from one source address, and drops a
connection whose first frame (session hello or enrollment request, at most
``MAX_FIRST_FRAME_BYTES``) has not arrived within ``FIRST_FRAME_SECONDS``.  One
idle unauthenticated LAN connection therefore holds a slot for about two
seconds and can no longer block sync or pairing.

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
import hashlib
import ipaddress
import json
import secrets
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .lan_address import is_lan_address
from .pairing import ENROLL_REQUEST_MAGIC, MAX_ENROLL_BYTES, DeviceIdentity, PairedDevice
from .state import SyncDisabled, SyncState

TRANSPORT_VERSION = 1
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
    error is the ``__cause__``.
    """


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
#: Deadline for the first frame of an inbound connection (a hello or enrollment request
#: is sent right after connecting; the iPhone app does the same).
FIRST_FRAME_SECONDS = 2.0
#: Largest first frame accepted: an enrollment request (``MAX_ENROLL_BYTES``) or a
#: session hello (well under 1 KiB).
MAX_FIRST_FRAME_BYTES = 64 * 1024
#: Listen backlog (connections the OS queues before ``accept``).
LISTEN_BACKLOG = 8


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
_HELLO_FIELDS = frozenset({"counter", "device_id", "exchange_public", "group_id", "nonce", "session_id",
                           "signature", "signing_public", "version"})
_FRAME_FIELDS = frozenset({"ciphertext", "counter", "nonce", "session_id", "version"})


def _is_version(value: Any) -> bool:
    """True only for the JSON integer TRANSPORT_VERSION (not ``true`` or ``1.0``)."""
    return type(value) is int and value == TRANSPORT_VERSION


@dataclass(frozen=True)
class SessionHello:
    session_id: bytes
    group_id: str
    device_id: str
    signing_public: bytes
    exchange_public: bytes
    nonce: bytes
    counter: int
    signature: bytes
    version: int = TRANSPORT_VERSION

    def unsigned_dict(self) -> dict[str, Any]:
        return {"version": self.version, "session_id": _b64e(self.session_id),
                "group_id": self.group_id, "device_id": self.device_id,
                "signing_public": _b64e(self.signing_public),
                "exchange_public": _b64e(self.exchange_public),
                "nonce": _b64e(self.nonce), "counter": self.counter}

    def signing_bytes(self) -> bytes:
        return b"localgatekeys|sync|session-hello|v1|" + _canonical(self.unsigned_dict())

    def to_bytes(self) -> bytes:
        result = dict(self.unsigned_dict())
        result["signature"] = _b64e(self.signature)
        return _canonical(result)

    @classmethod
    def from_bytes(cls, value: bytes) -> SessionHello:
        if not isinstance(value, bytes) or len(value) > MAX_MESSAGE_BYTES:
            raise FrameTooLarge("Session hello exceeds the bound")
        try:
            raw = _strict_json(value)
        except (ValueError, TypeError):
            raise FrameError("Session hello is malformed") from None
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
            nonce=_b64d(raw.get("nonce"), 32, "session nonce"), counter=counter,
            signature=_b64d(raw.get("signature"), 64, "session signature"),
        )


def create_session_hello(identity: DeviceIdentity, group_id: str, session_id: bytes,
                         *, counter: int = 1, _nonce: bytes | None = None) -> SessionHello:
    if not isinstance(identity, DeviceIdentity) or not isinstance(group_id, str) or not group_id:
        raise AuthenticationError("Session identity or group is malformed")
    if not isinstance(session_id, bytes) or len(session_id) != SESSION_ID_BYTES:
        raise AuthenticationError("Session ID is malformed")
    if type(counter) is not int or not 0 <= counter <= 2**63 - 1:
        raise AuthenticationError("Session counter is malformed")
    hello = SessionHello(session_id, group_id, identity.device_id, identity.signing_public_key,
                         identity.exchange_public_key, _nonce or secrets.token_bytes(32), counter, b"")
    return SessionHello(hello.session_id, hello.group_id, hello.device_id,
                        hello.signing_public, hello.exchange_public, hello.nonce,
                        hello.counter, identity.sign(hello.signing_bytes()))


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
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(hello.signing_public).verify(
            hello.signature, hello.signing_bytes())
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise AuthenticationError("Session hello signature is invalid") from exc


def _derive_key(local: DeviceIdentity, remote: PairedDevice, session_id: bytes,
                transcript: bytes) -> bytes:
    if len(session_id) != SESSION_ID_BYTES or len(transcript) > MAX_MESSAGE_BYTES:
        raise AuthenticationError("Session transcript is malformed")
    try:
        shared = local.exchange_key.exchange(
            x25519.X25519PublicKey.from_public_bytes(remote.exchange_public))
    except (ValueError, TypeError) as exc:
        raise AuthenticationError("Peer exchange key is malformed") from exc
    salt = hashlib.sha256(b"localgatekeys|sync|session-salt|" + transcript).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"localgatekeys|sync|session-key|" + session_id).derive(shared)


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
        return cls(_derive_key(local, remote, session_id, transcript),
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
            sock.settimeout(min(SOCKET_POLL_SECONDS, max(0.001, deadline - time.monotonic())))
            try:
                sock.connect(self._socket_address(endpoint))
            except TimeoutError as exc:
                raise TransportTimeout("Transport connect timed out") from exc
            except OSError as exc:
                raise TransportError("Transport connect failed") from exc
            self._send_all(sock, encode_frame(payload), deadline)
            reply = self._read_socket_frame(sock, deadline)[FRAME_HEADER.size:]
            if len(reply) > MAX_ENROLL_BYTES:
                raise FrameTooLarge("Enrollment reply exceeds the bound")
            return reply
        finally:
            self._release_socket(sock)
            self._close_socket(sock)

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

    def _reserve_inbound(self, sock: socket.socket, address: str) -> bool:
        """Take an inbound slot for *sock* from *address*; False when the total or per-address cap is reached."""
        with self._socket_lock:
            if len(self._inbound) >= MAX_INBOUND_CONNECTIONS:
                return False
            if sum(1 for a in self._inbound.values() if a == address) >= MAX_INBOUND_PER_ADDRESS:
                return False
            self._inbound[sock] = address
            return True

    def _release_inbound(self, sock: socket.socket) -> None:
        with self._socket_lock:
            self._inbound.pop(sock, None)

    def _take_all_sockets(self) -> list[socket.socket]:
        """Detach the outbound and every inbound socket (stop/cancel closes them)."""
        with self._socket_lock:
            taken = [s for s in (self._active_socket, *self._inbound) if s is not None]
            self._active_socket = None
            self._inbound.clear()
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
                reply = enroll(first)
                if isinstance(reply, bytes) and 1 <= len(reply) <= MAX_ENROLL_BYTES:
                    self._send_all(client, encode_frame(reply), deadline)
                return
            remote_hello = SessionHello.from_bytes(first)
            peer = self._peer_for_hello(remote_hello)
            local_hello = self._local_hello(remote_hello.session_id)
            self._send_all(client, encode_frame(local_hello.to_bytes()), deadline)
            channel = establish_channel(
                self.state.identity, peer, group_id=self.state.group_id,
                session_id=remote_hello.session_id, role="responder",
                local_hello=local_hello, remote_hello=remote_hello, state=self.state,
            )
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
        try:
            try:
                sock.settimeout(min(SOCKET_POLL_SECONDS, max(0.001, deadline - time.monotonic())))
                try:
                    sock.connect(self._socket_address(endpoint))
                except TimeoutError as exc:
                    if self._cancel.cancelled:
                        raise TransportCancelled("Sync operation was cancelled") from exc
                    raise TransportTimeout("Transport connect timed out") from exc
                except OSError as exc:
                    if self._cancel.cancelled:
                        raise TransportCancelled("Sync operation was cancelled") from exc
                    raise TransportError("Transport connect failed") from exc
                session_id = secrets.token_bytes(SESSION_ID_BYTES)
                local_hello = self._local_hello(session_id)
                self._send_all(sock, encode_frame(local_hello.to_bytes()), deadline)
                hello_frame = self._read_socket_frame(sock, deadline)
            except (TransportCancelled, AuthenticationError, SyncDisabled):
                raise
            except (TransportError, OSError) as exc:
                # Nothing of the request was sent: the peer dropped or never took the connection.
                raise PeerNotAnswering(f"Peer did not answer: {exc}") from exc
            remote_hello = SessionHello.from_bytes(hello_frame[FRAME_HEADER.size:])
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
    "AuthenticationError", "CancellationToken", "FrameError", "FrameTooLarge",
    "LANEndpoint", "LANTransport", "LanTransport", "PeerNotAnswering", "ReplayError", "RetryBackoff",
    "SecureChannel", "SessionHello", "SyncTransport", "TransportCancelled",
    "TransportError", "TransportTimeout", "create_session_hello", "decode_frame",
    "encode_frame", "establish_channel", "verify_session_hello",
]
