"""Explicit, local-only device pairing for the M8 sync protocol.

This module deliberately does not open a listener or perform discovery.  An
application supplies a manually selected LAN endpoint to :func:`create_offer`
and carries the resulting bundle through a trusted out-of-band channel.  The
offer contains both a short human code and a high-entropy one-use secret; a
code by itself can never enroll a peer.

Format rules (version 1; the iOS app implements these byte for byte)
--------------------------------------------------------------------
* Canonical JSON here is ``json.dumps(value, ensure_ascii=True, sort_keys=True,
  separators=(",", ":"))`` encoded as UTF-8, at most 64 KiB.  This differs from the sealed-view
  and keyring canonical JSON (``ensure_ascii=False``; see ``keyring.py``).  Every number in this
  protocol is an integer (``expires_at`` is a Unix time in whole seconds, never a float).
  Base64 is the standard alphabet WITH padding unless stated; "raw" means the decoded bytes.
  Identifiers (``offer_id``, ``group_id``, device ids) are ASCII ``[A-Za-z0-9._:-]``, 1..128.
* Offer bundle (``PairingOffer.bundle_dict``): ``{"version":1,"offer_id","group_id",
  "endpoint":{"host","port"},"inviter_device_id","inviter_signing_public","inviter_exchange_public",
  "certificate_fingerprint","expires_at","transcript_nonce","pairing_secret","code"}``.  Keys are
  base64 of 32 raw bytes; ``certificate_fingerprint`` is the lowercase hex SHA-256 of the raw
  inviter signing public key; ``transcript_nonce`` and ``pairing_secret`` are base64 of 32 random
  bytes; ``code`` is 8 ASCII digits; ``endpoint.host`` is a literal private/loopback/link-local IP;
  ``expires_at`` is an int in 1..2**53-1.  ``public_dict`` is the bundle without ``pairing_secret``
  and ``code``.
* QR text: ``"lgk-pair:"`` + base64url (alphabet ``A-Za-z0-9-_``, NO padding) of the canonical
  bundle JSON, at most 1200 characters.  A reader rejects other prefixes, padding, other
  characters, non-canonical base64 and JSON that is not byte-identical to its own canonical form.
* Enrollment transcript = canonical JSON of ``{"protocol":"localgatekeys-sync-enrollment",
  "version":2,"offer":public_dict,"code":code,"invitee_device_id","invitee_signing_public"
  (base64),"invitee_exchange_public" (base64),"invitee_endpoint":null|{"host","port"},
  "invitee_name"}`` (``ENROLL_VERSION``; version 1 had no ``invitee_name``).  ``invitee_name`` is
  the new device's name for the inviter's Accept prompt: 1..64 UTF-8 bytes, no control
  character (U+0000..U+001F, U+007F).
* Verification code (``verification_code``): the first 4 bytes of SHA-256(
  ``b"localgatekeys|sync|enroll-verify|v2|"`` + transcript) as a big-endian unsigned integer,
  modulo 10**6, as 6 ASCII digits.  The new device shows it while it waits; the inviter shows it
  next to the device name with Accept and Decline, and answers only after Accept.
* Request (new device -> inviter): ``b"LGKENROLL1\\n"`` + canonical JSON ``{"offer_id","eph",
  "nonce","ct"}`` with ``eph`` the base64 of a fresh X25519 public key (32 raw), ``nonce`` 12 random
  bytes.  Key = ``HKDF(SHA256, 32, salt=transcript_nonce (raw 32),
  info=b"localgatekeys|sync|enroll-request|v1|" + offer_id).derive(X25519(eph_private,
  inviter_exchange_public))``.  ``ct`` = AES-256-GCM(key, nonce, plaintext, AAD) (ciphertext
  followed by the 16-byte tag, base64), AAD = canonical JSON ``{"offer_id","eph"}``.  The
  plaintext is canonical JSON of ``{"version":2,"offer_id","device_id","signing_public",
  "exchange_public","endpoint":null|{"host","port"},"name","signature","mac"}`` with ``signature`` =
  Ed25519(invitee signing key) over ``b"localgatekeys|sync|enroll-sig|v1|" + transcript`` (base64
  of 64 bytes) and ``mac`` = HMAC-SHA256(pairing_secret raw,
  ``b"localgatekeys|sync|enroll-mac|v1|" + transcript``) (base64 of 32 bytes).  The endpoint
  shape is exactly ``{"host":str,"port":int}`` and is the same object as in the transcript.
* Reply (inviter -> new device): ``b"LGKENROLLOK1\\n"`` + canonical JSON ``{"eph","nonce","ct",
  "sig"}``.  ``bound`` = SHA-256 of the transcript (raw 32).  Key = ``HKDF(SHA256, 32, salt=bound,
  info=b"localgatekeys|sync|enroll-reply|v1|" + offer_id).derive(X25519(eph_private,
  invitee_exchange_public))``.  ``header`` = ``{"eph","nonce"}`` (base64 strings).  ``ct`` =
  AES-256-GCM(key, nonce, plaintext, AAD = canonical(header) + bound).  The plaintext is canonical
  JSON of ``{"group_id","epoch","key","device_id","signing_public"}`` (``key`` base64 of the 32-byte
  group key; ``device_id`` and ``signing_public`` repeat the invitee's, which it must check).
  ``sig`` = Ed25519(inviter signing key) over ``b"localgatekeys|sync|enroll-reply-sig|v1|" + bound
  + canonical(header) + ct`` (``ct`` as raw bytes), checked against the signing key pinned by the QR.
* Refusal: ``b"LGKENROLLNO1\\n"`` + canonical JSON ``{"reason"}`` with a reason from
  ``REFUSAL_REASONS``: ``declined`` (the user chose Decline, or did not answer within the
  Accept timeout), ``update-needed`` (a version-1 request: the new device needs an update).
  Requests and replies are at most 16 KiB.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import secrets
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .engine import is_valid_id
from .lan_address import is_lan_address

PAIRING_PROTOCOL_VERSION = 1
PAIRING_TTL_SECONDS = 120
PAIRING_MAX_ATTEMPTS = 5
PAIRING_SECRET_BYTES = 32
PAIRING_CODE_DIGITS = 8
MAX_DEVICE_ID_LENGTH = 128
MAX_GROUP_ID_LENGTH = 128
MAX_TRANSCRIPT_BYTES = 64 * 1024
_MAX_INT = 2**53 - 1
QR_PREFIX = "lgk-pair:"
# Upper bound on the scanned text.  A real offer is about 863 characters with an IPv4
# endpoint and about 896 with a long IPv6 one (QR version 24-25 at error correction M).
MAX_QR_PAYLOAD = 1200


class PairingError(ValueError):
    """Base error for malformed or rejected enrollment data."""


class PairingExpired(PairingError):
    pass


class PairingCodeError(PairingError):
    pass


class PairingAuthenticationError(PairingError):
    pass


class PairingReplayError(PairingError):
    pass


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: Any, *, length: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise PairingError(f"{field} is malformed")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - stable parser error
        raise PairingError(f"{field} is malformed") from exc
    if len(decoded) != length:
        raise PairingError(f"{field} has an invalid length")
    return decoded


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise PairingError("Pairing transcript is not serializable") from exc
    data = encoded.encode("utf-8")
    if len(data) > MAX_TRANSCRIPT_BYTES:
        raise PairingError("Pairing transcript is too large")
    return data


def _text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        raise PairingError(f"{field} is malformed")
    return value


def _ident(value: Any, field: str) -> str:
    """A device or group id: the sync format's ASCII identifier rule (``engine.is_valid_id``)."""
    if not is_valid_id(value):
        raise PairingError(f"{field} is malformed")
    return value


def _now(value: float | int | None) -> float:
    result = time.time() if value is None else float(value)
    if result < 0 or result > 2**63 - 1:
        raise PairingError("Pairing clock value is malformed")
    return result


def _private_lan_endpoint(host: Any, port: Any) -> tuple[str, int]:
    if not isinstance(host, str) or len(host) > 255:
        raise PairingError("Pairing endpoint host is malformed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise PairingError("Pairing endpoint must be a literal LAN address") from None
    # Only the explicit ranges in lan_address are accepted (no ipaddress flags).
    if not is_lan_address(address):
        raise PairingError("Pairing endpoint must be a private LAN address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise PairingError("Pairing endpoint port is malformed")
    return str(address), port


def _public_bytes(key: Any) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw)


@dataclass
class DeviceIdentity:
    """Long-lived device keys.

    Private material is intentionally only represented by this in-memory
    object and by :meth:`protected_dict`, which is meant to be encrypted by
    :class:`localvault.sync.state.SyncState` before persistence.
    """

    device_id: str
    signing_key: ed25519.Ed25519PrivateKey = field(repr=False)
    exchange_key: x25519.X25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls, device_id: str | None = None) -> DeviceIdentity:
        device_id = str(uuid.uuid4()) if device_id is None else _ident(device_id, "device id")
        return cls(device_id, ed25519.Ed25519PrivateKey.generate(),
                   x25519.X25519PrivateKey.generate())

    @property
    def signing_public_key(self) -> bytes:
        return _public_bytes(self.signing_key.public_key())

    @property
    def exchange_public_key(self) -> bytes:
        return _public_bytes(self.exchange_key.public_key())

    @property
    def fingerprint(self) -> str:
        """Stable exact fingerprint pinned by the out-of-band offer review."""

        return hashlib.sha256(self.signing_public_key).hexdigest()

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, bytes) or len(message) > MAX_TRANSCRIPT_BYTES:
            raise PairingError("Signed transcript is malformed")
        return self.signing_key.sign(message)

    def protected_dict(self) -> dict[str, str]:
        """Return private material for immediate encryption by a vault owner."""

        return {
            "device_id": _ident(self.device_id, "device id"),
            "signing_private": _b64e(self.signing_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())),
            "exchange_private": _b64e(self.exchange_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())),
        }

    @classmethod
    def from_protected_dict(cls, value: Mapping[str, Any]) -> DeviceIdentity:
        if not isinstance(value, Mapping):
            raise PairingError("Protected device identity is malformed")
        device_id = _ident(value.get("device_id"), "device id")
        signing_raw = _b64d(value.get("signing_private"), length=32,
                             field="signing private key")
        exchange_raw = _b64d(value.get("exchange_private"), length=32,
                             field="exchange private key")
        try:
            signing = ed25519.Ed25519PrivateKey.from_private_bytes(signing_raw)
            exchange = x25519.X25519PrivateKey.from_private_bytes(exchange_raw)
        except (ValueError, TypeError) as exc:
            raise PairingError("Protected device identity is malformed") from exc
        return cls(device_id, signing, exchange)


@dataclass(frozen=True)
class PairingOffer:
    """Short-lived out-of-band enrollment bundle.

    ``pairing_secret`` and ``code`` are marked non-repr fields so accidental
    diagnostics cannot print either enrollment credential.
    """

    offer_id: str
    group_id: str
    endpoint_host: str
    endpoint_port: int
    inviter_device_id: str
    inviter_signing_public: bytes
    inviter_exchange_public: bytes
    certificate_fingerprint: str
    expires_at: int
    transcript_nonce: bytes
    pairing_secret: bytes = field(repr=False)
    code: str = field(repr=False)
    version: int = PAIRING_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        _ident(self.offer_id, "offer id")
        _ident(self.group_id, "group id")
        _ident(self.inviter_device_id, "inviter device id")
        _private_lan_endpoint(self.endpoint_host, self.endpoint_port)
        if len(self.inviter_signing_public) != 32 or len(self.inviter_exchange_public) != 32:
            raise PairingError("Pairing public key is malformed")
        if len(self.transcript_nonce) != 32 or len(self.pairing_secret) != PAIRING_SECRET_BYTES:
            raise PairingError("Pairing enrollment secret is malformed")
        if (not isinstance(self.certificate_fingerprint, str)
                or len(self.certificate_fingerprint) != 64
                or any(char not in "0123456789abcdef" for char in self.certificate_fingerprint)):
            raise PairingError("Pairing certificate fingerprint is malformed")
        if type(self.expires_at) is not int or not 0 < self.expires_at <= _MAX_INT:
            raise PairingError("Pairing expiration is malformed")
        if (not isinstance(self.code, str) or len(self.code) != PAIRING_CODE_DIGITS
                or not self.code.isascii() or not self.code.isdigit()):
            raise PairingError("Pairing code is malformed")

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.endpoint_host, self.endpoint_port

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def public_dict(self) -> dict[str, Any]:
        """The reviewable bundle excluding the two enrollment credentials."""

        return {
            "version": self.version,
            "offer_id": self.offer_id,
            "group_id": self.group_id,
            "endpoint": {"host": self.endpoint_host, "port": self.endpoint_port},
            "inviter_device_id": self.inviter_device_id,
            "inviter_signing_public": _b64e(self.inviter_signing_public),
            "inviter_exchange_public": _b64e(self.inviter_exchange_public),
            "certificate_fingerprint": self.certificate_fingerprint,
            "expires_at": self.expires_at,
            "transcript_nonce": _b64e(self.transcript_nonce),
        }

    def bundle_dict(self) -> dict[str, Any]:
        result = self.public_dict()
        result.update({"pairing_secret": _b64e(self.pairing_secret), "code": self.code})
        return result

    def transcript(self, invitee_device_id: str, invitee_signing_public: bytes,
                   invitee_exchange_public: bytes) -> bytes:
        return _canonical({
            "protocol": "localgatekeys-sync-pairing",
            "version": self.version,
            "offer": self.public_dict(),
            "invitee_device_id": _ident(invitee_device_id, "invitee device id"),
            "invitee_signing_public": _b64e(invitee_signing_public),
            "invitee_exchange_public": _b64e(invitee_exchange_public),
        })

    @classmethod
    def from_bundle_dict(cls, value: Mapping[str, Any]) -> PairingOffer:
        if not isinstance(value, Mapping):
            raise PairingError("Pairing offer is malformed")
        endpoint = value.get("endpoint")
        if not isinstance(endpoint, Mapping):
            raise PairingError("Pairing endpoint is malformed")
        host, port = _private_lan_endpoint(endpoint.get("host"), endpoint.get("port"))
        return cls(
            offer_id=_ident(value.get("offer_id"), "offer id"),
            group_id=_ident(value.get("group_id"), "group id"),
            endpoint_host=host,
            endpoint_port=port,
            inviter_device_id=_ident(value.get("inviter_device_id"), "inviter device id"),
            inviter_signing_public=_b64d(value.get("inviter_signing_public"), length=32,
                                          field="inviter signing key"),
            inviter_exchange_public=_b64d(value.get("inviter_exchange_public"), length=32,
                                          field="inviter exchange key"),
            certificate_fingerprint=_text(value.get("certificate_fingerprint"),
                                          "certificate fingerprint", 64),
            expires_at=value.get("expires_at"),  # strict int, checked by __post_init__ (no conversion)
            transcript_nonce=_b64d(value.get("transcript_nonce"), length=32,
                                    field="transcript nonce"),
            pairing_secret=_b64d(value.get("pairing_secret"), length=PAIRING_SECRET_BYTES,
                                  field="pairing secret"),
            code=_text(value.get("code"), "pairing code", PAIRING_CODE_DIGITS),
            version=value.get("version", PAIRING_PROTOCOL_VERSION),
        )


@dataclass(frozen=True)
class PairingConfirmation:
    offer_id: str
    group_id: str
    device_id: str
    signing_public: bytes
    exchange_public: bytes
    inviter_fingerprint: str
    confirmed_at: float
    explicit: bool
    signature: bytes = field(repr=False)
    version: int = PAIRING_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "offer_id": self.offer_id,
            "group_id": self.group_id,
            "device_id": self.device_id,
            "signing_public": _b64e(self.signing_public),
            "exchange_public": _b64e(self.exchange_public),
            "inviter_fingerprint": self.inviter_fingerprint,
            "confirmed_at": self.confirmed_at,
            "explicit": self.explicit,
            "signature": _b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PairingConfirmation:
        if not isinstance(value, Mapping):
            raise PairingError("Pairing confirmation is malformed")
        signature = _b64d(value.get("signature"), length=64, field="pairing signature")
        return cls(
            offer_id=_text(value.get("offer_id"), "offer id", MAX_DEVICE_ID_LENGTH),
            group_id=_ident(value.get("group_id"), "group id"),
            device_id=_ident(value.get("device_id"), "device id"),
            signing_public=_b64d(value.get("signing_public"), length=32,
                                 field="signing public key"),
            exchange_public=_b64d(value.get("exchange_public"), length=32,
                                  field="exchange public key"),
            inviter_fingerprint=_text(value.get("inviter_fingerprint"),
                                      "inviter fingerprint", 64),
            confirmed_at=_now(value.get("confirmed_at")),
            explicit=value.get("explicit") is True,
            signature=signature,
            version=value.get("version", PAIRING_PROTOCOL_VERSION),
        )


@dataclass(frozen=True)
class PairedDevice:
    """Public trust record produced only after both confirmations succeed."""

    device_id: str
    group_id: str
    signing_public: bytes
    exchange_public: bytes
    fingerprint: str
    enrolled_at: float
    enrollment_signature: bytes = field(repr=False)
    revoked: bool = False
    version: int = PAIRING_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "device_id": self.device_id,
            "group_id": self.group_id,
            "signing_public": _b64e(self.signing_public),
            "exchange_public": _b64e(self.exchange_public),
            "fingerprint": self.fingerprint,
            "enrolled_at": self.enrolled_at,
            "enrollment_signature": _b64e(self.enrollment_signature),
            "revoked": self.revoked,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PairedDevice:
        """Rebuild a stored trust record; the fingerprint must match the signing key."""
        if not isinstance(value, Mapping) or value.get("version", PAIRING_PROTOCOL_VERSION) != PAIRING_PROTOCOL_VERSION:
            raise PairingError("Paired device record is malformed")
        signing = _b64d(value.get("signing_public"), length=32, field="signing public key")
        fingerprint = _text(value.get("fingerprint"), "fingerprint", 64)
        if not hmac.compare_digest(fingerprint, hashlib.sha256(signing).hexdigest()):
            raise PairingError("Paired device fingerprint does not match its key")
        if type(value.get("revoked", False)) is not bool:
            raise PairingError("Paired device record is malformed")
        return cls(
            device_id=_ident(value.get("device_id"), "device id"),
            group_id=_ident(value.get("group_id"), "group id"),
            signing_public=signing,
            exchange_public=_b64d(value.get("exchange_public"), length=32, field="exchange public key"),
            fingerprint=fingerprint,
            enrolled_at=_now(value.get("enrolled_at")),
            enrollment_signature=_b64d(value.get("enrollment_signature"), length=64,
                                       field="enrollment signature"),
            revoked=value.get("revoked", False),
        )


def create_pairing_offer(identity: DeviceIdentity, group_id: str, endpoint_host: str,
                         endpoint_port: int, *, now: float | int | None = None,
                         ttl_seconds: int = PAIRING_TTL_SECONDS) -> PairingOffer:
    """Create a manually reviewed, short-lived enrollment bundle."""

    if not isinstance(identity, DeviceIdentity):
        raise PairingError("A device identity is required")
    group_id = _ident(group_id, "group id")
    _ident(identity.device_id, "device id")
    host, port = _private_lan_endpoint(endpoint_host, endpoint_port)
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= PAIRING_TTL_SECONDS:
        raise PairingError("Pairing lifetime is outside the accepted bound")
    created = _now(now)
    return PairingOffer(
        offer_id=str(uuid.uuid4()), group_id=group_id, endpoint_host=host,
        endpoint_port=port, inviter_device_id=identity.device_id,
        inviter_signing_public=identity.signing_public_key,
        inviter_exchange_public=identity.exchange_public_key,
        certificate_fingerprint=identity.fingerprint,
        expires_at=math.ceil(created) + ttl_seconds, transcript_nonce=secrets.token_bytes(32),
        pairing_secret=secrets.token_bytes(PAIRING_SECRET_BYTES),
        code=f"{secrets.randbelow(10**PAIRING_CODE_DIGITS):0{PAIRING_CODE_DIGITS}d}",
    )


def _check_offer(offer: PairingOffer, now: float | int | None) -> None:
    if not isinstance(offer, PairingOffer):
        raise PairingError("Pairing offer is malformed")
    if _now(now) >= offer.expires_at:
        raise PairingExpired("Pairing offer has expired")
    expected = hashlib.sha256(offer.inviter_signing_public).hexdigest()
    if not hmac.compare_digest(expected, offer.certificate_fingerprint):
        raise PairingAuthenticationError("Pairing certificate fingerprint does not match the pinned key")


def confirm_pairing_offer(offer: PairingOffer, identity: DeviceIdentity, *, code: str,
                          pairing_secret: bytes, expected_fingerprint: str | None = None,
                          now: float | int | None = None,
                          explicit_confirmation: bool = True) -> PairingConfirmation:
    """Confirm the peer side of an offer and sign the enrollment transcript."""

    _check_offer(offer, now)
    if not isinstance(identity, DeviceIdentity) or identity.device_id == offer.inviter_device_id:
        raise PairingAuthenticationError("A distinct invitee device identity is required")
    if expected_fingerprint is not None and not hmac.compare_digest(
            expected_fingerprint, offer.certificate_fingerprint):
        raise PairingAuthenticationError("Pinned pairing fingerprint does not match")
    if not explicit_confirmation:
        raise PairingAuthenticationError("Explicit confirmation is required on both devices")
    if not isinstance(pairing_secret, bytes):
        raise PairingCodeError("Pairing secret is malformed")
    if not (hmac.compare_digest(str(code), offer.code)
            and hmac.compare_digest(pairing_secret, offer.pairing_secret)):
        raise PairingCodeError("Pairing code or secret is incorrect")
    transcript = offer.transcript(identity.device_id, identity.signing_public_key,
                                  identity.exchange_public_key)
    return PairingConfirmation(
        offer_id=offer.offer_id, group_id=offer.group_id, device_id=identity.device_id,
        signing_public=identity.signing_public_key, exchange_public=identity.exchange_public_key,
        inviter_fingerprint=offer.certificate_fingerprint, confirmed_at=_now(now), explicit=True,
        signature=identity.sign(transcript),
    )


def _final_transcript(offer: PairingOffer, confirmation: PairingConfirmation) -> bytes:
    return _canonical({
        "protocol": "localgatekeys-sync-pairing-complete",
        "offer": offer.public_dict(),
        "confirmation": confirmation.to_dict(),
    })


def complete_pairing(offer: PairingOffer, inviter: DeviceIdentity,
                     confirmation: PairingConfirmation, *, code: str,
                     pairing_secret: bytes, now: float | int | None = None,
                     explicit_inviter_confirmation: bool = True) -> PairedDevice:
    """Perform the inviter confirmation and return a pinned peer trust record."""

    _check_offer(offer, now)
    if not isinstance(inviter, DeviceIdentity):
        raise PairingAuthenticationError("Inviter identity is malformed")
    if inviter.device_id != offer.inviter_device_id:
        raise PairingAuthenticationError("Inviter identity does not match the offer")
    if inviter.fingerprint != offer.certificate_fingerprint:
        raise PairingAuthenticationError("Inviter key does not match the pinned offer")
    if not explicit_inviter_confirmation:
        raise PairingAuthenticationError("Explicit confirmation is required on both devices")
    if not (hmac.compare_digest(str(code), offer.code)
            and isinstance(pairing_secret, bytes)
            and hmac.compare_digest(pairing_secret, offer.pairing_secret)):
        raise PairingCodeError("Pairing code or secret is incorrect")
    if (confirmation.offer_id != offer.offer_id or confirmation.group_id != offer.group_id
            or confirmation.inviter_fingerprint != offer.certificate_fingerprint
            or not confirmation.explicit or confirmation.device_id == inviter.device_id):
        raise PairingAuthenticationError("Pairing confirmation is not bound to this offer")
    try:
        invitee_key = ed25519.Ed25519PublicKey.from_public_bytes(confirmation.signing_public)
        invitee_key.verify(confirmation.signature,
                           offer.transcript(confirmation.device_id, confirmation.signing_public,
                                            confirmation.exchange_public))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PairingAuthenticationError("Invitee confirmation signature is invalid") from exc
    final = _final_transcript(offer, confirmation)
    return PairedDevice(
        device_id=confirmation.device_id, group_id=offer.group_id,
        signing_public=confirmation.signing_public, exchange_public=confirmation.exchange_public,
        fingerprint=hashlib.sha256(confirmation.signing_public).hexdigest(),
        enrolled_at=_now(now), enrollment_signature=inviter.sign(final),
    )


class PairingSession:
    """Stateful one-use wrapper that rate-limits wrong code attempts."""

    def __init__(self, offer: PairingOffer, *, max_attempts: int = PAIRING_MAX_ATTEMPTS,
                 clock: Callable[[], float] | None = None) -> None:
        if not isinstance(offer, PairingOffer):
            raise PairingError("Pairing offer is malformed")
        if type(max_attempts) is not int or not 1 <= max_attempts <= PAIRING_MAX_ATTEMPTS:
            raise PairingError("Pairing attempt limit is malformed")
        self.offer = offer
        self.max_attempts = max_attempts
        self.attempts = 0
        self._consumed = False
        self._clock = clock or time.time

    @property
    def exhausted(self) -> bool:
        return self._consumed or self.attempts >= self.max_attempts

    def confirm(self, identity: DeviceIdentity, *, code: str, pairing_secret: bytes,
                expected_fingerprint: str | None = None,
                explicit_confirmation: bool = True,
                now: float | int | None = None) -> PairingConfirmation:
        if self.exhausted:
            raise PairingReplayError("Pairing offer was already consumed or exhausted")
        try:
            result = confirm_pairing_offer(
                self.offer, identity, code=code, pairing_secret=pairing_secret,
                expected_fingerprint=expected_fingerprint,
                now=self._clock() if now is None else now,
                explicit_confirmation=explicit_confirmation,
            )
        except (PairingCodeError, PairingAuthenticationError) as exc:
            self.attempts += 1
            if self.attempts >= self.max_attempts:
                self._consumed = True
            raise exc
        self._consumed = True
        return result

    def accept_enrollment(self, inviter: DeviceIdentity, raw: bytes, *,
                          now: float | int | None = None,
                          reserved_ids: frozenset[str] | set[str] = frozenset(),
                          ) -> tuple[PairedDevice, EnrollmentRequest]:
        """Verify one network enrollment request (see :func:`build_enrollment_request`).

        One success consumes the offer.  A request that does not even decrypt
        (size, magic, JSON shape, another offer, AES-GCM) is refused without
        counting, so a sender without the QR code cannot burn the offer.  Once it
        decrypts, any failure (malformed body, MAC, signature, a device id in
        *reserved_ids* or the inviter's own) counts as an attempt; after
        ``max_attempts`` failures the offer is dead.  An expired offer raises
        ``PairingExpired`` without counting.
        """
        if self.exhausted:
            raise PairingReplayError("Pairing offer was already consumed or exhausted")
        when = self._clock() if now is None else now
        _check_offer(self.offer, when)
        if (not isinstance(inviter, DeviceIdentity) or inviter.device_id != self.offer.inviter_device_id
                or inviter.fingerprint != self.offer.certificate_fingerprint):
            raise PairingAuthenticationError("Inviter identity does not match the offer")
        plain = _decrypt_enrollment_request(self.offer, inviter, raw)
        try:
            request = _verify_enrollment_body(self.offer, plain, frozenset(reserved_ids))
        except PairingError:
            self.attempts += 1
            if self.attempts >= self.max_attempts:
                self._consumed = True
            raise
        self._consumed = True
        final = _canonical({"protocol": "localgatekeys-sync-enrollment-complete",
                            "transcript": hashlib.sha256(request.transcript).hexdigest()})
        peer = PairedDevice(
            device_id=request.device_id, group_id=self.offer.group_id,
            signing_public=request.signing_public, exchange_public=request.exchange_public,
            fingerprint=hashlib.sha256(request.signing_public).hexdigest(),
            enrolled_at=_now(when), enrollment_signature=inviter.sign(final),
        )
        return peer, request


# --- one-use network enrollment -------------------------------------------------------------
#
# The new device sends ENROLL_REQUEST_MAGIC + canonical JSON {"offer_id","eph","nonce","ct"}.
# ct = AES-GCM(key, body, aad=canonical({"offer_id","eph"})) with key = HKDF-SHA256(
# X25519(eph, inviter exchange key from the QR), salt=offer transcript nonce,
# info=_REQUEST_INFO + offer_id).  The body carries the device id, both public keys, an
# optional listening endpoint, an Ed25519 signature over the enrollment transcript and
# HMAC-SHA256(pairing secret, _MAC_LABEL + transcript).  The transcript binds the whole
# public offer (offer id, inviter keys, endpoint, nonce), the short code and the new
# device's id, keys and endpoint.  The reply carries (group_id, epoch, G) encrypted to the
# new device's exchange key, bound to sha256(transcript) and signed by the inviter's
# pinned signing key.

ENROLL_REQUEST_MAGIC = b"LGKENROLL1\n"
ENROLL_REPLY_MAGIC = b"LGKENROLLOK1\n"
ENROLL_REFUSED_MAGIC = b"LGKENROLLNO1\n"
MAX_ENROLL_BYTES = 16 * 1024
_REQUEST_INFO = b"localgatekeys|sync|enroll-request|v1|"
_REPLY_INFO = b"localgatekeys|sync|enroll-reply|v1|"
_MAC_LABEL = b"localgatekeys|sync|enroll-mac|v1|"
_SIG_LABEL = b"localgatekeys|sync|enroll-sig|v1|"
_REPLY_SIG_LABEL = b"localgatekeys|sync|enroll-reply-sig|v1|"
_VERIFY_LABEL = b"localgatekeys|sync|enroll-verify|v2|"
#: Version of the enrollment request body and transcript (2 added the device name and the Accept step).
ENROLL_VERSION = 2
_REQUEST_FIELDS = frozenset({"version", "offer_id", "device_id", "signing_public", "exchange_public",
                             "endpoint", "name", "signature", "mac"})
_REPLY_FIELDS = frozenset({"group_id", "epoch", "key", "device_id", "signing_public"})
#: Longest device name in an enrollment request, in UTF-8 bytes (the keyring's member name rule).
MAX_ENROLL_NAME_BYTES = 64
#: The name this desktop gives itself when it joins by QR (no host name: see keyring.DEFAULT_DEVICE_NAME_PC).
DEFAULT_ENROLL_NAME = "Windows PC"


#: Refusal reasons the inviter may state: generic, offer used up or expired, peer list full,
#: declined on the inviting device (or no answer in time), and a request of an older version.
REFUSAL_REASONS = frozenset({"refused", "used-or-expired", "full", "declined", "update-needed"})


def check_device_name(name: Any) -> str:
    """A device name for the Accept prompt: 1..64 UTF-8 bytes, no C0 control character and no DEL."""
    if not isinstance(name, str) or any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise PairingError("Device name is malformed")
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PairingError("Device name is malformed") from exc
    if not 1 <= size <= MAX_ENROLL_NAME_BYTES:
        raise PairingError("Device name must be 1..64 UTF-8 bytes")
    return name


def verification_code(transcript: bytes) -> str:
    """The 6-digit code both screens show for one enrollment (see the module docstring)."""
    digest = hashlib.sha256(_VERIFY_LABEL + transcript).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 10**6:06d}"


class EnrollmentOutdated(PairingError):
    """A request that decrypted but has the version-1 body: the new device needs an update."""


class EnrollmentRefused(PairingAuthenticationError):
    """The inviting device answered with a refusal; ``reason`` is one of ``REFUSAL_REASONS``."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"The inviting device refused the enrollment ({reason})")
        self.reason = reason


def enrollment_refusal(reason: str = "refused") -> bytes:
    """The one-frame refusal reply (no secrets; *reason* is one of ``REFUSAL_REASONS``)."""
    return ENROLL_REFUSED_MAGIC + _canonical({"reason": reason if reason in REFUSAL_REASONS else "refused"})


@dataclass(frozen=True)
class EnrollmentRequest:
    """A verified enrollment request (the new device's public identity)."""

    device_id: str
    signing_public: bytes
    exchange_public: bytes
    endpoint: tuple[str, int] | None
    transcript: bytes = field(repr=False)
    name: str = DEFAULT_ENROLL_NAME

    @property
    def code(self) -> str:
        """The verification code the new device shows (``verification_code``)."""
        return verification_code(self.transcript)


def _hkdf(shared: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)


def _strict_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                          parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise PairingError("Enrollment message is malformed") from exc


def _endpoint_dict(endpoint: tuple[str, int] | None) -> dict[str, Any] | None:
    return None if endpoint is None else {"host": endpoint[0], "port": endpoint[1]}


def _parse_endpoint(value: Any) -> tuple[str, int] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {"host", "port"}:
        raise PairingError("Enrollment endpoint is malformed")
    return _private_lan_endpoint(value["host"], value["port"])


def enrollment_transcript(offer: PairingOffer, device_id: str, signing_public: bytes,
                          exchange_public: bytes, endpoint: tuple[str, int] | None,
                          name: str = DEFAULT_ENROLL_NAME) -> bytes:
    return _canonical({
        "protocol": "localgatekeys-sync-enrollment",
        "version": ENROLL_VERSION,
        "offer": offer.public_dict(),
        "code": offer.code,
        "invitee_device_id": _ident(device_id, "invitee device id"),
        "invitee_signing_public": _b64e(signing_public),
        "invitee_exchange_public": _b64e(exchange_public),
        "invitee_endpoint": _endpoint_dict(endpoint),
        "invitee_name": check_device_name(name),
    })


def _mac(offer: PairingOffer, transcript: bytes) -> bytes:
    return hmac.new(offer.pairing_secret, _MAC_LABEL + transcript, hashlib.sha256).digest()


def build_enrollment_request(offer: PairingOffer, identity: DeviceIdentity, *,
                             endpoint: tuple[str, int] | None = None,
                             name: str = DEFAULT_ENROLL_NAME,
                             now: float | int | None = None,
                             _eph_seed: bytes | None = None,
                             _nonce: bytes | None = None) -> bytes:
    """New-device side: the one enrollment request for a scanned *offer*.

    *name* is shown on the inviting device's Accept prompt.  ``_eph_seed`` (32-byte
    X25519 private key) and ``_nonce`` (12 bytes) exist only for the deterministic test vectors.
    """
    _check_offer(offer, now)
    if not isinstance(identity, DeviceIdentity) or identity.device_id == offer.inviter_device_id:
        raise PairingAuthenticationError("A distinct invitee device identity is required")
    if endpoint is not None:
        endpoint = _private_lan_endpoint(*endpoint)
    transcript = enrollment_transcript(offer, identity.device_id, identity.signing_public_key,
                                       identity.exchange_public_key, endpoint, name)
    body = {
        "version": ENROLL_VERSION, "offer_id": offer.offer_id, "device_id": identity.device_id,
        "signing_public": _b64e(identity.signing_public_key),
        "exchange_public": _b64e(identity.exchange_public_key),
        "endpoint": _endpoint_dict(endpoint), "name": name,
        "signature": _b64e(identity.sign(_SIG_LABEL + transcript)),
        "mac": _b64e(_mac(offer, transcript)),
    }
    eph = _ephemeral(_eph_seed)
    try:
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(offer.inviter_exchange_public))
    except ValueError as exc:
        raise PairingAuthenticationError("Inviter exchange key is unusable") from exc
    key = _hkdf(shared, offer.transcript_nonce, _REQUEST_INFO + offer.offer_id.encode("ascii"))
    header = {"offer_id": offer.offer_id, "eph": _b64e(_public_bytes(eph.public_key()))}
    nonce = _enroll_nonce(_nonce)
    ct = AESGCM(key).encrypt(nonce, _canonical(body), _canonical(header))
    raw = ENROLL_REQUEST_MAGIC + _canonical({**header, "nonce": _b64e(nonce), "ct": _b64e(ct)})
    if len(raw) > MAX_ENROLL_BYTES:
        raise PairingError("Enrollment request is too large")
    return raw


def _ephemeral(seed: bytes | None) -> x25519.X25519PrivateKey:
    if seed is None:
        return x25519.X25519PrivateKey.generate()
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise PairingError("Ephemeral key seed is malformed")
    return x25519.X25519PrivateKey.from_private_bytes(seed)


def _enroll_nonce(nonce: bytes | None) -> bytes:
    if nonce is None:
        return secrets.token_bytes(12)
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise PairingError("Enrollment nonce is malformed")
    return nonce


def _decrypt_enrollment_request(offer: PairingOffer, inviter: DeviceIdentity, raw: Any) -> Any:
    """Size, magic, JSON shape and AES-GCM checks; failures here never count as an attempt."""
    if (not isinstance(raw, bytes) or len(raw) > MAX_ENROLL_BYTES
            or not raw.startswith(ENROLL_REQUEST_MAGIC)):
        raise PairingError("Enrollment request is malformed")
    outer = _strict_json(raw[len(ENROLL_REQUEST_MAGIC):])
    if not isinstance(outer, dict) or set(outer) != {"offer_id", "eph", "nonce", "ct"}:
        raise PairingError("Enrollment request is malformed")
    if outer["offer_id"] != offer.offer_id:
        raise PairingAuthenticationError("Enrollment request is for another offer")
    eph = _b64d(outer["eph"], length=32, field="enrollment key")
    nonce = _b64d(outer["nonce"], length=12, field="enrollment nonce")
    if not isinstance(outer["ct"], str):
        raise PairingError("Enrollment request is malformed")
    try:
        ct = base64.b64decode(outer["ct"].encode("ascii"), validate=True)
        shared = inviter.exchange_key.exchange(x25519.X25519PublicKey.from_public_bytes(eph))
    except (ValueError, UnicodeEncodeError) as exc:
        raise PairingAuthenticationError("Enrollment request cannot be opened") from exc
    key = _hkdf(shared, offer.transcript_nonce, _REQUEST_INFO + offer.offer_id.encode("ascii"))
    header = {"offer_id": outer["offer_id"], "eph": outer["eph"]}
    try:
        plain = AESGCM(key).decrypt(nonce, ct, _canonical(header))
    except (InvalidTag, ValueError) as exc:
        raise PairingAuthenticationError("Enrollment request authentication failed") from exc
    return plain


def _verify_enrollment_body(offer: PairingOffer, plain: bytes,
                            reserved_ids: frozenset[str]) -> EnrollmentRequest:
    """Checks after a successful decrypt (the sender holds the QR); failures count as attempts."""
    body = _strict_json(plain)
    if (isinstance(body, dict) and type(body.get("version")) is int and body["version"] < ENROLL_VERSION
            and body.get("offer_id") == offer.offer_id):
        raise EnrollmentOutdated("The new device needs an update (enrollment version 1)")
    if (not isinstance(body, dict) or set(body) != _REQUEST_FIELDS or type(body["version"]) is not int
            or body["version"] != ENROLL_VERSION or body["offer_id"] != offer.offer_id):
        raise PairingError("Enrollment request is malformed")
    device_id = _ident(body["device_id"], "invitee device id")
    if device_id == offer.inviter_device_id or device_id in reserved_ids:
        raise PairingAuthenticationError("This device id is already in use in the group")
    signing = _b64d(body["signing_public"], length=32, field="invitee signing key")
    exchange = _b64d(body["exchange_public"], length=32, field="invitee exchange key")
    endpoint = _parse_endpoint(body["endpoint"])
    name = check_device_name(body["name"])
    transcript = enrollment_transcript(offer, device_id, signing, exchange, endpoint, name)
    mac = _b64d(body["mac"], length=32, field="enrollment mac")
    if not hmac.compare_digest(mac, _mac(offer, transcript)):
        raise PairingCodeError("Enrollment does not prove the pairing secret")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(signing).verify(
            _b64d(body["signature"], length=64, field="enrollment signature"), _SIG_LABEL + transcript)
    except (InvalidSignature, ValueError) as exc:
        raise PairingAuthenticationError("Enrollment signature is invalid") from exc
    return EnrollmentRequest(device_id, signing, exchange, endpoint, transcript, name)


def seal_enrollment_reply(inviter: DeviceIdentity, offer: PairingOffer, request: EnrollmentRequest,
                          group_id: str, epoch: int, key: bytes, *,
                          _eph_seed: bytes | None = None,
                          _nonce: bytes | None = None) -> bytes:
    """Inviter side: the group key for an accepted *request*, sealed to the new device.

    ``_eph_seed`` and ``_nonce`` exist only for the deterministic test vectors.
    """
    if type(epoch) is not int or epoch < 1 or not isinstance(key, bytes) or len(key) != 32:
        raise PairingError("Group key is malformed")
    bound = hashlib.sha256(request.transcript).digest()
    eph = _ephemeral(_eph_seed)
    try:
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(request.exchange_public))
    except ValueError as exc:
        raise PairingAuthenticationError("Invitee exchange key is unusable") from exc
    secret = _hkdf(shared, bound, _REPLY_INFO + offer.offer_id.encode("ascii"))
    nonce = _enroll_nonce(_nonce)
    header = {"eph": _b64e(_public_bytes(eph.public_key())), "nonce": _b64e(nonce)}
    body = {"group_id": _ident(group_id, "group id"), "epoch": epoch, "key": _b64e(key),
            "device_id": request.device_id, "signing_public": _b64e(request.signing_public)}
    ct = AESGCM(secret).encrypt(nonce, _canonical(body), _canonical(header) + bound)
    signature = inviter.sign(_REPLY_SIG_LABEL + bound + _canonical(header) + ct)
    return ENROLL_REPLY_MAGIC + _canonical({**header, "ct": _b64e(ct), "sig": _b64e(signature)})


def open_enrollment_reply(offer: PairingOffer, identity: DeviceIdentity, raw: Any, *,
                          endpoint: tuple[str, int] | None = None,
                          name: str = DEFAULT_ENROLL_NAME) -> tuple[str, int, bytes]:
    """New-device side: verify the inviter's reply and return (group_id, epoch, key)."""
    if isinstance(raw, bytes) and raw.startswith(ENROLL_REFUSED_MAGIC):
        reason = "refused"
        try:
            value = _strict_json(raw[len(ENROLL_REFUSED_MAGIC):])
            if isinstance(value, dict) and value.get("reason") in REFUSAL_REASONS:
                reason = value["reason"]
        except PairingError:
            pass
        raise EnrollmentRefused(reason)
    if not isinstance(raw, bytes) or len(raw) > MAX_ENROLL_BYTES or not raw.startswith(ENROLL_REPLY_MAGIC):
        raise PairingError("Enrollment reply is malformed")
    outer = _strict_json(raw[len(ENROLL_REPLY_MAGIC):])
    if not isinstance(outer, dict) or set(outer) != {"eph", "nonce", "ct", "sig"}:
        raise PairingError("Enrollment reply is malformed")
    if endpoint is not None:
        endpoint = _private_lan_endpoint(*endpoint)
    transcript = enrollment_transcript(offer, identity.device_id, identity.signing_public_key,
                                       identity.exchange_public_key, endpoint, name)
    bound = hashlib.sha256(transcript).digest()
    header = {"eph": outer["eph"], "nonce": outer["nonce"]}
    eph = _b64d(outer["eph"], length=32, field="reply key")
    nonce = _b64d(outer["nonce"], length=12, field="reply nonce")
    if not isinstance(outer["ct"], str):
        raise PairingError("Enrollment reply is malformed")
    try:
        ct = base64.b64decode(outer["ct"].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise PairingError("Enrollment reply is malformed") from exc
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(offer.inviter_signing_public).verify(
            _b64d(outer["sig"], length=64, field="reply signature"),
            _REPLY_SIG_LABEL + bound + _canonical(header) + ct)
        shared = identity.exchange_key.exchange(x25519.X25519PublicKey.from_public_bytes(eph))
        plain = AESGCM(_hkdf(shared, bound, _REPLY_INFO + offer.offer_id.encode("ascii"))).decrypt(
            nonce, ct, _canonical(header) + bound)
    except (InvalidSignature, InvalidTag, ValueError) as exc:
        raise PairingAuthenticationError("Enrollment reply is not from the pinned inviter") from exc
    body = _strict_json(plain)
    if not isinstance(body, dict) or set(body) != _REPLY_FIELDS:
        raise PairingError("Enrollment reply is malformed")
    if (body["device_id"] != identity.device_id
            or body["signing_public"] != _b64e(identity.signing_public_key)):
        raise PairingAuthenticationError("Inviter pinned another device identity")
    if body["group_id"] != offer.group_id or type(body["epoch"]) is not int or body["epoch"] < 1:
        raise PairingError("Enrollment reply group is malformed")
    return body["group_id"], body["epoch"], _b64d(body["key"], length=32, field="group key")


# --- QR payload ---------------------------------------------------------------------------

_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = item
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def offer_qr_payload(offer: PairingOffer) -> str:
    """The text a QR code carries: ``lgk-pair:`` + unpadded base64url(canonical bundle JSON).

    The bundle includes the one-use secret and the short code, so the QR code is
    shown only on the inviting device and only for the offer's lifetime.
    """
    if not isinstance(offer, PairingOffer):
        raise PairingError("Pairing offer is malformed")
    encoded = base64.urlsafe_b64encode(_canonical(offer.bundle_dict())).rstrip(b"=").decode("ascii")
    text = QR_PREFIX + encoded
    if len(text) > MAX_QR_PAYLOAD:
        raise PairingError("Pairing QR payload is too large")
    return text


def parse_qr_payload(text: Any) -> dict[str, Any]:
    """Strictly parse a scanned QR text back into a validated offer bundle dict.

    Rejects a missing or different prefix, padding or any non-base64url character,
    text over ``MAX_QR_PAYLOAD``, duplicate JSON keys, non-canonical JSON and any
    bundle :meth:`PairingOffer.from_bundle_dict` refuses.
    """
    if not isinstance(text, str) or len(text) > MAX_QR_PAYLOAD or not text.startswith(QR_PREFIX):
        raise PairingError("Not a LocalGateKeys pairing code")
    body = text[len(QR_PREFIX):]
    if not body or len(body) % 4 == 1 or any(char not in _B64URL for char in body):
        raise PairingError("Pairing QR payload is malformed")
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != body:
            raise ValueError("non-canonical base64")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                           parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise PairingError("Pairing QR payload is malformed") from exc
    if not isinstance(value, dict):
        raise PairingError("Pairing QR payload is malformed")
    if _canonical(value) != raw:
        raise PairingError("Pairing QR payload is not canonical")
    PairingOffer.from_bundle_dict(value)  # full field validation
    return value


def render_qr_png(payload: str, scale: int = 6) -> bytes:
    """Render *payload* as a PNG QR code (error correction M, no micro QR) with ``segno``."""
    if not isinstance(payload, str) or not payload or len(payload) > MAX_QR_PAYLOAD:
        raise PairingError("Pairing QR payload is malformed")
    if type(scale) is not int or not 1 <= scale <= 32:
        raise PairingError("QR scale is outside the accepted bound")
    import io

    import segno

    out = io.BytesIO()
    segno.make(payload, error="m", micro=False, boost_error=False).save(out, kind="png", scale=scale)
    return out.getvalue()


__all__ = [
    "DeviceIdentity", "PairingOffer", "PairingConfirmation", "PairedDevice",
    "PairingSession", "PairingError", "PairingExpired", "PairingCodeError",
    "PairingAuthenticationError", "PairingReplayError", "create_pairing_offer",
    "confirm_pairing_offer", "complete_pairing", "PAIRING_TTL_SECONDS",
    "PAIRING_MAX_ATTEMPTS", "MAX_QR_PAYLOAD", "QR_PREFIX", "offer_qr_payload", "parse_qr_payload",
    "render_qr_png", "EnrollmentRequest", "ENROLL_REQUEST_MAGIC", "ENROLL_REPLY_MAGIC",
    "ENROLL_REFUSED_MAGIC", "MAX_ENROLL_BYTES", "build_enrollment_request", "enrollment_transcript",
    "open_enrollment_reply", "seal_enrollment_reply", "EnrollmentRefused", "REFUSAL_REASONS",
    "enrollment_refusal",
]
