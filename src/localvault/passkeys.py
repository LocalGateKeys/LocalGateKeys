"""WebAuthn software authenticator backed by vault items (ES256, attestation "none").

Pure logic, no UI and no vault access: :mod:`localvault.browser_broker` owns
unlock, consent, user verification and storage, and calls in here to validate
requests, create credentials and sign assertions.

Security boundary
-----------------
``origin`` always comes from the browser (the extension's ``sender``
metadata, forwarded by the native host), never from the page.  The agent
builds ``clientDataJSON`` itself from that origin, so a page cannot choose
the origin that gets signed.  The rpId must equal the origin's host or be a
registrable suffix of it (WebAuthn §5.1.3/§5.1.4, Public Suffix List).

Counter policy: the signature counter is always 0 and the backup-eligible
and backed-up flags are set.  These are synced-style passkeys: a changing
counter would rewrite the vault item on every sign-in and fight with device
sync, and WebAuthn defines 0 as "this authenticator has no counter".
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import ipaddress
import json
import re
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .origin import OriginError, _ascii_host, canonicalize_origin, public_suffix, suffix_rules

AAGUID = uuid.UUID("b7d2a6f0-1c4e-4a5b-9e3d-5a1f7c2e8d41").bytes
ES256 = -7
ALGORITHM_NAME = "ES256"
CREDENTIAL_ID_BYTES = 16

MAX_USER_ID = 64
MIN_CHALLENGE = 16
MAX_CHALLENGE = 1024
MAX_CREDENTIAL_LIST = 64
MAX_CREDENTIAL_ID = 1023
MAX_NAME = 256
MAX_RP_ID = 253
USER_VERIFICATION = ("required", "preferred", "discouraged")

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

_B64U_RE = re.compile(r"[A-Za-z0-9_-]*")


class PasskeyError(ValueError):
    """A request the authenticator will not serve.

    ``code`` tells the broker what the page sees: ``fallback`` hands the
    request to the browser's own authenticator, ``security_error`` and
    ``invalid_state`` become the matching ``DOMException``.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class CreateOptions:
    rp_id: str
    rp_name: str
    user_id: bytes
    user_name: str
    user_display_name: str
    challenge: bytes
    exclude_ids: tuple[bytes, ...]
    user_verification: str
    cred_props: bool


@dataclass(frozen=True)
class GetOptions:
    rp_id: str
    challenge: bytes
    allow_ids: tuple[bytes, ...]
    user_verification: str


# -- encodings ---------------------------------------------------------------

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str, *, max_bytes: int) -> bytes:
    if not isinstance(text, str) or len(text) > (max_bytes * 4 + 2) // 3 or not _B64U_RE.fullmatch(text):
        raise PasskeyError("fallback", "expected base64url text")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise PasskeyError("fallback", "expected base64url text") from exc
    if len(data) > max_bytes:
        raise PasskeyError("fallback", "value is too long")
    return data


def _cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    if value <= 0xFF:
        return bytes([major << 5 | 24, value])
    if value <= 0xFFFF:
        return bytes([major << 5 | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([major << 5 | 26]) + value.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + value.to_bytes(8, "big")


def cbor_encode(value: Any) -> bytes:
    """Encode the CBOR subset WebAuthn needs. Map keys keep insertion order."""
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _cbor_head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        return _cbor_head(5, len(value)) + b"".join(cbor_encode(k) + cbor_encode(v) for k, v in value.items())
    raise TypeError(f"cannot CBOR-encode {type(value).__name__}")


def client_data_json(ceremony: str, challenge: bytes, origin: str) -> bytes:
    if ceremony not in ("webauthn.create", "webauthn.get"):
        raise ValueError("unknown WebAuthn ceremony")
    return json.dumps({"type": ceremony, "challenge": b64u_encode(challenge), "origin": origin,
                       "crossOrigin": False}, separators=(",", ":")).encode("utf-8")


def authenticator_data(rp_id: str, *, user_verified: bool,
                       attested: tuple[bytes, bytes] | None = None) -> bytes:
    flags = FLAG_UP | FLAG_BE | FLAG_BS | (FLAG_UV if user_verified else 0) | (FLAG_AT if attested else 0)
    data = hashlib.sha256(rp_id.encode("ascii")).digest() + bytes([flags]) + (0).to_bytes(4, "big")
    if attested is not None:
        credential_id, cose_key = attested
        data += AAGUID + len(credential_id).to_bytes(2, "big") + credential_id + cose_key
    return data


def cose_es256_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    return cbor_encode({1: 2, 3: ES256, -1: 1, -2: numbers.x.to_bytes(32, "big"),
                        -3: numbers.y.to_bytes(32, "big")})


# -- request validation -------------------------------------------------------

def validate_rp_id(origin: str, rp_id: str | None) -> str:
    """Return the effective rpId for ``origin`` or raise ``security_error``."""
    try:
        canonical = canonicalize_origin(origin)
    except (OriginError, TypeError) as exc:
        raise PasskeyError("security_error", "origin cannot use passkeys") from exc
    host = (urlsplit(canonical).hostname or "").strip("[]")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise PasskeyError("security_error", "IP-address origins cannot use passkeys")
    if rp_id is None:
        return host
    if not isinstance(rp_id, str) or len(rp_id) > MAX_RP_ID:
        raise PasskeyError("security_error", "rpId is malformed")
    try:
        candidate = _ascii_host(rp_id)
    except OriginError as exc:
        raise PasskeyError("security_error", "rpId is malformed") from exc
    if candidate == host:
        return candidate
    if not host.endswith("." + candidate):
        raise PasskeyError("security_error", "rpId does not match the page")
    rules = suffix_rules()
    if rules is None or public_suffix(candidate, rules) == candidate:
        raise PasskeyError("security_error", "rpId is a public suffix")
    return candidate


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PasskeyError("fallback", f"{field} must be an object")
    return value


# Line breaks, other control characters and bidi controls in page-supplied
# names. They are shown in the consent dialog, where a page could otherwise
# add a fake "Site:" line or reorder the text.
_NAME_BREAK_RE = re.compile("[\x00-\x1f\x7f-\x9f  ]+")
_NAME_BIDI_RE = re.compile("[‎‏‪-‮⁦-⁩]")


def _name(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise PasskeyError("fallback", "names must be text")
    return " ".join(_NAME_BREAK_RE.sub(" ", _NAME_BIDI_RE.sub("", value)).split())[:MAX_NAME]


def _challenge(value: Any) -> bytes:
    challenge = b64u_decode(value, max_bytes=MAX_CHALLENGE)
    if len(challenge) < MIN_CHALLENGE:
        raise PasskeyError("fallback", "challenge is too short")
    return challenge


def _credential_list(value: Any) -> tuple[bytes, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_CREDENTIAL_LIST:
        raise PasskeyError("fallback", "credential list is malformed")
    ids = []
    for entry in value:
        entry = _mapping(entry, "credential descriptor")
        if entry.get("type", "public-key") != "public-key":
            continue
        credential_id = b64u_decode(entry.get("id"), max_bytes=MAX_CREDENTIAL_ID)
        if not credential_id:
            raise PasskeyError("fallback", "credential id is empty")
        ids.append(credential_id)
    return tuple(ids)


def _user_verification(value: Any) -> str:
    return value if value in USER_VERIFICATION else "preferred"


def parse_create_options(origin: str, raw: Any) -> CreateOptions:
    raw = _mapping(raw, "options")
    rp = _mapping(raw.get("rp"), "rp")
    rp_id_value = rp.get("id")
    if rp_id_value is not None and not isinstance(rp_id_value, str):
        raise PasskeyError("fallback", "rp.id must be text")
    rp_id = validate_rp_id(origin, rp_id_value)
    user = _mapping(raw.get("user"), "user")
    user_id = b64u_decode(user.get("id"), max_bytes=MAX_USER_ID)
    if not user_id:
        raise PasskeyError("fallback", "user.id is empty")
    params = raw.get("pubKeyCredParams")
    if not isinstance(params, list) or len(params) > MAX_CREDENTIAL_LIST:
        raise PasskeyError("fallback", "pubKeyCredParams is malformed")
    # An empty list means the WebAuthn defaults, which include ES256.
    if params and not any(isinstance(p, Mapping) and p.get("type") == "public-key" and p.get("alg") == ES256
                          for p in params):
        raise PasskeyError("fallback", "ES256 was not offered")
    selection = raw.get("authenticatorSelection") or {}
    selection = _mapping(selection, "authenticatorSelection")
    extensions = raw.get("extensions") or {}
    extensions = _mapping(extensions, "extensions")
    return CreateOptions(
        rp_id=rp_id,
        rp_name=_name(rp.get("name")),
        user_id=user_id,
        user_name=_name(user.get("name")),
        user_display_name=_name(user.get("displayName")),
        challenge=_challenge(raw.get("challenge")),
        exclude_ids=_credential_list(raw.get("excludeCredentials")),
        user_verification=_user_verification(selection.get("userVerification")),
        cred_props=extensions.get("credProps") is True,
    )


def parse_get_options(origin: str, raw: Any) -> GetOptions:
    raw = _mapping(raw, "options")
    rp_id_value = raw.get("rpId")
    if rp_id_value is not None and not isinstance(rp_id_value, str):
        raise PasskeyError("fallback", "rpId must be text")
    return GetOptions(
        rp_id=validate_rp_id(origin, rp_id_value),
        challenge=_challenge(raw.get("challenge")),
        allow_ids=_credential_list(raw.get("allowCredentials")),
        user_verification=_user_verification(raw.get("userVerification")),
    )


# -- keys and ceremonies --------------------------------------------------------

def _load_private_key(text: Any) -> ec.EllipticCurvePrivateKey | None:
    try:
        key = serialization.load_der_private_key(b64u_decode(text, max_bytes=4096), password=None)
    except (PasskeyError, ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        return None
    return key


def usable_record(record: Mapping[str, Any]) -> bool:
    """True when a stored passkey can sign: ES256 with a P-256 PKCS#8 key."""
    if record.get("algorithm") != ALGORITHM_NAME:
        return False
    try:
        if not b64u_decode(record.get("credential_id", ""), max_bytes=MAX_CREDENTIAL_ID):
            return False
    except PasskeyError:
        return False
    return _load_private_key(record.get("private_key")) is not None


def create_credential(origin: str, opts: CreateOptions, *, user_verified: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate a passkey. Returns ``(item_fields, response)``; bytes are base64url."""
    key = ec.generate_private_key(ec.SECP256R1())
    public_key = key.public_key()
    credential_id = secrets.token_bytes(CREDENTIAL_ID_BYTES)
    auth_data = authenticator_data(opts.rp_id, user_verified=user_verified,
                                   attested=(credential_id, cose_es256_public_key(public_key)))
    attestation = cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data = client_data_json("webauthn.create", opts.challenge, origin)
    title = opts.rp_name or opts.rp_id
    if opts.user_name:
        title = f"{title} ({opts.user_name})"
    fields = {
        "title": title,
        "relying_party_id": opts.rp_id,
        "rp_name": opts.rp_name,
        "user_handle": b64u_encode(opts.user_id),
        "user_name": opts.user_name,
        "user_display_name": opts.user_display_name,
        "credential_id": b64u_encode(credential_id),
        "private_key": b64u_encode(key.private_bytes(serialization.Encoding.DER,
                                                     serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption())),
        "algorithm": ALGORITHM_NAME,
        "created": _dt.date.today().isoformat(),
        "discoverable": True,
    }
    response: dict[str, Any] = {
        "credential_id": fields["credential_id"],
        "client_data_json": b64u_encode(client_data),
        "attestation_object": b64u_encode(attestation),
        "authenticator_data": b64u_encode(auth_data),
        "public_key_spki": b64u_encode(public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
        "public_key_algorithm": ES256,
        "transports": ["internal"],
    }
    if opts.cred_props:
        response["cred_props_rk"] = True
    return fields, response


def get_assertion(origin: str, opts: GetOptions, record: Mapping[str, Any], *, user_verified: bool) -> dict[str, Any]:
    """Sign ``authenticatorData || SHA-256(clientDataJSON)`` with a stored passkey."""
    key = _load_private_key(record.get("private_key"))
    if key is None or record.get("algorithm") != ALGORITHM_NAME:
        raise PasskeyError("fallback", "stored passkey cannot sign")
    auth_data = authenticator_data(opts.rp_id, user_verified=user_verified)
    client_data = client_data_json("webauthn.get", opts.challenge, origin)
    signature = key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "credential_id": str(record.get("credential_id", "")),
        "client_data_json": b64u_encode(client_data),
        "authenticator_data": b64u_encode(auth_data),
        "signature": b64u_encode(signature),
        "user_handle": str(record.get("user_handle", "")),
    }
