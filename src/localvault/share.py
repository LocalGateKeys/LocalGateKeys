"""Secure local sharing, ``.lgkshare`` v1: one item, encrypted under a 6-word one-time code.

The byte-level format is in ``docs/formats/LGKSHARE_V1.md`` and the shared vectors in
``tests/vectors/share``. This module is the format core only: seal, read the clear header, open.
Receiving (private storage, the pop-up, three wrong codes, the Incoming list) is app work.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .i18n import t

FORMAT = "localgatekeys-share"
VERSION = 1
CODE_WORDS = 6
LIFETIME = 24 * 3600
CLOCK_SKEW = 300
#: Argon2id parameters, fixed for v1 (a reader refuses others): about 0.2 s on a phone.
KDF = {"name": "argon2id", "time_cost": 2, "memory_cost_kib": 19456, "parallelism": 1}
MAX_PACKAGE = 256 * 1024
QR_LIMIT = 2048
SENDER_LIMIT = 64
#: Kinds that may be shared; attachments and passkeys never travel in v1.
FORBIDDEN_FIELDS = ("attachments", "attachment_ids", "passkeys", "passkey")
_LOCAL_ONLY = ("policy", "password_history", "collection_ids", "favorite", "usage", "last_used_at")


class ShareError(ValueError):
    """A package cannot be made or opened; ``reason`` is one of the codes in the spec."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _words() -> list[str]:
    from .vault import bip39_words

    return bip39_words()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: Any, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ShareError("malformed", t("share.theSharedItemIsDamaged"))
    try:
        out = base64.b64decode(value, validate=True)
    except ValueError:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged")) from None
    if size is not None and len(out) != size:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged"))
    return out


def generate_code() -> str:
    """Six words from the BIP39 English list (66 bits), shown on the sender's screen only."""
    words = _words()
    return " ".join(words[secrets.randbelow(len(words))] for _ in range(CODE_WORDS))


def normalize_code(text: str) -> str:
    """Lower case, words split on spaces, dots, dashes or commas; exactly six list words."""
    tokens = [t for t in re.split(r"[\s·.,\-]+", str(text or "").strip().lower()) if t]
    allowed = set(_words())
    if len(tokens) != CODE_WORDS or any(t not in allowed for t in tokens):
        raise ShareError("bad-code", t("share.enterTheSixWordsOf"))
    return " ".join(tokens)


def _key(code: str, salt: bytes) -> bytes:
    return hash_secret_raw(normalize_code(code).encode("utf-8"), salt, time_cost=KDF["time_cost"],
                           memory_cost=KDF["memory_cost_kib"], parallelism=KDF["parallelism"], hash_len=32,
                           type=Type.ID)


def _clean_item(item: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(item, Mapping) or not isinstance(item.get("kind"), str) or not item.get("kind"):
        raise ShareError("malformed", t("share.onlyASavedItemCan"))
    if item.get("kind") == "passkey" or any(item.get(k) for k in FORBIDDEN_FIELDS):
        raise ShareError("not-shareable", t("share.passkeysAndAttachmentsCannotBe"))
    return {k: v for k, v in dict(item).items() if k not in _LOCAL_ONLY and k not in FORBIDDEN_FIELDS}


def _aad(header: Mapping[str, Any]) -> bytes:
    return _canonical({k: header[k] for k in ("format", "version", "id", "sender", "kdf", "nonce")})


def seal(item: Mapping[str, Any], code: str, *, sender: str, now: int, package_id: str | None = None,
         salt: bytes | None = None, nonce: bytes | None = None) -> bytes:
    """The ``.lgkshare`` bytes for one item. ``package_id``/``salt``/``nonce`` are for vectors only."""
    sender = str(sender or "").strip()[:SENDER_LIMIT] or "A LocalGateKeys device"
    salt = secrets.token_bytes(16) if salt is None else salt
    nonce = secrets.token_bytes(12) if nonce is None else nonce
    header = {"format": FORMAT, "version": VERSION, "id": package_id or str(uuid.uuid4()), "sender": sender,
              "kdf": {**KDF, "salt": _b64e(salt)}, "nonce": _b64e(nonce)}
    payload = {"version": VERSION, "created_at": int(now), "expires_at": int(now) + LIFETIME,
               "item": _clean_item(item)}
    ciphertext = AESGCM(_key(code, salt)).encrypt(nonce, _canonical(payload), _aad(header))
    data = _canonical({**header, "ciphertext": _b64e(ciphertext)})
    if len(data) > MAX_PACKAGE:
        raise ShareError("too-large", t("share.thisItemIsTooLarge2"))
    return data


def read_header(data: bytes) -> dict[str, Any]:
    """The clear part, for the pop-up before the code is typed: ``id`` and ``sender``."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_PACKAGE:
        raise ShareError("malformed", t("share.thisIsNotAShared"))
    try:
        envelope = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ShareError("malformed", t("share.thisIsNotAShared")) from None
    if not isinstance(envelope, dict) or envelope.get("format") != FORMAT:
        raise ShareError("malformed", t("share.thisIsNotAShared"))
    if envelope.get("version") != VERSION:
        raise ShareError("unsupported", t("share.thisItemWasSharedBy"))
    if set(envelope) != {"format", "version", "id", "sender", "kdf", "nonce", "ciphertext"}:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged"))
    kdf = envelope["kdf"]
    if not isinstance(kdf, dict) or {k: kdf.get(k) for k in KDF} != KDF or set(kdf) != {*KDF, "salt"}:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged"))
    try:
        package_id = str(uuid.UUID(str(envelope["id"])))
    except ValueError:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged")) from None
    if package_id != envelope["id"] or not isinstance(envelope["sender"], str) \
            or len(envelope["sender"]) > SENDER_LIMIT:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged"))
    _b64d(kdf["salt"], 16)
    _b64d(envelope["nonce"], 12)
    return {"id": package_id, "sender": envelope["sender"], "envelope": envelope}


def open_package(data: bytes, code: str, *, now: int, opened: Iterable[str] = ()) -> dict[str, Any]:
    """Decrypt and check one package: ``{"id", "sender", "created_at", "expires_at", "item"}``.

    ``opened`` holds the package ids this device already opened; such a package is refused.
    """
    header = read_header(data)
    envelope = header["envelope"]
    if header["id"] in set(opened):
        raise ShareError("already-opened", t("share.thisSharedItemWasAlready"))
    try:
        plain = AESGCM(_key(code, _b64d(envelope["kdf"]["salt"], 16))).decrypt(
            _b64d(envelope["nonce"], 12), _b64d(envelope["ciphertext"]), _aad(envelope))
    except InvalidTag:
        raise ShareError("wrong-code", t("share.thatCodeDoesNotOpen")) from None
    try:
        payload = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ShareError("malformed", t("share.theSharedItemIsDamaged")) from None
    if not isinstance(payload, dict) or payload.get("version") != VERSION \
            or set(payload) != {"version", "created_at", "expires_at", "item"}:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged"))
    created, expires = payload["created_at"], payload["expires_at"]
    if type(created) is not int or type(expires) is not int or expires != created + LIFETIME:
        raise ShareError("malformed", t("share.theSharedItemIsDamaged"))
    if created > now + CLOCK_SKEW:
        raise ShareError("malformed", t("share.theSharedItemHasA"))
    if now >= expires:
        raise ShareError("expired", t("share.thisSharedItemExpiredAsk"))
    item = _clean_item(payload["item"]) if isinstance(payload["item"], Mapping) else None
    if item is None or item != payload["item"]:
        raise ShareError("not-shareable", t("share.thisSharedItemHoldsContent"))
    return {"id": header["id"], "sender": header["sender"], "created_at": created, "expires_at": expires,
            "item": item}


CREDENTIAL_KINDS = ("web", "desktop")


def _origin_of(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.scheme or not parts.netloc:
        return url
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def stored_form(item: Mapping[str, Any]) -> dict[str, Any]:
    """The item in the stored shape the spec defines (``scope`` for logins, ``payload`` for typed items).

    Every sender seals the stored record. Packages made by early builds may carry the display shape instead
    (a login's top-level ``urls`` and a typed item's ``fields``); a receiver converts those here, before its
    own schema checks. A record already in the stored shape is returned unchanged (as a copy).
    """
    import copy

    rec = copy.deepcopy(dict(item))
    kind = rec.get("kind")
    if kind in CREDENTIAL_KINDS:
        if "label" not in rec and isinstance(rec.get("title"), str):
            rec["label"] = rec["title"]
        rec.pop("title", None)
        urls = rec.pop("urls", None)
        if not isinstance(rec.get("scope"), dict) and kind == "web":
            rows = [dict(row) for row in urls if isinstance(row, dict) and isinstance(row.get("url"), str)] \
                if isinstance(urls, list) else []
            scope: dict[str, Any] = {"origin": ""}
            if rows:
                first = rows[0]
                scope["origin"] = first["url"] if first.get("match") == "exact_origin" else _origin_of(first["url"])
                scope["urls"] = rows
            rec["scope"] = scope
    else:
        if "title" not in rec and isinstance(rec.get("label"), str):
            rec["title"] = rec["label"]
        rec.pop("label", None)
        fields = rec.pop("fields", None)
        if not isinstance(rec.get("payload"), dict):
            rec["payload"] = dict(fields) if isinstance(fields, dict) else {}
    return rec


def fits_qr(data: bytes) -> bool:
    """Small packages may travel as a QR code; larger ones go as a file."""
    return len(data) <= QR_LIMIT


def code_qr_text(code: str) -> str:
    """The second QR (the key), when the code is not read out."""
    return "lgkshare-code:" + normalize_code(code).replace(" ", "-")


def code_from_qr_text(text: str) -> str:
    if not isinstance(text, str) or not text.startswith("lgkshare-code:"):
        raise ShareError("bad-code", t("share.thisQrCodeIsNot"))
    return normalize_code(text[len("lgkshare-code:"):])
