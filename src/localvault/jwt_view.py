"""Read-only JWT decode for API-key items. Never verifies the signature.

Mirror of Swift ``JWTView`` and Kotlin ``JwtView``; vectors in ``tests/vectors/jwt/cases.json``.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

from .strict_json import strict_loads

MAX_JWT_CHARS = 16 * 1024
_SHAPE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_MAX_TIMESTAMP = 32503680000  # 3000-01-01T00:00:00Z; later values are ignored


@dataclass(frozen=True)
class JwtInfo:
    header: dict[str, Any]
    claims: dict[str, Any]
    alg: str | None = None
    issued: int | None = None
    not_before: int | None = None
    expires: int | None = None

    def expired(self, now: int) -> bool:
        return self.expires is not None and self.expires <= now


def _part(text: str) -> dict[str, Any] | None:
    if len(text) % 4 == 1:
        return None
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        value = strict_loads(data)
    except (binascii.Error, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _time(claims: dict[str, Any], name: str) -> int | None:
    """Only a JSON integer is a timestamp: numeric strings, floats and booleans are ignored."""
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_TIMESTAMP:
        return None
    return value


def decode_jwt(value: str) -> JwtInfo | None:
    """Decode ``header.payload.signature`` (base64url, no padding); None when it is not a JWT."""
    if not isinstance(value, str) or len(value) > MAX_JWT_CHARS or _SHAPE.fullmatch(value) is None:
        return None
    head, body, _signature = value.split(".")
    header, claims = _part(head), _part(body)
    if header is None or claims is None:
        return None
    alg = header.get("alg")
    return JwtInfo(header=header, claims=claims, alg=alg if isinstance(alg, str) else None,
                   issued=_time(claims, "iat"), not_before=_time(claims, "nbf"), expires=_time(claims, "exp"))
