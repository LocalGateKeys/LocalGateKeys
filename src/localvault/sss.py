"""Shamir's secret sharing over GF(256) for emergency-access shards (sub-plan 08, Task 1).

Byte-exact rules (vectors: ``tests/vectors/sss``; ``hashicorp.json`` holds the ``hashicorp/vault`` ``shamir``
package's field known answers, ``v1.json`` the derived share vectors and how they were made):

* The field is GF(2^8) with the AES reduction polynomial ``x^8 + x^4 + x^3 + x + 1`` (0x11b); addition is XOR.
* The secret is exactly 32 bytes (the recovery entropy).  Each secret byte ``j`` is the constant term of its own
  polynomial of degree ``k - 1``; the other coefficients come from one call ``rng(32 * (k - 1))``, read as
  ``coeffs[j * (k - 1) + (d - 1)]`` = the degree-``d`` coefficient for byte ``j``.  Coefficients are uniform and
  may be zero (as in ``hashicorp/vault``); secrecy of k-1 shares needs only uniform coefficients.
* Share ``i`` (``x = 1..n``) is ``bytes([x]) + 32 bytes`` of the polynomials evaluated at ``x``.
* ``combine`` is Lagrange interpolation at ``x = 0``.  It cannot detect a wrong or tampered share, or too few
  shares: it then returns unrelated bytes.  Integrity belongs to the signed ``.lgkheir`` envelope around a shard.

Side channels (best effort; Python integers give no constant-time guarantee):

* The log/exp tables are only ever indexed by *public* values: the x-coordinates (share indices) when computing
  the Lagrange basis.  Secret bytes (the secret, the coefficients, the share values) never index a table and
  never choose a branch: they only go through ``_gf_mul``, a fixed eight-round shift-and-xor multiply that uses
  masks instead of ``if``.  This is the same approach as the current ``hashicorp/vault`` ``shamir.mult``.
* Intermediate coefficient buffers are ``bytearray`` and are overwritten before return (best effort: ``bytes``
  returned by ``rng`` and the returned shares/secret are immutable and are the caller's to manage).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence

__all__ = ["SSSError", "SECRET_LEN", "SHARE_LEN", "MIN_K", "MAX_N", "split", "combine"]

SECRET_LEN = 32
SHARE_LEN = 1 + SECRET_LEN
MIN_K = 2
MAX_N = 5


class SSSError(ValueError):
    """Bad parameters or malformed shares."""


def _build_tables() -> tuple[tuple[int, ...], tuple[int, ...]]:
    # 0x03 generates the multiplicative group of GF(2^8) mod 0x11b.
    exp = [0] * 510
    log = [0] * 256
    value = 1
    for power in range(255):
        exp[power] = value
        log[value] = power
        value ^= ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF  # value * 3
    for power in range(255, 510):
        exp[power] = exp[power - 255]
    return tuple(exp), tuple(log)


_EXP, _LOG = _build_tables()


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) mod 0x11b without table lookups or data-dependent branches (best effort)."""
    p = 0
    for _ in range(8):
        p ^= a & -(b & 1)
        a = ((a << 1) ^ (0x1B & -(a >> 7))) & 0xFF
        b >>= 1
    return p


def _gf_div(a: int, b: int) -> int:
    """``a / b`` with log/exp tables.  Only for public values (share indices): it branches and indexes tables."""
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[_LOG[a] + 255 - _LOG[b]]


def _evaluate(coeffs: Sequence[int], x: int) -> int:
    """Horner evaluation of ``coeffs[0] + coeffs[1] x + ...`` at ``x``."""
    y = 0
    for c in reversed(coeffs):
        y = _gf_mul(y, x) ^ c
    return y


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def split(
    secret: bytes | bytearray, *, k: int, n: int, rng: Callable[[int], bytes] = secrets.token_bytes
) -> list[bytes]:
    """Split a 32-byte ``secret`` into ``n`` shares, any ``k`` of which recover it (2 <= k <= n <= 5)."""
    if not _is_int(k) or not _is_int(n):
        raise SSSError("k and n must be integers")
    if not (MIN_K <= k <= n <= MAX_N):
        raise SSSError(f"need {MIN_K} <= k <= n <= {MAX_N}")
    if not isinstance(secret, (bytes, bytearray, memoryview)):
        raise SSSError("secret must be bytes")
    secret_buf = bytearray(secret)
    try:
        if len(secret_buf) != SECRET_LEN:
            raise SSSError(f"secret must be {SECRET_LEN} bytes")
        degree = k - 1
        raw = rng(SECRET_LEN * degree)
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != SECRET_LEN * degree:
            raise SSSError("rng returned the wrong number of bytes")
        coeffs = bytearray(raw)
        poly = bytearray(k)
        outs = [bytearray(SHARE_LEN) for _ in range(n)]
        try:
            for j in range(SECRET_LEN):
                poly[0] = secret_buf[j]
                poly[1:] = coeffs[j * degree : (j + 1) * degree]
                for i, out in enumerate(outs):
                    out[1 + j] = _evaluate(poly, i + 1)
            shares = []
            for i, out in enumerate(outs):
                out[0] = i + 1
                shares.append(bytes(out))
            return shares
        finally:
            for buf in (coeffs, poly, *outs):
                buf[:] = bytes(len(buf))
    finally:
        secret_buf[:] = bytes(len(secret_buf))


def combine(shares: Sequence[bytes]) -> bytes:
    """Recover the secret from 2..5 shares with distinct indices.  Fewer than ``k`` shares give unrelated bytes."""
    if isinstance(shares, (bytes, bytearray, memoryview, str)):
        raise SSSError("shares must be a sequence of shares")
    shares = list(shares)
    if not (MIN_K <= len(shares) <= MAX_N):
        raise SSSError(f"need {MIN_K} to {MAX_N} shares")
    bufs: list[bytearray] = []
    try:
        for share in shares:
            if not isinstance(share, (bytes, bytearray, memoryview)):
                raise SSSError("each share must be bytes")
            buf = bytearray(share)
            bufs.append(buf)
            if len(buf) != SHARE_LEN:
                raise SSSError(f"each share must be {SHARE_LEN} bytes")
        xs = [buf[0] for buf in bufs]
        if 0 in xs:
            raise SSSError("share index 0 is not allowed")
        if len(set(xs)) != len(xs):
            raise SSSError("duplicate share index")
        # Lagrange basis at x = 0 depends only on the public indices: L_i = prod(x_m) / prod(x_i - x_m), m != i.
        basis = []
        for i, xi in enumerate(xs):
            num, den = 1, 1
            for m, xm in enumerate(xs):
                if m != i:
                    num = _gf_mul(num, xm)
                    den = _gf_mul(den, xi ^ xm)
            basis.append(_gf_div(num, den))
        out = bytearray(SECRET_LEN)
        try:
            for j in range(SECRET_LEN):
                acc = 0
                for buf, li in zip(bufs, basis, strict=True):
                    acc ^= _gf_mul(buf[1 + j], li)
                out[j] = acc
            return bytes(out)
        finally:
            out[:] = bytes(SECRET_LEN)
    finally:
        for buf in bufs:
            buf[:] = bytes(len(buf))
