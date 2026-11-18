"""Write tests/vectors/sss/v1.json: run from the repo root with ``python tests/vectors/sss/generate.py``.

Provenance
----------
``hashicorp.json`` (written by hand, not by this script) holds the known-answer values from the ``hashicorp/vault``
``shamir`` package test file (``shamir/shamir_test.go``: ``TestField_Add``, ``TestField_Mult``,
``TestField_Divide``, ``TestPolynomial_Eval``), plus the FIPS-197 section 4.2 product ``{57} x {83} = {c1}``.
That package publishes no fixed share vectors (its split picks random x-coordinates and its interpolation test is a
random round trip), so ``v1.json`` is derived here from the same algorithm: GF(2^8) with the AES polynomial
``x^8 + x^4 + x^3 + x + 1`` (0x11b), each secret byte is the constant term of its own polynomial, share ``i`` is
the polynomial evaluated at ``x = i``, and the secret is the Lagrange interpolation at ``x = 0``.

This script is a deliberately independent, slow reference: bit-by-bit multiplication and Fermat inversion
(``a^254``), no log/exp tables, nothing imported from ``localvault``.  ``src/localvault/sss.py`` must reproduce
every share byte for byte from ``secret`` and ``coefficients``, and recombine every listed subset.

Coefficient layout (also the order ``sss.split`` consumes its ``rng`` output): ``rng(32 * (k - 1))`` is read as
``coefficients[j * (k - 1) + (d - 1)]`` = the degree-``d`` coefficient of the polynomial for secret byte ``j``.

LGKCore (Swift) and lgk-core (Kotlin) read the same files.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def gf_inv(a: int) -> int:
    r = 1
    for _ in range(254):
        r = gf_mul(r, a)
    return r


def evaluate(coeffs: list[int], x: int) -> int:
    y = 0
    for c in reversed(coeffs):
        y = gf_mul(y, x) ^ c
    return y


def interpolate0(points: list[tuple[int, int]]) -> int:
    s = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = gf_mul(num, xj)
                den = gf_mul(den, xi ^ xj)
        s ^= gf_mul(yi, gf_mul(num, gf_inv(den)))
    return s


def stream(label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"lgk-sss-v1|{label}|{counter}".encode()).digest()
        counter += 1
    return out[:length]


def make_case(name: str, secret: bytes, k: int, n: int) -> dict:
    coeffs = stream(f"{name}|coeff", 32 * (k - 1))
    shares = []
    for x in range(1, n + 1):
        ys = bytes(
            evaluate([secret[j]] + list(coeffs[j * (k - 1) : (j + 1) * (k - 1)]), x)
            for j in range(32)
        )
        shares.append(bytes([x]) + ys)
    subsets = [list(c) for r in range(k, n + 1) for c in itertools.combinations(range(1, n + 1), r)]
    for sub in subsets:
        got = bytes(interpolate0([(x, shares[x - 1][1 + j]) for x in sub]) for j in range(32))
        assert got == secret, (name, sub)
    return {
        "name": name,
        "k": k,
        "n": n,
        "secret": secret.hex(),
        "coefficients": coeffs.hex(),
        "shares": [s.hex() for s in shares],
        "combine_subsets": subsets,
    }


def main() -> None:
    cases = [
        make_case("zero-secret-2of2", bytes(32), 2, 2),
        make_case("ff-secret-2of3", b"\xff" * 32, 2, 3),
        make_case("counting-3of5", bytes(range(32)), 3, 5),
        make_case("hashed-4of5", stream("hashed-4of5|secret", 32), 4, 5),
        make_case("hashed-5of5", stream("hashed-5of5|secret", 32), 5, 5),
        make_case("hashed-3of4", stream("hashed-3of4|secret", 32), 3, 4),
    ]
    doc = {
        "format": "lgk-sss-v1",
        "field": "GF(2^8), reduction polynomial 0x11b (AES)",
        "share_layout": "bytes([x]) + 32 bytes of y, x = 1..n",
        "coefficient_layout": "coefficients[j*(k-1) + (d-1)] = degree-d coefficient for secret byte j",
        "source": "derived by tests/vectors/sss/generate.py (independent bitwise reference) from the "
        "hashicorp/vault shamir algorithm; see hashicorp.json for that package's own known answers",
        "cases": cases,
    }
    (HERE / "v1.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
