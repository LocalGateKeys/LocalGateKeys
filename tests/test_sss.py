"""Shamir secret sharing over GF(256) (``localvault.sss``): vectors, round trips, secrecy, input checks."""

from __future__ import annotations

import itertools
import json
import random
from pathlib import Path

import pytest

from localvault import sss

VECTORS = Path(__file__).resolve().parent / "vectors" / "sss"
SECRET = bytes(range(100, 132))


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _seeded_rng(seed: int):
    return random.Random(seed).randbytes  # noqa: S311 - deterministic seed on purpose (no flakes)


def _fixed_rng(data: bytes):
    calls = []

    def rng(size: int) -> bytes:
        calls.append(size)
        assert size == len(data)
        return data

    rng.calls = calls
    return rng


# --- hashicorp/vault shamir known answers -------------------------------------------------------------------------


def test_hashicorp_field_vectors():
    v = _load("hashicorp.json")
    for case in v["add"]:
        assert case["a"] ^ case["b"] == case["out"]
    for case in v["mult"]:
        assert sss._gf_mul(case["a"], case["b"]) == case["out"], case
    for case in v["div"]:
        assert sss._gf_div(case["a"], case["b"]) == case["out"], case


def test_hashicorp_polynomial_eval_at_zero_is_intercept():
    case = _load("hashicorp.json")["polynomial_eval"][0]
    for coeff in (0, 1, 0x53, 0xFF):
        assert sss._evaluate([case["intercept"], coeff], case["x"]) == case["out"]


def test_mult_matches_bitwise_reference_for_all_pairs():
    def ref(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
            b >>= 1
        return p

    for a in range(256):
        for b in range(256):
            assert sss._gf_mul(a, b) == ref(a, b)


def test_division_inverts_multiplication():
    for a in range(256):
        for b in range(1, 256):
            assert sss._gf_div(sss._gf_mul(a, b), b) == a
    with pytest.raises(ZeroDivisionError):
        sss._gf_div(1, 0)


# --- derived share vectors ----------------------------------------------------------------------------------------


def test_v1_vectors_split_byte_for_byte():
    cases = _load("v1.json")["cases"]
    assert len(cases) >= 6
    for case in cases:
        rng = _fixed_rng(bytes.fromhex(case["coefficients"]))
        shares = sss.split(bytes.fromhex(case["secret"]), k=case["k"], n=case["n"], rng=rng)
        assert [s.hex() for s in shares] == case["shares"], case["name"]
        assert rng.calls == [32 * (case["k"] - 1)]


def test_v1_vectors_combine_every_listed_subset():
    for case in _load("v1.json")["cases"]:
        shares = [bytes.fromhex(s) for s in case["shares"]]
        for subset in case["combine_subsets"]:
            picked = [shares[x - 1] for x in subset]
            assert sss.combine(picked) == bytes.fromhex(case["secret"]), (case["name"], subset)
            assert sss.combine(list(reversed(picked))) == bytes.fromhex(case["secret"])


# --- round trips --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("k,n", [(k, n) for n in range(2, 6) for k in range(2, n + 1)])
def test_any_k_of_n_combine_to_secret(k, n):
    shares = sss.split(SECRET, k=k, n=n)
    assert len(shares) == n
    assert [s[0] for s in shares] == list(range(1, n + 1))
    assert all(len(s) == 33 and isinstance(s, bytes) for s in shares)
    for r in range(k, n + 1):
        for subset in itertools.combinations(shares, r):
            assert sss.combine(subset) == SECRET
            assert sss.combine(list(reversed(subset))) == SECRET


def test_default_rng_gives_fresh_shares_each_time():
    assert sss.split(SECRET, k=2, n=3) != sss.split(SECRET, k=2, n=3)


# --- secrecy: k-1 shards reveal nothing ---------------------------------------------------------------------------


def _chi_square(counts: list[int], total: int) -> float:
    expected = total / 256
    return sum((c - expected) ** 2 / expected for c in counts)


# df = 255: the upper 0.1% point of chi-square is about 330.5, the lower 0.1% point about 190.
# The seeds are fixed, so each run sees the same samples and the test cannot flake.
CHI_HIGH = 330.5
CHI_LOW = 190.0


@pytest.mark.parametrize("k", [3, 4, 5])
def test_k_minus_1_shards_reconstruct_uniform_bytes(k):
    secret = bytes(32)  # the most structured secret possible
    rng = _seeded_rng(0x5EED_0000 + k)
    counts = [0] * 256
    hits = 0
    trials = 1000
    for _ in range(trials):
        shares = sss.split(secret, k=k, n=5, rng=rng)
        guess = sss.combine(shares[: k - 1])
        for byte in guess:
            counts[byte] += 1
        hits += sum(1 for a, b in zip(guess, secret, strict=True) if a == b)
    stat = _chi_square(counts, trials * 32)
    assert CHI_LOW < stat < CHI_HIGH, stat
    # A uniform guess matches each secret byte with probability 1/256: 125 expected out of 32000.
    assert 70 < hits < 190, hits


@pytest.mark.parametrize("k", [2, 3, 4, 5])
def test_k_minus_1_shard_values_are_uniform(k):
    secret = b"\xa5" * 32
    rng = _seeded_rng(0xC0FFEE + k)
    counts = [0] * 256
    trials = 1000
    for _ in range(trials):
        shares = sss.split(secret, k=k, n=5, rng=rng)
        for share in shares[: k - 1]:
            for byte in share[1:]:
                counts[byte] += 1
    stat = _chi_square(counts, trials * 32 * (k - 1))
    assert CHI_LOW < stat < CHI_HIGH, stat


def test_single_share_is_a_bijection_of_the_coefficient():
    """Exhaustive perfect-secrecy check for k = 2: for every secret byte, the 256 coefficients hit all 256 values."""
    for x in range(1, 6):
        for secret_byte in range(256):
            assert len({sss._evaluate([secret_byte, a], x) for a in range(256)}) == 256


# --- input checks -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("k,n", [(1, 3), (0, 2), (-1, 2), (2, 6), (6, 6), (4, 3), (3, 2), (2, 1)])
def test_split_rejects_bad_parameters(k, n):
    with pytest.raises(sss.SSSError):
        sss.split(SECRET, k=k, n=n)


@pytest.mark.parametrize("k,n", [(True, 3), (2.0, 3), (2, "3")])
def test_split_rejects_non_int_parameters(k, n):
    with pytest.raises(sss.SSSError):
        sss.split(SECRET, k=k, n=n)


@pytest.mark.parametrize("secret", [b"", bytes(31), bytes(33), "x" * 32])
def test_split_rejects_bad_secret(secret):
    with pytest.raises(sss.SSSError):
        sss.split(secret, k=2, n=3)


def test_split_rejects_bad_rng_output():
    with pytest.raises(sss.SSSError):
        sss.split(SECRET, k=3, n=5, rng=lambda size: bytes(size - 1))
    with pytest.raises(sss.SSSError):
        sss.split(SECRET, k=3, n=5, rng=lambda size: "x" * size)


def test_sss_error_is_value_error():
    assert issubclass(sss.SSSError, ValueError)


def test_combine_rejects_duplicate_indices():
    shares = sss.split(SECRET, k=2, n=3)
    with pytest.raises(sss.SSSError):
        sss.combine([shares[0], shares[0]])
    altered = bytes([shares[0][0]]) + shares[1][1:]
    with pytest.raises(sss.SSSError):
        sss.combine([shares[0], altered, shares[2]])


def test_combine_rejects_bad_shares():
    shares = sss.split(SECRET, k=2, n=3)
    for bad in (
        [],
        [shares[0]],
        [shares[0], shares[1][:-1]],
        [shares[0], shares[1] + b"\x00"],
        [shares[0], b"\x00" + shares[1][1:]],
        [shares[0], "not bytes"],
        sss.split(SECRET, k=2, n=5) + [b"\x06" + bytes(32)],
    ):
        with pytest.raises(sss.SSSError):
            sss.combine(bad)


def test_combine_accepts_bytearray_and_memoryview():
    shares = sss.split(SECRET, k=2, n=2)
    assert sss.combine([bytearray(shares[0]), memoryview(shares[1])]) == SECRET
