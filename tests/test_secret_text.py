"""SecretText and the zero-copy Argon2id call."""
from __future__ import annotations

import hmac
import pickle

import pytest
from argon2.low_level import Type, hash_secret_raw

from localvault import secret_text
from localvault.secret_text import SecretText, argon2id_raw, as_secret
from localvault.vault import VaultError, _derive_key

PASSWORD = "correct horse battery staple"


def test_from_str_holds_utf8_and_counts_characters() -> None:
    s = SecretText.from_str("ñ日")
    assert bytes(s.buffer) == "ñ日".encode()
    assert s.char_count == 2


def test_wipe_zeroes_in_place_and_blocks_reuse() -> None:
    s = SecretText.from_str("hunter2-hunter2")
    buf = s.buffer
    s.wipe()
    s.wipe()  # idempotent
    assert buf == bytearray(len(buf))
    with pytest.raises(ValueError, match="secret was wiped"):
        s.buffer
    with pytest.raises(ValueError, match="secret was wiped"):
        s.char_count
    with pytest.raises(ValueError, match="secret was wiped"):
        s.equals(SecretText.from_str("x"))


def test_with_block_wipes_on_exception() -> None:
    holder: list[SecretText] = []
    with pytest.raises(RuntimeError):
        with SecretText.from_str("abcdefghijkl") as s:
            holder.append(s)
            raise RuntimeError("boom")
    with pytest.raises(ValueError):
        holder[0].buffer


def test_str_repr_eq_pickle_never_reveal() -> None:
    s = SecretText.from_str("abcdefghijkl")
    assert repr(s) == "SecretText(***)"
    with pytest.raises(TypeError):
        str(s)
    with pytest.raises(TypeError):
        s == s  # noqa: B015
    with pytest.raises(TypeError):
        hash(s)
    with pytest.raises(TypeError):
        pickle.dumps(s)


def test_equals_is_constant_time_compare(monkeypatch) -> None:
    calls: list[int] = []
    real = hmac.compare_digest
    monkeypatch.setattr(hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    assert SecretText.from_str("same-secret-1").equals(SecretText.from_str("same-secret-1"))
    assert not SecretText.from_str("same-secret-1").equals(SecretText.from_str("same-secret-2"))
    assert len(calls) == 2


def test_as_secret_reports_ownership() -> None:
    owned, owns = as_secret("abcdefghijkl")
    assert owns and owned.char_count == 12
    given = SecretText.from_str("abcdefghijkl")
    same, owns = as_secret(given)
    assert same is given and not owns


def test_argon2id_raw_matches_hash_secret_raw() -> None:
    salt = b"\x01" * 16
    expected = hash_secret_raw(secret=PASSWORD.encode(), salt=salt, time_cost=1, memory_cost=8192,
                               parallelism=1, hash_len=32, type=Type.ID)
    got = argon2id_raw(bytearray(PASSWORD.encode()), salt, time_cost=1, memory_cost=8192,
                       parallelism=1, hash_len=32)
    assert isinstance(got, bytearray)
    assert got == bytearray(expected)


def test_derive_key_matches_hash_secret_raw_for_non_ascii() -> None:
    import base64
    password = "Pässwörd-ñ-日本語-✓✓✓"
    salt = b"\x02" * 16
    kdf = {"name": "argon2id", "salt": base64.b64encode(salt).decode(), "time_cost": 1,
           "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
    expected = hash_secret_raw(secret=password.encode("utf-8"), salt=salt, time_cost=1, memory_cost=8192,
                               parallelism=1, hash_len=32, type=Type.ID)
    secret = SecretText.from_str(password)
    assert _derive_key(secret, kdf) == bytearray(expected)
    # A SecretText passed in stays usable; a str is accepted too.
    assert _derive_key(secret, kdf) == bytearray(expected)
    assert _derive_key(password, kdf) == bytearray(expected)


def test_argon2id_raw_wipes_cffi_output(monkeypatch) -> None:
    captured: list = []
    real_ffi = secret_text.ffi

    class Spy:
        def __getattr__(self, name):
            return getattr(real_ffi, name)

        def new(self, *args, **kwargs):
            buf = real_ffi.new(*args, **kwargs)
            captured.append(buf)
            return buf

    monkeypatch.setattr(secret_text, "ffi", Spy())
    got = argon2id_raw(bytearray(PASSWORD.encode()), b"\x01" * 16, time_cost=1, memory_cost=8192,
                       parallelism=1, hash_len=32)
    out = captured[0]
    assert bytes(out[0:32]) == b"\0" * 32
    assert got != bytearray(32)


def test_argon2id_raw_failure_carries_no_secret() -> None:
    with pytest.raises(RuntimeError, match="Argon2 failed") as info:
        argon2id_raw(bytearray(b"top-secret-value"), b"\x01" * 16, time_cost=1, memory_cost=1,
                     parallelism=1, hash_len=32)
    assert "top-secret" not in str(info.value)


def test_lone_surrogate_password_fails_with_fixed_message() -> None:
    import base64
    bad = "abcdefghijk\ud83dl"
    with pytest.raises(ValueError) as info:
        SecretText.from_str(bad)
    assert str(info.value) == "secret is not valid text"
    assert info.value.__cause__ is None and info.value.__suppress_context__

    kdf = {"name": "argon2id", "salt": base64.b64encode(b"\x02" * 16).decode(), "time_cost": 1,
           "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
    with pytest.raises(VaultError) as info:
        _derive_key(bad, kdf)
    exc = info.value
    assert "\ud83d" not in str(exc) and "position" not in str(exc)
    assert exc.__cause__ is None and exc.__suppress_context__
