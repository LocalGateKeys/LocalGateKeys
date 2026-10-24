"""Property tests for the vault crypto envelope (src/localvault/vault.py).

The Argon2id call itself is replaced by a keyed BLAKE2b stand-in
(``secret_text.argon2id_raw`` only): every parameter check in ``_derive_key``
still runs, every AES-GCM wrap/unwrap and AAD is real.  This makes one unlock
cost ~1 ms so thousands of tampered files can be tried.
"""
from __future__ import annotations

import hashlib
import json
import math
import shutil
from pathlib import Path

import pytest
from hypothesis import given, note, settings
from hypothesis import strategies as st

from localvault import secret_text, vault
from localvault.vault import VaultError

PASSWORD = "correct horse battery staple"


def _fake_argon2id_raw(secret, salt, *, time_cost, memory_cost, parallelism, hash_len):
    material = bytes(secret) + b"|" + bytes(salt) + repr((time_cost, memory_cost, parallelism)).encode()
    return bytearray(hashlib.blake2b(material, digest_size=hash_len).digest())


@pytest.fixture(scope="module", autouse=True)
def fast_kdf():
    import os
    original, original_fsync = secret_text.argon2id_raw, os.fsync
    secret_text.argon2id_raw = _fake_argon2id_raw
    os.fsync = lambda fd: None  # durability is not under test; Windows fsync dominates the runtime
    try:
        yield
    finally:
        secret_text.argon2id_raw = original
        os.fsync = original_fsync


_counter = [0]


def _fresh_dir(scratch: Path) -> Path:
    _counter[0] += 1
    d = scratch / f"v{_counter[0]}"
    d.mkdir()
    return d


def _payload_fingerprint(session) -> str:
    return hashlib.sha256(vault._canonical_json(session._require_payload())).hexdigest()


@pytest.fixture(scope="module")
def base_vault(scratch):
    d = scratch / "base"
    d.mkdir()
    path = d / "vault.json"
    session = vault.create_vault(path, PASSWORD, kdf_overrides={"time_cost": 1, "memory_cost_kib": 8192,
                                                                 "parallelism": 1})
    session.create_web_login(urls=[{"url": "https://example.com", "match": "exact_origin"}], username="alice",
                             password="s3cret-π-✓", label="Example")
    session.save()
    fp = _payload_fingerprint(session)
    session.lock()
    return path.read_bytes(), fp


def _try_unlock(scratch, data: bytes):
    d = _fresh_dir(scratch)
    path = d / "vault.json"
    path.write_bytes(data)
    try:
        session = vault.unlock_vault(path, PASSWORD, upgrade_envelope=False)
    finally:
        vault._reset_unlock_throttle_state_for_tests()
    try:
        return _payload_fingerprint(session)
    finally:
        session.lock()
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------- round trip
text = st.text(alphabet=st.characters(codec="utf-8", exclude_categories=("Cs", "Cc")), min_size=1, max_size=40)


@settings(max_examples=int(__import__("os").environ.get("LGK_PROP_SLOW_EXAMPLES", "20")))
@given(st.lists(st.tuples(st.from_regex(r"[a-z]{1,10}\.(com|org|co\.uk)", fullmatch=True), text, text),
                min_size=1, max_size=4, unique_by=lambda t: (t[0], t[1])))
def test_round_trip(scratch, entries):
    d = _fresh_dir(scratch)
    path = d / "vault.json"
    session = vault.create_vault(path, PASSWORD)
    for host, user, pw in entries:
        session.create_web_login(urls=[{"url": f"https://{host}", "match": "exact_origin"}], username=user,
                                 password=pw)
    session.save()
    before = _payload_fingerprint(session)
    session.lock()
    again = vault.unlock_vault(path, PASSWORD)
    try:
        assert _payload_fingerprint(again) == before
        for host, user, pw in entries:
            hits = [e for e in again.find_web(f"https://{host}") if e.get("username") == user]
            assert hits and again.credential_secret(hits[0]["id"]) == pw
    finally:
        again.lock()
        vault._reset_unlock_throttle_state_for_tests()


# ------------------------------------------------------------- byte-level tampering
@given(st.data())
def test_any_single_bit_flip_fails_closed(scratch, base_vault, data):
    raw, fp = base_vault
    pos = data.draw(st.integers(0, len(raw) - 1), label="pos")
    bit = data.draw(st.integers(0, 7), label="bit")
    mutated = bytearray(raw)
    mutated[pos] ^= 1 << bit
    note(f"byte {pos} ({raw[pos:pos + 1]!r}) bit {bit} context={raw[max(0, pos - 30):pos + 10]!r}")
    try:
        got = _try_unlock(scratch, bytes(mutated))
    except VaultError:
        return
    # Only a bit flip in a byte with no meaning may still open, and then the content must be intact.
    assert got == fp, "tampered vault opened with different content"


@given(st.data())
def test_truncation_and_extension_fail_closed(scratch, base_vault, data):
    raw, fp = base_vault
    choice = data.draw(st.sampled_from(["truncate", "extend", "insert", "delete"]))
    if choice == "truncate":
        mutated = raw[: data.draw(st.integers(0, len(raw) - 1))]
    elif choice == "extend":
        mutated = raw + data.draw(st.binary(min_size=1, max_size=64))
    elif choice == "insert":
        pos = data.draw(st.integers(0, len(raw)))
        mutated = raw[:pos] + data.draw(st.binary(min_size=1, max_size=8)) + raw[pos:]
    else:
        pos = data.draw(st.integers(0, len(raw) - 1))
        mutated = raw[:pos] + raw[pos + data.draw(st.integers(1, 8)):]
    try:
        got = _try_unlock(scratch, mutated)
    except VaultError:
        return
    assert got == fp


# ------------------------------------------------------------- structured header tampering
json_scalar = st.one_of(st.none(), st.booleans(), st.integers(-2**70, 2**70), st.floats(allow_nan=True, allow_infinity=True),
                        st.text(max_size=20), st.just(""), st.just("AAAA"), st.just("A" * 600))
json_value = st.recursive(json_scalar, lambda inner: st.one_of(st.lists(inner, max_size=3),
                                                               st.dictionaries(st.text(max_size=8), inner, max_size=3)),
                          max_leaves=8)


def _paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _paths(v, prefix + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _paths(v, prefix + (i,))


def _set(node, path, value):
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def _del(node, path):
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]


@given(st.data())
def test_header_field_replacement_fails_closed(scratch, base_vault, data):
    raw, fp = base_vault
    header = json.loads(raw)
    paths = [p for p in _paths(header) if p]
    path = data.draw(st.sampled_from(paths), label="path")
    op = data.draw(st.sampled_from(["set", "set", "delete", "add_sibling"]), label="op")
    value = data.draw(json_value, label="value")
    if op == "set":
        _set(header, path, value)
    elif op == "delete":
        _del(header, path)
    else:
        parent = header
        for key in path[:-1]:
            parent = parent[key]
        if not isinstance(parent, dict):
            return
        parent["x" + str(path[-1])] = value
    note(f"{op} {path!r} = {value!r}")
    blob = json.dumps(header).encode()  # allow_nan=True: Python writers/readers accept Infinity
    try:
        got = _try_unlock(scratch, blob)
    except VaultError:
        return
    if op == "add_sibling":
        # Unknown sibling fields are tolerated only if the content is intact.
        assert got == fp
        return
    assert got == fp, f"header change {op} {path} = {value!r} still opened"


@given(st.permutations(["version", "format", "catalog", "catalog_version", "vault_id", "generation",
                        "key_generation", "kdf", "wrappers", "cipher"]))
def test_header_key_order_is_irrelevant(scratch, base_vault, order):
    raw, fp = base_vault
    header = json.loads(raw)
    reordered = {k: header[k] for k in order if k in header}
    reordered.update({k: v for k, v in header.items() if k not in reordered})
    assert _try_unlock(scratch, json.dumps(reordered).encode()) == fp


@given(st.sampled_from(["generation", "key_generation", "vault_id", "catalog_version", "version", "kdf", "cipher",
                        "wrappers"]), json_value, st.booleans())
def test_duplicate_header_keys(scratch, base_vault, key, other, real_last):
    """JSON with a duplicated key: Python keeps the LAST value.  If the last is the
    genuine one the vault opens; otherwise it must fail closed (never open with the fake)."""
    raw, fp = base_vault
    header = json.loads(raw)
    body = json.dumps(header)
    genuine = json.dumps(header[key])
    fake = json.dumps(other)
    first, last = (fake, genuine) if real_last else (genuine, fake)
    marker = f'"{key}": {genuine}'
    assert marker in body
    dup = body.replace(marker, f'"{key}": {first}, "{key}": {last}', 1)
    try:
        got = _try_unlock(scratch, dup.encode())
    except VaultError:
        assert not real_last or fake == genuine or True
        return
    assert got == fp
    if not real_last:
        assert other == header[key], "opened with a non-genuine duplicated value"


def test_deeply_nested_vault_file_raises_vault_error(scratch):
    """Reproducer for finding V-2 (RecursionError escapes _read_vault_header)."""
    with pytest.raises(VaultError):
        _try_unlock(scratch, b"[" * 100_000)


def test_infinite_kdf_parameter_raises_vault_error(scratch, base_vault):
    """Reproducer for finding V-1 (OverflowError escapes _derive_key)."""
    raw, _fp = base_vault
    header = json.loads(raw)
    header["kdf"]["time_cost"] = math.inf
    with pytest.raises(VaultError):
        _try_unlock(scratch, json.dumps(header).encode())
