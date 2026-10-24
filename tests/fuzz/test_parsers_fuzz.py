"""Deterministic mutation fuzzing of the parsers that read untrusted bytes.

Every target below consumes data an attacker could hand to the application:
a vault file, a backup envelope or container, a transfer package, a local IPC
frame, or a scanned Google Authenticator export link.  For each one we build a
valid artifact, apply seeded random mutations (bit flips, byte substitution,
truncation, insertion, duplication, structure-aware JSON/ZIP edits) and assert
that the parser either succeeds or raises ONLY its documented error type.
Anything else (AttributeError, struct.error, UnicodeDecodeError, ...) is a
robustness bug: callers only catch the documented type, so a leak becomes an
unhandled crash in the UI or native host.

The runs are deterministic (fixed seed, fixed iteration counts) so a failure is
reproducible by re-running the test, and small (inputs stay well under 64 KiB)
so a hang cannot be caused by input size.

Iteration count: ``LGK_FUZZ_ITERATIONS`` (default 2000) scales every target.
The two targets that must run a real Argon2id derivation for every mutation
that survives header validation (vault, backup v1) use a quarter of that
budget so the whole module stays around 15-20 s and can live in the default
test run; ``-m fuzz`` selects only these tests, ``-m "not fuzz"`` skips them.

Known, documented leaks live in ``KNOWN_ISSUES``.  They are matched by
exception type + message regex, keep the suite green while the owning module
is fixed, and MUST be removed once they stop reproducing (the test fails if a
listed issue is no longer observed, mirroring ``xfail(strict=True)``).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import random
import re
import struct
import warnings
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from localvault import backup, pipe_transport, totp, transfer, vault
from localvault.backup import BackupError
from localvault.config import atomic_write_json
from localvault.protocol import MAX_LOCAL_MESSAGE, ProtocolError
from localvault.totp import TotpError
from localvault.transfer import TransferError
from localvault.vault import VaultError

pytestmark = pytest.mark.fuzz

SEED = 20261005
ITERATIONS = int(os.environ.get("LGK_FUZZ_ITERATIONS", "2000"))
KDF_BOUND_ITERATIONS = max(100, ITERATIONS // 4)
MAX_INPUT_BYTES = 48 * 1024

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "fuzz master password 12345"
BACKUP_PASSWORD = "fuzz backup password 12345"
TRANSFER_PASSWORD = "fuzz transfer password 12345"

# (target name, exception type, message regex): documented-but-unfixed leaks.
KNOWN_ISSUES: list[tuple[str, type[BaseException], str]] = []


# --------------------------------------------------------------------------
# Generic mutation helpers
# --------------------------------------------------------------------------
INTERESTING_BYTES = (
    b"\x00", b"\xff", b"\x7f", b"\x80", b'"', b"\\", b"{", b"}", b"[", b"]", b",", b":",
    b"\n", b"\r", b" ", b"0", b"-", b"9", b"e", b"=", b"+", b"/", b"\xc0", b"\xed\xa0\x80",
)
INTERESTING_INTS = (0, 1, -1, 2, 7, 8, 11, 12, 15, 16, 31, 32, 255, 256, 65535, 65536,
                    2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63, -(2**63), 10**30, -(10**30))


def mutate_bytes(rng: random.Random, data: bytes) -> bytes:
    """Apply 1-4 random byte-level mutations and keep the result bounded."""
    buf = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        choice = rng.randrange(9)
        n = len(buf)
        if choice == 0 and n:  # bit flip
            i = rng.randrange(n)
            buf[i] ^= 1 << rng.randrange(8)
        elif choice == 1 and n:  # byte replace
            buf[rng.randrange(n)] = rng.randrange(256)
        elif choice == 2 and n:  # interesting byte(s)
            i = rng.randrange(n)
            buf[i:i + 1] = rng.choice(INTERESTING_BYTES)
        elif choice == 3 and n > 1:  # delete slice
            i = rng.randrange(n)
            j = min(n, i + rng.randint(1, 16))
            del buf[i:j]
        elif choice == 4 and n:  # duplicate slice
            i = rng.randrange(n)
            j = min(n, i + rng.randint(1, 32))
            buf[i:i] = buf[i:j]
        elif choice == 5:  # insert random bytes
            i = rng.randrange(n + 1)
            buf[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        elif choice == 6 and n > 1:  # truncate
            del buf[rng.randrange(1, n):]
        elif choice == 7 and n > 1:  # swap two bytes
            i, j = rng.randrange(n), rng.randrange(n)
            buf[i], buf[j] = buf[j], buf[i]
        elif n > 1:  # drop a prefix
            del buf[:rng.randrange(1, min(n, 8))]
    return bytes(buf[:MAX_INPUT_BYTES])


def _random_b64(rng: random.Random, max_len: int = 96) -> str:
    raw = bytes(rng.randrange(256) for _ in range(rng.randint(0, max_len)))
    return base64.b64encode(raw).decode("ascii")


def _random_scalar(rng: random.Random) -> Any:
    choice = rng.randrange(10)
    if choice == 0:
        return None
    if choice == 1:
        return rng.choice([True, False])
    if choice == 2:
        return rng.choice(INTERESTING_INTS)
    if choice == 3:
        return rng.choice([0.0, -0.0, 1.5, 1e308, -1e308, float("nan"), float("inf")])
    if choice == 4:
        return ""
    if choice == 5:
        return _random_b64(rng)
    if choice == 6:
        return "x" * rng.choice([1, 15, 16, 17, 100, 1000, 5000])
    if choice == 7:
        return []
    if choice == 8:
        return {}
    return "\udcff\x00" if rng.random() < 0.5 else "\U0001f512" * rng.randint(1, 8)


def _walk_paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    paths = [prefix] if prefix else []
    if isinstance(value, dict):
        for key, child in value.items():
            paths.extend(_walk_paths(child, (*prefix, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value[:8]):
            paths.extend(_walk_paths(child, (*prefix, index)))
    return paths


def _parent(root: Any, path: tuple[Any, ...]) -> Any:
    node = root
    for key in path[:-1]:
        node = node[key]
    return node


def mutate_json(rng: random.Random, document: Any) -> Any:
    """Structure-aware mutation: delete/replace/duplicate keys, retype values."""
    doc = copy.deepcopy(document)
    if not _walk_paths(doc):
        return _random_scalar(rng)
    for _ in range(rng.randint(1, 3)):
        paths = _walk_paths(doc)
        if not paths:
            return doc
        path = rng.choice(paths)
        node = _parent(doc, path)
        choice = rng.randrange(6)
        if choice == 0:
            del node[path[-1]]
        elif choice == 1:
            node[path[-1]] = _random_scalar(rng)
        elif choice == 2:
            if isinstance(node, dict):
                node[f"{path[-1]}_{rng.randrange(1000)}"] = _random_scalar(rng)
        elif choice == 3:
            current = node[path[-1]]
            if isinstance(current, str):
                raw = mutate_bytes(rng, current.encode("utf-8", "surrogatepass"))
                node[path[-1]] = raw.decode("utf-8", "replace")
            elif isinstance(current, int) and not isinstance(current, bool):
                node[path[-1]] = current + rng.choice([-1, 1, 2**31, -(2**31), 10**20])
            else:
                node[path[-1]] = _random_scalar(rng)
        elif choice == 4:
            # Type confusion: wrap the value in a container.
            node[path[-1]] = [node[path[-1]]] if rng.random() < 0.5 else {"v": node[path[-1]]}
        elif rng.random() < 0.1:
            return _random_scalar(rng)
    return doc


def dump_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=True).encode("utf-8", "surrogatepass")


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
class LeakReport:
    def __init__(self, target: str, allowed: tuple[type[BaseException], ...]) -> None:
        self.target = target
        self.allowed = allowed
        self.leaks: list[tuple[int, BaseException]] = []
        self.successes = 0
        self.rejections = 0
        self.seen_known: set[int] = set()

    def run(self, iteration: int, action: Callable[[], Any]) -> None:
        try:
            action()
        except self.allowed:
            self.rejections += 1
        except Exception as exc:  # noqa: BLE001 - catching leaks is the point
            for index, (target, kind, pattern) in enumerate(KNOWN_ISSUES):
                if target == self.target and isinstance(exc, kind) and re.search(pattern, str(exc)):
                    self.seen_known.add(index)
                    break
            else:
                self.leaks.append((iteration, exc))
        else:
            self.successes += 1

    def assert_clean(self) -> None:
        expected_known = {
            i for i, (target, _, _) in enumerate(KNOWN_ISSUES) if target == self.target
        }
        stale = expected_known - self.seen_known
        details = []
        if self.leaks:
            kinds: dict[str, list[tuple[int, BaseException]]] = {}
            for iteration, exc in self.leaks:
                kinds.setdefault(type(exc).__name__, []).append((iteration, exc))
            for name, items in sorted(kinds.items()):
                sample = "; ".join(f"#{i}: {str(e)[:120]!r}" for i, e in items[:3])
                details.append(f"{len(items)}x {name} (e.g. {sample})")
        if stale:
            gone = ", ".join(
                f"{KNOWN_ISSUES[i][1].__name__} /{KNOWN_ISSUES[i][2]}/" for i in sorted(stale)
            )
            details.append(f"KNOWN_ISSUES no longer reproduce, remove them: {gone}")
        allowed = "/".join(a.__name__ for a in self.allowed)
        assert not details, (
            f"{self.target}: parser leaked non-{allowed} exceptions after {self.successes} accepts "
            f"and {self.rejections} clean rejections:\n  " + "\n  ".join(details)
        )
        # A fuzzer that never exercises the parser proves nothing.
        assert self.rejections > 0, f"{self.target}: no mutation was rejected"


def _fast_derive(password: str, salt: bytes, kdf: Any = None, *_args: Any, **_kwargs: Any) -> bytes:
    """Deterministic stand-in for the backup KDF that keeps its validation.

    The target of these tests is the envelope/container parser; Argon2id at the
    production cost (32 MiB, t=3) would make thousands of iterations take
    minutes.  Parameter validation (``backup._kdf_parameters``) and the salt /
    password checks are still exercised so bounds bugs remain visible; only the
    expensive hash is replaced.
    """
    if not isinstance(password, str) or not 12 <= len(password) <= 4096:
        raise BackupError("Backup password must contain at least 12 characters")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise BackupError("Malformed encryption header")
    validate = getattr(backup, "_kdf_parameters", None)
    if validate is not None and kdf is not None:
        validate(kdf)
    return hashlib.sha256(b"fuzz|" + password.encode("utf-8") + b"|" + salt).digest()


# --------------------------------------------------------------------------
# Fixtures that build valid seed artifacts
# --------------------------------------------------------------------------
@pytest.fixture
def seed_vault(tmp_path: Path) -> tuple[Path, bytes]:
    path = tmp_path / "seed" / "vault.json"
    path.parent.mkdir()
    session = vault.create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(
        origin="https://fuzz.example.test", username="alice", password="pw-1234567890"
    )
    session.lock()
    return path, path.read_bytes()


# --------------------------------------------------------------------------
# 1. Vault file parser
# --------------------------------------------------------------------------
def _mutate_either(rng: random.Random, i: int, every: int, document: Any, original: bytes) -> bytes:
    """Alternate structure-aware JSON mutation (every ``every``-th) with byte mutation."""
    if i % every == 0:
        return dump_json(mutate_json(rng, document))
    return mutate_bytes(rng, original)


def test_vault_file_parser_only_raises_vault_error(
    tmp_path: Path, seed_vault: tuple[Path, bytes]
) -> None:
    _, original = seed_vault
    document = json.loads(original)
    rng = random.Random(SEED)
    report = LeakReport("vault", (VaultError,))
    target = tmp_path / "fuzz-vault.json"

    def _open() -> None:
        session = vault.unlock_vault(target, MASTER)
        session.lock()

    for i in range(KDF_BOUND_ITERATIONS):
        target.write_bytes(_mutate_either(rng, i, 3, document, original))
        # The migration journal / generation anchor live beside the vault; start clean.
        for sidecar in target.parent.glob("fuzz-vault.*"):
            if sidecar != target:
                sidecar.unlink(missing_ok=True)
        report.run(i, _open)
    report.assert_clean()


# --------------------------------------------------------------------------
# 2. Backup v1 envelope and v2 container parsers
# --------------------------------------------------------------------------
def test_backup_envelope_parser_only_raises_backup_error(
    tmp_path: Path, seed_vault: tuple[Path, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "_derive", _fast_derive)
    vault_path, _ = seed_vault
    source = tmp_path / "seed.lgk"
    backup.export_encrypted_backup(
        source, vault_file=vault_path, settings_file=None, profile_name="Fuzz",
        backup_password=BACKUP_PASSWORD,
    )
    original = source.read_bytes()
    document = json.loads(original)
    rng = random.Random(SEED + 1)
    report = LeakReport("backup-v1", (BackupError,))
    target = tmp_path / "fuzz.lgk"

    def _verify() -> None:
        backup.verify_encrypted_backup(
            target, backup_password=BACKUP_PASSWORD, vault_password=MASTER
        )

    # verify_encrypted_backup unlocks the inner vault with a real Argon2id run
    # whenever the outer envelope survives, so this target is KDF-bound too.
    for i in range(KDF_BOUND_ITERATIONS):
        target.write_bytes(_mutate_either(rng, i, 2, document, original))
        report.run(i, _verify)
    report.assert_clean()


def _rewrite_zip(rng: random.Random, original: bytes) -> bytes:
    """Structure-aware ZIP mutation: edit, drop, rename or duplicate members."""
    with zipfile.ZipFile(io.BytesIO(original)) as src:
        members = [(info.filename, src.read(info)) for info in src.infolist()]
    choice = rng.randrange(7)
    if choice == 0 and members:
        name, data = members.pop(rng.randrange(len(members)))
        if name == "header.json":
            try:
                data = dump_json(mutate_json(rng, json.loads(data)))
            except ValueError:
                data = mutate_bytes(rng, data)
        else:
            data = mutate_bytes(rng, data)
        members.append((name, data))
    elif choice == 1 and members:
        members.pop(rng.randrange(len(members)))
    elif choice == 2 and members:
        members.append(rng.choice(members))
    elif choice == 3 and members:
        index = rng.randrange(len(members))
        hostile = ["../evil.bin", "data/../x.bin", "DATA/0.bin", "data/9999.bin", "", "\x00",
                   "/abs.bin"]
        members[index] = (rng.choice(hostile), members[index][1])
    elif choice == 4:
        junk = bytes(rng.randrange(256) for _ in range(rng.randint(0, 64)))
        members.append((f"data/{rng.randrange(100)}.bin", junk))
    elif choice == 5 and members:
        rng.shuffle(members)
    out = io.BytesIO()
    compression = zipfile.ZIP_DEFLATED if choice == 6 else zipfile.ZIP_STORED
    with warnings.catch_warnings():
        # Duplicate member names are a deliberate hostile input; zipfile warns.
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(out, "w", compression=compression) as dst:
            for name, data in members:
                dst.writestr(name, data)
    return out.getvalue()


def test_full_backup_container_parser_only_raises_backup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup, "_derive", _fast_derive)
    profile = tmp_path / "profile"
    profile.mkdir()
    session = vault.create_vault(profile / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://fuzz.example.test", username="bob", password="pw-0987654321")
    session.lock()
    atomic_write_json(profile / "settings.json", {})
    source = tmp_path / "seed-full.lgk"
    backup.export_full_backup(
        source, profile_dir=profile, profile_name="Fuzz", backup_password=BACKUP_PASSWORD
    )
    original = source.read_bytes()
    rng = random.Random(SEED + 2)
    report = LeakReport("backup-v2", (BackupError,))
    target = tmp_path / "fuzz-full.lgk"

    def _preflight() -> None:
        backup.preflight_full_backup(target, backup_password=BACKUP_PASSWORD)

    for i in range(ITERATIONS):
        blob = _rewrite_zip(rng, original) if i % 2 == 0 else mutate_bytes(rng, original)
        target.write_bytes(blob)
        report.run(i, _preflight)
    report.assert_clean()


# --------------------------------------------------------------------------
# 3. Transfer package parser
# --------------------------------------------------------------------------
def test_transfer_package_parser_only_raises_transfer_error(
    tmp_path: Path, seed_vault: tuple[Path, bytes]
) -> None:
    vault_path, _ = seed_vault
    session = vault.unlock_vault(vault_path, MASTER)
    item_id = session.items.create_note("Fuzz note", "fuzz body")
    package = tmp_path / "seed.lgt"
    transfer.export_transfer(session, package, TRANSFER_PASSWORD, ids=[item_id])
    session.lock()
    original = package.read_bytes()
    document = json.loads(original)
    rng = random.Random(SEED + 3)
    report = LeakReport("transfer", (TransferError,))
    target = tmp_path / "fuzz.lgt"

    def _inspect() -> None:
        transfer.inspect_transfer(target)

    for i in range(ITERATIONS):
        target.write_bytes(_mutate_either(rng, i, 2, document, original))
        report.run(i, _inspect)
    report.assert_clean()


# --------------------------------------------------------------------------
# 4. Local IPC frame parser
# --------------------------------------------------------------------------
def test_pipe_frame_parser_only_raises_protocol_error() -> None:
    rng = random.Random(SEED + 4)
    report = LeakReport("pipe-frame", (ProtocolError,))
    seeds = [
        pipe_transport._encode({"action": "ping"}),
        pipe_transport._encode(
            {"action": "fill", "origin": "https://example.test", "token": "a" * 64}
        ),
        pipe_transport._encode(
            {"nested": {"deep": [1, 2, {"x": None}]}, "unicode": "\U0001f512 ünïcödé"}
        ),
        pipe_transport._encode({}),
    ]
    lengths = [0, 1, MAX_LOCAL_MESSAGE, MAX_LOCAL_MESSAGE + 1, 2**32 - 1]
    bodies = [b"[]", b"null", b"1", b'"s"', b"\xff\xfe", b"{", b"{}" * 3]
    for i in range(ITERATIONS):
        seed = rng.choice(seeds)
        kind = rng.randrange(5)
        if kind == 0:
            blob = mutate_bytes(rng, seed)
        elif kind == 1:
            # Valid JSON body behind a lying length prefix.
            body = seed[4:]
            blob = struct.pack("!I", rng.choice([*lengths, len(body) - 1, len(body) + 1])) + body
        elif kind == 2:
            # Correct length prefix around an arbitrary (non-object / non-UTF-8) body.
            body = rng.choice([*bodies, dump_json(_random_scalar(rng))])
            blob = struct.pack("!I", len(body)) + body
        elif kind == 3:
            blob = seed[:rng.randrange(len(seed) + 1)]
        else:
            blob = seed + bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        report.run(i, lambda frame=blob: pipe_transport._decode(frame))
    report.assert_clean()


# --------------------------------------------------------------------------
# 5. otpauth-migration (Google Authenticator export) parser
# --------------------------------------------------------------------------
def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def _field(number: int, wire: int, payload: bytes | int) -> bytes:
    key = _varint((number << 3) | wire)
    if wire == 0:
        assert isinstance(payload, int)
        return key + _varint(payload)
    assert isinstance(payload, bytes)
    return key + _varint(len(payload)) + payload


def _migration_payload(rng: random.Random, accounts: int) -> bytes:
    body = bytearray()
    for index in range(accounts):
        secret = bytes(rng.randrange(256) for _ in range(rng.choice([10, 16, 20, 32])))
        account = (
            _field(1, 2, secret)
            + _field(2, 2, f"Issuer{index}:user{index}@example.test".encode())
            + _field(3, 2, f"Issuer{index}".encode())
            + _field(4, 0, rng.choice([0, 1, 2, 3]))
            + _field(5, 0, rng.choice([0, 1, 2]))
            + _field(6, 0, rng.choice([0, 1, 2]))
        )
        body += _field(1, 2, bytes(account))
    body += _field(2, 0, 1) + _field(3, 0, 0) + _field(4, 0, rng.randrange(2**31)) + _field(5, 0, 1)
    return bytes(body)


def _migration_uri(raw: bytes) -> str:
    return "otpauth-migration://offline?data=" + base64.urlsafe_b64encode(raw).decode("ascii")


def _u64(rng: random.Random) -> int:
    return rng.choice(INTERESTING_INTS) & (2**64 - 1)


def _random_protobuf(rng: random.Random) -> bytes:
    """Arbitrary fields with random numbers, wire types and (lying) lengths."""
    parts = bytearray()
    for _ in range(rng.randint(1, 6)):
        number, wire = rng.randint(0, 20), rng.randint(0, 7)
        parts += _varint((number << 3) | wire)
        if wire == 0:
            parts += _varint(_u64(rng))
        elif wire in (2, 3, 4, 6, 7):
            payload = bytes(rng.randrange(256) for _ in range(rng.randint(0, 40)))
            parts += _varint(rng.choice([len(payload), len(payload) + 1, 2**40, 0])) + payload
        else:
            parts += bytes(rng.randrange(256) for _ in range(rng.randint(0, 8)))
    return bytes(parts)


def _hostile_account(rng: random.Random) -> bytes:
    """Account whose sub-fields have huge varints, wrong wire types, giant secrets."""
    account = bytearray()
    for sub in rng.sample(range(1, 8), rng.randint(1, 6)):
        if rng.random() < 0.5:
            account += _field(sub, 0, _u64(rng))
        else:
            size = rng.choice([0, 1, 9, 10, 64, 600])
            account += _field(sub, 2, bytes(rng.randrange(256) for _ in range(size)))
    return _field(1, 2, bytes(account)) + _field(2, 0, _u64(rng)) + _field(3, 0, _u64(rng))


def test_otpauth_migration_parser_only_raises_totp_error() -> None:
    rng = random.Random(SEED + 5)
    report = LeakReport("otpauth-migration", (TotpError,))
    seeds = [_migration_payload(rng, n) for n in (1, 2, 5)]
    for seed in seeds:  # the seeds themselves must parse
        parsed = totp.parse_migration_uri(_migration_uri(seed))
        assert parsed["accounts"] or parsed["skipped"]

    for i in range(ITERATIONS):
        seed = rng.choice(seeds)
        kind = rng.randrange(4)
        if kind == 0:
            uri = _migration_uri(mutate_bytes(rng, seed))
        elif kind == 1:
            # Mutate the URI text itself (scheme, host, query, Base64 alphabet).
            uri = mutate_bytes(rng, _migration_uri(seed).encode("utf-8")).decode("utf-8", "replace")
        elif kind == 2:
            uri = _migration_uri(_random_protobuf(rng))
        else:
            uri = _migration_uri(_hostile_account(rng))
        report.run(i, lambda link=uri: totp.parse_migration_uri(link))
    report.assert_clean()


# --------------------------------------------------------------------------
# 6. Password-manager import parsers (every format a switching buyer imports)
# --------------------------------------------------------------------------
IMPORT_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "imports"
IMPORT_ITERATIONS = max(200, ITERATIONS // 2)


def _zip_tree(root: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
    return buffer.getvalue()


def _import_seeds() -> dict[str, tuple[bytes, Callable[[bytes], Any]]]:
    """(seed bytes, loader) per import target; loaders are called directly, not via load_records."""
    from localvault.importers import (
        bitwarden,
        chrome,
        dashlane,
        kdbx,
        keepass_csv,
        lastpass,
        onepassword,
        protonpass,
    )

    fixture = IMPORT_FIXTURES.joinpath
    one_pux = io.BytesIO()
    with zipfile.ZipFile(one_pux, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(fixture("onepassword", "export.data"), "export.data")
    protected = bitwarden.encrypt_bitwarden_export(
        json.loads(fixture("bitwarden.json").read_text(encoding="utf-8")), "fuzz export password", iterations=1000)
    return {
        "bitwarden-json": (fixture("bitwarden.json").read_bytes(), bitwarden.load_bitwarden_json),
        "bitwarden-protected": (dump_json(protected),
                                lambda data: bitwarden.load_bitwarden_json(data, password="fuzz export password")),
        "bitwarden-csv": (fixture("bitwarden.csv").read_bytes(), bitwarden.load_bitwarden_csv),
        "1pux": (one_pux.getvalue(), onepassword.load_1pux),
        "1password-csv": (fixture("onepassword.csv").read_bytes(), onepassword.load_1password_csv),
        "lastpass-csv": (fixture("lastpass.csv").read_bytes(), lastpass.load_lastpass_csv),
        "chrome-csv": (fixture("chrome.csv").read_bytes(), chrome.load_browser_csv),
        "firefox-csv": (fixture("firefox.csv").read_bytes(), chrome.load_browser_csv),
        "generic-csv": (fixture("keepass2.csv").read_bytes(), chrome.load_generic_csv),
        "keepass-csv": (fixture("keepassxc.csv").read_bytes(), keepass_csv.load_keepass_csv),
        "keepass-xml": (fixture("keepass.xml").read_bytes(), kdbx.load_keepass_xml),
        "protonpass-zip": (_zip_tree(fixture("protonpass")), protonpass.load_protonpass_json),
        "protonpass-json": (fixture("protonpass", "Proton Pass", "data.json").read_bytes(),
                            protonpass.load_protonpass_json),
        "protonpass-csv": (fixture("protonpass.csv").read_bytes(), protonpass.load_protonpass_csv),
        "dashlane-zip": (_zip_tree(fixture("dashlane")), dashlane.load_dashlane_zip),
        "dashlane-csv": (fixture("dashlane", "payments.csv").read_bytes(), dashlane.load_dashlane_csv),
    }


def _mutate_import(rng: random.Random, i: int, original: bytes) -> bytes:
    """JSON-aware, ZIP-aware or byte-level mutation depending on the seed."""
    if original[:2] == b"PK" and i % 2 == 0:
        with zipfile.ZipFile(io.BytesIO(original)) as src:
            members = [(info.filename, src.read(info)) for info in src.infolist()]
        name, data = members.pop(rng.randrange(len(members)))
        try:
            data = dump_json(mutate_json(rng, json.loads(data)))
        except ValueError:
            data = mutate_bytes(rng, data)
        members.append((name if rng.random() < 0.9 else rng.choice(["", "../x", "data.json", "export.data"]), data))
        out = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
                for member, payload in members:
                    dst.writestr(member, payload)
        return out.getvalue()
    if original.lstrip()[:1] == b"{" and i % 3 == 0:
        return dump_json(mutate_json(rng, json.loads(original)))
    return mutate_bytes(rng, original)


@pytest.mark.parametrize("target", sorted(_import_seeds()))
def test_import_parsers_only_raise_importer_error(target: str) -> None:
    from localvault.import_workflow import ImportWorkflowError, normalise_records
    from localvault.importers import ImporterError
    from localvault.importers.detect import detect_format

    original, loader = _import_seeds()[target]
    loader(original)  # the seed itself must parse
    rng = random.Random(SEED + 6 + sum(map(ord, target)))
    report = LeakReport(f"import:{target}", (ImporterError, ImportWorkflowError))
    iterations = IMPORT_ITERATIONS // 8 if target == "bitwarden-protected" else IMPORT_ITERATIONS

    def _parse(blob: bytes) -> None:
        detect_format(Path("fuzz.bin"), blob)
        result = loader(blob)
        # The planning step must also cope with whatever a parser accepted.
        normalise_records(result.records)

    for i in range(iterations):
        blob = _mutate_import(rng, i, original)
        report.run(i, lambda blob=blob: _parse(blob))
    report.assert_clean()


def test_accepted_imports_always_apply(tmp_path: Path) -> None:
    """Whatever a parser accepts must plan and apply; one bad row would abort the whole import."""
    from localvault.import_workflow import apply_import_plan, plan_records
    from localvault.importers import ImporterError

    session = vault.create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    applied = 0
    for target, (original, loader) in sorted(_import_seeds().items()):
        if target == "bitwarden-protected":
            continue
        rng = random.Random(SEED + 7 + sum(map(ord, target)))
        for i in range(max(20, IMPORT_ITERATIONS // 25)):
            try:
                result = loader(_mutate_import(rng, i, original))
            except ImporterError:
                continue
            plan = plan_records(session, result.records)
            plan.review()
            try:
                with session.transaction():  # roll back so every iteration starts from an empty vault
                    apply_import_plan(session, plan)
                    applied += 1
                    raise _Rollback
            except _Rollback:
                pass
    assert applied > 100


class _Rollback(Exception):
    pass
