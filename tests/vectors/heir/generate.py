"""Write tests/vectors/heir/v1.json: run from the repo root with ``python tests/vectors/heir/generate.py``.

The emergency access files as the desktop writes them (``heir.py``, ``heir_flow.py``, ``envelope.py``; byte rules in
``docs/formats/LGKHEIR_V1.md``), made from fixed keys so they are reproducible.  lgk-core (Kotlin) and LGKCore (Swift)
read the same file and must:

- read every ``packages`` entry to the listed shard facts, combine any ``k`` of them to ``entropy`` (whose phrase is
  ``phrase``), and re-seal each package byte for byte from ``signing_seed``, ``package_ids`` and the plan facts;
- derive ``check``, ``backup_public`` and ``holder_keys`` from the entropy / shares;
- re-make ``request`` byte for byte from the requester's seeds (and verify its holder proof with the holder key),
  the same for ``deny`` and for ``grant`` (fixed ephemeral key), and open ``grant`` with the requester's box key;
- read ``descriptor`` (a backup descriptor signed by the plan key) as valid;
- refuse every ``refused`` package with its ``reason``;
- reproduce ``synced`` (``heir.synced_record`` of ``record``) and every ``merges`` case (``heir.merge_synced`` with
  a phone's stored record: no ``folder`` and ``home``), or refuse it with ``conflict`` / ``malformed``.

``request``, ``deny`` and ``grant`` are written by the desktop's own writers (``request_access``, ``_write_deny``,
``_seal_grant``) with only their uuid and ephemeral-key seams fixed, so a payload change there changes this file.
``tests/test_heir_vectors.py`` regenerates the file in memory and compares it with the committed one.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import tempfile
import types
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

from localvault import envelope, heir, heir_flow, sss  # noqa: E402
from localvault.vault import phrase_from_entropy  # noqa: E402

HERE = Path(__file__).resolve().parent


def _seed(label: str, size: int = 32) -> bytes:
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"lgk-heir-vectors|{label}|{counter}".encode()).digest()
        counter += 1
    return out[:size]


ENTROPY = _seed("entropy")
PLAN_ID = "5d1f9a3c-7b2e-4c80-9d41-2a6e8f0b1c37"
CREATED = 1_800_000_000
OWNER = "Ελένη Π."
HOLDERS = ["Νίκος", "Anna", "Ben"]
K, N, WAIT = 2, 3, 7
SIGNING_SEED = _seed("plan-signing")
SALT = _seed("check-salt", 16)
PACKAGE_IDS = ["0b8c6f2e-1d4a-4e57-8c3b-9a0f1e2d3c41", "1c9d7a3f-2e5b-4f68-9d4c-0b1a2f3e4d52",
               "2dae8b40-3f6c-4a79-ae5d-1c2b3a4f5e63"]
COEFFS = _seed("coefficients", 32 * (K - 1))

REQUESTER_SIGNING = _seed("requester-signing")
REQUESTER_BOX = _seed("requester-box")
REQUEST_ID = "6e2f0b4d-8c3a-4d91-be52-3b7f9a1c0d48"
REQUEST_CREATED = 1_800_100_000
REQUEST_HOLDER = 2  # Anna

DENY_ID = "7f301c5e-9d4b-4ea2-8f63-4c8a0b2d1e59"
DENY_CREATED = 1_800_200_000
GRANT_ID = "8a412d6f-ae5c-4fb3-9074-5d9b1c3e2f6a"
GRANT_CREATED = 1_800_300_000
GRANT_EPHEMERAL = _seed("grant-ephemeral")
DESCRIPTOR_ID = "9b523e70-bf6d-40c4-a185-6eac2d4f3a7b"
DESCRIPTOR_WRITTEN = 1_800_050_000


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _key(seed: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _plan() -> dict[str, Any]:
    key = _key(SIGNING_SEED)
    shares = sss.split(ENTROPY, k=K, n=N, rng=lambda size: COEFFS[:size])
    check = heir.entropy_check(ENTROPY, plan_id=PLAN_ID, salt=SALT)
    packages = []
    for holder, share, package_id in zip(HOLDERS, shares, PACKAGE_IDS, strict=True):
        payload = {"kind": heir.KIND, "plan_id": PLAN_ID, "index": share[0], "holder": holder, "k": K, "n": N,
                   "wait_days": WAIT, "created": CREATED, "share": b64(share), "check_salt": b64(SALT),
                   "check": b64(check)}
        packages.append(envelope.seal_signed(heir.FORMAT, heir.VERSION, package_id=package_id, sender=OWNER,
                                             payload=payload, signing_key=key))
    for data in packages:
        heir.read_package(data)
    assert heir.combine_packages(packages[:2]) == ENTROPY
    holder_keys = [heir.holder_key(share, plan_id=PLAN_ID, salt=SALT) for share in shares]
    backup_public = heir.backup_public_key(ENTROPY, plan_id=PLAN_ID, salt=SALT)
    record = {"version": 1, "plan_id": PLAN_ID, "k": K, "n": N, "holders": HOLDERS, "wait_days": WAIT,
              "folder": "C:\\Shared\\Family", "created": CREATED, "owner": OWNER,
              "signer": b64(key.public_key().public_bytes_raw()), "signing_key": b64(SIGNING_SEED),
              "check_salt": b64(SALT), "check": b64(check), "backup_public": b64(backup_public),
              "holder_keys": [b64(h) for h in holder_keys], "home": True, "denied": [DENY_ID]}
    heir._parse(record)
    return {"shares": shares, "check": check, "packages": packages, "holder_keys": holder_keys,
            "backup_public": backup_public, "record": record, "key": key}


class _Fixed:
    """The writers' random seams (``uuid.uuid4`` and the grant's ephemeral key) fixed, so the real desktop code
    writes the vector files: a change to their payloads in ``heir_flow`` changes ``v1.json`` and fails the test."""

    def __init__(self, package_id: str, ephemeral: bytes | None = None) -> None:
        self._patches = [mock.patch.object(heir_flow.uuid, "uuid4", return_value=uuid.UUID(package_id))]
        if ephemeral is not None:
            fixed = X25519PrivateKey.from_private_bytes(ephemeral)
            self._patches.append(mock.patch.object(heir_flow, "X25519PrivateKey",
                                                   types.SimpleNamespace(generate=lambda: fixed)))

    def __enter__(self) -> None:
        for p in self._patches:
            p.start()

    def __exit__(self, *exc: object) -> None:
        for p in reversed(self._patches):
            p.stop()


def _identity() -> heir_flow.RequesterIdentity:
    return heir_flow.RequesterIdentity(_key(REQUESTER_SIGNING), X25519PrivateKey.from_private_bytes(REQUESTER_BOX))


def _request(plan: dict[str, Any]) -> bytes:
    """``heir_flow.request_access`` itself, into a scratch folder."""
    with tempfile.TemporaryDirectory() as folder, _Fixed(REQUEST_ID):
        path = heir_flow.request_access(folder, plan["packages"][REQUEST_HOLDER - 1], _identity(),
                                        now=REQUEST_CREATED)
        return path.read_bytes()


def _deny(plan: dict[str, Any]) -> bytes:
    """``heir_flow._write_deny`` itself (what ``deny`` and the lost-deny rewrite call)."""
    parsed, key, _holder_keys = heir._parse(plan["record"])
    with tempfile.TemporaryDirectory() as folder, _Fixed(DENY_ID):
        return heir_flow._write_deny(Path(folder), parsed, key, REQUEST_ID, DENY_CREATED).read_bytes()


def _grant(plan: dict[str, Any]) -> bytes:
    """``heir_flow._seal_grant`` itself (what ``grant_now`` writes)."""
    parsed, key, _holder_keys = heir._parse(plan["record"])
    identity = _identity()
    request = heir_flow.Request(request_id=REQUEST_ID, plan_id=PLAN_ID, holder_index=REQUEST_HOLDER,
                                requester=HOLDERS[REQUEST_HOLDER - 1], signer=identity.signer,
                                box_public=identity.box_public, created=REQUEST_CREATED, proof=b"")
    with _Fixed(GRANT_ID, GRANT_EPHEMERAL):
        return heir_flow._seal_grant(parsed, key, request, ENTROPY, now=GRANT_CREATED)


def _descriptor(plan: dict[str, Any]) -> bytes:
    payload = {"kind": heir_flow.BACKUP_KIND, "plan_id": PLAN_ID, "file": "backup-20270115-080000-0a1b2c3d.lgk",
               "size": 123456, "sha256": hashlib.sha256(b"backup").hexdigest(), "written_at": DESCRIPTOR_WRITTEN,
               "backup_public": b64(plan["backup_public"])}
    return envelope.seal_signed(heir.FORMAT, heir.VERSION, package_id=DESCRIPTOR_ID, sender="", payload=payload,
                                signing_key=plan["key"])


def _resign(data: bytes, mutate: Any, *, key: ed25519.Ed25519PrivateKey) -> bytes:
    """Re-seal a package with its payload changed by ``mutate`` (still a valid signature)."""
    outer = json.loads(data)
    payload = json.loads(base64.b64decode(outer["payload"]))
    mutate(payload)
    return envelope.seal_signed(heir.FORMAT, heir.VERSION, package_id=outer["id"], sender=outer["sender"],
                                payload=payload, signing_key=key)


def _outer(data: bytes, mutate: Any) -> bytes:
    outer = json.loads(data)
    mutate(outer)
    return envelope.canonical(outer)


def _refused(plan: dict[str, Any]) -> list[dict[str, Any]]:
    good = plan["packages"][0]
    key = plan["key"]
    cases = {
        "bad-signature": _outer(good, lambda o: o.update(sender="Mallory")),
        "unsupported-version": _outer(good, lambda o: o.update(version=2)),
        "wrong-format": _outer(good, lambda o: o.update(format="localgatekeys-share")),
        "extra-outer-key": _outer(good, lambda o: o.update(extra=1)),
        "upper-case-id": _outer(good, lambda o: o.update(id=o["id"].upper())),
        "short-signer": _outer(good, lambda o: o.update(signer=b64(bytes(31)))),
        "extra-payload-key": _resign(good, lambda p: p.update(extra=1), key=key),
        "index-mismatch": _resign(good, lambda p: p.update(index=2), key=key),
        "k-above-n": _resign(good, lambda p: p.update(k=4), key=key),
        "float-k": _resign(good, lambda p: p.update(k=2.0), key=key),
        "bool-index": _resign(good, lambda p: p.update(index=True), key=key),
        "wait-31": _resign(good, lambda p: p.update(wait_days=31), key=key),
        "control-in-holder": _resign(good, lambda p: p.update(holder="Ann\u200b"), key=key),
        "untrimmed-holder": _resign(good, lambda p: p.update(holder=" Ann"), key=key),
        "long-holder": _resign(good, lambda p: p.update(holder="x" * 33), key=key),
        "short-share": _resign(good, lambda p: p.update(share=b64(bytes([1]) + bytes(31))), key=key),
        "unpadded-base64": _resign(good, lambda p: p.update(check_salt=b64(SALT).rstrip("=")), key=key),
        "wrong-kind": _resign(good, lambda p: p.update(kind="heir-request"), key=key),
        "not-json": b"not json",
        "duplicate-key": good[:-1] + b',"sig":"x"}',
    }
    out = []
    for name, data in cases.items():
        try:
            heir.read_package(data)
        except heir.HeirError as exc:
            out.append({"name": name, "package": data.decode("utf-8", "replace"), "reason": exc.reason})
            continue
        raise AssertionError(f"{name} was accepted")
    return out


def _merges(plan: dict[str, Any]) -> list[dict[str, Any]]:
    local = heir.synced_record(plan["record"])
    other_deny = "0a1b2c3d-4e5f-4061-8293-a4b5c6d7e8f9"
    cases: list[dict[str, Any]] = []

    def case(name: str, local_record: Any, remote: dict[str, Any]) -> None:
        # The phone stores the synced form; the desktop's own copy adds this device's folder and home.
        desktop_local = None if local_record is None else {**local_record, "folder": None, heir.HOME_KEY: False}
        try:
            merged = heir.merge_synced(desktop_local, remote)
        except heir.HeirError as exc:
            cases.append({"name": name, "local": local_record, "remote": remote, "reason": exc.reason})
            return
        stored = {k: v for k, v in merged.items() if k not in heir.LOCAL_ONLY_KEYS}
        cases.append({"name": name, "local": local_record, "remote": remote, "stored": stored})

    remote = copy.deepcopy(local)
    remote["denied"] = [other_deny]
    case("denies-union", local, remote)
    same = copy.deepcopy(local)
    case("same-plan", local, same)
    stale = copy.deepcopy(local)
    stale["stale"] = True
    case("stale-either", local, stale)
    reordered = copy.deepcopy(local)
    reordered["denied"] = [other_deny, DENY_ID]
    local_two = copy.deepcopy(local)
    local_two["denied"] = [DENY_ID, other_deny]
    case("nothing-new-keeps-remote-order", local_two, reordered)
    case("first-plan", None, copy.deepcopy(local))
    rekeyed = copy.deepcopy(local)
    other_key = _key(_seed("other-signing"))
    rekeyed["signing_key"] = b64(_seed("other-signing"))
    rekeyed["signer"] = b64(other_key.public_key().public_bytes_raw())
    case("rekeyed-conflict", local, rekeyed)
    holders = copy.deepcopy(local)
    holders["holders"] = ["Νίκος", "Anna", "Carl"]
    case("holders-conflict", local, holders)
    newer = copy.deepcopy(local)
    newer["plan_id"] = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
    newer["created"] = CREATED + 10
    case("another-plan-replaces", local, newer)
    extra = copy.deepcopy(local)
    extra["folder"] = None
    case("folder-is-not-synced", local, extra)
    missing = copy.deepcopy(local)
    del missing["stale"]
    case("missing-stale", local, missing)
    bad_signer = copy.deepcopy(local)
    bad_signer["signer"] = b64(bytes(32))
    case("signer-not-of-key", None, bad_signer)
    many = copy.deepcopy(local)
    many["denied"] = [f"{i:08x}-0000-4000-8000-000000000000" for i in range(65)]
    case("too-many-denied", None, many)
    return cases


def build() -> dict[str, Any]:
    plan = _plan()
    request = _request(plan)
    deny = _deny(plan)
    grant = _grant(plan)
    descriptor = _descriptor(plan)
    box = X25519PrivateKey.from_private_bytes(REQUESTER_BOX)
    opened = heir_flow._open(grant, heir_flow.GRANT_KIND, heir_flow._GRANT_FIELDS)
    identity = heir_flow.RequesterIdentity(_key(REQUESTER_SIGNING), box)
    assert opened is not None and bytes(heir_flow._open_grant(opened, identity) or b"") == ENTROPY
    shards = [heir.read_package(data) for data in plan["packages"]]
    return {
        "format": "lgk-heir-vectors-v1",
        "spec": "docs/formats/LGKHEIR_V1.md",
        "entropy": ENTROPY.hex(),
        "phrase": phrase_from_entropy(ENTROPY),
        "plan_id": PLAN_ID,
        "owner": OWNER,
        "holders": HOLDERS,
        "k": K,
        "n": N,
        "wait_days": WAIT,
        "created": CREATED,
        "signing_seed": SIGNING_SEED.hex(),
        "signer": b64(plan["key"].public_key().public_bytes_raw()),
        "check_salt": SALT.hex(),
        "check": plan["check"].hex(),
        "backup_public": plan["backup_public"].hex(),
        "coefficients": COEFFS.hex(),
        "shares": [share.hex() for share in plan["shares"]],
        "holder_keys": [h.hex() for h in plan["holder_keys"]],
        "package_ids": PACKAGE_IDS,
        "packages": [data.decode("utf-8") for data in plan["packages"]],
        "qr": [heir.shard_qr_text(data) for data in plan["packages"]],
        "shards": [{"index": s.index, "holder": s.holder, "package_id": s.package_id} for s in shards],
        "requester": {"signing_seed": REQUESTER_SIGNING.hex(), "box_key": REQUESTER_BOX.hex(),
                      "record": heir_flow.RequesterIdentity(_key(REQUESTER_SIGNING), box).to_record()},
        "request": {"id": REQUEST_ID, "created": REQUEST_CREATED, "holder_index": REQUEST_HOLDER,
                    "file": f"request-{REQUEST_ID}{heir_flow.REQUEST_SUFFIX}", "data": request.decode("utf-8")},
        "deny": {"id": DENY_ID, "created": DENY_CREATED, "file": f"deny-{REQUEST_ID}{heir_flow.DENY_SUFFIX}",
                 "data": deny.decode("utf-8")},
        "grant": {"id": GRANT_ID, "created": GRANT_CREATED, "ephemeral": GRANT_EPHEMERAL.hex(),
                  "file": f"grant-{REQUEST_ID}{heir_flow.GRANT_SUFFIX}", "data": grant.decode("utf-8")},
        "descriptor": {"file": "backup-20270115-080000-0a1b2c3d.lgkheirbackup", "written_at": DESCRIPTOR_WRITTEN,
                       "data": descriptor.decode("utf-8")},
        "record": plan["record"],
        "synced": heir.synced_record(plan["record"]),
        "wrapper": {"ns": "heir", "schema": 1, "updated_at": CREATED, "record": heir.synced_record(plan["record"])},
        "refused": _refused(plan),
        "merges": _merges(plan),
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    (HERE / "v1.json").write_text(render(), encoding="utf-8", newline="\n")
