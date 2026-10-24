"""Deterministic phone backup test vectors (tests/vectors/backup).

The committed files are the contract the Android and iPhone apps must open and, with the same
salt, nonce and inputs, reproduce byte for byte.  Production Argon2id runs a few seconds per
derivation, so a module-wide memo keeps the number of real derivations to a handful.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from localvault import phone_backup
from localvault.phone_backup import (
    KDF,
    PhoneBackupError,
    _derive,
    inspect_phone_backup,
    read_phone_backup,
    write_phone_backup,
)
from localvault.sync.engine import ItemState

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "backup"
SCRIPT = ROOT / "scripts" / "make_backup_vectors.py"
EXPECTED = json.loads((VEC / "expected.json").read_text(encoding="utf-8"))
REJECTED = sorted(EXPECTED["rejected"])


def _load_generator():
    spec = importlib.util.spec_from_file_location("make_backup_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["make_backup_vectors"] = module
    spec.loader.exec_module(module)
    return module


def state_dict(s: ItemState) -> dict:
    return {"deleted": s.deleted, "deleted_at": s.deleted_at, "id": s.item_id, "item": s.item, "vv": dict(s.vv)}


@pytest.fixture(scope="module", autouse=True)
def _memo_derive():
    """Real Argon2id, computed once per (password, salt, kdf) for the whole module."""
    real = phone_backup._derive
    cache: dict[tuple, bytes] = {}

    def derive(password, salt, kdf):
        k = (password, bytes(salt), tuple(sorted(kdf.items())))
        if k not in cache:
            cache[k] = real(password, salt, kdf)
        return cache[k]

    patch = pytest.MonkeyPatch()
    patch.setattr(phone_backup, "_derive", derive)
    yield
    patch.undo()


def test_generator_reproduces_committed_files_byte_for_byte(tmp_path):
    generator = _load_generator()
    out = tmp_path / "backup"
    generator.generate(out)
    fresh = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    # from_android/ is written by the Android core (LGK_WRITE_FROM_ANDROID=1), not by this generator.
    committed = sorted(
        rel for rel in (p.relative_to(VEC).as_posix() for p in VEC.rglob("*") if p.is_file())
        if not rel.startswith("from_android/")
    )
    assert fresh == committed == list(generator.GENERATED_FILES)
    for rel in committed:
        assert (out / rel).read_bytes() == (VEC / rel).read_bytes(), rel


def test_committed_files_are_byte_exact_in_git_and_use_lf():
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    for line in ("*.lgkm binary", "tests/vectors/** -text"):
        assert line in attributes
    for rel in ("README.md", "expected.json"):
        assert b"\r" not in (VEC / rel).read_bytes(), rel
    for path in [VEC / "backup.lgkm", *sorted((VEC / "rejected").glob("*.lgkm"))]:
        raw = path.read_bytes()
        assert b"\r" not in raw and not raw.endswith(b"\n"), path.name


def test_backup_vector_decodes_to_expected_states():
    raw = (VEC / "backup.lgkm").read_bytes()
    backup = read_phone_backup(raw, EXPECTED["password"])
    assert [state_dict(s) for s in backup.states] == EXPECTED["states"]
    assert backup.device_id == EXPECTED["device_id"]
    assert (backup.app_version, backup.pro_hint) == (EXPECTED["app_version"], EXPECTED["pro_hint"])
    assert backup.header.created_at == EXPECTED["created_at"] and backup.header.platform == EXPECTED["platform"]
    assert inspect_phone_backup(raw) == backup.header
    salt = base64.b64decode(EXPECTED["salt_b64"])
    assert backup.header.salt == salt and backup.header.nonce == base64.b64decode(EXPECTED["nonce_b64"])
    assert _derive(EXPECTED["password"], salt, KDF).hex() == EXPECTED["key_hex"]
    assert EXPECTED["header"] == json.loads(raw)["header"]
    assert len(EXPECTED["states"]) == 10
    assert EXPECTED["states"][-1]["id"].startswith("lic:")


def test_expected_aad_and_payload_match_the_file():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from localvault.updates import canonical_json

    raw = (VEC / "backup.lgkm").read_bytes()
    env = json.loads(raw)
    aad = canonical_json(env["header"])
    assert aad.hex() == EXPECTED["aad_hex"]
    plain = AESGCM(bytes.fromhex(EXPECTED["key_hex"])).decrypt(
        base64.b64decode(EXPECTED["nonce_b64"]), base64.b64decode(env["ciphertext"]), aad)
    assert plain.decode("utf-8") == EXPECTED["payload_canonical"]
    assert json.loads(plain)["states"] == EXPECTED["states"]


def test_rejected_listing_is_complete_and_has_passwords():
    on_disk = sorted(p.name for p in (VEC / "rejected").glob("*.lgkm"))
    assert on_disk == REJECTED
    for name, entry in EXPECTED["rejected"].items():
        assert set(entry) == {"password", "reason"}
        assert entry["password"] == ("wrong" if name == "wrong_password.lgkm" else EXPECTED["password"])
    assert {e["reason"] for e in EXPECTED["rejected"].values()} == {
        "wrong-password-or-damaged", "unsupported-version", "bad-kdf", "not-a-backup", "bad-payload"}
    assert (VEC / "rejected" / "wrong_password.lgkm").read_bytes() == (VEC / "backup.lgkm").read_bytes()
    assert (VEC / "rejected" / "truncated.lgkm").read_bytes() == (VEC / "backup.lgkm").read_bytes()[:100]


@pytest.mark.parametrize("name", REJECTED)
def test_rejected_vectors_give_their_reason(name):
    entry = EXPECTED["rejected"][name]
    with pytest.raises(PhoneBackupError) as caught:
        read_phone_backup((VEC / "rejected" / name).read_bytes(), entry["password"])
    assert caught.value.reason == entry["reason"]


def test_writing_again_with_the_fixed_inputs_gives_the_same_bytes():
    generator = _load_generator()
    data = write_phone_backup(
        generator.input_states(), password=EXPECTED["password"], device_id=EXPECTED["device_id"],
        platform=EXPECTED["platform"], app_version=EXPECTED["app_version"], created_at=EXPECTED["created_at"],
        pro_hint=EXPECTED["pro_hint"], _salt=base64.b64decode(EXPECTED["salt_b64"]),
        _nonce=base64.b64decode(EXPECTED["nonce_b64"]))
    assert data == (VEC / "backup.lgkm").read_bytes()
    # a read -> write round trip is byte-identical too
    again = write_phone_backup(
        read_phone_backup(data, EXPECTED["password"]).states, password=EXPECTED["password"],
        device_id=EXPECTED["device_id"], platform=EXPECTED["platform"], app_version=EXPECTED["app_version"],
        created_at=EXPECTED["created_at"], pro_hint=EXPECTED["pro_hint"],
        _salt=base64.b64decode(EXPECTED["salt_b64"]), _nonce=base64.b64decode(EXPECTED["nonce_b64"]))
    assert again == data


def test_backup_states_are_what_a_device_publishes():
    """The stored form (copies with their own record id and suffixed label), never the engine form."""
    sync = ROOT / "tests" / "vectors" / "sync"
    merged = json.loads((sync / "expected_merge.json").read_text(encoding="utf-8"))
    lic = json.loads((sync / "license_state.json").read_text(encoding="utf-8"))
    stored = [{k: s[k] for k in ("deleted", "deleted_at", "id", "item", "vv")}
              for s in merged["bridge_stored_states"]]
    states = EXPECTED["states"]
    assert [s for s in states if not s["id"].startswith("lic:")] == stored
    assert [s["item"] for s in states if s["id"].startswith("lic:")] == [lic["wrapper"]]
    for state in states:
        if state["item"] is not None:
            assert "id" not in state["item"], state["id"]  # no engine-form conflict copy
            if state["item"]["ns"] in ("entry", "item"):
                assert state["item"]["record"]["id"] == state["id"]
