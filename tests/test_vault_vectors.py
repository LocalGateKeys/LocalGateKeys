"""Deterministic format-3 vault vectors (tests/vectors/vault).

The committed vault is a fixed known answer for the v3 envelope: it must open with its password
to the expected catalog, the catalog AAD must bind ``vault_id`` and ``generation``, and the
generator must reproduce every file byte for byte.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from localvault import vault
from localvault.vault import InvalidMasterPassword, unlock_vault

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "vault"
SCRIPT = ROOT / "scripts" / "make_vault_vectors.py"
EXPECTED = json.loads((VEC / "v3_expected.json").read_text(encoding="utf-8"))


def _load_generator():
    spec = importlib.util.spec_from_file_location("make_vault_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["make_vault_vectors"] = module
    spec.loader.exec_module(module)
    return module


def _copy(tmp_path: Path, name: str) -> Path:
    # Opening writes a rollback anchor next to the vault: never next to the committed copy.
    target = tmp_path / "vault.json"
    shutil.copyfile(VEC / name, target)
    return target


def test_committed_v3_vector_opens_to_the_expected_payload(tmp_path: Path) -> None:
    session = unlock_vault(_copy(tmp_path, "v3_vault.json"), EXPECTED["password"], upgrade_envelope=False)
    try:
        assert vault._header_version(session._header) == vault.FORMAT_VERSION
        assert bytes(session._key).hex() == EXPECTED["data_key_hex"]
        payload = session._require_payload()
        for key, value in EXPECTED["payload"].items():
            assert payload[key] == value, key
        assert session._header["vault_id"] == EXPECTED["vault_id"]
        assert session._header["generation"] == EXPECTED["generation"]
    finally:
        session.lock()


def test_committed_v3_vector_aad_is_the_v3_contract() -> None:
    header = json.loads((VEC / "v3_vault.json").read_bytes())
    aad = base64.b64decode(EXPECTED["catalog_aad_b64"])
    assert vault._aad(header) == aad
    assert aad.startswith(b"localgatekeys|vault|v3|")
    body = json.loads(aad[len(b"localgatekeys|vault|v3|"):])
    assert body["vault_id"] == EXPECTED["vault_id"] and body["generation"] == EXPECTED["generation"]
    assert "kdf" not in body
    assert vault._wrapper_aad(header, "password", {"kdf": header["kdf"]}) == base64.b64decode(
        EXPECTED["wrapper_aad_b64"])


def test_committed_v3_vector_refuses_a_wrong_password(tmp_path: Path) -> None:
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(_copy(tmp_path, "v3_vault.json"), "wrong password, twelve+", upgrade_envelope=False)


@pytest.mark.parametrize("name", sorted(EXPECTED["rejected"]))
def test_edited_v3_vectors_do_not_open(tmp_path: Path, name: str) -> None:
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(_copy(tmp_path, name), EXPECTED["password"], upgrade_envelope=False)


def test_generator_reproduces_committed_files_byte_for_byte(tmp_path: Path) -> None:
    generator = _load_generator()
    out = tmp_path / "vault"
    generator.write(out)
    produced = sorted(p.name for p in out.iterdir())
    assert produced == sorted(generator.GENERATED_FILES)
    assert sorted(p.name for p in VEC.iterdir()) == produced
    for name in produced:
        assert (out / name).read_bytes() == (VEC / name).read_bytes(), name
