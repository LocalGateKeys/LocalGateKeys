"""The Python core reproduces the shared feature-pack vectors (contract 2026-11-15)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from localvault import access_policy, hygiene, import_undo, item_history, privacy_proof, travel
from localvault.sync.vault_bridge import normal_form
from localvault.updates import canonical_json

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors"


def cases(name: str) -> list[dict]:
    return json.loads((VEC / name).read_text(encoding="utf-8"))["cases"]


def test_generator_output_is_committed_byte_for_byte() -> None:
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "make_feature_pack_vectors.py"), "--check"],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", cases("history/prune.json"), ids=lambda c: c["name"])
def test_history_prune(case: dict) -> None:
    kept = item_history.prune(case["rows"], case["now"], case["limits"])
    assert [row["snapshot_id"] for row in kept] == case["expected_ids"]


@pytest.mark.parametrize("case", cases("history/diff.json"), ids=lambda c: c["name"])
def test_history_diff(case: dict) -> None:
    assert item_history.diff(case["before"], case["after"], case["kind"], reveal=case["reveal"]) == case["expected"]


@pytest.mark.parametrize("case", cases("history/restore_field.json"), ids=lambda c: c["name"])
def test_history_restore_field(case: dict) -> None:
    if "error" in case:
        with pytest.raises(item_history.RestoreError) as caught:
            item_history.restore_field(case["current"], case["snapshot"], case["path"], case["now"])
        assert caught.value.code == case["error"]
    else:
        assert item_history.restore_field(case["current"], case["snapshot"], case["path"], case["now"]) == case["expected"]


@pytest.mark.parametrize("case", cases("travel/visible.json"), ids=lambda c: c["name"])
def test_travel_hidden_ids(case: dict) -> None:
    assert travel.hidden_ids(case["items"], case["setting"]) == case["expected_hidden"]


@pytest.mark.parametrize("case", cases("hygiene/duplicates.json"), ids=lambda c: c["name"])
def test_hygiene_findings(case: dict) -> None:
    assert hygiene.findings(case["records"], case["now"], case["today"]) == case["expected"]


@pytest.mark.parametrize("case", cases("hygiene/expired.json"), ids=lambda c: c["name"])
def test_hygiene_expired(case: dict) -> None:
    found = [f["ids"] for f in hygiene.findings(case["records"], case["now"], case["today"]) if f["type"] == "expired"]
    assert (found[0] if found else []) == case["expected_ids"]


@pytest.mark.parametrize("case", cases("hygiene/merge.json"), ids=lambda c: c["name"])
def test_hygiene_merge(case: dict) -> None:
    if "error" in case:
        with pytest.raises(hygiene.MergeRefused) as caught:
            hygiene.merge(case["keeper"], case["other"], case["now"])
        assert caught.value.code == case["error"]
    else:
        assert hygiene.merge(case["keeper"], case["other"], case["now"]) == case["expected"]


@pytest.mark.parametrize("case", cases("access/effective.json"), ids=lambda c: c["name"])
def test_access_effective(case: dict) -> None:
    assert access_policy.effective(case["record"], case["device_class"], case["today"]) == case["expected"]


@pytest.mark.parametrize("case", cases("access/preserve.json"), ids=lambda c: c["name"])
def test_access_preserved_by_normaliser(case: dict) -> None:
    normal = normal_form("entry", case["input_entry"])
    assert normal == case["expected_normal_form"]
    assert canonical_json(normal["scope"]["access"]) == canonical_json(case["input_entry"]["scope"]["access"])


@pytest.mark.parametrize("case", cases("access/stricter.json"), ids=lambda c: c["name"])
def test_access_stricter(case: dict) -> None:
    assert access_policy.stricter_access(case["a"], case["b"]) == case["expected"]


def test_privacy_proof_signed_vector() -> None:
    import base64

    vec = json.loads((VEC / "privacy_proof" / "signed.json").read_text(encoding="utf-8"))
    ids = json.loads((VEC / "sync" / "identities.json").read_text(encoding="utf-8"))["devices"]["A"]
    doc = dict(vec["unsigned_document"], signature=None)
    # Version 2: everything but signature.value is signed, including the device id and the public key.
    assert privacy_proof.signed_bytes(vec["signed_body"]).hex() == vec["signed_bytes_hex"]
    assert privacy_proof.signed_bytes(vec["signed_document"]).hex() == vec["signed_bytes_hex"]
    assert vec["signed_body"]["signature"] == {k: v for k, v in vec["signature"].items() if k != "value"}
    signed = privacy_proof.sign(doc, base64.b64decode(ids["private"]["signing_private"]), ids["device_id"])
    assert signed == vec["signed_document"] and signed["signature"] == vec["signature"]
    data = (VEC / "privacy_proof" / "signed.json").read_bytes()
    assert privacy_proof.verify_bytes(json.dumps(vec["signed_document"]).encode()) == {
        "result": "valid", "device_id": ids["device_id"], "fingerprint": vec["fingerprint"], "reason": ""}
    assert data  # the wrapper itself is not a proof file


def test_privacy_proof_unsigned_and_rejected() -> None:
    vec = json.loads((VEC / "privacy_proof" / "unsigned.json").read_text(encoding="utf-8"))
    assert privacy_proof.verify_document(vec["document"])["result"] == "unsigned"
    rejected = sorted((VEC / "privacy_proof" / "rejected").glob("*.json"))
    assert [p.name for p in rejected] == ["device_id_changed.json", "duplicate_key.json", "extra_top_key.json",
                                          "key_fields_unsigned.json", "tampered_fact.json", "version_1.json",
                                          "version_3.json", "wrong_prefix.json"]
    for path in rejected:
        assert privacy_proof.verify_bytes(path.read_bytes())["result"] == "invalid", path.name


def test_import_undo_vector() -> None:
    for case in cases("import/report/undo.json"):
        result = import_undo.plan(case["journal"], case["current_records"], case["now"])
        assert result["records"] == case["expected_after_undo"]
        assert result["kept"] == case["expected_kept_ids"]
        assert result["trashed"] == case["expected_trashed_ids"]
        assert result["restored"] == case["expected_restored_ids"]
        for record in case["after_records"]:
            rid = record["id"]
            if rid in case["journal"]["created"]:
                assert import_undo.digest(record) == case["journal"]["created"][rid]
