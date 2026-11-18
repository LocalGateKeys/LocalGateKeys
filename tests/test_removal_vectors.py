"""Signed removal notice vectors shared with the Swift and Kotlin cores (tests/vectors/sync/removal).

``scripts/gen_removal_vectors.py`` must reproduce the committed files byte for byte, and every
case must give its expected result with the Python implementation.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault.sync import removal

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "sync" / "removal"
SCRIPT = ROOT / "scripts" / "gen_removal_vectors.py"
NOTICES = json.loads((VEC / "notices.json").read_text(encoding="utf-8"))
WRITER = json.loads((VEC / "writer.json").read_text(encoding="utf-8"))
WATCH = json.loads((VEC / "watch.json").read_text(encoding="utf-8"))


def _generator():
    spec = importlib.util.spec_from_file_location("gen_removal_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_removal_vectors"] = module
    spec.loader.exec_module(module)
    return module


def _watch(doc: dict) -> removal.Watch:
    return removal.Watch(doc["group_id"], doc["device_id"], doc["epoch"], doc["install_id"], doc["folder"],
                         dict(doc["signers"]))


def _ring(name: str) -> bytes:
    return base64.b64decode(NOTICES["keyrings"][name]["b64"])


def test_generator_reproduces_the_committed_vectors() -> None:
    for name, data in _generator().build().items():
        assert (VEC / name).read_bytes() == data, name


def test_vector_files_use_lf() -> None:
    for path in VEC.glob("*.json"):
        assert b"\r" not in path.read_bytes(), path


@pytest.mark.parametrize("case", NOTICES["cases"], ids=lambda c: c["name"])
def test_verify_notice_case(case: dict) -> None:
    raw = base64.b64decode(case["notice_b64"])
    watch = _watch(NOTICES["watches"][case["watch"]])
    expected = case["expected"]
    if expected["accept"]:
        n = removal.verify_notice(raw, watch, _ring(case["folder_keyring"]))
        assert {"group_id": n.group_id, "device_id": n.device_id, "epoch": n.epoch, "signer": n.signer,
                "issued_at": n.issued_at} == expected["notice"]
    else:
        with pytest.raises(removal.RemovalError) as err:
            removal.verify_notice(raw, watch, _ring(case["folder_keyring"]))
        assert err.value.reason == expected["reason"]


def test_every_rejection_reason_is_covered() -> None:
    reasons = {c["expected"]["reason"] for c in NOTICES["cases"]}
    assert reasons == {None, "bad-notice", "not-for-this-device", "stale", "unknown-signer", "bad-signature",
                       "bad-key", "keyring"}


def test_locked_check_finds_the_valid_notice(tmp_path: Path) -> None:
    """``check`` reads the same two files from the folder layout and agrees with the vectors."""
    for case in NOTICES["cases"]:
        doc = dict(NOTICES["watches"][case["watch"]], folder=str(tmp_path / case["name"]))
        sync = Path(doc["folder"]) / "LocalGateKeys Sync"
        (sync / "removed").mkdir(parents=True)
        (sync / "removed" / f"{doc['device_id']}.lgkremoved").write_bytes(base64.b64decode(case["notice_b64"]))
        (sync / "keyring.lgkkeys").write_bytes(_ring(case["folder_keyring"]))
        found = removal.check(_watch(doc), install_id=doc["install_id"])
        assert (found is not None) == case["expected"]["accept"], case["name"]


@pytest.mark.parametrize("case", WRITER["cases"], ids=lambda c: c["description"])
def test_writer_case(case: dict) -> None:
    i = case["inputs"]
    key = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(i["signing_private_seed_b64"]))
    raw = removal.make_notice(key, group_id=i["group_id"], device_id=i["device_id"], epoch=i["epoch"],
                              signer=i["signer"], now=i["issued_at"])
    assert raw == case["notice_text"].encode("ascii")
    notice, message, sig = removal.parse_notice(raw)
    assert message.hex() == case["signed_message_hex"]
    assert base64.b64encode(sig).decode() == case["sig_b64"]
    assert case["path"].endswith(removal.notice_name(notice.device_id))


@pytest.mark.parametrize("case", WRITER["refusals"], ids=lambda c: c["description"])
def test_writer_refusal(case: dict) -> None:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(32))
    i = case["inputs"]
    with pytest.raises(removal.RemovalError) as err:
        removal.make_notice(key, group_id=i["group_id"], device_id=i["device_id"], epoch=i["epoch"],
                            signer=i["signer"], now=i["issued_at"])
    assert err.value.reason == case["error"]


@pytest.mark.parametrize("case", WATCH["parse"], ids=lambda c: c["name"])
def test_watch_parse_case(case: dict, tmp_path: Path) -> None:
    path = tmp_path / "vault.sync-watch.json"
    path.write_bytes(base64.b64decode(case["b64"]))
    w = removal.load_watch(path)
    assert (None if w is None else w.to_dict()) == case["expected"]


def test_watch_example_and_paths(tmp_path: Path) -> None:
    w = _watch(WATCH["example"]["parsed"])
    path = tmp_path / "vault.sync-watch.json"
    assert removal.save_watch(path, w)
    assert path.read_bytes() == WATCH["example"]["watch_text"].encode("utf-8")
    for p in WATCH["paths"]:
        assert removal.watch_path(tmp_path / p["vault"]).name == p["watch"]


@pytest.mark.parametrize("case", WATCH["derive"], ids=lambda c: c["name"])
def test_watch_derive_case(case: dict) -> None:
    s = case["state"]
    state = SimpleNamespace(keyring=_ring(s["keyring"]), install_id=s["install_id"], group_id=s["group_id"],
                            device_id=s["device_id"], epoch=s["epoch"], unacked_members=tuple(s["unacked_members"]))
    w = removal.watch_from_state(state, case["folder"])
    assert json.dumps(w.to_dict(), sort_keys=True, separators=(",", ":")) == case["watch_text"]


@pytest.mark.parametrize("case", WATCH["pinned"], ids=lambda c: c["name"])
def test_watch_pinned_case(case: dict) -> None:
    old = None if case["old"] is None else _watch(case["old"])
    assert removal.pinned(_watch(case["fresh"]), old).to_dict() == case["expected"]
