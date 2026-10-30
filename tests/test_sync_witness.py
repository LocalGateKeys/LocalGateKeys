"""Rollback witnesses: view format 2, witness files and the pure check (Part B, 2026-10-29 update)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.sync import group as g
from localvault.sync import witness as w
from localvault.sync.engine import ItemState
from localvault.updates import canonical_json

KEY = bytes(range(32))
GK = g.GroupKey("grp-1", 1, KEY)
VECTORS = Path(__file__).parent / "vectors" / "sync"


def live(i: str = "a") -> ItemState:
    return ItemState(i, {"d1": 1}, False, None, {"id": i, "updated_at": 5, "title": "T"})


def v2(device: str = "d1", generation: int = 40, witness: dict | None = None, states=(), counter: int = 3) -> bytes:
    return g.encode_view(GK, device, counter, states, 1000, vault_generation=generation, witness=witness or {})


# --- format 2 -----------------------------------------------------------------------------------


def test_v2_header_round_trips_generation_and_witness() -> None:
    raw = v2(generation=40, witness={"d2": 12, "d3": 0}, states=[live()])
    view = g.decode_view(GK, raw, expected_device_id="d1")
    assert view.format == 2 and view.vault_generation == 40 and view.witness == {"d2": 12, "d3": 0}
    assert [s.item_id for s in view.states] == ["a"]
    header = json.loads(raw[len(g.MAGIC):raw.index(b"\n", len(g.MAGIC))])
    assert set(header) == {"format", "group_id", "device_id", "epoch", "counter", "written_at",
                           "vault_generation", "witness"} and header["format"] == 2


def test_format1_is_still_written_by_default_and_reads_without_witness() -> None:
    raw = g.encode_view(GK, "d1", 3, [live()], 1000)
    view = g.decode_view(GK, raw)
    assert view.format == 1 and view.vault_generation is None and view.witness == {}
    assert b'"format":1' in raw and b"vault_generation" not in raw


def test_format1_peer_is_read_without_witness_check() -> None:
    """The committed format-1 vector still decodes; it yields no observation."""
    gk1 = _vector_gk()
    raw = (VECTORS / "devices" / "A.lgksync").read_bytes()
    view = g.decode_view(gk1, raw)
    assert view.vault_generation is None and w.observation(view) is None


def _vector_gk() -> g.GroupKey:
    expected = json.loads((VECTORS / "expected.json").read_text(encoding="utf-8"))
    return g.GroupKey(expected["group_id"], 1, bytes.fromhex(expected["epochs"]["1"]["group_key_hex"]))


@pytest.mark.parametrize("witness", [
    [], "x", {f"p{i:02}": 1 for i in range(65)}, {"bad id!": 1}, {"d2": -1}, {"d2": 2**53}, {"d2": True},
    {"d2": 1.0}, {"d1": 5},  # the writer's own id
])
def test_v2_header_rejects_bad_witness(witness) -> None:
    with pytest.raises(g.SyncFormatError) as exc:
        v2(witness=witness) if isinstance(witness, dict) else g.encode_view(
            GK, "d1", 3, (), 1000, vault_generation=1, witness=witness)
    assert exc.value.reason == "bad-header"
    # The decoder refuses the same header even when someone writes it by hand.
    header = {"format": 2, "group_id": "grp-1", "device_id": "d1", "epoch": 1, "counter": 3,
              "written_at": 1000, "vault_generation": 1, "witness": witness}
    with pytest.raises(g.SyncFormatError) as exc:
        g.decode_view(GK, _hand_written(header))
    assert exc.value.reason == "bad-header"


@pytest.mark.parametrize("generation", [-1, 2**53, True, 1.5, "1", None])
def test_v2_header_rejects_bad_generation(generation) -> None:
    header = {"format": 2, "group_id": "grp-1", "device_id": "d1", "epoch": 1, "counter": 3,
              "written_at": 1000, "vault_generation": generation, "witness": {}}
    with pytest.raises(g.SyncFormatError) as exc:
        g.decode_view(GK, _hand_written(header))
    assert exc.value.reason == "bad-header"


@pytest.mark.parametrize("drop_or_add", ["drop-witness", "drop-generation", "v1-with-generation", "extra",
                                         "format-3"])
def test_exact_key_set_per_format(drop_or_add) -> None:
    base = {"format": 2, "group_id": "grp-1", "device_id": "d1", "epoch": 1, "counter": 3,
            "written_at": 1000, "vault_generation": 1, "witness": {}}
    if drop_or_add == "drop-witness":
        del base["witness"]
    elif drop_or_add == "drop-generation":
        del base["vault_generation"]
    elif drop_or_add == "v1-with-generation":
        base["format"] = 1
    elif drop_or_add == "extra":
        base["x"] = 1
    else:
        base["format"] = 3
    with pytest.raises(g.SyncFormatError) as exc:
        g.decode_view(GK, _hand_written(base))
    assert exc.value.reason == "bad-header"


def _hand_written(header: dict) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    line = canonical_json(header)
    nonce = b"\x07" * 12
    return g.MAGIC + line + b"\n" + nonce + AESGCM(GK.file_key()).encrypt(nonce, b"[]", line)


def test_v2_header_is_authenticated() -> None:
    raw = v2(generation=40)
    forged = raw.replace(b'"vault_generation":40', b'"vault_generation":90')
    assert forged != raw
    with pytest.raises(g.SyncFormatError) as exc:
        g.decode_view(GK, forged)
    assert exc.value.reason == "auth-failed"


def test_witness_without_generation_is_refused() -> None:
    with pytest.raises(g.SyncFormatError):
        g.encode_view(GK, "d1", 3, (), 1000, witness={"d2": 1})


def test_v2_view_signs_and_verifies() -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    raw = v2()
    header = g.decode_view(GK, raw).header
    assert g.verify_view_signature(g.sign_view(raw, key), raw, header) == key.public_key().public_bytes_raw()


# --- observation --------------------------------------------------------------------------------


def test_observation_from_v2_view_and_from_matching_witness_file() -> None:
    main_v2 = g.decode_view(GK, v2(generation=7, witness={"d2": 3}))
    assert w.observation(main_v2) == w.Observation("d1", 7, {"d2": 3})
    main_v1 = g.decode_view(GK, g.encode_view(GK, "d1", 3, [live()], 1000))
    side = g.decode_view(GK, v2(generation=9, witness={"d2": 4}, counter=3))
    assert w.observation(main_v1, side) == w.Observation("d1", 9, {"d2": 4})


@pytest.mark.parametrize("side", [
    dict(counter=2), dict(counter=4), dict(device="d9"), dict(states=[live()]),
])
def test_witness_file_must_match_the_view(side) -> None:
    main_v1 = g.decode_view(GK, g.encode_view(GK, "d1", 3, [live()], 1000))
    file = g.decode_view(GK, v2(**side))
    assert w.observation(main_v1, file) is None


def test_witness_file_of_format1_is_ignored() -> None:
    main_v1 = g.decode_view(GK, g.encode_view(GK, "d1", 3, [live()], 1000))
    other_v1 = g.decode_view(GK, g.encode_view(GK, "d1", 3, (), 1000))
    assert w.observation(main_v1, other_v1) is None


# --- the check ----------------------------------------------------------------------------------


def test_peer_going_backwards_is_reported_and_not_forgotten() -> None:
    res = w.check("A", 10, [w.Observation("B", 30)], {"B": 50}, 0)
    assert [(i.kind, i.detail) for i in res.issues] == [("peer-vault-rollback", "B")]
    assert res.peer_generations == {"B": 50}


def test_peer_moving_forward_is_remembered_silently() -> None:
    res = w.check("A", 10, [w.Observation("B", 51, {"A": 9})], {"B": 50}, 0)
    assert res.issues == () and res.peer_generations == {"B": 51} and res.capable == {"B"}


def test_equal_generation_is_no_rollback() -> None:
    res = w.check("A", 10, [w.Observation("B", 50, {"A": 10})], {"B": 50}, 0)
    assert res.issues == () and res.rollback_suspected == 0


def test_peer_seen_newer_copy_of_us_flags_vault_rollback() -> None:
    res = w.check("A", 30, [w.Observation("B", 5, {"A": 50})], {}, 0)
    assert [i.kind for i in res.issues] == ["vault-rollback"] and res.rollback_suspected == 50


def test_rollback_issue_persists_until_acknowledged() -> None:
    res = w.check("A", 31, [], {"B": 5}, 50)
    assert [i.kind for i in res.issues] == ["vault-rollback"] and res.rollback_suspected == 50


def test_rollback_suspicion_is_sticky_after_saves_pass_it() -> None:
    """Many saves after the restore must not silently clear the warning (only an acknowledgement does)."""
    res = w.check("A", 51, [w.Observation("B", 6, {"A": 50})], {"B": 5}, 50)
    assert [i.kind for i in res.issues] == ["vault-rollback"] and res.rollback_suspected == 50


def test_only_the_highest_suspicion_is_kept() -> None:
    res = w.check("A", 1, [w.Observation("B", 5, {"A": 40}), w.Observation("C", 5, {"A": 70})], {}, 60)
    assert res.rollback_suspected == 70 and [i.kind for i in res.issues] == ["vault-rollback"]


def test_own_observation_is_ignored_and_no_views_report_nothing() -> None:
    assert w.check("A", 1, [w.Observation("A", 0, {"A": 99})], {}, 0).issues == ()
    res = w.check("A", 1, [], {}, 0)
    assert res.issues == () and res.peer_generations == {} and res.rollback_suspected == 0


def test_check_is_pure() -> None:
    remembered = {"B": 50}
    w.check("A", 10, [w.Observation("B", 60)], remembered, 0)
    assert remembered == {"B": 50}


def test_own_witness_drops_removed_members_and_caps_at_64() -> None:
    gens = {f"p{i:03}": i for i in range(100)} | {"gone": 5, "A": 7}
    out = w.own_witness(gens, [*(f"p{i:03}" for i in range(100)), "A"], "A")
    assert len(out) == 64 and "gone" not in out and "A" not in out
    assert list(out) == sorted(out)


def test_clamp_and_session_generation() -> None:
    assert w.clamp_generation(2**60) == 2**53 - 1 and w.clamp_generation(-3) == 0

    class S:
        generation = 12

    assert w.session_generation(S()) == 12 and w.session_generation(object()) is None
