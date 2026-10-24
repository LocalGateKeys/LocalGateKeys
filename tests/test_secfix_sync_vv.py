"""Audit 2026-10-24 M-6: poisoned version vectors must not stop a device's sync."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from test_sync_folder_transport import NOW, _group, _web, kinds
from test_sync_phone_restore import PASSWORD, PHONE, FakeLease, _vault

from localvault.phone_backup import read_phone_backup, write_phone_backup
from localvault.sync import engine
from localvault.sync.engine import ItemState, implausible_vv
from localvault.sync.group import decode_view, encode_view
from localvault.sync.phone_restore import plan_restore, restore
from localvault.sync.vault_bridge import (
    COUNTER_OVERFLOW,
    load_sync_state,
    local_view,
    save_sync_state,
)

MAX = 2**53 - 1
VECTORS = Path(__file__).parent / "vectors" / "sync" / "hardening_cases.json"


def test_implausible_vv_rules() -> None:
    known = {"a", "b"}
    assert implausible_vv({"a": 3, "b": 9}, {"a": 1}, known) is None
    assert implausible_vv({"a": engine.MAX_VV_COUNTER}, None, known) is None
    assert implausible_vv({"a": engine.MAX_VV_COUNTER + 1}, None, known) == "implausible-counter"
    assert implausible_vv({"a": MAX}, {"a": MAX}, known) is None  # nothing new
    # an honest edit just past the bound is fine next to the local value
    assert implausible_vv({"a": engine.MAX_VV_COUNTER + 2}, {"a": engine.MAX_VV_COUNTER}, known) is None
    # unknown keys get the tighter bound, unless the local vector already has them
    assert implausible_vv({"zz": engine.MAX_UNKNOWN_VV_COUNTER}, None, known) is None
    assert implausible_vv({"zz": engine.MAX_UNKNOWN_VV_COUNTER + 1}, None, known) == "implausible-counter"
    assert implausible_vv({"zz": engine.MAX_UNKNOWN_VV_COUNTER + 1}, {"zz": 5}, known) is None
    many = {f"d{i}": 1 for i in range(engine.MAX_VV_KEYS + 1)}
    assert implausible_vv(many, None, known) == "too-many-keys"


def test_shared_vv_vectors_match() -> None:
    cases = json.loads(VECTORS.read_text(encoding="utf-8"))["vv"]
    assert cases
    for case in cases:
        assert implausible_vv(case["remote"], case["local"], set(case["known"])) == case["expected"], case


def _poison(m, item_id: str, members: list[str], *, counter_bump: int = 5) -> None:
    """m (a group-key holder whose views nobody pinned) republishes *item_id* with MAX counters."""
    gk = m.gk()
    view = decode_view(gk, m.own_file.read_bytes(), expected_device_id=m.device_id)
    states = [ItemState(s.item_id, {d: MAX for d in members}, s.deleted, s.deleted_at, s.item)
              if s.item_id == item_id else s for s in view.states]
    m.own_file.write_bytes(encode_view(gk, m.device_id, m.state.own_counter + counter_bump, states, NOW + 1))


def _unpin(*devs) -> None:
    """Forget every peer signing key, as on a device that only ever saw unsigned (older) views."""
    for d in devs:
        st = d.state
        own = {k: v for k, v in st.view_signers.items() if k == st.device_id}
        save_sync_state(d.session, dataclasses.replace(st, view_signers=own))


def test_poisoned_vector_is_quarantined_and_sync_continues(tmp_path: Path) -> None:
    root = tmp_path / "OneDrive"
    root.mkdir()
    a, b, m = _group(tmp_path, root, 3)
    eid = _web(a, "bank")
    for d in (a, b, m):
        d.sync(NOW)
    sig = root / "LocalGateKeys Sync" / "signatures" / f"{m.device_id}.lgksig"
    sig.unlink()
    _unpin(a, b)  # m looks like a member that runs an older (unsigned) app
    _poison(m, eid, [a.device_id, b.device_id, m.device_id])

    for d in (a, b):
        report = d.sync(NOW + 2)
        assert kinds(report) == ["implausible-vv"]
        assert report.issues[0].detail == f"{m.device_id}:{eid}"
        assert max(local_view(d.session, d.lease, device_id=d.device_id, now=NOW + 2)[eid].vv.values()) < 10

    a.session.update_entry_fields(eid, password="new-password-after-poison")
    report = a.sync(NOW + 10)
    assert "local-data" not in kinds(report) and report.wrote
    b.sync(NOW + 11)
    assert b.entry(eid)["password"] == "new-password-after-poison"
    eid2 = _web(a, "other")
    a.sync(NOW + 12)
    b.sync(NOW + 13)
    assert any(e["id"] == eid2 for e in b.session._payload["entries"])


def test_stored_overflowing_vector_skips_only_that_item(tmp_path: Path) -> None:
    root = tmp_path / "OneDrive"
    root.mkdir()
    a, b = _group(tmp_path, root, 2)
    bad, good = _web(a, "poisoned"), _web(a, "fine")
    a.sync(NOW)
    b.sync(NOW)
    # a vector accepted before the plausibility rule existed: this device's counter is at the maximum
    with a.session.transaction():
        meta = a.session._require_typed_catalog()["sync_meta"]["items"][bad]
        meta["vv"] = {**meta["vv"], a.device_id: MAX}
    a.session.update_entry_fields(bad, password="edited-1")
    a.session.update_entry_fields(good, password="edited-2")
    view = local_view(a.session, a.lease, device_id=a.device_id, now=NOW + 5)
    assert view.skipped == {bad: COUNTER_OVERFLOW} and good in view
    report = a.sync(NOW + 6)
    assert "local-data" not in kinds(report) and report.wrote
    b.sync(NOW + 7)
    assert b.entry(good)["password"] == "edited-2"


def test_phone_backup_with_poisoned_vectors_is_skipped(tmp_path: Path) -> None:
    lease = FakeLease()
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    good = phone.upsert_web(origin="https://good.example.com", username="me", password="pw-123456")
    bad = phone.upsert_web(origin="https://bad.example.com", username="me", password="pw-123456")
    states = [ItemState(s.item_id, {PHONE: MAX, "desk-id": MAX}, s.deleted, s.deleted_at, s.item)
              if s.item_id == bad else s
              for s in local_view(phone, lease, device_id=PHONE, now=NOW).values()]
    data = write_phone_backup(states, password=PASSWORD, device_id=PHONE, platform="android",
                              app_version="1.0", created_at=NOW, pro_hint=False,
                              kdf={"name": "argon2id", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1})
    plan = plan_restore(desk, lease, read_phone_backup(data, PASSWORD), now=NOW)
    assert plan.skipped == 1 and plan.new == 1
    report = restore(desk, lease, plan, now=NOW)
    ids = {e["id"] for e in desk._payload["entries"]}
    assert good in ids and bad not in ids and report.issues == ()
    # the desktop can still edit and sync everything afterwards
    desk.update_entry_fields(good, password="later")
    assert good in local_view(desk, lease, device_id="desk-id", now=NOW + 1)
    assert load_sync_state(desk) is None


@pytest.mark.parametrize("value", [engine.MAX_VV_COUNTER + 1, MAX])
def test_run_merge_quarantines_only_the_bad_record(tmp_path: Path, value: int) -> None:
    from test_sync_vault_bridge import _vault as bridge_vault

    from localvault.sync import runner
    from localvault.sync.group import View

    lease = FakeLease()
    src, dst = bridge_vault(tmp_path, "src"), bridge_vault(tmp_path, "dst")
    one = src.upsert_web(origin="https://one.example.com", username="me", password="pw-123456")
    two = src.upsert_web(origin="https://two.example.com", username="me", password="pw-123456")
    states = tuple(ItemState(s.item_id, {"src": value}, s.deleted, s.deleted_at, s.item) if s.item_id == two else s
                   for s in local_view(src, lease, device_id="src", now=NOW).values())
    report = runner.run_merge(dst, lease, device_id="dst", views=[View({"device_id": "src"}, states)], now=NOW)
    assert [(i.kind, i.detail) for i in report.issues] == [("implausible-vv", f"src:{two}")]
    ids = {e["id"] for e in dst._payload["entries"]}
    assert one in ids and two not in ids
