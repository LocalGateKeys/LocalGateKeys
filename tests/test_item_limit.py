"""Free plan item limit: creation paths are gated, existing items stay usable."""
from __future__ import annotations

import copy
import shutil
import time
import uuid
from pathlib import Path

import pytest

from localvault.attachments import DocumentService
from localvault.import_workflow import ImportWorkflowError, apply_import_plan, plan_records
from localvault.importers import ImportedRecord
from localvault.sync.engine import merge
from localvault.sync.vault_bridge import apply, local_view
from localvault.vault import ItemLimitReached, VaultError, create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "item limit master"
MESSAGE = "The free plan holds up to 4 items. Upgrade to LocalGateKeys Pro for unlimited items."
NOW = int(time.time())


class FakeLease:
    def check(self) -> None:
        return None


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"item-limit-{request.node.name}-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _vault(case_dir: Path, name: str = "vault", *, limit: int | None = 4):
    session = create_vault(case_dir / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)
    session.item_limit = limit
    return session


def _fill(session, count: int, *, start: int = 0) -> list[str]:
    """Add ``count`` web logins while the limit is lifted (simulates an older or Pro vault)."""
    limit, session.item_limit = session.item_limit, None
    try:
        return [session.upsert_web(origin=f"https://site{start + i}.example", username="me",
                                   password=f"pw-{start + i}") for i in range(count)]
    finally:
        session.item_limit = limit


def _snapshot(session) -> tuple[dict, bytes]:
    return copy.deepcopy(session._payload), Path(session.path).read_bytes()


def _desktop(session, label: str = "Steam") -> str:
    return session.add_desktop(
        label=label, username="alice", password="pw", exe_path=r"C:\Games\Steam\steam.exe",
        exe_sha256="A" * 64, window_title="Steam Sign In",
        control_fingerprint=[{"class_name": "Edit", "is_password": True}],
        username_selector={"index": 0, "is_password": False},
        password_selector={"index": 1, "is_password": True},
    )


def _assert_blocked(session, action) -> None:
    before = _snapshot(session)
    with pytest.raises(ItemLimitReached) as caught:
        action()
    assert str(caught.value) == MESSAGE
    assert caught.value.limit == 4 and caught.value.count == session.live_item_count()
    assert isinstance(caught.value, VaultError)
    assert _snapshot(session) == before


def test_live_item_count_counts_entries_and_items_not_trash(case_dir: Path) -> None:
    session = _vault(case_dir)
    ids = _fill(session, 2)
    session.items.create_note("Memo", "body")
    assert session.live_item_count() == 3
    session.delete(ids[0])
    assert session.live_item_count() == 2


@pytest.mark.parametrize("action", [
    lambda s: s.upsert_web(origin="https://new.example", username="me", password="pw"),
    lambda s: s.create_web_login(urls=[{"url": "https://new.example"}], username="me", password="pw"),
    lambda s: _desktop(s),
    lambda s: s.items.create_note("Memo", "body"),
    lambda s: s.items.create_bookmark("Link", "https://example.com"),
    lambda s: s.items.create_typed("warranty", "Typed", {}),
    lambda s: s.items.create_identity("Me", {"given_name": "Alice"}),
    lambda s: s.items.create_card("Visa", number="4111111111111111"),
    lambda s: s.items.create_wifi("Home", ssid="home", password="pw"),
    lambda s: s.items.create_license("Tool", license_value="KEY"),
    lambda s: s.items.create_purchase("Laptop"),
    lambda s: s.items.create_passkey("Pk", relying_party_id="example.com"),
], ids=["upsert_web", "create_web_login", "add_desktop", "note", "bookmark", "typed", "identity", "card",
        "wifi", "license", "purchase", "passkey"])
def test_every_create_path_blocked_at_limit(case_dir: Path, action) -> None:
    session = _vault(case_dir)
    _fill(session, 4)
    _assert_blocked(session, lambda: action(session))


def test_document_creation_blocked_before_sidecar_written(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 4)
    source = case_dir / "doc.txt"
    source.write_bytes(b"synthetic document")
    service = DocumentService(session)
    blobs_before = sorted(service.store.root.glob("*.blob")) if service.store.root.exists() else []
    _assert_blocked(session, lambda: service.create(source, title="Doc"))
    blobs_after = sorted(service.store.root.glob("*.blob")) if service.store.root.exists() else []
    assert blobs_after == blobs_before


def test_restore_login_from_trash_blocked_at_limit(case_dir: Path) -> None:
    session = _vault(case_dir)
    ids = _fill(session, 5)
    session.delete(ids[0])
    assert session.live_item_count() == 4
    _assert_blocked(session, lambda: session.restore_deleted(ids[0]))


def test_restore_typed_item_from_trash_blocked_at_limit(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 3)
    note_id = session.items.create_note("Memo", "body")
    session.items.delete_item(note_id)
    _fill(session, 1, start=10)
    assert session.live_item_count() == 4
    _assert_blocked(session, lambda: session.items.restore_item(note_id))


def test_update_existing_login_never_blocked(case_dir: Path) -> None:
    session = _vault(case_dir)
    ids = _fill(session, 6)
    assert session.upsert_web(origin="https://site0.example", username="me", password="changed") == ids[0]
    assert session.get_entry(ids[0])["password"] == "changed"


def test_over_limit_vault_still_edits_and_deletes(case_dir: Path) -> None:
    session = _vault(case_dir)
    ids = _fill(session, 5)
    limit, session.item_limit = session.item_limit, None
    note_id = session.items.create_note("Memo", "body")
    session.item_limit = limit
    assert session.live_item_count() == 6
    session.update_entry_fields(ids[1], label="Renamed", password="new-pw")
    assert session.get_entry(ids[1])["label"] == "Renamed"
    assert session.items.update_item(note_id, title="Memo 2")
    assert session.items.delete_item(note_id)
    assert session.delete(ids[2])
    assert session.live_item_count() == 4


def test_delete_down_to_three_allows_exactly_one_create(case_dir: Path) -> None:
    session = _vault(case_dir)
    ids = _fill(session, 6)
    for entry_id in ids[:3]:
        session.delete(entry_id)
    assert session.live_item_count() == 3
    session.items.create_note("Memo", "body")
    assert session.live_item_count() == 4
    with pytest.raises(ItemLimitReached):
        session.upsert_web(origin="https://another.example", username="me", password="pw")


def test_no_limit_means_unlimited(case_dir: Path) -> None:
    session = _vault(case_dir, limit=None)
    for i in range(6):
        session.upsert_web(origin=f"https://u{i}.example", username="me", password="pw")
    session.items.create_note("Memo", "body")
    _desktop(session)
    assert session.live_item_count() == 8


def test_sync_bridge_apply_inserts_beyond_limit(case_dir: Path) -> None:
    lease = FakeLease()
    source = _vault(case_dir, "a", limit=None)
    _fill(source, 6, start=100)
    target = _vault(case_dir, "b")
    _fill(target, 4)
    a_view = local_view(source, lease, device_id="device-a", now=NOW)
    b_view = local_view(target, lease, device_id="device-b", now=NOW)
    apply(target, lease, merge(b_view, a_view.values()), device_id="device-b", now=NOW)
    assert target.live_item_count() == 10
    with pytest.raises(ItemLimitReached):
        target.items.create_note("Memo", "body")


def test_import_beyond_limit_brings_in_only_the_free_slots(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 3)
    records = [ImportedRecord(kind="login", title=f"Imp {i}", username="me", password=f"pw{i}",
                              urls=[f"https://imp{i}.example"], source_row=i + 2) for i in range(3)]
    plan = plan_records(session, records)
    assert [row.limited for row in plan.rows] == [False, True, True]
    plan.review()
    assert apply_import_plan(session, plan) == 1
    assert session.live_item_count() == 4


def test_import_drifting_past_limit_fails_cleanly_without_partial_write(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 1)
    records = [ImportedRecord(kind="login", title=f"Imp {i}", username="me", password=f"pw{i}",
                              urls=[f"https://imp{i}.example"], source_row=i + 2) for i in range(3)]
    plan = plan_records(session, records)
    plan.review()
    _fill(session, 2, start=10)
    before = _snapshot(session)
    with pytest.raises(ImportWorkflowError, match="free plan"):
        apply_import_plan(session, plan)
    assert _snapshot(session) == before
    assert session.live_item_count() == 3


def test_item_limit_cause_finds_the_limit_behind_an_import_failure(case_dir: Path) -> None:
    from localvault.import_workflow import item_limit_cause

    session = _vault(case_dir)
    _fill(session, 1)
    records = [ImportedRecord(kind="login", title=f"Imp {i}", username="me", password=f"pw{i}",
                              urls=[f"https://imp{i}.example"], source_row=i + 2) for i in range(3)]
    plan = plan_records(session, records)
    plan.review()
    _fill(session, 2, start=10)
    with pytest.raises(ImportWorkflowError) as caught:
        apply_import_plan(session, plan)
    cause = item_limit_cause(caught.value)
    assert isinstance(cause, ItemLimitReached) and cause.limit == 4
    direct = ItemLimitReached(4, 4)
    assert item_limit_cause(direct) is direct
    assert item_limit_cause(ImportWorkflowError("other")) is None
    assert item_limit_cause(None) is None


def test_free_slots_note_for_the_import_review(case_dir: Path) -> None:
    from localvault.import_workflow import free_slots_note

    session = _vault(case_dir)
    _fill(session, 3)
    assert free_slots_note(session) == "1 free slot left on the free plan"
    _fill(session, 2, start=10)
    assert free_slots_note(session) == "0 free slots left on the free plan"
    session.item_limit = None
    assert free_slots_note(session) == ""
