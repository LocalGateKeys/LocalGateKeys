"""Encrypted transfer import respects the free plan item limit (no Tk)."""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest

from localvault.transfer import export_transfer, import_transfer, preview_transfer
from localvault.vault import ItemLimitReached, create_vault, free_item_slots

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "transfer limit master password"
TRANSFER_PASSWORD = "transfer limit package password"


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"transfer-limit-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _vault(case_dir: Path, name: str, *, limit: int | None = 4):
    session = create_vault(case_dir / f"{name}.json", MASTER, kdf_overrides=KDF)
    session.item_limit = limit
    return session


def _notes(session, count: int, prefix: str = "n") -> list[str]:
    return [session.items.create_note(f"{prefix}{i}", "body") for i in range(count)]


def test_free_item_slots(case_dir: Path) -> None:
    session = _vault(case_dir, "v")
    assert free_item_slots(session) == 4
    _notes(session, 3)
    assert free_item_slots(session) == 1
    session.item_limit = None
    assert free_item_slots(session) is None
    session.item_limit = 2
    assert free_item_slots(session) == 0  # over the limit never goes negative


def test_reviewer_scenario_copy_import_into_full_vault_skips_all(case_dir: Path) -> None:
    session = _vault(case_dir, "a")
    ids = _notes(session, 4)
    package = case_dir / "notes.lgt"
    export_transfer(session, package, TRANSFER_PASSWORD, ids=ids)

    preview = preview_transfer(package, session, TRANSFER_PASSWORD, conflict_policy="copy")
    assert preview["copied_ids"] == [] and len(preview["limit_skipped_ids"]) == 4
    assert preview["item_limit"] == 4 and preview["free_slots"] == 0

    result = import_transfer(package, session, TRANSFER_PASSWORD, conflict_policy="copy")
    assert session.live_item_count() == 4
    assert len(result["limit_skipped_ids"]) == 4
    assert result["copied_ids"] == [] and result["committed"] is True


def test_import_fills_remaining_slots_in_plan_order(case_dir: Path) -> None:
    source = _vault(case_dir, "src", limit=None)
    ids = _notes(source, 5, "src")
    package = case_dir / "five.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=ids)

    destination = _vault(case_dir, "dst")
    _notes(destination, 2)
    result = import_transfer(package, destination, TRANSFER_PASSWORD)
    assert destination.live_item_count() == 4
    assert len(result["imported_ids"]) == 2 and len(result["limit_skipped_ids"]) == 3
    order = [row for row in result["id_map"]]  # plan order
    assert result["imported_ids"] == [key for key in order if key in result["imported_ids"]]
    assert set(result["imported_ids"]) | set(result["limit_skipped_ids"]) == set(ids)
    titles = sorted(item["title"] for item in destination.items.list_items())
    assert titles[:2] == ["n0", "n1"] and len(titles) == 4


def test_pro_session_imports_everything(case_dir: Path) -> None:
    source = _vault(case_dir, "src", limit=None)
    ids = _notes(source, 6, "src")
    package = case_dir / "six.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=ids)

    destination = _vault(case_dir, "dst", limit=None)
    result = import_transfer(package, destination, TRANSFER_PASSWORD)
    assert destination.live_item_count() == 6
    assert result["limit_skipped_ids"] == [] and result["item_limit"] is None
    assert result["free_slots"] is None


def test_replace_updates_are_never_limited(case_dir: Path) -> None:
    session = _vault(case_dir, "a", limit=None)
    ids = _notes(session, 5)
    package = case_dir / "same.lgt"
    export_transfer(session, package, TRANSFER_PASSWORD, ids=ids)
    session.item_limit = 4  # over the limit, as after an upgrade from 0.4.0

    result = import_transfer(package, session, TRANSFER_PASSWORD, conflict_policy="replace", allow_replace=True)
    assert sorted(result["replaced_ids"]) == sorted(ids)
    assert result["limit_skipped_ids"] == []
    assert session.live_item_count() == 5


def test_credentials_count_against_the_limit(case_dir: Path) -> None:
    source = _vault(case_dir, "src", limit=None)
    ids = [source.upsert_web(origin=f"https://s{i}.example", username="me", password=f"pw{i}") for i in range(3)]
    package = case_dir / "logins.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=ids)

    destination = _vault(case_dir, "dst")
    _notes(destination, 3)
    result = import_transfer(package, destination, TRANSFER_PASSWORD)
    assert destination.live_item_count() == 4
    assert len(result["imported_ids"]) == 1 and len(result["limit_skipped_ids"]) == 2


def test_document_skipped_by_limit_takes_its_referencing_item_along(case_dir: Path) -> None:
    source = _vault(case_dir, "src", limit=None)
    document_path = case_dir / "receipt.txt"
    document_path.write_text("receipt contents", encoding="utf-8")
    document_id = source.documents.create(document_path, title="Receipt")
    purchase_id = source.items.create_purchase("Purchase", document_ids=[document_id])
    package = case_dir / "docs.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[document_id, purchase_id])

    destination = _vault(case_dir, "dst")
    _notes(destination, 3)  # one slot: the pair needs two
    result = import_transfer(package, destination, TRANSFER_PASSWORD)
    assert destination.live_item_count() == 4
    kinds = sorted(item["kind"] for item in destination.items.list_items())
    assert "purchase" not in kinds  # never a purchase pointing at a missing document
    assert purchase_id in result["limit_skipped_ids"]


def test_commit_guard_raises_item_limit_if_vault_filled_after_plan(case_dir: Path, monkeypatch) -> None:
    from localvault import transfer

    source = _vault(case_dir, "src", limit=None)
    ids = _notes(source, 2, "src")
    package = case_dir / "two.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=ids)
    destination = _vault(case_dir, "dst")
    _notes(destination, 2)

    real_commit = transfer._commit_plan

    def racing_commit(session, plan, cancel):
        _notes(session, 1, "race")  # another writer took a slot between plan and commit
        return real_commit(session, plan, cancel)

    monkeypatch.setattr(transfer, "_commit_plan", racing_commit)
    with pytest.raises(ItemLimitReached):
        import_transfer(package, destination, TRANSFER_PASSWORD)
    assert destination.live_item_count() == 3


# --- transfer UI text and routing (pure functions, no Tk window) ---


def test_limit_lines_preview_and_result_name_the_count_and_offer_pro() -> None:
    from localvault.app.transfer_controller import import_limit_lines

    preview = {"limit_skipped_ids": ["a", "b", "c", "d"], "item_limit": 4, "free_slots": 0,
               "requires_confirmation": True}
    lines = import_limit_lines(preview)
    text = " ".join(lines)
    assert "4 new records will be skipped" in text and "free plan" in text and "Pro" in text
    assert "0 free slots left" in text

    result = {"limit_skipped_ids": ["a"], "item_limit": 4, "free_slots": 1, "committed": True}
    text = " ".join(import_limit_lines(result))
    assert "1 new record was skipped" in text and "Pro" in text


def test_limit_lines_empty_for_pro_and_mention_slots_when_nothing_skipped() -> None:
    from localvault.app.transfer_controller import import_limit_lines

    assert import_limit_lines({"limit_skipped_ids": [], "item_limit": None, "free_slots": None}) == []
    assert import_limit_lines({}) == []
    assert import_limit_lines({"limit_skipped_ids": [], "item_limit": 4, "free_slots": 3,
                               "requires_confirmation": True}) == ["3 free slots left on the free plan."]


def test_controller_summary_carries_limit_fields(case_dir: Path) -> None:
    from localvault.app.transfer_controller import TransferController

    session = _vault(case_dir, "a")
    ids = _notes(session, 4)
    package = case_dir / "notes.lgt"
    export_transfer(session, package, TRANSFER_PASSWORD, ids=ids)
    controller = TransferController(session)
    preview = controller.preview_import(package, TRANSFER_PASSWORD, conflict_policy="copy")
    assert len(preview["limit_skipped_ids"]) == 4 and preview["item_limit"] == 4 and preview["free_slots"] == 0
    result = controller.import_package(package, TRANSFER_PASSWORD, confirm=True, conflict_policy="copy")
    assert len(result["limit_skipped_ids"]) == 4 and session.live_item_count() == 4


def test_limit_notice_routes_to_callback_and_survives_failure() -> None:
    from localvault.app.transfer_controller import notify_item_limit

    seen = []
    assert notify_item_limit(seen.append, {"limit_skipped_ids": ["x", "y"], "item_limit": 4}) is True
    assert isinstance(seen[0], ItemLimitReached) and seen[0].limit == 4
    assert notify_item_limit(seen.append, {"limit_skipped_ids": [], "item_limit": 4}) is False
    assert notify_item_limit(None, {"limit_skipped_ids": ["x"], "item_limit": 4}) is False

    def broken(exc):
        raise RuntimeError("dialog failed")

    assert notify_item_limit(broken, {"limit_skipped_ids": ["x"], "item_limit": 4}) is False
