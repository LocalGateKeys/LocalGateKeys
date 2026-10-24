"""Third-party import on the free plan brings in only the free slots left (no Tk)."""
from __future__ import annotations

import copy
import shutil
import uuid
from pathlib import Path

import pytest

from localvault.import_workflow import (
    ImportWorkflowError,
    apply_import_plan,
    build_import_plan,
    item_limit_cause,
    plan_records,
)
from localvault.importers import ImportedRecord
from localvault.vault import ItemLimitReached, create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "import limit master"


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"import-limit-{request.node.name}-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _vault(case_dir: Path, *, limit: int | None = 4):
    session = create_vault(case_dir / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    session.item_limit = limit
    return session


def _fill(session, count: int, *, start: int = 0) -> list[str]:
    limit, session.item_limit = session.item_limit, None
    try:
        return [session.upsert_web(origin=f"https://site{start + i}.example", username="me",
                                   password=f"pw-{start + i}") for i in range(count)]
    finally:
        session.item_limit = limit


def _snapshot(session) -> tuple[dict, bytes]:
    return copy.deepcopy(session._payload), Path(session.path).read_bytes()


def _login(i: int, *, origin: str | None = None, password: str | None = None) -> ImportedRecord:
    return ImportedRecord(kind="login", title=f"Imp {i}", username="me", password=password or f"imp-{i}",
                          urls=[origin or f"https://imp{i}.example"], source_row=i + 2)


def _csv(case_dir: Path, rows: int) -> Path:
    path = case_dir / "chrome.csv"
    lines = ["name,url,username,password"]
    lines += [f"Imp {i},https://imp{i}.example/login,me,imp-pw-{i}" for i in range(rows)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _origins(session) -> set[str]:
    return {entry["scope"]["origin"] for entry in session.all_entries() if entry.get("kind") == "web"}


def test_free_vault_with_one_item_imports_three_of_six_csv_rows(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 1)
    plan = build_import_plan(session, _csv(case_dir, 6))
    assert plan.free_slots == 3
    assert [row.limited for row in plan.rows] == [False, False, False, True, True, True]
    assert [view["limited"] for view in plan.preview] == [False, False, False, True, True, True]
    counts = plan.summary()
    assert counts["limited"] == 3 and counts["add"] == 3
    assert plan.limit_note() == "3 will be imported on the free plan; 3 need Pro"
    plan.review()
    written = apply_import_plan(session, plan)
    assert written == 3
    assert session.live_item_count() == 4
    assert _origins(session) == {"https://site0.example", "https://imp0.example", "https://imp1.example",
                                 "https://imp2.example"}
    assert plan.limit_note() == "3 will be imported on the free plan; 3 need Pro"
    summary = plan.limit_summary()
    assert summary["item_limit"] == 4 and len(summary["limit_skipped_ids"]) == 3


def test_limit_note_without_limited_rows_shows_free_slots(case_dir: Path) -> None:
    session = _vault(case_dir)
    plan = plan_records(session, [_login(0)])
    assert plan.limit_note() == "4 free slots left on the free plan"
    assert plan.limit_summary()["limit_skipped_ids"] == []


def test_replace_and_merge_at_the_limit_are_still_applied(case_dir: Path) -> None:
    session = _vault(case_dir)
    ids = _fill(session, 4)
    records = [
        _login(0, origin="https://site0.example", password="changed-0"),
        _login(1, origin="https://site1.example", password="changed-1"),
        _login(2),
    ]
    plan = plan_records(session, records)
    assert plan.free_slots == 0
    plan.set_decision(plan.rows[0], "replace")
    plan.set_decision(plan.rows[1], "merge")
    assert [row.limited for row in plan.rows] == [False, False, True]
    assert plan.limit_note() == "2 will be imported on the free plan; 1 need Pro"
    plan.review()
    assert apply_import_plan(session, plan) == 2
    assert session.live_item_count() == 4
    assert session.get_entry(ids[0])["password"] == "changed-0"
    assert session.get_entry(ids[1])["password"] == "changed-1"
    assert "https://imp2.example" not in _origins(session)


def test_keep_both_copies_consume_slots(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 3)
    records = [_login(0, origin="https://site0.example", password="other-0"),
               _login(1, origin="https://site1.example", password="other-1")]
    plan = plan_records(session, records)
    plan.set_decision(plan.rows[0], "keep_both")
    plan.set_decision(plan.rows[1], "keep_both")
    assert [row.limited for row in plan.rows] == [False, True]
    plan.review()
    assert apply_import_plan(session, plan) == 1
    assert session.live_item_count() == 4


def test_identity_with_extra_details_note_needs_two_slots(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 3)
    identity = ImportedRecord(kind="identity", title="Me", identity={"given_name": "Alice", "shoe_size": "7"},
                              source_row=2)
    plan = plan_records(session, [identity, _login(1)])
    assert plan.rows[0].extra is not None
    assert [row.limited for row in plan.rows] == [True, False]
    plan.review()
    assert apply_import_plan(session, plan) == 1
    assert session.live_item_count() == 4


def test_pro_imports_everything(case_dir: Path) -> None:
    session = _vault(case_dir, limit=None)
    _fill(session, 4)
    plan = plan_records(session, [_login(i) for i in range(6)])
    assert plan.free_slots is None
    assert not any(row.limited for row in plan.rows)
    assert plan.summary()["limited"] == 0
    assert plan.limit_note() == ""
    assert plan.limit_summary()["item_limit"] is None
    plan.review()
    assert apply_import_plan(session, plan) == 6
    assert session.live_item_count() == 10


def test_changing_an_action_recomputes_the_limited_rows(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 2)
    plan = plan_records(session, [_login(i) for i in range(4)])
    assert [row.limited for row in plan.rows] == [False, False, True, True]
    plan.set_decision(plan.rows[0], "skip")
    assert [row.limited for row in plan.rows] == [False, False, False, True]
    plan.set_decision(plan.rows[0], "add")
    assert [row.limited for row in plan.rows] == [False, False, True, True]
    plan.set_all("skip")
    assert not any(row.limited for row in plan.rows)
    plan.set_all("add", statuses=("new",))
    assert [row.limited for row in plan.rows] == [False, False, True, True]


def test_nothing_partially_written_when_slots_drift_after_preview(case_dir: Path) -> None:
    session = _vault(case_dir)
    _fill(session, 1)
    plan = plan_records(session, [_login(i) for i in range(3)])
    assert not any(row.limited for row in plan.rows)
    _fill(session, 2, start=10)
    plan.review()
    before = _snapshot(session)
    with pytest.raises(ImportWorkflowError) as caught:
        apply_import_plan(session, plan)
    assert isinstance(item_limit_cause(caught.value), ItemLimitReached)
    assert _snapshot(session) == before
    assert session.live_item_count() == 3


def test_nothing_partially_written_when_a_later_row_fails(case_dir: Path) -> None:
    session = _vault(case_dir)
    plan = plan_records(session, [_login(0), _login(1)])
    plan.review()
    session.upsert_web(origin="https://imp1.example", username="me", password="raced")
    before = _snapshot(session)
    with pytest.raises(ImportWorkflowError):
        apply_import_plan(session, plan)
    assert _snapshot(session) == before


def test_over_limit_vault_still_applies_updates(case_dir: Path) -> None:
    session = _vault(case_dir)
    ids = _fill(session, 6)
    plan = plan_records(session, [_login(0, origin="https://site0.example", password="new-0"), _login(1)])
    plan.set_decision(plan.rows[0], "replace")
    assert [row.limited for row in plan.rows] == [False, True]
    plan.review()
    assert apply_import_plan(session, plan) == 1
    assert session.get_entry(ids[0])["password"] == "new-0"
    assert session.live_item_count() == 6


def test_commit_result_text_reports_the_limited_rows(case_dir: Path) -> None:
    from localvault.app.import_export import import_summary_text
    from localvault.app.transfer_controller import notify_item_limit

    session = _vault(case_dir)
    _fill(session, 2)
    plan = plan_records(session, [_login(i) for i in range(4)])
    plan.review()
    written = apply_import_plan(session, plan)
    text = import_summary_text(plan, written)
    assert "2 record(s) written." in text
    assert "2 will be imported on the free plan; 2 need Pro." in text
    offered: list[ItemLimitReached] = []
    assert notify_item_limit(offered.append, plan.limit_summary()) is True
    assert offered and offered[0].limit == 4


def test_commit_result_text_without_limit_has_no_pro_line(case_dir: Path) -> None:
    from localvault.app.import_export import import_summary_text
    from localvault.app.transfer_controller import notify_item_limit

    session = _vault(case_dir, limit=None)
    plan = plan_records(session, [_login(i) for i in range(2)])
    plan.review()
    text = import_summary_text(plan, apply_import_plan(session, plan))
    assert "Pro" not in text
    assert notify_item_limit(lambda exc: None, plan.limit_summary()) is False


def test_legacy_preview_wrapper_refuses_rather_than_silently_dropping_rows(case_dir: Path) -> None:
    from localvault import import_preview

    session = _vault(case_dir)
    _fill(session, 3)
    rows = [import_preview.ImportRow(i + 2, f"Imp {i}", f"https://imp{i}.example", "me", f"pw{i}") for i in range(2)]
    before = _snapshot(session)
    with pytest.raises(import_preview.ImportError, match="free plan"):
        import_preview.apply_import(session, rows)
    assert _snapshot(session) == before
    assert import_preview.apply_import(session, rows[:1]) == 1
