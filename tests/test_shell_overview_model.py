import os
from datetime import date

import pytest

from localvault.shell.overview_model import (
    BackupStatus,
    age_text,
    backup_status,
    health_overview,
    upcoming_lines,
)


def test_score_counts_weak_and_reused_once():
    h = health_overview({"total": 10, "weak_ids": ["a", "b"], "reused_ids": ["b", "c"], "no_2fa_ids": ["d"]})
    assert (h.score, h.label, h.weak, h.reused, h.no_2fa) == (70, "Fair", 2, 2, 1)
    assert h.attention_ids == {"a", "b", "c"} and h.breached is None
    assert h.no_2fa_ids == {"d"}


def test_breached_counts_into_attention():
    h = health_overview({"total": 4, "weak_ids": [], "reused_ids": [], "no_2fa_ids": []}, breached_ids={"x"})
    assert h.breached == 1 and h.attention_ids == {"x"} and h.score == 75


def test_empty_vault_has_no_score():
    h = health_overview({"total": 0, "weak_ids": [], "reused_ids": [], "no_2fa_ids": []})
    assert (h.score, h.label) == (None, "No logins yet")


@pytest.mark.parametrize("attention,label", [(0, "Good"), (2, "Good"), (5, "Fair"), (6, "Poor")])
def test_label_thresholds(attention, label):
    ids = [str(i) for i in range(attention)]
    h = health_overview({"total": 10, "weak_ids": ids, "reused_ids": [], "no_2fa_ids": []})
    assert h.label == label


def test_backup_status_reads_newest_rolling_backup(tmp_path):
    for i, name in enumerate(["vault-1.json", "vault-2.json"]):
        p = tmp_path / name
        p.write_text("{}")
        os.utime(p, (1000 + i, 1000 + i))
    (tmp_path / "other.json").write_text("{}")
    assert backup_status(tmp_path) == BackupStatus(1001.0, 2, "")


def test_backup_status_missing_dir(tmp_path):
    assert backup_status(tmp_path / "nope") == BackupStatus(None, 0, "")


def test_backup_status_carries_warning(tmp_path):
    assert backup_status(tmp_path, "disk full").warning == "disk full"


@pytest.mark.parametrize("secs,text", [(30, "just now"), (7200, "2 hours ago"), (6 * 86400, "6 days ago"),
                                       (3600, "1 hour ago"), (300, "5 minutes ago")])
def test_age_text(secs, text):
    assert age_text(secs) == text


def test_upcoming_lines_sorted_and_limited():
    # Real ReminderService rows carry an ISO "due_date" string.
    rows = [{"label": "Passport expires", "due_date": "2027-01-10"}, {"label": "Netflix renews", "due_date": "2026-10-18"},
            {"label": "Office", "due_date": "2026-11-02"}, {"label": "Later", "due_date": "2027-05-01"}]
    lines = upcoming_lines(rows, date(2026, 10, 14))
    assert [(l.date_text, l.label, l.meta) for l in lines] == [
        ("OCT 18", "Netflix renews", "4 days"), ("NOV 2", "Office", "19 days"), ("JAN 10", "Passport expires", "88 days")]


def test_upcoming_lines_overdue_and_date_objects():
    rows = [{"label": "Late", "due_date": date(2026, 10, 10)}, {"label": "Now", "due_date": "2026-10-14"}]
    lines = upcoming_lines(rows, date(2026, 10, 14))
    assert [(l.label, l.meta, l.overdue) for l in lines] == [("Late", "overdue", True), ("Now", "today", False)]


def test_upcoming_lines_skip_missing_or_malformed_due_dates():
    rows = [{"label": "No date"}, {"label": "Blank", "due_date": ""}, {"label": "None", "due_date": None},
            {"label": "Bad", "due_date": "next tuesday"}, {"label": "Bad month", "due_date": "2026-13-01"},
            {"label": "Good", "due_date": "2026-10-20"}]
    lines = upcoming_lines(rows, date(2026, 10, 14))
    assert [(line.label, line.meta) for line in lines] == [("Good", "6 days")]
