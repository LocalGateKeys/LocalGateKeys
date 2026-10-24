"""Security center content model: no Tk, no vault."""
from __future__ import annotations

from localvault.app.security import ROUTES
from localvault.settings import AppSettings
from localvault.shell.overview_model import BackupStatus
from localvault.shell.security_model import UnlockMethods, issues_for, lock_summary, security_center

NOW = 1_800_000_000.0


def _health(**ids):
    labels = {"a": "Steam", "b": "Router admin", "c": "Printer", "d": "Netflix", "e": "Spotify"}
    rows = [{"id": key, "label": label} for key, label in labels.items()]
    return {"total": len(rows), "rows": rows, **{f"{name}_ids": value for name, value in ids.items()}}


def _model(health=None, breached=None, methods=None, backup=None, settings=None):
    return security_center(health if health is not None else _health(), breached, methods or UnlockMethods(),
                           backup or BackupStatus(NOW - 3600, 5, ""), settings or AppSettings(), now=NOW)


def test_issues_are_ordered_by_risk_and_zero_counts_are_left_out():
    issues = issues_for(_health(weak=["a", "b", "c"], reused=["d", "e"], no_2fa=["a"], old=[]), None)
    assert [i.key for i in issues] == ["weak", "reused", "no_2fa"]
    assert issues[0].count == 3
    assert issues[0].description == "Printer, Router admin, Steam"


def test_breach_issue_appears_only_after_a_scan_this_session():
    health = _health(weak=["a"])
    assert "breached" not in [i.key for i in issues_for(health, None)]
    assert "breached" not in [i.key for i in issues_for(health, set())]
    found = issues_for(health, {"d", "not-in-vault"})
    assert found[0].key == "breached"
    assert found[0].count == 1
    assert found[0].tone == "danger"


def test_long_name_lists_are_truncated():
    issues = issues_for(_health(weak=["a", "b", "c", "d", "e"]), None)
    assert issues[0].description.endswith("and 2 more")


def test_review_actions_open_the_filtered_health_table():
    issues = issues_for(_health(weak=["a"], reused=["d", "e"], no_2fa=["a"], old=["b"]), {"a"})
    filters = {i.key: dict(i.action.kwargs)["initial_filter"] for i in issues}
    assert filters == {"breached": "exposed", "weak": "weak", "reused": "reused", "no_2fa": "no_2fa", "old": "old"}
    assert all(i.action.method == "password_health_clicked" for i in issues)


def test_score_and_headline_agree_with_the_home_card():
    model = _model(_health(weak=["a"]))
    assert model.score == 80
    assert model.label == "Good"
    assert "bring you to 100" in model.headline
    clean = _model(_health())
    assert clean.score == 100
    assert clean.headline == "Good overall. Nothing urgent to fix."
    empty = _model({"total": 0, "rows": []})
    assert empty.score is None


def test_every_action_maps_to_a_webview_route():
    model = _model(_health(weak=["a"], reused=["d", "e"], no_2fa=["a"], old=["b"]), {"a"},
                   UnlockMethods(hello_available=True))
    actions = [i.action for i in model.issues] + [r.action for p in model.panels for r in p.rows]
    for action in actions:
        assert action.method in ROUTES, action


def test_unlock_panel_reflects_enrolment_without_secrets():
    off = _model(methods=UnlockMethods(hello_available=True, hello_enrolled=False, face_enrolled=False,
                                       recovery_phrase=False))
    unlock = off.panels[0]
    rows = {r.label: r for r in unlock.rows}
    assert unlock.title == "How you unlock"
    assert rows["Windows Hello"].action.label == "Set up"
    assert rows["Recovery phrase"].meta == "Not set"
    assert rows["Recovery phrase"].meta_tone == "warning"
    no_hello = _model(methods=UnlockMethods(hello_available=False))
    assert "Windows Hello" not in {r.label for r in no_hello.panels[0].rows}


def test_lock_summary_reads_the_lock_settings():
    settings = AppSettings(auto_lock_seconds=900, lock_on_session_lock=True, lock_on_sleep=True)
    assert lock_summary(settings) == "After 15 minutes idle · when Windows locks · on sleep"
    assert lock_summary(AppSettings(auto_lock_seconds=0, lock_on_session_lock=False,
                                    lock_on_sleep=False)) == "No inactivity lock"


def test_backup_panel_warns_when_stale_or_missing():
    stale = _model(backup=BackupStatus(NOW - 9 * 86400, 2, "")).panels[1].rows[0]
    assert stale.meta_tone == "warning"
    assert stale.meta.startswith("9 days ago")
    missing = _model(backup=BackupStatus(None, 0, "")).panels[1].rows[0]
    assert missing.meta == "No backup yet"
    assert missing.action.kwargs == (("allow_locked", True),)


def test_privacy_toggles_flip_the_current_setting():
    rows = {r.label: r for r in _model(settings=AppSettings(breach_check_enabled=True,
                                                             strict_offline_mode=False)).panels[3].rows}
    assert dict(rows["Breach checks"].action.kwargs) == {"key": "breach_check_enabled", "value": False}
    assert dict(rows["Strict offline mode"].action.kwargs) == {"key": "strict_offline_mode", "value": True}
    assert rows["Breach checks"].action.method == "security_set_setting"
