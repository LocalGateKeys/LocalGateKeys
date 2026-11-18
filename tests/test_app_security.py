"""Stage 4a: the Security center and password health with consented breach checks."""
from __future__ import annotations

import json

import pytest


from localvault.api.result import ApiError
from localvault.app import health
from localvault.app.controller import WebController
from localvault.app.health import HealthService
from localvault.app.home import HomeService
from localvault.app.security import SecurityService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.site_features import SiteFeatures

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.asked, self.answers = [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True

    def notify(self, kind, title, message):
        self.asked.append(title)

    def ask_password(self, title, message):
        return None

    def show_upgrade(self, **kwargs):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    # no_2fa needs site data: both test sites offer TOTP
    monkeypatch.setattr("localvault.site_features.load",
                        lambda path=None: SiteFeatures({"weak.test": ["totp"], "ok.test": ["totp"]}))
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    settings = AppSettings(idle_source="vault", breach_check_enabled=True, strict_offline_mode=False)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    bus = Bus()
    controller = WebController(profiles=profiles, settings=settings, bus=bus, scheduler=Sched(),
                               create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    session = controller.session
    weak = session.create_web_login(urls=[{"url": "https://weak.test", "match": "exact_origin"}], username="a",
                                    password="password1", label="Weak")
    strong = session.create_web_login(urls=[{"url": "https://ok.test", "match": "exact_origin"}], username="b",
                                      password="Xq7!vR2#mP9$wL4@", label="Strong")
    home = HomeService(controller)
    port = Port()
    checked = []

    def check(password, *, consent, strict_offline=False):
        checked.append(password)
        return 42 if password == "password1" else 0

    health = HealthService(controller, port, home, bus, check=check, spawn=lambda fn: fn(), sleep=lambda s: None)
    security = SecurityService(controller, home)
    return {"controller": controller, "home": home, "port": port, "bus": bus, "health": health,
            "security": security, "weak": weak, "strong": strong, "checked": checked}


def test_center_maps_actions_to_page_routes(env):
    center = env["security"].center()
    assert center["score"] is not None
    weak = next(i for i in center["issues"] if i["key"] == "weak")
    assert weak["action"] == {"label": "Review 1", "route": "health", "params": {"filter": "weak"}}
    rows = [r for p in center["panels"] for r in p["rows"]]
    master = next(r for r in rows if r["action"]["label"] == "Change…")
    assert master["action"]["route"] == "master"
    backup = next(r for r in rows if r["action"]["label"] == "Back up now")
    assert backup["action"] == {"label": "Back up now", "route": "recovery", "params": {"initial": "create"}}
    restore = next(r for r in rows if r["action"]["label"] == "Restore…")
    assert restore["action"] == {"label": "Restore…", "route": "recovery", "params": {"initial": "restore"}}
    breach = next(r for r in rows if r["label"] == "Breach checks")
    assert breach["action"]["route"] == "set" and breach["action"]["params"] == {"key": "breach_check_enabled",
                                                                                 "value": False}


def test_center_lists_agent_exposure_so_a_vault_without_logins_can_reach_it(env):
    security = env["security"]
    assert all(i["key"] != "agent_exposed" for i in security.center()["issues"])
    security.agent_exposed = lambda session: 2
    issue = next(i for i in security.center()["issues"] if i["key"] == "agent_exposed")
    assert issue["count"] == 2 and issue["title"] == "Exposed to an AI agent"
    assert issue["action"] == {"label": "Review 2", "route": "health", "params": {"filter": "agent"}}

    def broken(session):
        raise RuntimeError("log unreadable")
    security.agent_exposed = broken
    assert all(i["key"] != "agent_exposed" for i in security.center()["issues"])


def test_set_setting_saves_privacy_switches_only(env):
    env["security"].set_setting("strict_offline_mode", True)
    assert env["controller"].settings.strict_offline_mode is True
    with pytest.raises(ApiError):
        env["security"].set_setting("auto_lock_seconds", 0)


def test_network_activity_lists_the_ledger_and_needs_an_unlocked_vault(env):
    from localvault import net_ledger

    net_ledger._reset_for_tests()
    net_ledger.record(net_ledger.UPDATE_CHECK, "updates.localgatekeys.app", "ok")
    net_ledger.record(net_ledger.WEBSITE_ICON, "weak.test", "ok")
    view = env["security"].network_activity()
    assert {(e["purpose"], e["host"]) for e in view["entries"]} == {
        ("update_check", "updates.localgatekeys.app"), ("website_icon", "weak.test")}
    env["controller"].lock()
    with pytest.raises(ApiError):
        env["security"].network_activity()
    net_ledger.flush()
    net_ledger._reset_for_tests()


def test_report_summary_and_rows_hold_no_passwords(env):
    report = env["health"].report()
    assert report["summary"] == "2 logins · 1 weak · 0 reused · 2 without 2FA · 0 older than a year"
    assert {r["breach"] for r in report["rows"]} == {"Not checked"}
    assert "password1" not in json.dumps(report)
    assert [f["key"] for f in report["filters"]] == [None, "weak", "reused", "no_2fa", "old", "http", "passkey",
                                                      "exposed", "agent"]


@pytest.mark.parametrize("setting,text,key", [
    ("strict_offline_mode", health.OFFLINE_TEXT, None),  # a privacy choice: only a way to Settings
    ("breach_check_enabled", health.DISABLED_TEXT, "breach_check_enabled"),  # one click turns it on
])
def test_scan_refusals(env, setting, text, key):
    setattr(env["controller"].settings, setting, setting == "strict_offline_mode")
    with pytest.raises(ApiError) as refused:
        env["health"].scan(None)
    assert refused.value.code == "needs_setting" and refused.value.message == text
    assert refused.value.fix["section"] == "privacy" and refused.value.fix.get("key") == key
    assert env["checked"] == []


def test_declined_consent_checks_nothing(env):
    env["port"].answers = [False]
    with pytest.raises(ApiError) as declined:
        env["health"].scan([env["weak"]])
    assert declined.value.code == "cancelled"
    assert env["port"].asked == ["Check selected password with HIBP?"] and env["checked"] == []


def test_scan_all_marks_breached_and_reports_without_passwords(env):
    env["health"].scan(None)
    assert env["port"].asked == ["Check every password with HIBP?"]
    assert env["home"].breached_ids == {env["weak"]}
    report = env["health"].report()
    status = {r["id"]: r["breach"] for r in report["rows"]}
    assert status == {env["weak"]: "Found in 42 breaches", env["strong"]: "Not found"}
    assert report["summary"].endswith(" · 1 exposed in breaches")
    done = [d for n, d in env["bus"].events if n == "job.done"]
    assert done[-1]["message"] == ("Checked 2 unique passwords · 1 logins exposed · 0 errors. "
                                   "Not found does not prove a password is safe.")
    blob = json.dumps(env["bus"].events)
    assert "password1" not in blob and "Xq7" not in blob


def test_single_check_adds_to_breached(env):
    env["home"].breached_ids = {"other"}
    env["health"].scan([env["weak"]])
    assert env["home"].breached_ids == {"other", env["weak"]}


def test_lock_mid_scan_cancels_and_keeps_ids(env):
    controller = env["controller"]

    def check(password, *, consent, strict_offline=False):
        controller.lock()
        return 7

    env["health"]._check = check
    env["health"].scan(None)
    assert env["home"].breached_ids == set()
    done = [d for n, d in env["bus"].events if n == "job.done"]
    assert done[-1] == {"job": "health", "ok": False, "message": "Breach check cancelled."}


def test_lock_between_check_and_commit_writes_nothing(env):
    health, home = env["health"], env["home"]
    original = health._commit_guard

    def lock_then_check(lease):
        env["controller"].lock()
        return original(lease)

    health._commit_guard = lock_then_check
    health.scan(None)
    assert home.breached_ids == set() and health._exposure == {}


def test_second_scan_is_refused_while_consent_is_open(env):
    health, port = env["health"], env["port"]
    inner = []

    def confirm(title, message):
        with pytest.raises(ApiError) as busy:
            health.scan(None)
        inner.append(busy.value.message)
        return False

    port.confirm = confirm
    with pytest.raises(ApiError):
        health.scan(None)
    assert inner == ["Wait for the current breach check to finish."]
    assert health._running is False


def test_center_flags_passkey_available_until_a_passkey_item_exists(env, monkeypatch):
    monkeypatch.setattr("localvault.site_features.load", lambda path=None: SiteFeatures({"pk.test": ["passkey"]}))
    session = env["controller"].session
    session.create_web_login(urls=[{"url": "https://app.pk.test", "match": "exact_origin"}], username="c",
                             password="Xq7!vR2#mP9$wL4@", label="Pk")
    keys = [i["key"] for i in env["security"].center()["issues"]]
    assert "passkey" in keys
    session.item_service.create_passkey("Pk passkey", relying_party_id="pk.test")
    assert "passkey" not in [i["key"] for i in env["security"].center()["issues"]]
