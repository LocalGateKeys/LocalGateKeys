"""Stage 5b: device sync for the WebView UI (the sync engine is faked; jobs are recorded)."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.sync import SyncWebService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings
from localvault.sync.lan_interfaces import Interface, NetworkSnapshot
from localvault.sync.runner import SyncIssue
from localvault.sync.transport import LANEndpoint

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
STRONG = "violet-orbit-cactus-lantern-91"


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
        self.passwords, self.prompts, self.notices = [], [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True

    def ask_password(self, title, message):
        self.prompts.append(title)
        return SecretText.from_str(self.passwords.pop(0) if self.passwords else MASTER)

    def notify(self, level, title, message):
        self.notices.append((level, title))


class Dialogs:
    def __init__(self, folder):
        self.folder = folder

    def choose_folder(self, title):
        return self.folder


class FakeService:
    def __init__(self):
        self.install_id = "install-1"
        self.jobs, self.stopped, self.runs = [], False, 0
        self.result, self.error = None, None
        self.armed, self.cancelled = [], []
        self.enrolled = None
        self.listening = "match"  # "match": listens on the saved endpoint; None: nothing listens
        self.listen_issue = None
        self.settings = None

    def lan_listen_state(self):
        if self.listening == "match":
            host, _, port = self.settings.sync_lan_endpoint.rpartition(":")
            return LANEndpoint(host.strip("[]"), int(port)), None
        return self.listening, self.listen_issue

    def on_unlock(self):
        pass

    def stop(self):
        self.stopped = True

    def run_now(self):
        self.runs += 1

    def lan_transport(self):
        return None

    def submit(self, job, on_done=None, *, run_after=False):
        if self.stopped:
            return False
        self.jobs.append((job, run_after))
        on_done(self.result, self.error)
        return True

    def reset(self, on_done):
        on_done(True)
        return True

    def arm_enrollment(self, offer):
        self.armed.append(offer.offer_id)

    def enrollment_result(self, offer_id):
        return self.enrolled

    def cancel_enrollment(self, offer_id):
        self.cancelled.append(offer_id)
        return True


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    calls = []
    for name in ("create_group_job", "join_folder_job", "rotate_job", "leave_job", "remove_lan_peer_job",
                 "enroll_job", "snapshot_job"):
        monkeypatch.setattr(f"localvault.app.sync.{name}",
                            lambda *args, _n=name: calls.append((_n, args)) or (lambda s, l, g: None))
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    fake = FakeService()
    port = Port()
    fake.settings = controller.settings
    network = SimpleNamespace(snapshot=NetworkSnapshot(
        (Interface("Wi-Fi", ("192.168.1.20",)),), frozenset({"192.168.1.20"}), primary="192.168.1.20"))
    service = SyncWebService(controller, port, bus, Dialogs(str(tmp_path / "cloud")), factory=lambda c, cb: fake,
                             network=lambda: network.snapshot)
    service.start()
    return SimpleNamespace(service=service, fake=fake, controller=controller, port=port, bus=bus, calls=calls,
                           network=network)


def test_lock_stops_the_service_and_unlock_does_not_restart_without_enable(env):
    env.controller.lock()
    assert env.fake.stopped and env.service.service is None
    with pytest.raises(ApiError) as stopped:
        env.service.sync_now()
    assert stopped.value.message == "Sync runs while the vault is unlocked on this PC. Unlock and try again."


def test_enable_starts_after_unlock(env):
    env.controller.lock()
    env.service.enable()
    env.controller.unlock(MASTER)
    assert env.service.service is env.fake


def test_view_has_both_cards(env):
    view = env.service.view()
    assert [c["key"] for c in view["cards"]] == ["wifi", "folder"] and view["available"] is True


def test_create_needs_a_folder_from_the_dialog_and_a_strong_password(env):
    with pytest.raises(ApiError) as no_folder:
        env.service.create("made-up-token", STRONG, STRONG)
    assert no_folder.value.message == "Choose the sync folder first."
    token = env.service.choose_folder()["token"]
    with pytest.raises(ApiError) as weak:
        env.service.create(token, "short", "short")
    assert weak.value.message == "Use at least 12 characters."
    token = env.service.choose_folder()["token"]
    result = env.service.create(token, STRONG, STRONG)
    assert result["message"].startswith("Sync group created.")
    assert [n for n, _ in env.calls if n == "create_group_job"]
    with pytest.raises(ApiError):
        env.service.create(token, STRONG, STRONG)  # a folder token is single-use


def test_passwords_never_reach_events(env):
    token = env.service.choose_folder()["token"]
    env.service.create(token, STRONG, STRONG)
    assert STRONG not in json.dumps(env.bus.events, default=str)


def test_job_errors_use_the_sync_copy(env):
    env.fake.error = OSError("disk")
    token = env.service.choose_folder()["token"]
    with pytest.raises(ApiError) as failed:
        env.service.join(token, "whatever pw")
    assert failed.value.code == "sync_failed" and failed.value.message


def test_a_result_after_a_lock_is_dropped(env):
    original = env.fake.submit

    def submit(job, on_done=None, *, run_after=False):
        env.controller.lock()  # the vault locks while the job runs
        return original(job, on_done, run_after=run_after)

    env.fake.submit = submit
    with pytest.raises(ApiError) as stopped:
        env.service.leave()
    assert stopped.value.code == "stopped"


def test_one_action_at_a_time(env):
    env.service._busy.acquire()
    with pytest.raises(ApiError) as busy:
        env.service.leave()
    assert busy.value.code == "busy"


def test_leave_and_reset_confirm(env):
    env.port.answers = [False]
    with pytest.raises(ApiError):
        env.service.leave()
    assert env.port.asked == ["Leave sync"]
    env.port.asked.clear()
    env.port.answers = [True, False]
    with pytest.raises(ApiError):
        env.service.reset()
    assert env.port.asked == ["Reset sync on this PC", "Reset sync on this PC"]
    assert env.service.reset()["message"] == "Sync was reset on this PC."


def test_wifi_endpoint_validation(env):
    with pytest.raises(ApiError):
        env.service.wifi_enable("8.8.8.8:47821")
    env.service.wifi_enable("192.168.1.20:47821")
    assert env.controller.settings.sync_lan_endpoint == "192.168.1.20:47821"
    env.service.wifi_disable()
    assert env.controller.settings.sync_lan_endpoint == ""


def test_pairing_flow(env, monkeypatch):
    env.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    offer = SimpleNamespace(offer_id="o1", code="123-456", expires_at=9e12)
    env.fake.result = offer
    monkeypatch.setattr("localvault.app.sync.begin_pairing_job", lambda *a: (lambda s, l, g: offer))
    monkeypatch.setattr("localvault.sync.pairing.offer_qr_payload", lambda o: "lgk-pair:secret-payload")
    monkeypatch.setattr("localvault.sync.pairing.render_qr_png", lambda payload, scale=6: b"\x89PNG")
    shown = env.service.qr_show()
    assert shown["code"] == "123-456" and shown["image"].startswith("data:image/png;base64,")
    assert "secret-payload" not in json.dumps(shown)
    assert env.fake.armed == ["o1"]
    assert env.service.qr_poll("o1")["state"] == "waiting"
    env.controller.clipboard = SimpleNamespace(copy=lambda text: setattr(env, "copied", text))
    env.service.qr_copy("o1")
    assert env.copied == "lgk-pair:secret-payload"
    env.fake.enrolled = "device-2"
    assert env.service.qr_poll("o1")["state"] == "paired" and env.fake.runs == 1
    env.service.qr_close("o1")
    assert env.fake.cancelled == ["o1"]


def test_licence_adopted_by_sync_reapplies_the_limit(env):
    seen = []
    env.service._on_licence = lambda: seen.append(1)
    env.service._status_changed(env.fake, SimpleNamespace(license_adopted=True))
    assert seen == [1]
    env.service._status_changed(object(), SimpleNamespace(license_adopted=True))  # stale service: ignored
    assert seen == [1]


# ----------------------------------------------------------- review fixes
def test_sync_waits_for_the_vault_lock_and_gives_up_when_cancelled():
    import threading

    from localvault.app.sync import VaultLockBarrier
    from localvault.sync.service import SyncAborted, SyncGate

    lock = threading.Lock()
    gate = SyncGate(VaultLockBarrier(lock, poll=0.01))
    lock.acquire()  # a user save is in progress
    cancelled = {"value": False}
    gate.cancelled = lambda: cancelled["value"]
    entered = threading.Event()
    failed = []

    def run():
        try:
            with gate.hold():
                entered.set()
        except SyncAborted:
            failed.append(1)

    worker = threading.Thread(target=run)
    worker.start()
    assert not entered.wait(0.2)  # sync cannot touch the vault while the save holds the lock
    lock.release()
    worker.join(2)
    assert entered.is_set() and not lock.locked()
    lock.acquire()
    cancelled["value"] = True
    worker = threading.Thread(target=run)
    worker.start()
    worker.join(2)
    assert failed == [1]
    lock.release()


def test_offers_are_dropped_on_lock(env, monkeypatch):
    env.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    offer = SimpleNamespace(offer_id="o1", code="1", expires_at=9e12)
    env.fake.result = offer
    monkeypatch.setattr("localvault.app.sync.begin_pairing_job", lambda *a: (lambda s, l, g: offer))
    monkeypatch.setattr("localvault.sync.pairing.offer_qr_payload", lambda o: "payload")
    monkeypatch.setattr("localvault.sync.pairing.render_qr_png", lambda payload, scale=6: b"x")
    env.service.qr_show()
    env.controller.lock()
    with pytest.raises(ApiError):
        env.service.qr_copy("o1")


def test_a_timed_out_job_keeps_the_service_busy_until_it_ends(env):
    pending = []
    env.fake.submit = lambda job, on_done=None, *, run_after=False: pending.append(on_done) or True
    env.service._timeout = 0.05
    with pytest.raises(ApiError) as slow:
        env.service.leave()
    assert slow.value.code == "timeout"
    with pytest.raises(ApiError) as busy:
        env.service.sync_now() if False else env.service.leave()
    assert busy.value.code == "busy"
    pending[0](None, None)  # the worker finishes later
    env.fake.submit = FakeService.submit.__get__(env.fake)
    env.service.leave()


def test_folder_device_removal_checks_the_password_before_asking(env, monkeypatch):
    env.service._snapshot = SimpleNamespace(folder_path="C:/cloud", names=lambda: {})
    monkeypatch.setattr(env.service, "_members", lambda card: [SimpleNamespace(device_id="d2", name="Laptop")])
    with pytest.raises(ApiError) as weak:
        env.service.remove_device("folder", "d2", "short", "short")
    assert weak.value.code == "invalid" and env.port.asked == []


def test_sync_stays_off_when_the_install_id_cannot_be_read(env, monkeypatch):
    from localvault import error_log
    from localvault.app import sync as app_sync
    from localvault.sync import install

    logged = []
    monkeypatch.setattr(error_log, "log_exception", lambda where, exc: logged.append(where))

    def unreadable(directory=None):
        raise PermissionError("locked")
    monkeypatch.setattr(install, "load_or_create_install_id", unreadable)
    service = app_sync.SyncWebService(env.controller, env.port, env.bus, None)  # the real factory
    service.start()
    assert service.service is None and logged == ["sync-start"] and env.controller.is_unlocked()


# ------------------------------------------------- Wi-Fi pairing address and listener checks
OWNER_PC = NetworkSnapshot(
    (Interface("Ethernet 2", ("192.168.56.1",)), Interface("Ethernet", ("192.168.60.26",))),
    frozenset({"192.168.60.26"}), primary="192.168.60.26")


@pytest.fixture
def pairing(env, monkeypatch):
    offer = SimpleNamespace(offer_id="o1", code="123-456", expires_at=9e12)
    env.fake.result = offer
    hosts = []
    monkeypatch.setattr("localvault.app.sync.begin_pairing_job",
                        lambda host, port, install_id: hosts.append((host, port)) or (lambda s, l, g: offer))
    monkeypatch.setattr("localvault.sync.pairing.offer_qr_payload", lambda o: "payload")
    monkeypatch.setattr("localvault.sync.pairing.render_qr_png", lambda payload, scale=6: b"x")
    env.hosts = hosts
    return env


def test_qr_shows_the_address_and_the_hint(pairing):
    pairing.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    shown = pairing.service.qr_show()
    assert shown["address"] == "192.168.1.20:47821" and shown["notice"] == ""
    assert shown["hint"] == ("Phone and PC must be on the same Wi-Fi. If the phone can't connect, allow "
                             "LocalGateKeys through Windows Firewall on Private networks.")


def test_owner_pc_virtualbox_address_is_offered_with_the_wired_lan(pairing):
    pairing.network.snapshot = OWNER_PC
    pairing.controller.settings.sync_lan_endpoint = "192.168.56.1:47821"
    asked = pairing.service.qr_show()
    assert asked["choose_address"] is True and not pairing.fake.armed
    assert [a["value"] for a in asked["addresses"]] == ["192.168.60.26:47821", "192.168.56.1:47821"]
    assert asked["addresses"][1]["label"] == "192.168.56.1 (saved)"
    assert asked["current"] == "192.168.60.26:47821"  # VirtualBox: the gateway LAN is preselected
    assert pairing.controller.settings.sync_lan_endpoint == "192.168.56.1:47821"  # nothing rewritten
    pairing.service.wifi_enable("192.168.60.26:47821")  # the user picks the wired LAN
    assert pairing.service.qr_show()["address"] == "192.168.60.26:47821"


def _owned_but_not_candidate(pairing, snapshot, saved):
    pairing.network.snapshot = snapshot
    pairing.controller.settings.sync_lan_endpoint = saved
    asked = pairing.service.qr_show()
    assert asked["choose_address"] is True and asked["current"] == saved
    assert asked["addresses"][0]["value"] == saved and pairing.controller.settings.sync_lan_endpoint == saved
    pairing.service.wifi_enable(saved)  # the user keeps it
    shown = pairing.service.qr_show()
    assert shown["address"] == saved and shown["notice"] == ""
    assert pairing.service.qr_show()["address"] == saved  # and it is not questioned again
    assert pairing.controller.settings.sync_lan_endpoint == saved


WIFI = Interface("Wi-Fi", ("192.168.1.9",))


def test_a_kept_no_gateway_address_is_not_rewritten(pairing):
    _owned_but_not_candidate(pairing, NetworkSnapshot(
        (WIFI, Interface("Ethernet 2", ("192.168.137.1",))), frozenset({"192.168.1.9"})), "192.168.137.1:47821")


def test_a_kept_direct_cable_link_local_address_is_not_rewritten(pairing):
    _owned_but_not_candidate(pairing, NetworkSnapshot(
        (WIFI, Interface("Ethernet", ("169.254.20.5",))), frozenset({"192.168.1.9"})), "169.254.20.5:47821")


def test_a_kept_ipv6_ula_address_is_not_rewritten(pairing):
    _owned_but_not_candidate(pairing, NetworkSnapshot(
        (Interface("Wi-Fi", ("192.168.1.9", "fd12:3456::7")),), frozenset({"192.168.1.9"})), "[fd12:3456::7]:47821")


def test_a_hyper_v_external_switch_address_preselects_the_real_adapter_but_can_be_kept(pairing):
    pairing.network.snapshot = NetworkSnapshot(
        (WIFI, Interface("vEthernet (External)", ("192.168.60.40",))), frozenset({"192.168.1.9", "192.168.60.40"}))
    pairing.controller.settings.sync_lan_endpoint = "192.168.60.40:47821"
    asked = pairing.service.qr_show()
    assert asked["current"] == "192.168.1.9:47821"
    assert [a["value"] for a in asked["addresses"]] == ["192.168.1.9:47821", "192.168.60.40:47821"]
    pairing.service.wifi_enable("192.168.60.40:47821")  # the user keeps the saved one anyway
    assert pairing.service.qr_show()["address"] == "192.168.60.40:47821"
    assert pairing.service.qr_show()["address"] == "192.168.60.40:47821"


def test_a_saved_virtual_address_without_candidates_stays_preselected(pairing):
    pairing.network.snapshot = NetworkSnapshot((Interface("vEthernet (WSL)", ("172.20.112.1",)),), frozenset())
    pairing.controller.settings.sync_lan_endpoint = "172.20.112.1:47821"
    asked = pairing.service.qr_show()
    assert asked["current"] == "172.20.112.1:47821"
    assert [a["value"] for a in asked["addresses"]] == ["172.20.112.1:47821"]


def test_malformed_legacy_setting_does_not_break_the_wifi_form(env):
    env.controller.settings.sync_lan_endpoint = "garbage:port"
    suggested = env.service.wifi_suggest()
    assert suggested["value"] == "192.168.1.20:47821"


def test_listener_check_failure_disarms_the_offer(pairing):
    pairing.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    original = pairing.fake.submit
    calls = []

    def submit(job, on_done=None, *, run_after=False):
        calls.append(job)
        if len(calls) == 2:  # the no-op that waits for the arming job
            pairing.fake.error = OSError("worker died")
        return original(job, on_done, run_after=run_after)

    pairing.fake.submit = submit
    with pytest.raises(ApiError):
        pairing.service.qr_show()
    assert pairing.fake.armed == ["o1"] and pairing.fake.cancelled == ["o1"]


def test_an_address_from_an_old_network_is_corrected(pairing):
    pairing.controller.settings.sync_lan_endpoint = "10.0.0.7:47821"
    shown = pairing.service.qr_show()
    assert shown["address"] == "192.168.1.20:47821" and "no longer belongs to this PC" in shown["notice"]


def test_several_real_networks_ask_the_user_to_choose(pairing):
    pairing.network.snapshot = NetworkSnapshot(
        (Interface("Wi-Fi", ("192.168.1.9",)), Interface("Ethernet", ("192.168.60.26",))),
        frozenset({"192.168.1.9", "192.168.60.26"}), primary="192.168.60.26")
    pairing.controller.settings.sync_lan_endpoint = "10.0.0.7:47821"
    asked = pairing.service.qr_show()
    assert asked["choose_address"] is True and "offer_id" not in asked and not pairing.fake.armed
    assert [a["value"] for a in asked["addresses"]] == ["192.168.60.26:47821", "192.168.1.9:47821"]
    assert pairing.controller.settings.sync_lan_endpoint == "10.0.0.7:47821"  # unchanged until the user picks
    pairing.service.wifi_enable(asked["addresses"][1]["value"])
    assert pairing.service.qr_show()["address"] == "192.168.1.9:47821"


def test_no_adapter_data_keeps_the_saved_address(pairing):
    pairing.network.snapshot = NetworkSnapshot()
    pairing.controller.settings.sync_lan_endpoint = "10.0.0.7:47821"
    assert pairing.service.qr_show()["address"] == "10.0.0.7:47821"


def test_no_qr_when_the_bind_failed(pairing):
    pairing.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    pairing.fake.listening = None
    pairing.fake.listen_issue = SyncIssue("listen-failed", "this address does not belong to this PC any more "
                                                           "(OSError 10049)")
    with pytest.raises(ApiError) as failed:
        pairing.service.qr_show()
    assert failed.value.code == "listen_failed"
    assert "192.168.1.20:47821" in failed.value.message and "10049" in failed.value.message
    assert pairing.fake.armed == ["o1"] and pairing.fake.cancelled == ["o1"]  # the offer is disarmed again
    with pytest.raises(ApiError):
        pairing.service.qr_copy("o1")


def test_no_qr_when_the_listener_is_on_another_address_or_not_joined(pairing):
    pairing.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    pairing.fake.listening = LANEndpoint("192.168.56.1", 47821)
    with pytest.raises(ApiError) as other:
        pairing.service.qr_show()
    assert other.value.code == "listen_failed"
    pairing.fake.listening, pairing.fake.listen_issue = None, SyncIssue("rejoin-required", "install-mismatch")
    with pytest.raises(ApiError) as rejoin:
        pairing.service.qr_show()
    assert "not listening on 192.168.1.20:47821" in rejoin.value.message


def test_wifi_suggest_uses_the_gateway_adapter_not_the_first_resolved(env):
    env.network.snapshot = OWNER_PC
    env.controller.settings.sync_lan_endpoint = ""
    suggested = env.service.wifi_suggest()
    assert suggested["value"] == "192.168.60.26:47821"
    assert [c["value"] for c in suggested["choices"]] == ["192.168.60.26:47821"]
    env.controller.settings.sync_lan_endpoint = "192.168.56.1:47821"
    assert env.service.wifi_suggest()["value"] == "192.168.60.26:47821"


class FakeFirewall:
    def __init__(self, status):
        self.status, self.allowed_calls = status, []

    def firewall_status(self, port, *, interface=""):
        self.asked = (port, interface)
        return self.status

    def allow_inbound(self, port, *, status=None):
        from localvault.sync.firewall import AllowResult, FirewallStatus

        self.allowed_calls.append(port)
        self.status = FirewallStatus(supported=True, allowed=True, profile="Private")
        return AllowResult(True, message="ok")


def test_firewall_status_and_allow_are_explicit(env):
    from localvault.sync.firewall import FirewallStatus

    env.network.snapshot = OWNER_PC
    env.controller.settings.sync_lan_endpoint = "192.168.60.26:47821"
    fake = FakeFirewall(FirewallStatus(supported=True, allowed=False, profile="Private"))
    env.service._firewall = fake
    status = env.service.firewall_status()
    assert status["profile"] == "Private" and not status["allowed"] and status["can_allow"]
    assert fake.asked == (47821, "Ethernet") and fake.allowed_calls == []  # looking changes nothing
    allowed = env.service.firewall_allow()
    assert allowed["allowed"] and fake.allowed_calls == [47821] and allowed["message"] == "ok"


@pytest.mark.parametrize("profile", ["Public", "DomainAuthenticated"])
def test_firewall_button_is_refused_on_public_and_domain_networks(env, profile):
    from localvault.sync.firewall import FirewallStatus

    env.network.snapshot = OWNER_PC
    env.controller.settings.sync_lan_endpoint = "192.168.60.26:47821"
    fake = FakeFirewall(FirewallStatus(supported=True, allowed=False, profile=profile))
    env.service._firewall = fake
    status = env.service.firewall_status()
    assert not status["can_allow"] and status["advice"]
    if profile == "Public":
        assert "set it to Private in Windows Settings" in status["advice"]
    with pytest.raises(ApiError):
        env.service.firewall_allow()
    assert fake.allowed_calls == []


def test_firewall_success_is_not_claimed_while_a_block_rule_wins(env):
    from localvault.sync.firewall import AllowResult, FirewallStatus

    env.network.snapshot = OWNER_PC
    env.controller.settings.sync_lan_endpoint = "192.168.60.26:47821"
    fake = FakeFirewall(FirewallStatus(supported=True, allowed=False, profile="Private"))
    blocked = FirewallStatus(supported=True, allowed=False, profile="Private", blocked_by="python.exe")
    fake.allow_inbound = lambda port, *, status=None: (setattr(fake, "status", blocked), AllowResult(True, message="ok"))[1]
    env.service._firewall = fake
    result = env.service.firewall_allow()
    assert not result["allowed"] and "still does not allow" in result["message"] and "python.exe" in result["message"]
    assert not result["can_allow"]  # the button would not help: the block rule must go first


def test_firewall_allow_off_windows_is_refused(env):
    from localvault.sync.firewall import FirewallStatus

    env.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    fake = FakeFirewall(FirewallStatus(supported=False))
    env.service._firewall = fake
    with pytest.raises(ApiError) as refused:
        env.service.firewall_allow()
    assert refused.value.code == "unavailable" and fake.allowed_calls == []


def test_qr_is_capped_and_uses_whole_pixels_per_module():
    from localvault.app.sync import QR_MAX_CSS_PX, qr_layout

    for payload in ("x" * 40, "x" * 300, "x" * 1200):
        scale, size = qr_layout(payload)
        assert size <= QR_MAX_CSS_PX and scale % 2 == 0 and scale >= 2
        import segno

        modules = segno.make(payload, error="m", micro=False, boost_error=False).symbol_size()[0]  # quiet zone in
        assert size % modules == 0 and scale == 2 * (size // modules)


def test_qr_show_renders_at_the_layout_scale(pairing, monkeypatch):
    scales = []
    monkeypatch.setattr("localvault.sync.pairing.render_qr_png",
                        lambda payload, scale=6: scales.append(scale) or b"x")
    pairing.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    shown = pairing.service.qr_show()
    assert 100 <= shown["size"] <= 260 and scales == [2 * (shown["size"] // 29)]  # "payload": 21 modules + 2 x 4 quiet zone


def test_the_confirmed_endpoint_is_saved_and_validated(tmp_path):
    path = tmp_path / "settings.json"
    AppSettings(sync_lan_endpoint="192.168.137.1:47821", sync_lan_endpoint_confirmed="192.168.137.1:47821").save(path)
    assert AppSettings.load(path).sync_lan_endpoint_confirmed == "192.168.137.1:47821"
    raw = json.loads(path.read_text())
    raw["sync_lan_endpoint_confirmed"] = "8.8.8.8:47821"
    path.write_text(json.dumps(raw))
    assert AppSettings.load(path).sync_lan_endpoint_confirmed == ""


def test_turning_wifi_sync_off_forgets_the_confirmation(env):
    env.service.wifi_enable("192.168.1.20:47821")
    assert env.controller.settings.sync_lan_endpoint_confirmed == "192.168.1.20:47821"
    env.service.wifi_disable()
    assert env.controller.settings.sync_lan_endpoint_confirmed == ""


# --- audit 2026-10-18 (M9, M10, pairing Undo) -----------------------------------------------------


def _folder_snapshot(unacked=(), lan_removed=False, folder="C:/cloud", peers=()):
    from localvault.app import sync_view as ui

    members = (ui.MemberSnapshot("me", "This PC", True), ui.MemberSnapshot("d2", "Laptop"),
               ui.MemberSnapshot("d3", "Tablet"))
    return ui.GroupSnapshot("me", folder, 1, True, members, peers, unacked=unacked, lan_removed=lan_removed)


def test_rotation_confirmation_lists_who_gets_the_key_and_passes_that_keep_list(env):
    env.service._snapshot = _folder_snapshot(unacked=("d3",))
    env.port.messages = []
    original = env.port.confirm
    env.port.confirm = lambda title, message: env.port.messages.append(message) or original(title, message)
    env.service.change_password(STRONG, STRONG)
    assert "goes only to: Laptop, this PC" in env.port.messages[0] and "Tablet" in env.port.messages[0]
    name, args = next(c for c in env.calls if c[0] == "rotate_job")
    assert args[1] == () and args[4] == ("d2",)  # the unconfirmed Tablet does not get the key
    env.calls.clear()
    env.service.remove_device("folder", "d2", STRONG, STRONG)
    assert "Remove Laptop from sync?" in env.port.messages[-1] and "goes only to: this PC" in env.port.messages[-1]
    name, args = next(c for c in env.calls if c[0] == "rotate_job")
    assert args[1] == ("d2",) and args[4] == ()


def test_cancelling_the_rotation_confirmation_runs_nothing(env):
    env.service._snapshot = _folder_snapshot()
    env.port.answers = [False]
    with pytest.raises(ApiError) as cancelled:
        env.service.change_password(STRONG, STRONG)
    assert cancelled.value.code == "cancelled" and not any(c[0] == "rotate_job" for c in env.calls)


def test_confirming_new_devices_acknowledges_exactly_the_shown_ones(env, monkeypatch):
    seen = []
    monkeypatch.setattr("localvault.app.sync.acknowledge_job",
                        lambda ids, install: seen.append(ids) or (lambda s, le, g: len(ids)))
    env.service._snapshot = _folder_snapshot(unacked=("d3",))
    result = env.service.acknowledge_members()
    assert seen == [("d3",)] and "Confirmed: Tablet." == result["message"]
    env.service._snapshot = _folder_snapshot()
    assert env.service.acknowledge_members()["message"] == "There are no new devices to confirm."


def test_adding_a_folder_after_a_wifi_removal_asks_and_uses_a_fresh_key(env, monkeypatch):
    from localvault.app import sync_view as ui

    made = []
    monkeypatch.setattr("localvault.app.sync.add_folder_job",
                        lambda *args: made.append(args) or (lambda s, le, g: None))
    monkeypatch.setattr(ui, "add_folder_job", lambda *args: made.append(("plain", *args)) or (lambda s, le, g: None))
    env.service._snapshot = _folder_snapshot(folder=None, lan_removed=True, peers=(ui.PeerSnapshot("phone", None),))
    token = env.service.choose_folder()["token"]
    env.port.answers = [False]
    with pytest.raises(ApiError) as cancelled:
        env.service.folder_setup("add-folder", token, STRONG, STRONG)
    assert cancelled.value.code == "cancelled" and env.port.asked[-1] == "New sync key"
    token = env.service.choose_folder()["token"]
    env.service.folder_setup("add-folder", token, STRONG, STRONG)
    assert made[-1][-1] is True  # fresh_key


def test_paired_device_is_named_with_an_undo(env, monkeypatch):
    env.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    offer = SimpleNamespace(offer_id="o1", code="123-456", expires_at=9e12)
    env.fake.result = offer
    monkeypatch.setattr("localvault.app.sync.begin_pairing_job", lambda *a: (lambda s, le, g: offer))
    monkeypatch.setattr("localvault.sync.pairing.offer_qr_payload", lambda o: "lgk-pair:payload")
    monkeypatch.setattr("localvault.sync.pairing.render_qr_png", lambda payload, scale=6: b"\x89PNG")
    env.service.qr_show()
    env.fake.enrolled = "device-2abcdef"
    env.fake.enrollment_peer = lambda offer_id: SimpleNamespace(fingerprint="0123456789abcdef" * 4)
    polled = env.service.qr_poll("o1")
    assert polled["state"] == "paired"
    assert polled["device"] == {"id": "device-2abcdef", "name": "Device device-2", "fingerprint": "0123 4567 89ab cdef"}
    assert "Undo" in polled["message"] and "0123 4567" in polled["message"]
