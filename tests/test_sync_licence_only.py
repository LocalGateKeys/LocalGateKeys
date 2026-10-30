"""Licence-only sync on a free PC (App Store / Play licence plan, Task 6).

A free PC may pair and run rounds that accept only ``license`` records: it
adopts a valid synced licence, stores no other record and publishes nothing.
No Tk; the LAN part runs over loopback like ``test_sync_lan``.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import test_licensing
import test_sync_lan as lan_t
import test_sync_service as svc_t

from localvault import licensing
from localvault.app.controller import WebController
from localvault.app.sync import SyncWebService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.sync import folder_transport as ft
from localvault.sync import lan_sync as lan
from localvault.sync import service as svc
from localvault.sync.vault_bridge import load_sync_state

signer = test_licensing.signer
devs = lan_t.devs
make_bundle = test_licensing.make_bundle
ISSUED = test_licensing.ISSUED
PRO = frozenset({"sync", "totp", "attachments", "unlimited_items"})


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _labels(session) -> list[str]:
    return sorted(e["label"] for e in session._payload["entries"])


def _free_pair(tmp_path: Path, bundles=()):
    """Free PC A and Pro PC B in one folder group; B publishes *bundles* (vault copy first) and an item."""
    root, (a, la), (b, lb) = svc_t._folder_pair(tmp_path)
    a.pro_features = frozenset()
    a.upsert_web(origin="https://mine.example.com", username="me", password="pw-123456", label="mine")
    for n, bundle in enumerate(bundles):
        if n == 0:
            licensing.store_in_vault(b, bundle)
        else:
            sid = licensing.sync_state_id(bundle["license"]["license_id"])
            with b.transaction():
                b._require_typed_catalog().setdefault("sync_licenses", {})[sid] = bundle
    b.upsert_web(origin="https://theirs.example.com", username="me", password="pw-123456", label="theirs")
    ft.FolderSync(root, install_id="install-b", _kdf_override=svc_t.CHEAP).run_once(b, lb, now=svc_t.NOW)
    return root, (a, la), (b, lb)


def _licence_only_service(session, lease, posted):
    clock = svc_t.FakeClock()
    adapter = svc.FolderAdapter(install_id=svc_t.INSTALL, _kdf_override=svc_t.CHEAP)
    service = svc.SyncService(session, lease, install_id=svc_t.INSTALL, transports=[adapter], clock=clock,
                              scheduler=svc_t.FakeScheduler(clock), worker=svc_t.InlineWorker(),
                              post_result=posted.append, licence_only=True)
    return service


def _round(session, lease) -> list:
    posted: list = []
    service = _licence_only_service(session, lease, posted)
    service.run_now()
    service._worker.drain()
    return posted


# --- the web service: free plan builds a licence-only service, a synced licence switches to full sync ---


class _Fake:
    def __init__(self, licence_only: bool) -> None:
        self.licence_only = licence_only
        self.install_id = "install-1"
        self.stopped = False
        self.unlocked = 0

    def on_unlock(self) -> None:
        self.unlocked += 1

    def stop(self) -> None:
        self.stopped = True


def _web_service(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = SimpleNamespace(events=[], emit=lambda name, detail: None)
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=SimpleNamespace(call_later=lambda d, fn: fn, cancel=lambda h: None),
                               create_kwargs={"kdf_overrides": svc_t.TEST_KDF})
    controller.create("correct horse battery", "correct horse battery")
    built: list[_Fake] = []

    def factory(c, cb, *, licence_only: bool = False):
        built.append(_Fake(licence_only))
        return built[-1]

    web = SyncWebService(controller, SimpleNamespace(), bus, SimpleNamespace(choose_folder=lambda t: None),
                         factory=factory)
    return web, controller, built


def test_free_pc_adopts_synced_licence_and_turns_pro(tmp_path, signer, monkeypatch) -> None:
    bundle = make_bundle(signer)
    _root, (a, la), _b = _free_pair(tmp_path, [bundle])
    assert licensing.status(build_date=ISSUED).state == "free"
    posted = _round(a, la)
    assert licensing.status(build_date=ISSUED).state == "pro"
    assert licensing.vault_copy(a) == bundle
    assert posted[-1].license_adopted is True

    # The app: free plan -> licence-only service; the adopted licence makes the plan Pro -> full sync.
    web, controller, built = _web_service(tmp_path / "app", monkeypatch)
    controller.session.pro_features = frozenset()
    web._on_licence = web.plan_changed
    web.start()
    assert built[-1].licence_only is True and web.view()["licence_only"] is True
    assert web.view()["pro"] is False  # the page still says Pro is needed to sync items
    first = built[-1]
    controller.session.pro_features = PRO
    web._status_changed(first, SimpleNamespace(license_adopted=True))
    assert first.stopped
    assert web.service is built[-1] and built[-1].licence_only is False and built[-1].unlocked == 1
    assert web.view()["licence_only"] is False


def test_free_pc_publishes_nothing(tmp_path, signer, devs) -> None:
    # Folder: the round writes no file at all (no view, witness, signature, capability or keyring).
    root, (a, la), _b = _free_pair(tmp_path, [make_bundle(signer)])
    before = _tree(root)
    state_before = load_sync_state(a)
    _round(a, la)
    assert _tree(root) == before
    assert load_sync_state(a) == state_before

    # Wi-Fi: a free PC (the host) serves a phone an empty view, and sends one when it dials a PC.
    pc = devs("pc", group=True)
    pc.responder.licence_only = True
    lan_t._web(pc, "pc-secret")
    phone = devs("phone")
    lan_t._pair(pc, phone, listen=False)
    phone.relisten()
    lan_t._web(phone, "from-phone")
    report = phone.sync_with(pc)
    assert lan_t.kinds(report) == []
    assert "pc-secret" not in phone.labels()
    other = devs("other")
    lan_t._pair(pc, other)
    lan_t._web(other, "other-item")
    pc_report = lan.sync_with(pc.transport, other.device_id, pc.session, pc.lease, install_id=pc.install,
                              now=svc_t.NOW, licence_only=True)
    assert lan_t.kinds(pc_report) == [] and not pc_report.wrote
    assert "pc-secret" not in other.labels()
    assert pc.labels() == ["pc-secret"]


def test_free_pc_drops_item_records(tmp_path, signer, devs) -> None:
    _root, (a, la), _b = _free_pair(tmp_path, [make_bundle(signer)])
    items_before, entries_before = a.items.list_items(), _labels(a)
    meta_before = dict(a._require_typed_catalog().get("sync_meta", {}).get("items", {}))
    _round(a, la)
    assert _labels(a) == entries_before == ["mine"]
    assert a.items.list_items() == items_before
    assert dict(a._require_typed_catalog().get("sync_meta", {}).get("items", {})) == meta_before

    pc = devs("pc", group=True)
    pc.responder.licence_only = True
    phone = devs("phone")
    lan_t._pair(pc, phone, listen=False)
    phone.relisten()
    lan_t._web(phone, "from-phone")
    phone.sync_with(pc)
    assert pc.labels() == []
    assert "sync_meta" not in pc.session._require_typed_catalog() or not \
        pc.session._require_typed_catalog()["sync_meta"].get("items")


def test_free_pc_rejects_revoked_licence(tmp_path, signer, monkeypatch) -> None:
    revoked = make_bundle(signer)
    expired = make_bundle(signer, license_id="lic-0003", issued_at="2019-01-01", updates_until="2019-06-01")
    _root, (a, la), _b = _free_pair(tmp_path, [revoked, expired])
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset({"lic-0001"}))
    posted = _round(a, la)
    assert licensing.status(build_date=ISSUED).state == "free"
    assert not licensing.license_path().exists()
    assert licensing.vault_copy(a) is None
    assert posted[-1].license_adopted is False
    assert _labels(a) == ["mine"]
    assert not a._require_typed_catalog().get("sync_licenses")


def test_removal_marker_blocks_licence_only_adoption(tmp_path, signer) -> None:
    bundle = make_bundle(signer)
    _root, (a, la), _b = _free_pair(tmp_path, [bundle])
    licensing.install_license(licensing.encode_paste(bundle))
    licensing.remove_license()  # the user removed the licence on this PC
    assert licensing.removal_pending()
    posted = _round(a, la)
    assert licensing.status(build_date=ISSUED).state == "free"
    assert not licensing.license_path().exists()
    assert licensing.vault_copy(a) is None
    assert posted[-1].license_adopted is False


def test_licence_only_runs_no_background_listener(tmp_path) -> None:
    session = svc_t.create_vault(tmp_path / "a.json", svc_t.MASTER, kdf_overrides=svc_t.TEST_KDF)
    session.pro_features = frozenset()
    svc_t._lan_group(session)
    svc_t.FakeSyncTransport.instances.clear()
    clock = svc_t.FakeClock()
    adapter = svc.LanAdapter(install_id=svc_t.INSTALL, endpoint=lambda: svc_t.ENDPOINT,
                             transport_factory=svc_t.FakeSyncTransport, clock=clock)
    sched = svc_t.FakeScheduler(clock)
    service = svc.SyncService(session, svc_t.FakeLease(), install_id=svc_t.INSTALL, transports=[adapter],
                              clock=clock, scheduler=sched, worker=svc_t.InlineWorker(), licence_only=True)
    service.on_unlock()
    service._worker.drain()
    assert not adapter.listening and not sched.timers  # nothing in the background after unlock

    service.run_now()  # a round the user started
    service._worker.drain()
    assert adapter.listening and adapter.responder.licence_only is True
    sched.advance(svc.LICENCE_ONLY_LISTEN_SECONDS + 1)
    service._worker.drain()
    assert not adapter.listening and svc_t.FakeSyncTransport.instances[-1].stopped
    assert not sched.timers  # no five-minute timer either

    # Pairing arms the listener until the code expired (plus the window), then it stops again.
    offer = lan.begin_pairing(session, svc_t.FakeLease(), svc_t.ENDPOINT.host, svc_t.ENDPOINT.port,
                              install_id=svc_t.INSTALL, now=clock.now)
    service.arm_enrollment(offer)
    service._worker.drain()
    assert adapter.listening
    sched.advance(float(offer.expires_at) - clock.now + svc.ENROLL_GRACE_SECONDS + svc.LICENCE_ONLY_LISTEN_SECONDS + 1)
    service._worker.drain()
    assert not adapter.listening
    service.stop()


def test_licences_received_while_serving_survive_a_later_refused_request(monkeypatch) -> None:
    """A licence-only PC stores nothing, so the responder keeps received licences until the next run."""
    from localvault.sync.runner import RunReport, SyncIssue

    replies = iter([RunReport(licenses=({"licence": 1},)), RunReport(issues=(SyncIssue("unknown-peer", "x"),))])
    monkeypatch.setattr(lan, "_serve", lambda *a, **k: ({"type": "ok"}, next(replies)))
    responder = object.__new__(lan.LanResponder)
    responder.session = responder.lease = responder.inbox = None
    responder.install_id, responder.clock, responder.licence_only = "i", lambda: 0, True
    responder.last_report, responder.on_served = None, None
    responder(None, b"{}")
    responder(None, b"{}")
    assert responder.last_report.licenses == ({"licence": 1},)
    assert [i.kind for i in responder.last_report.issues] == ["unknown-peer"]
