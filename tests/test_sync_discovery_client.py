"""This PC as a discovery client: finding a paired Wi-Fi host whose pinned address stopped answering."""
from __future__ import annotations

import base64
import dataclasses

import pytest

from localvault.sync import discovery
from localvault.sync import discovery_client as dc
from localvault.sync import lan_sync as lan
from localvault.sync import service as svc
from localvault.sync.group import GroupKey
from localvault.sync.transport import LANEndpoint, TransportError

from test_sync_lan import NOW, _group_ab, _offer_for, _web, devs  # noqa: F401 - devs is a fixture

GK = GroupKey("group-1", 1, bytes(range(32)))
HOST = "host-device"
PORT = 47821


def _txt(host: str = HOST, gk: GroupKey = GK, now: float = NOW) -> dict[str, str]:
    return discovery.txt_record(gk, host, now)


def test_candidates_keep_only_matching_lan_announcements_on_the_pinned_port() -> None:
    good = dc.Found("192.168.1.23", PORT, _txt())
    found = [
        dc.Found("192.168.1.9", PORT, _txt(host="other-host")),  # another host's tag
        dc.Found("8.8.8.8", PORT, _txt()),  # not a LAN address
        dc.Found("192.168.1.10", PORT + 1, _txt()),  # another port
        dc.Found("192.168.1.11", PORT, {"v": "2", "t": _txt()["t"]}),  # unknown version
        dc.Found("not-an-ip", PORT, _txt()),
        dc.Found("fe80::1%3", PORT, _txt()),  # zone id
        good, good,
        dc.Found("192.168.1.24", PORT, discovery.txt_record(GK, HOST, NOW - 86400)),  # yesterday's tag
        dc.Found("192.168.1.25", PORT, discovery.txt_record(GK, HOST, NOW - 3 * 86400)),  # too old
    ]
    got = dc.candidates(found, GK, HOST, NOW, port=PORT)
    assert got == [LANEndpoint("192.168.1.23", PORT), LANEndpoint("192.168.1.24", PORT)]
    assert dc.candidates(found, GK, HOST, NOW, port=PORT, exclude=LANEndpoint("192.168.1.23", PORT)) == [
        LANEndpoint("192.168.1.24", PORT)]


def test_candidates_are_capped() -> None:
    found = [dc.Found(f"10.0.0.{i}", PORT, _txt()) for i in range(1, 20)]
    assert len(dc.candidates(found, GK, HOST, NOW, port=PORT)) == dc.MAX_DIALS == 4


class FakeBrowser:
    def __init__(self, found: list[dc.Found]) -> None:
        self.found, self.calls = found, 0

    def browse(self, service_type: str, timeout: float) -> list[dc.Found]:
        assert service_type == "_lgksync._tcp" and timeout <= dc.BROWSE_SECONDS
        self.calls += 1
        return list(self.found)


def _adapter(dev, browser) -> svc.LanAdapter:
    return svc.LanAdapter(install_id=dev.install, endpoint=lambda: dev.endpoint, browser=browser, timeout=2.0)


def _gk(dev) -> GroupKey:
    s = dev.state
    return GroupKey(s.group_id, s.epoch, s.key)


def _move_pinned(b, a, host: str) -> None:
    lan.save_peer_endpoint(b.session, b.lease, a.device_id, LANEndpoint(host, a.endpoint.port), install_id=b.install)


def test_unreachable_host_is_found_by_its_announcement_and_the_address_is_saved(devs) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    _web(a, "mail")
    _move_pinned(b, a, "127.0.0.2")  # the host "moved": the pinned address answers no more
    assert "unreachable" in [i.kind for i in b.sync_with(a).issues]
    real = dc.Found("127.0.0.1", a.endpoint.port, discovery.txt_record(_gk(b), a.device_id, NOW))
    spoof = dc.Found("127.0.0.3", a.endpoint.port, {"v": "1", "t": "aaaaaaaaaaaaaaaa"})
    browser = FakeBrowser([spoof, real])
    found_box: list = []
    report = _adapter(b, browser)._find_again(b.transport, svc.SyncGate(), b.session, b.lease, a.device_id,
                                              NOW, found_box)
    assert report is not None and report.wrote and "mail" in b.labels()
    assert lan.peer_endpoint(b.state, a.device_id) == a.endpoint
    assert browser.calls == 1


def test_announcement_of_the_wrong_device_is_never_saved(devs) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    c = devs("c", group=True)  # another group's PC answers on the announced address
    _move_pinned(b, a, "127.0.0.2")
    # The announcement carries a's correct tag but points at c's listener (same port is not needed for
    # this check, so the adapter is given c's port as the "pinned" port by moving the pin there).
    lan.save_peer_endpoint(b.session, b.lease, a.device_id, LANEndpoint("127.0.0.2", c.endpoint.port),
                           install_id=b.install)
    fake = dc.Found("127.0.0.1", c.endpoint.port, discovery.txt_record(_gk(b), a.device_id, NOW))
    report = _adapter(b, FakeBrowser([fake]))._find_again(b.transport, svc.SyncGate(), b.session, b.lease,
                                                          a.device_id, NOW, [])
    assert report is None, "the hello did not carry a's pinned keys"
    assert lan.peer_endpoint(b.state, a.device_id) == LANEndpoint("127.0.0.2", c.endpoint.port)


def test_no_discovery_without_a_browser_or_announcements(devs) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    _move_pinned(b, a, "127.0.0.2")
    assert _adapter(b, FakeBrowser([]))._find_again(b.transport, svc.SyncGate(), b.session, b.lease,
                                                    a.device_id, NOW, []) is None


def test_save_peer_endpoint_takes_lan_addresses_only(devs) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    with pytest.raises(TransportError):  # a public address is not even a LANEndpoint
        LANEndpoint("8.8.8.8", 47821)
    with pytest.raises(lan.LanSyncError):
        lan.save_peer_endpoint(b.session, b.lease, a.device_id, ("8.8.8.8", 47821), install_id=b.install)
    assert lan.peer_endpoint(b.state, a.device_id) == a.endpoint
    assert lan.save_peer_endpoint(b.session, b.lease, a.device_id, a.endpoint, install_id=b.install) is False


def test_find_again_qr_of_the_paired_host_updates_only_its_address(devs) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    _move_pinned(b, a, "127.0.0.2")
    peers_before = [dict(p) for p in b.state.lan_peers]
    _offer, text = _offer_for(a)
    assert lan.refind_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW) == a.device_id
    assert lan.peer_endpoint(b.state, a.device_id) == a.endpoint
    after = [dict(p) for p in b.state.lan_peers]
    assert [{k: v for k, v in p.items() if k != "endpoint"} for p in after] == \
        [{k: v for k, v in p.items() if k != "endpoint"} for p in peers_before]
    assert b.state.group_id == a.state.group_id


def test_find_again_qr_of_another_device_is_refused(devs) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    c = devs("c", group=True)
    before = b.state
    _offer, text = _offer_for(c)
    with pytest.raises(lan.LanSyncError) as err:
        lan.refind_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "not-this-device"
    assert b.state == before
    # Same device id and group but other keys: refused as well.
    offer, _text = _offer_for(a)
    forged = dataclasses.replace(offer, inviter_signing_public=bytes(32))
    with pytest.raises(lan.LanSyncError) as err:
        lan.refind_from_qr(forged.bundle_dict(), b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "not-this-device"
    assert base64.b64decode(lan.peer_entry(b.state, a.device_id)["signing_public"]) != bytes(32)
    for change in ({"inviter_exchange_public": bytes(32)}, {"certificate_fingerprint": "0" * 64}):
        forged = dataclasses.replace(offer, **change)
        with pytest.raises(lan.LanSyncError) as err:
            lan.refind_from_qr(forged.bundle_dict(), b.session, b.lease, install_id=b.install, now=NOW)
        assert err.value.reason in ("not-this-device", "bad-offer")
    assert b.state == before
