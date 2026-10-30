"""Bonjour announcement of the Wi-Fi sync listener (``sync/announce.py``), with a fake DNS-SD API."""
from __future__ import annotations

import pytest

from localvault.sync import discovery
from localvault.sync.announce import Announcer
from localvault.sync.group import GroupKey

GK = GroupKey("5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64", 1, bytes(range(32)))
DEVICE = "a1111111-0000-4000-8000-00000000000a"
NOW = 1790003600.0


class FakeApi:
    def __init__(self, fail: bool = False) -> None:
        self.live: dict[int, tuple] = {}
        self.calls: list[str] = []
        self.fail = fail
        self.indexes: list[int] = []
        self._n = 0

    def register(self, instance, host, ipv4, port, txt, interface_index):
        self.calls.append("register")
        if self.fail:
            raise OSError("no DNS-SD")
        self._n += 1
        self.indexes.append(interface_index)
        self.live[self._n] = (instance, host, ipv4, port, dict(txt))
        return self._n

    def deregister(self, handle):
        self.calls.append("deregister")
        del self.live[handle]


def make(profile="Private", api=None, now=None):
    api = api or FakeApi()
    clock = now or [NOW]
    a = Announcer(api_factory=lambda: api, profile=lambda host, port: (profile if isinstance(profile, str)
                  else profile(), 7), clock=lambda: clock[0], token="3f9a", start_thread=False)
    return a, api, clock


def test_announces_a_neutral_name_with_the_daily_tag_on_a_private_network():
    a, api, _ = make()
    a.start(GK, DEVICE, "192.168.1.23", 47821)
    a.refresh()
    assert a.state == "announcing"
    (instance, host, ipv4, port, txt), = api.live.values()
    assert instance == "LocalGateKeys-3f9a" and host == "lgk-3f9a.local"
    assert (ipv4, port) == ("192.168.1.23", 47821)
    assert txt == discovery.txt_record(GK, DEVICE, NOW) and set(txt) == {"v", "t"}
    assert api.indexes == [7]  # only the adapter that owns the address, never 0 (every adapter)
    a.refresh()
    assert api.calls == ["register"]  # unchanged: no re-registration


def test_nothing_on_a_public_or_unknown_network():
    for profile in ("Public", ""):
        a, api, _ = make(profile=profile)
        a.start(GK, DEVICE, "192.168.1.23", 47821)
        a.refresh()
        assert a.state == "public-network" and api.live == {}

    def broken():
        raise RuntimeError("powershell failed")

    a, api, _ = make(profile=broken)
    a.start(GK, DEVICE, "192.168.1.23", 47821)
    a.refresh()
    assert api.live == {}


def test_renews_the_tag_on_a_new_day_and_follows_address_and_rotation():
    a, api, clock = make()
    a.start(GK, DEVICE, "192.168.1.23", 47821)
    a.refresh()
    first = next(iter(api.live.values()))[4]["t"]
    clock[0] += 86400
    a.refresh()
    assert len(api.live) == 1 and next(iter(api.live.values()))[4]["t"] != first
    a.start(GK, DEVICE, "192.168.1.40", 47821)
    a.refresh()
    assert [v[2] for v in api.live.values()] == ["192.168.1.40"]
    a.start(GroupKey(GK.group_id, 2, GK.key), DEVICE, "192.168.1.40", 47821)
    a.refresh()
    assert len(api.live) == 1 and api.calls.count("deregister") == 3


def test_stop_withdraws_and_a_missing_api_is_reported():
    a, api, _ = make()
    a.start(GK, DEVICE, "192.168.1.23", 47821)
    a.refresh()
    a.stop()
    assert api.live == {} and a.state == "off"
    b, _, _ = make(api=FakeApi(fail=True))
    b.start(GK, DEVICE, "192.168.1.23", 47821)
    b.refresh()
    assert b.state == "unavailable"


def test_network_change_to_public_withdraws():
    profile = ["Private"]
    a, api, _ = make(profile=lambda: profile[0])
    a.start(GK, DEVICE, "192.168.1.23", 47821)
    a.refresh()
    profile[0] = "Public"
    a.refresh()
    assert api.live == {} and a.state == "public-network"


def test_no_announcement_without_an_adapter_index():
    api = FakeApi()
    a = Announcer(api_factory=lambda: api, profile=lambda host, port: ("Private", 0), clock=lambda: NOW,
                  token="3f9a", start_thread=False)
    a.start(GK, DEVICE, "192.168.1.23", 47821)
    a.refresh()
    assert api.live == {} and api.calls == []


@pytest.mark.skipif("sys.platform != 'win32'")
def test_real_profile_lookup_names_this_pcs_adapter():
    from localvault.sync.announce import _network_profile
    from localvault.sync.lan_interfaces import primary_address

    host = primary_address()
    if host is None:
        pytest.skip("no network")
    category, index = _network_profile(host, 47821)
    assert index > 0 and category in {"Private", "Public", "DomainAuthenticated"}


@pytest.mark.skipif("sys.platform != 'win32'")
def test_windows_dnssd_api_loads():
    from localvault.sync.announce import WindowsDnsSd

    WindowsDnsSd()  # Windows 10 1809+ on every supported PC
