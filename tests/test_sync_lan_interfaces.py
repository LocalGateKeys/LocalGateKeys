"""Choosing the address the Wi-Fi sync QR code advertises (pure: interface data is injected)."""
from __future__ import annotations

import socket

from localvault.sync.lan_interfaces import (
    Interface,
    NetworkSnapshot,
    adapter_kind,
    current_addresses,
    is_virtual_adapter,
    lan_candidates,
    obvious_candidate,
    parse_route_print,
    primary_address,
    probe_interfaces,
)

# The owner's PC: VirtualBox host-only is just "Ethernet 2" (no gateway); the real LAN is wired "Ethernet".
OWNER_INTERFACES = (
    Interface("Ethernet 2", ("192.168.56.1",)),
    Interface("Ethernet", ("192.168.60.26",)),
    Interface("Wi-Fi", ("169.254.12.7",), is_up=False),
    Interface("Loopback Pseudo-Interface 1", ("127.0.0.1",)),
)
OWNER_ROUTES = """\
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.60.1    192.168.60.26     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
     192.168.56.0    255.255.255.0         On-link      192.168.56.1    281
     192.168.60.0    255.255.255.0         On-link     192.168.60.26    281
===========================================================================
Persistent Routes:
  None
"""


def test_owner_pc_picks_the_wired_lan_not_virtualbox():
    snapshot = NetworkSnapshot(OWNER_INTERFACES, parse_route_print(OWNER_ROUTES), primary="192.168.60.26")
    candidates = lan_candidates(snapshot)
    assert [c.address for c in candidates] == ["192.168.60.26"]
    best = obvious_candidate(candidates)
    assert best is not None and best.address == "192.168.60.26" and best.kind == "ethernet" and best.has_gateway
    assert "192.168.56.1" in current_addresses(snapshot)  # still the PC's address, just not reachable


def test_route_print_parsing_is_language_independent():
    german = OWNER_ROUTES.replace("Active Routes:", "Aktive Routen:").replace("Network Destination", "Netzwerkziel")
    assert parse_route_print(german) == frozenset({"192.168.60.26"})
    assert parse_route_print("") == frozenset()
    assert parse_route_print("0.0.0.0 0.0.0.0 192.168.1.1 Default") == frozenset()


def test_virtual_and_vpn_adapters_are_excluded():
    for name in ("vEthernet (WSL)", "vEthernet (Default Switch)", "VirtualBox Host-Only Network", "VMware Network "
                 "Adapter VMnet8", "Tailscale", "ZeroTier One [abcd]", "WireGuard Tunnel", "wg0", "tun0", "utun3",
                 "OpenVPN TAP-Windows6", "TAP-Windows Adapter V9", "docker0", "Local Area Connection* 10",
                 "Bluetooth Network Connection", "lo0", "Hyper-V Virtual Ethernet Adapter"):
        assert is_virtual_adapter(name), name
    for name in ("Wi-Fi", "Ethernet", "Ethernet 2", "en0", "wlan0", "eth0", "WLAN"):
        assert not is_virtual_adapter(name), name
    assert adapter_kind("Wi-Fi") == "wifi" and adapter_kind("WLAN") == "wifi"
    assert adapter_kind("Ethernet 3") == "ethernet"


def test_loopback_link_local_public_and_down_adapters_are_skipped():
    snapshot = NetworkSnapshot((
        Interface("Wi-Fi", ("169.254.3.3", "127.0.0.1", "8.8.8.8", "192.168.1.20")),
        Interface("Ethernet", ("10.0.0.5",), is_up=False),
        Interface("vEthernet (WSL)", ("172.20.112.1",)),
    ))
    assert [c.address for c in lan_candidates(snapshot)] == ["192.168.1.20"]


def test_without_a_route_table_no_gateway_filter_is_applied():
    snapshot = NetworkSnapshot(OWNER_INTERFACES, None, primary="192.168.60.26")
    candidates = lan_candidates(snapshot)
    assert [c.address for c in candidates] == ["192.168.60.26", "192.168.56.1"]  # primary first
    assert obvious_candidate(candidates) is None  # two Ethernet adapters: ask


def test_wifi_and_ethernet_rank_before_other_adapters():
    snapshot = NetworkSnapshot((Interface("Cellular", ("10.1.1.1",)), Interface("Wi-Fi", ("192.168.1.9",))),
                               frozenset({"10.1.1.1", "192.168.1.9"}))
    candidates = lan_candidates(snapshot)
    assert [c.address for c in candidates] == ["192.168.1.9", "10.1.1.1"]
    assert obvious_candidate(candidates).address == "192.168.1.9"


def test_two_real_networks_with_gateways_are_not_obvious():
    snapshot = NetworkSnapshot((Interface("Wi-Fi", ("192.168.1.9",)), Interface("Ethernet", ("192.168.60.26",))),
                               frozenset({"192.168.1.9", "192.168.60.26"}), primary="192.168.60.26")
    candidates = lan_candidates(snapshot)
    assert candidates[0].address == "192.168.60.26" and obvious_candidate(candidates) is None
    assert obvious_candidate([]) is None


def test_primary_only_when_no_adapter_list():
    candidates = lan_candidates(NetworkSnapshot((), None, primary="192.168.1.30"))
    assert [c.address for c in candidates] == ["192.168.1.30"]


class FakeUdp:
    def __init__(self, address):
        self.address, self.connected = address, None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def connect(self, target):
        if self.address is None:
            raise OSError("unreachable")
        self.connected = target

    def getsockname(self):
        return (self.address, 50000)

    def send(self, *a):  # pragma: no cover - must never be called
        raise AssertionError("no packet may be sent")


def test_udp_trick_reads_the_source_address_without_sending():
    made = []

    def factory(family, kind):
        assert (family, kind) == (socket.AF_INET, socket.SOCK_DGRAM)
        made.append(FakeUdp("192.168.60.26"))
        return made[-1]

    assert primary_address(socket_factory=factory) == "192.168.60.26"
    assert made[0].connected == ("192.0.2.1", 9)
    assert primary_address(socket_factory=lambda f, k: FakeUdp(None)) is None
    assert primary_address(socket_factory=lambda f, k: FakeUdp("8.8.8.8")) is None  # public: not a LAN address


def test_probe_uses_the_route_table_only_on_windows():
    calls = []
    args = {"interfaces": lambda: OWNER_INTERFACES, "route_print": lambda: calls.append(1) or OWNER_ROUTES,
            "primary": lambda: "192.168.60.26", "resolved": lambda: ("192.168.56.1", "192.168.60.26")}
    windows = probe_interfaces(platform="win32", **args)
    assert windows.gateway_addresses == frozenset({"192.168.60.26"}) and calls == [1]
    mac = probe_interfaces(platform="darwin", **args)
    assert mac.gateway_addresses is None and calls == [1]
    broken = probe_interfaces(platform="win32", interfaces=lambda: None, route_print=lambda: None,
                              primary=lambda: None, resolved=lambda: ("192.168.56.1",))
    assert broken.gateway_addresses is None and broken.current == ("192.168.56.1",)


GERMAN_ROUTES = """\
Aktive Routen:
     Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik
          0.0.0.0          0.0.0.0     192.168.60.1    192.168.60.26     25
          0.0.0.0          0.0.0.0   Auf Verbindung    192.168.77.5     40
     192.168.56.0    255.255.255.0   Auf Verbindung     192.168.56.1    281
Ständige Routen:
  Keine
"""


def test_route_parsing_reads_the_interface_from_the_end_of_the_row():
    assert parse_route_print(GERMAN_ROUTES) == frozenset({"192.168.60.26", "192.168.77.5"})


def test_route_print_decodes_non_ascii_output_with_replacement(monkeypatch):
    from localvault.sync import lan_interfaces

    seen = {}

    class Done:
        returncode = 0
        stdout = GERMAN_ROUTES.replace("ä", "\ufffd")

    def run(args, **kwargs):
        seen.update(kwargs)
        return Done()

    monkeypatch.setattr(lan_interfaces.subprocess, "run", run)
    assert "192.168.60.26" in parse_route_print(lan_interfaces._route_print())
    assert seen["errors"] == "replace" and seen["text"] is True

    def broken(args, **kwargs):
        raise UnicodeDecodeError("cp850", b"\x81", 0, 1, "bad")

    monkeypatch.setattr(lan_interfaces.subprocess, "run", broken)
    assert lan_interfaces._route_print() is None


def test_a_route_decoding_failure_keeps_the_adapter_list():
    def route():
        raise UnicodeDecodeError("cp850", b"\x81", 0, 1, "bad")

    snapshot = probe_interfaces(platform="win32", interfaces=lambda: OWNER_INTERFACES, route_print=route,
                                primary=lambda: "192.168.60.26", resolved=lambda: ())
    assert snapshot.interfaces == OWNER_INTERFACES and snapshot.gateway_addresses is None


def test_ipv6_addresses_count_as_owned_but_never_as_candidates():
    from localvault.sync.lan_interfaces import same_address

    snapshot = NetworkSnapshot((Interface("Wi-Fi", ("192.168.1.9", "fd12:3456::7")),), frozenset({"192.168.1.9"}))
    assert [c.address for c in lan_candidates(snapshot)] == ["192.168.1.9"]
    assert any(same_address(a, "[fd12:3456:0::7]") for a in current_addresses(snapshot))


def test_virtual_addresses_by_adapter_name_or_virtualbox_range():
    from localvault.sync.lan_interfaces import is_virtual_address

    snapshot = NetworkSnapshot(OWNER_INTERFACES + (
        Interface("vEthernet (WSL)", ("172.20.112.1",)), Interface("Ethernet 3", ("192.168.137.1",))))
    assert is_virtual_address(snapshot, "192.168.56.1")  # VirtualBox host-only, named just "Ethernet 2"
    assert is_virtual_address(snapshot, "172.20.112.1")
    assert not is_virtual_address(snapshot, "192.168.137.1")  # Mobile Hotspot: may be deliberate
    assert not is_virtual_address(snapshot, "192.168.60.26")
    assert not is_virtual_address(snapshot, "not an address")
