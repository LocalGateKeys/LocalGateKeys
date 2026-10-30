"""Which of this PC's addresses a phone on the same Wi-Fi can reach.

The Wi-Fi sync QR code carries one address of this PC.  Name resolution of the
host name (``getaddrinfo(gethostname())``) lists every adapter in no useful
order, including VirtualBox host-only (192.168.56.x), Hyper-V / WSL
(``vEthernet``), VPN and other virtual adapters that a phone can never reach.
This module ranks the real candidates instead:

* only adapters that are up;
* only addresses whose adapter has a default gateway, when the routing table
  could be read (a VirtualBox host-only adapter is often named just
  "Ethernet 2", so the gateway is the reliable signal);
* never loopback, link-local (169.254.x) or non-private addresses;
* never adapters whose name marks them as virtual or VPN;
* Wi-Fi and Ethernet first, then the address the OS would use for outgoing
  traffic (the UDP-connect trick: no packet is sent).

:func:`lan_candidates` and :func:`obvious_candidate` are pure: the caller passes
the interface data.  :func:`probe_interfaces` reads it from the system (psutil,
``route print`` on Windows, the UDP trick everywhere).  Nothing here opens a
listening socket or sends a packet.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess  # noqa: S404 - fixed System32 route.exe, constant arguments
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from .lan_address import is_lan_address
from ..i18n import t

#: Adapter names that are virtual, VPN or otherwise never the home network.
_VIRTUAL = re.compile(
    r"vethernet|hyper-?v|\bwsl\b|virtualbox|\bvbox|vmware|\bvmnet|\bvirtual\b|\btap\b|tap-windows|\btun\b|"
    r"^tun\d|^tap\d|wireguard|^wg\d|tailscale|zerotier|^zt|docker|^br-|^veth|^virbr|npcap|loopback|"
    r"openvpn|\bvpn\b|nordlynx|^utun|^awdl|^llw|^bridge\d|^lo\d*$|bluetooth|isatap|teredo|"
    r"local area connection\*",
    re.IGNORECASE)
_WIFI = re.compile(r"wi-?fi|wlan|wireless|^wl|802\.11|airport", re.IGNORECASE)
_ETHERNET = re.compile(r"ethernet|^eth\d|^en\d|^enp|^eno|^ens|\blan\b", re.IGNORECASE)

#: Kind order: Wi-Fi and Ethernet are preferred over anything else.
KIND_RANK = {"wifi": 0, "ethernet": 0, "other": 1}


@dataclass(frozen=True)
class Interface:
    """One network adapter as the OS reports it (IPv4 and IPv6; only IPv4 become candidates)."""

    name: str
    addresses: tuple[str, ...]
    is_up: bool = True


@dataclass(frozen=True)
class Candidate:
    address: str
    interface: str
    kind: str  # "wifi", "ethernet" or "other"
    primary: bool = False  # the address the OS uses for outgoing traffic
    has_gateway: bool | None = None  # None: the routing table could not be read

    @property
    def label(self) -> str:
        kind = {"wifi": t("nav.type.wifi"), "ethernet": t("network.ethernet")}.get(self.kind, t("network.network"))
        name = self.interface if self.interface.lower() not in ("wi-fi", "ethernet") else ""
        return f"{self.address} ({kind}{' · ' + name if name else ''})"


@dataclass(frozen=True)
class NetworkSnapshot:
    """What :func:`probe_interfaces` found; the input of the pure functions below."""

    interfaces: tuple[Interface, ...] = ()
    gateway_addresses: frozenset[str] | None = None  # local addresses that own a default route
    primary: str | None = None
    current: tuple[str, ...] = field(default=())  # every IPv4 this PC owns now (any adapter)


def is_virtual_adapter(name: str) -> bool:
    return bool(_VIRTUAL.search(name or ""))


def adapter_kind(name: str) -> str:
    if _WIFI.search(name or ""):
        return "wifi"
    if _ETHERNET.search(name or ""):
        return "ethernet"
    return "other"


def _private_ipv4(text: str) -> ipaddress.IPv4Address | None:
    try:
        address = ipaddress.ip_address(str(text).split("%")[0])
    except ValueError:
        return None
    if address.version != 4 or address.is_loopback or address.is_link_local or address.is_unspecified:
        return None
    if address.is_multicast or not is_lan_address(address):
        return None
    return address  # type: ignore[return-value]


def lan_candidates(snapshot: NetworkSnapshot) -> list[Candidate]:
    """This PC's addresses a phone on the home network can reach, best first."""
    gateways = snapshot.gateway_addresses
    found: dict[str, Candidate] = {}
    for iface in snapshot.interfaces:
        if not iface.is_up or is_virtual_adapter(iface.name):
            continue
        kind = adapter_kind(iface.name)
        for text in iface.addresses:
            address = _private_ipv4(text)
            if address is None or str(address) in found:
                continue
            has_gateway = None if gateways is None else str(address) in gateways
            if has_gateway is False:
                continue
            found[str(address)] = Candidate(str(address), iface.name, kind, primary=str(address) == snapshot.primary,
                                            has_gateway=has_gateway)
    if not snapshot.interfaces and snapshot.primary and _private_ipv4(snapshot.primary) is not None:
        # No adapter list (psutil missing): the outgoing-traffic address is the best guess.
        found[snapshot.primary] = Candidate(snapshot.primary, "", "other", primary=True, has_gateway=None)
    return sorted(found.values(), key=lambda c: (KIND_RANK[c.kind], not c.primary, c.kind != "wifi", c.interface,
                                                  ipaddress.ip_address(c.address)))


def obvious_candidate(candidates: Iterable[Candidate]) -> Candidate | None:
    """The one candidate to use without asking, or None when the user has to choose (or there is none)."""
    items = list(candidates)
    if len(items) == 1:
        return items[0]
    preferred = [c for c in items if c.kind != "other"]
    if len(preferred) == 1:
        return preferred[0]
    return None


def same_address(a: str, b: str) -> bool:
    """True when *a* and *b* are the same IP address (IPv6 spellings and zone ids ignored)."""
    try:
        return ipaddress.ip_address(str(a).split("%")[0]) == ipaddress.ip_address(str(b).strip("[]").split("%")[0])
    except ValueError:
        return False


#: VirtualBox's default host-only network. psutil reports that adapter by its connection name
#: ("Ethernet 2"), so the name rules cannot see it; the range is VirtualBox's documented default.
VIRTUALBOX_HOST_ONLY = ipaddress.ip_network("192.168.56.0/24")


def is_virtual_address(snapshot: NetworkSnapshot, host: str) -> bool:
    """True when *host* sits on a virtual or VPN adapter (by its name, or VirtualBox's default range)."""
    try:
        address = ipaddress.ip_address(str(host).strip("[]").split("%")[0])
    except ValueError:
        return False
    if address.version == 4 and address in VIRTUALBOX_HOST_ONLY:
        return True
    return any(is_virtual_adapter(i.name) for i in snapshot.interfaces
               if any(same_address(a, str(address)) for a in i.addresses))


def current_addresses(snapshot: NetworkSnapshot) -> set[str]:
    """Every address this PC owns now (adapters that are up), virtual ones and IPv6 included."""
    owned = {str(a).split("%")[0] for iface in snapshot.interfaces if iface.is_up for a in iface.addresses}
    owned.update(snapshot.current)
    if snapshot.primary:
        owned.add(snapshot.primary)
    return owned



def followed_endpoint(stored: str, snapshot: NetworkSnapshot) -> str | None:
    """The ``host:port`` to listen on after this PC's address changed, or None to keep *stored*.

    Only when *stored*'s host is on no adapter any more and exactly one obvious candidate exists
    (the user is asked otherwise); the port is kept, so the firewall rule still applies.
    """
    host, sep, port = str(stored or "").rpartition(":")
    host = host.strip("[]")
    if not sep or not host or not port.isdigit():
        return None
    if not snapshot.interfaces and not snapshot.primary:
        return None  # nothing could be read: never move on a failed probe
    if any(same_address(a, host) for a in current_addresses(snapshot)):
        return None
    pick = obvious_candidate(lan_candidates(snapshot))
    return None if pick is None else f"{pick.address}:{int(port)}"

# --------------------------------------------------------------------------------------------- system probes
def parse_route_print(text: str) -> frozenset[str]:
    """Local interface addresses that own an IPv4 default route, from ``route print -4`` (any language).

    A row is ``destination netmask gateway interface metric``; the gateway can be a localized
    word or two ("On-link", "Auf Verbindung"), so the interface is read from the end of the row.
    """
    found: set[str] = set()
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0" or not parts[-1].isdigit():
            continue
        try:
            address = ipaddress.ip_address(parts[-2])
        except ValueError:
            continue
        if address.version == 4:
            found.add(str(address))
    return frozenset(found)


def _route_print() -> str | None:
    from ..winpaths import system32

    route = system32("route.exe")
    try:
        result = subprocess.run([route, "print", "-4"], capture_output=True, text=True,  # noqa: S603
                                errors="replace", timeout=5, check=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeDecodeError):
        return None
    return result.stdout if result.returncode == 0 else None


def primary_address(*, socket_factory: Callable[..., socket.socket] = socket.socket) -> str | None:
    """The IPv4 address the OS would send from (UDP connect sends no packet)."""
    for target in ("192.0.2.1", "10.255.255.255"):
        try:
            with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((target, 9))
                address = sock.getsockname()[0]
        except OSError:
            continue
        if _private_ipv4(address) is not None:
            return str(address)
    return None


def _psutil_interfaces() -> tuple[Interface, ...] | None:
    try:
        import psutil  # type: ignore[import-not-found]

        addrs: Mapping[str, list] = psutil.net_if_addrs()
        stats: Mapping[str, object] = psutil.net_if_stats()
    except Exception:  # noqa: BLE001 - psutil missing or refused: fall back to the UDP trick
        return None
    result = []
    for name, entries in addrs.items():
        found = tuple(str(e.address).split("%")[0] for e in entries
                      if e.family in (socket.AF_INET, getattr(socket, "AF_INET6", -1)))
        if not found:
            continue
        stat = stats.get(name)
        result.append(Interface(name, found, is_up=bool(getattr(stat, "isup", True))))
    return tuple(result)


def _resolved_addresses() -> tuple[str, ...]:
    found: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            if info[4][0] not in found:
                found.append(info[4][0])
    except OSError:
        pass
    return tuple(found)


def probe_interfaces(*, platform: str = sys.platform,
                     interfaces: Callable[[], tuple[Interface, ...] | None] = _psutil_interfaces,
                     route_print: Callable[[], str | None] = _route_print,
                     primary: Callable[[], str | None] = primary_address,
                     resolved: Callable[[], tuple[str, ...]] = _resolved_addresses) -> NetworkSnapshot:
    """Read this PC's adapters (each source may fail; the snapshot then has less detail)."""
    found = interfaces() or ()
    gateways = None
    if platform == "win32":
        try:
            text = route_print()
        except (OSError, ValueError, UnicodeDecodeError):
            text = None  # a decoding problem must not discard the adapter list
        if text is not None:
            gateways = parse_route_print(text) or None  # an empty table is "unknown", not "no gateway"
    return NetworkSnapshot(interfaces=tuple(found), gateway_addresses=gateways, primary=primary(),
                           current=() if found else resolved())
