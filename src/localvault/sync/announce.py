"""Announcing this PC's Wi-Fi sync listener on the local network (Bonjour / mDNS).

Paired phones look for it when the address they pinned stops answering (format in
``discovery.py``).  Windows 10 1809+ has a DNS-SD responder (``DnsServiceRegister`` in
``dnsapi.dll``), so nothing extra is installed; when it is missing nothing is announced.

What goes out: instance ``LocalGateKeys-xxxx._lgksync._tcp.local`` (random per app start),
host ``lgk-xxxx.local`` (not the computer name) at the listening address, and the TXT record
``v``/``t``, on the one adapter that owns the listening address (never every adapter).  Only on a
Private (or domain) network: the adapter's profile is read before announcing and again every
:data:`RECHECK_SECONDS`, which also renews the daily tag.
"""
from __future__ import annotations

import contextlib
import ctypes
import ipaddress
import secrets
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from . import discovery
from .group import GroupKey

RECHECK_SECONDS = 3 * 60
ANNOUNCE_PROFILES = frozenset({"Private", "DomainAuthenticated"})
_DNS_REQUEST_PENDING = 9506
_DNS_QUERY_REQUEST_VERSION1 = 1


class DnsSdApi(Protocol):
    def register(self, instance: str, host: str, ipv4: str, port: int, txt: dict[str, str],
                 interface_index: int) -> Any: ...
    def deregister(self, handle: Any) -> None: ...


@dataclass(frozen=True)
class Announcement:
    instance: str
    host: str
    ipv4: str
    port: int
    txt: dict[str, str]
    interface_index: int


class WindowsDnsSd:
    """``DnsServiceRegister`` / ``DnsServiceDeRegister`` over ctypes (Windows 10 1809+)."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("DNS-SD registration needs Windows")
        from ctypes import wintypes

        dll = ctypes.WinDLL("dnsapi.dll")
        if not hasattr(dll, "DnsServiceRegister"):
            raise OSError("DnsServiceRegister is not available on this Windows version")
        self._callback_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)

        class Request(ctypes.Structure):
            _fields_ = [("Version", wintypes.ULONG), ("InterfaceIndex", wintypes.ULONG),
                        ("pServiceInstance", ctypes.c_void_p), ("pRegisterCompletionCallback", self._callback_type),
                        ("pQueryContext", ctypes.c_void_p), ("hCredentials", wintypes.HANDLE),
                        ("unicastEnabled", wintypes.BOOL)]

        self._request_type = Request
        construct = dll.DnsServiceConstructInstance
        construct.restype = ctypes.c_void_p
        construct.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                              wintypes.WORD, wintypes.WORD, wintypes.WORD, wintypes.DWORD,
                              ctypes.POINTER(wintypes.LPCWSTR), ctypes.POINTER(wintypes.LPCWSTR)]
        dll.DnsServiceFreeInstance.argtypes = [ctypes.c_void_p]
        dll.DnsServiceFreeInstance.restype = None
        dll.DnsServiceRegister.argtypes = [ctypes.POINTER(Request), ctypes.c_void_p]
        dll.DnsServiceRegister.restype = wintypes.DWORD
        dll.DnsServiceDeRegister.argtypes = [ctypes.POINTER(Request), ctypes.c_void_p]
        dll.DnsServiceDeRegister.restype = wintypes.DWORD
        self._dll = dll
        self._wintypes = wintypes

    def register(self, instance: str, host: str, ipv4: str, port: int, txt: dict[str, str],
                 interface_index: int) -> Any:
        if interface_index <= 0:
            raise OSError("no adapter index: refusing to announce on every adapter")
        w = self._wintypes
        address = w.DWORD(struct.unpack("<I", ipaddress.IPv4Address(ipv4).packed)[0])  # network byte order
        keys = (w.LPCWSTR * len(txt))(*txt.keys())
        values = (w.LPCWSTR * len(txt))(*txt.values())
        inst = self._dll.DnsServiceConstructInstance(f"{instance}.{discovery.SERVICE_TYPE}.local", host,
                                                     ctypes.byref(address), None, port, 0, 0, len(txt), keys, values)
        if not inst:
            raise OSError("DnsServiceConstructInstance failed")

        def done(_status: int, _context: Any, result: Any) -> None:
            if result:
                self._dll.DnsServiceFreeInstance(result)

        callback = self._callback_type(done)
        request = self._request_type(_DNS_QUERY_REQUEST_VERSION1, interface_index, inst, callback, None, None,
                                     False)
        status = self._dll.DnsServiceRegister(ctypes.byref(request), None)
        if status != _DNS_REQUEST_PENDING:
            self._dll.DnsServiceFreeInstance(inst)
            raise OSError(f"DnsServiceRegister returned {status}")
        return (request, callback, inst)  # kept alive until deregistered

    def deregister(self, handle: Any) -> None:
        # Asynchronous: dnsapi keeps the request, its instance and the callback thunk until it calls back,
        # so they are never freed (a few hundred bytes per address or day change) rather than risk a
        # use-after-free.
        request, _callback, _inst = handle
        _RETIRED.append(handle)
        self._dll.DnsServiceDeRegister(ctypes.byref(request), None)


#: Deregistered requests, kept alive for dnsapi's completion callback (see ``deregister``).
_RETIRED: list[Any] = []


_PROFILE_SCRIPT = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$ip = Get-NetIPAddress -IPAddress $env:LGK_HOST | Select-Object -First 1
if ($ip) { $p = Get-NetConnectionProfile -InterfaceIndex $ip.InterfaceIndex | Select-Object -First 1
  Write-Output ("{0}|{1}" -f $ip.InterfaceIndex, $p.NetworkCategory) }
"""


def _network_profile(host: str, port: int) -> tuple[str, int]:
    """``(network category, adapter index)`` of the adapter that owns *host*; ``("", 0)`` when unknown."""
    from .firewall import _run_powershell

    ipaddress.IPv4Address(host)  # only ever an address goes to the script
    out = (_run_powershell(_PROFILE_SCRIPT, {"LGK_HOST": host}) or "").strip()
    index, _, category = out.partition("|")
    return (category, int(index)) if index.isdigit() and category else ("", 0)


class Announcer:
    """Keeps one announcement up while the listener runs; every call is cheap and thread-safe."""

    def __init__(self, *, api_factory: Callable[[], DnsSdApi] = WindowsDnsSd,
                 profile: Callable[[str, int], tuple[str, int]] = _network_profile, clock: Callable[[], float] = time.time,
                 token: str | None = None, recheck_seconds: float = RECHECK_SECONDS,
                 start_thread: bool = True) -> None:
        self._api_factory = api_factory
        self._api: DnsSdApi | None = None
        self._profile = profile
        self._clock = clock
        self._token = token or secrets.token_hex(2)
        self._recheck = recheck_seconds
        self._start_thread = start_thread
        self._mu = threading.Lock()
        self._wanted: tuple[GroupKey, str, str, int] | None = None
        self._current: tuple[Announcement, Any] | None = None
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self.state = "off"  # off | announcing | public-network | unavailable

    @property
    def instance(self) -> str:
        return discovery.instance_name(self._token)

    def start(self, group_key: GroupKey, device_id: str, host: str, port: int) -> None:
        with self._mu:
            self._wanted = (group_key, device_id, host, port)
            if self._start_thread and self._thread is None:
                self._thread = threading.Thread(target=self._loop, name="lgk-announce", daemon=True)
                self._thread.start()
        self._wake.set()

    def stop(self) -> None:
        with self._mu:
            self._wanted = None
        self._wake.set()
        if not self._start_thread:
            self.refresh()

    def refresh(self) -> None:
        """Bring the announcement in line with what is wanted (the thread calls this; tests call it directly)."""
        with self._mu:
            wanted = self._wanted
        target: Announcement | None = None
        state = "off"
        if wanted is not None:
            gk, device_id, host, port = wanted
            try:
                profile, index = self._profile(host, port)
            except Exception:  # noqa: BLE001 - unknown profile: treat as not private
                profile, index = "", 0
            if profile in ANNOUNCE_PROFILES and index > 0:
                target = Announcement(self.instance, f"lgk-{self._token}.local", host, port,
                                      discovery.txt_record(gk, device_id, self._clock()), index)
                state = "announcing"
            else:
                state = "public-network"
        with self._mu:
            current = self._current
            if current is not None and current[0] == target:
                self.state = state
                return
            if current is not None:
                with contextlib.suppress(Exception):
                    self._ensure_api().deregister(current[1])
                self._current = None
            if target is not None:
                try:
                    handle = self._ensure_api().register(target.instance, target.host, target.ipv4, target.port,
                                                         target.txt, target.interface_index)
                except OSError:
                    self.state = "unavailable"
                    return
                self._current = (target, handle)
            self.state = state

    def _ensure_api(self) -> DnsSdApi:
        if self._api is None:
            self._api = self._api_factory()
        return self._api

    def _loop(self) -> None:
        while True:
            self._wake.wait(self._recheck)
            self._wake.clear()
            self.refresh()
            with self._mu:
                if self._wanted is None and self._current is None:
                    self._thread = None
                    return
