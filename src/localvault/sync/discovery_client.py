"""Finding a paired Wi-Fi host again after its address changed (this PC as a discovery client).

When the pinned address of a paired host (another PC or a Mac) does not answer, this PC browses
``_lgksync._tcp`` for at most :data:`BROWSE_SECONDS` and keeps only announcements that

* carry ``v=1`` and a tag ``t`` equal to today's or yesterday's tag of THAT host
  (``discovery.accepted_tags``: a keyed MAC only group members can compute),
* name a LAN address (``lan_address.is_lan_address``) on the pinned port.

At most :data:`MAX_DIALS` such addresses are dialled per host and run, each with at most
:data:`DIAL_SECONDS`.  Discovery only changes where this PC dials, never whom it trusts: the
session hello still checks the host's pinned keys, and a new address is stored only after an
authenticated exchange with it completed (``lan_sync.save_peer_endpoint``).

Windows: ``DnsServiceBrowse`` / ``DnsServiceResolve`` from ``dnsapi.dll`` over ctypes (Windows 10
1809+, no extra install).  Where they are missing, or on any failure, browsing finds nothing.
"""
from __future__ import annotations

import ctypes
import ipaddress
import socket
import struct
import sys
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from . import discovery
from .group import GroupKey
from .lan_address import is_lan_address
from .transport import LANEndpoint, TransportError

BROWSE_SECONDS = 3.0
DIAL_SECONDS = 5.0
MAX_DIALS = 4
#: Announcements kept from one browse (a hostile network cannot grow the list without bound).
MAX_FOUND = 32
_MAX_TXT = 8
_MAX_TXT_VALUE = 64
_DNS_REQUEST_PENDING = 9506
_DNS_QUERY_REQUEST_VERSION1 = 1
_DNS_TYPE_PTR = 12
_DNS_FREE_RECORD_LIST = 1


@dataclass(frozen=True)
class Found:
    """One resolved announcement: the address it gave, its port and its TXT record."""

    host: str
    port: int
    txt: Mapping[str, str]


class Browser(Protocol):
    def browse(self, service_type: str, timeout: float) -> list[Found]: ...


def candidates(found: Iterable[Found], group_key: GroupKey, host_device_id: str, now: float, *,
               port: int, exclude: LANEndpoint | None = None, limit: int = MAX_DIALS) -> list[LANEndpoint]:
    """The addresses worth dialling for *host_device_id*: tag match, LAN address, pinned *port*, at most *limit*."""
    tags = discovery.accepted_tags(group_key, host_device_id, now)
    out: list[LANEndpoint] = []
    for item in found:
        if len(out) >= limit:
            break
        txt = item.txt if isinstance(item.txt, Mapping) else {}
        if txt.get("v") != discovery.TXT_VERSION or txt.get("t") not in tags:
            continue
        if type(item.port) is not int or item.port != port:
            continue
        try:
            address = ipaddress.ip_address(item.host)
        except (ValueError, TypeError):
            continue
        if not is_lan_address(address):
            continue
        try:
            endpoint = LANEndpoint(str(address), port)
        except TransportError:
            continue
        if endpoint != exclude and endpoint not in out:
            out.append(endpoint)
    return out


class NoBrowser:
    """Finds nothing (non-Windows, or DNS-SD missing)."""

    def browse(self, service_type: str, timeout: float) -> list[Found]:
        return []


class WindowsDnsSdBrowser:
    """``DnsServiceBrowse`` then ``DnsServiceResolve`` for each instance, within one deadline."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("DNS-SD browsing needs Windows")
        from ctypes import wintypes

        dll = ctypes.WinDLL("dnsapi.dll")
        for name in ("DnsServiceBrowse", "DnsServiceBrowseCancel", "DnsServiceResolve",
                     "DnsServiceResolveCancel", "DnsServiceFreeInstance", "DnsRecordListFree"):
            if not hasattr(dll, name):
                raise OSError(f"{name} is not available on this Windows version")
        self._w = wintypes

        class Record(ctypes.Structure):
            pass

        Record._fields_ = [("pNext", ctypes.POINTER(Record)), ("pName", wintypes.LPWSTR),
                           ("wType", wintypes.WORD), ("wDataLength", wintypes.WORD),
                           ("Flags", wintypes.DWORD), ("dwTtl", wintypes.DWORD),
                           ("dwReserved", wintypes.DWORD), ("pNameHost", wintypes.LPWSTR)]

        class Instance(ctypes.Structure):
            _fields_ = [("pszInstanceName", wintypes.LPWSTR), ("pszHostName", wintypes.LPWSTR),
                        ("ip4Address", ctypes.POINTER(wintypes.DWORD)), ("ip6Address", ctypes.c_void_p),
                        ("wPort", wintypes.WORD), ("wPriority", wintypes.WORD), ("wWeight", wintypes.WORD),
                        ("dwPropertyCount", wintypes.DWORD), ("keys", ctypes.POINTER(wintypes.LPWSTR)),
                        ("values", ctypes.POINTER(wintypes.LPWSTR)), ("dwInterfaceIndex", wintypes.DWORD)]

        self._browse_cb = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(Record))
        self._resolve_cb = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(Instance))

        class BrowseRequest(ctypes.Structure):
            _fields_ = [("Version", wintypes.ULONG), ("InterfaceIndex", wintypes.ULONG),
                        ("QueryName", wintypes.LPCWSTR), ("pBrowseCallback", self._browse_cb),
                        ("pQueryContext", ctypes.c_void_p)]

        class ResolveRequest(ctypes.Structure):
            _fields_ = [("Version", wintypes.ULONG), ("InterfaceIndex", wintypes.ULONG),
                        ("QueryName", wintypes.LPWSTR), ("pResolveCompletionCallback", self._resolve_cb),
                        ("pQueryContext", ctypes.c_void_p)]

        class Cancel(ctypes.Structure):
            _fields_ = [("reserved", ctypes.c_void_p)]

        self._Record, self._Instance = Record, Instance
        self._BrowseRequest, self._ResolveRequest, self._Cancel = BrowseRequest, ResolveRequest, Cancel
        dll.DnsServiceBrowse.argtypes = [ctypes.POINTER(BrowseRequest), ctypes.POINTER(Cancel)]
        dll.DnsServiceBrowse.restype = wintypes.DWORD
        dll.DnsServiceBrowseCancel.argtypes = [ctypes.POINTER(Cancel)]
        dll.DnsServiceBrowseCancel.restype = wintypes.DWORD
        dll.DnsServiceResolve.argtypes = [ctypes.POINTER(ResolveRequest), ctypes.POINTER(Cancel)]
        dll.DnsServiceResolve.restype = wintypes.DWORD
        dll.DnsServiceResolveCancel.argtypes = [ctypes.POINTER(Cancel)]
        dll.DnsServiceResolveCancel.restype = wintypes.DWORD
        dll.DnsServiceFreeInstance.argtypes = [ctypes.c_void_p]
        dll.DnsServiceFreeInstance.restype = None
        dll.DnsRecordListFree.argtypes = [ctypes.c_void_p, ctypes.c_int]
        dll.DnsRecordListFree.restype = None
        self._dll = dll

    def browse(self, service_type: str, timeout: float) -> list[Found]:
        deadline = time.monotonic() + max(0.0, min(timeout, BROWSE_SECONDS))
        names = self._browse_names(f"{service_type}.local", deadline)
        found: list[Found] = []
        for name in names[:MAX_FOUND]:
            if time.monotonic() >= deadline:
                break
            item = self._resolve(name, deadline)
            if item is not None:
                found.append(item)
        return found

    def _browse_names(self, query: str, deadline: float) -> list[str]:
        mu, names = threading.Lock(), []

        def on_records(_status: int, _context: Any, record: Any) -> None:
            try:
                node = record
                while node:
                    rec = node.contents
                    if rec.wType == _DNS_TYPE_PTR and rec.pNameHost:
                        with mu:
                            if len(names) < MAX_FOUND and rec.pNameHost not in names:
                                names.append(rec.pNameHost)
                    node = rec.pNext
            finally:
                if record:
                    self._dll.DnsRecordListFree(ctypes.cast(record, ctypes.c_void_p), _DNS_FREE_RECORD_LIST)

        callback = self._browse_cb(on_records)
        request = self._BrowseRequest(_DNS_QUERY_REQUEST_VERSION1, 0, query, callback, None)
        cancel = self._Cancel()
        if self._dll.DnsServiceBrowse(ctypes.byref(request), ctypes.byref(cancel)) != _DNS_REQUEST_PENDING:
            return []
        try:
            time.sleep(max(0.0, min(deadline - time.monotonic(), BROWSE_SECONDS * 2 / 3)))
        finally:
            self._dll.DnsServiceBrowseCancel(ctypes.byref(cancel))
            _RETIRED.append((request, callback, cancel))  # dnsapi may still call back after cancel
        with mu:
            return list(names)

    def _resolve(self, name: str, deadline: float) -> Found | None:
        done, box = threading.Event(), {}

        def on_instance(_status: int, _context: Any, inst: Any) -> None:
            try:
                if inst:
                    box["found"] = self._read_instance(inst.contents)
            except Exception:  # noqa: BLE001, S110 - a malformed answer is dropped
                pass
            finally:
                if inst:
                    self._dll.DnsServiceFreeInstance(ctypes.cast(inst, ctypes.c_void_p))
                done.set()

        callback = self._resolve_cb(on_instance)
        buf = ctypes.create_unicode_buffer(name)
        request = self._ResolveRequest(_DNS_QUERY_REQUEST_VERSION1, 0, ctypes.cast(buf, self._w.LPWSTR),
                                       callback, None)
        cancel = self._Cancel()
        if self._dll.DnsServiceResolve(ctypes.byref(request), ctypes.byref(cancel)) != _DNS_REQUEST_PENDING:
            return None
        if not done.wait(max(0.0, deadline - time.monotonic())):
            self._dll.DnsServiceResolveCancel(ctypes.byref(cancel))
        _RETIRED.append((request, callback, cancel, buf))
        return box.get("found")

    def _read_instance(self, inst: Any) -> Found | None:
        if not inst.ip4Address:
            return None  # IPv4 only, like the announcement
        host = socket.inet_ntoa(struct.pack("<I", inst.ip4Address.contents.value))
        txt: dict[str, str] = {}
        for i in range(min(int(inst.dwPropertyCount), _MAX_TXT)):
            key, value = inst.keys[i], inst.values[i]
            if key and value is not None and len(key) <= 16 and len(value) <= _MAX_TXT_VALUE:
                txt[key] = value
        return Found(host, int(inst.wPort), txt)


#: Requests (and their callbacks) handed to dnsapi, kept alive in case it calls back late.
_RETIRED: list[Any] = []


def default_browser() -> Browser:
    """The platform browser, or :class:`NoBrowser` when DNS-SD is unavailable."""
    try:
        return WindowsDnsSdBrowser()
    except (OSError, AttributeError):
        return NoBrowser()
