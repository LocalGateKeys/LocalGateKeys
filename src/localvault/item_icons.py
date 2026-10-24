"""Private, bounded item-icon helpers (website favicons, desktop app icons), without any UI toolkit.

Restored from the classic ``entry_icons`` module when Tk was removed; the WebView list shows these icons.

The vault never needs an icon to list or search an entry.  This module keeps
that property explicit: canonical local type icons are always available, while
bounded website downloads are queued only for visible web rows when the caller
allows network access.  Downloaded and native images are process-memory only.
"""
from __future__ import annotations

import ctypes
import http.client
import io
import ipaddress
import os
import re
import socket
import ssl
import threading
from collections import OrderedDict
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .origin import OriginError, canonicalize_origin

MAX_CACHED_SOURCES = 128
MAX_CACHE_BYTES = 8 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 256 * 1024
MAX_ICON_DIMENSION = 1024
MAX_ICON_PIXELS = 1_048_576
MAX_RETAINED_DIMENSION = 256
MAX_DOWNLOAD_SECONDS = 5.0
MAX_IN_FLIGHT = 2
MAX_ICON_WORKERS = MAX_IN_FLIGHT
MAX_DNS_RESOLVERS = MAX_IN_FLIGHT
_UNSET = object()

_DNS_RESOLVER_SLOTS = threading.BoundedSemaphore(MAX_DNS_RESOLVERS)

CANONICAL_ICON_BY_KIND = {
    "web": "row.websiteGlobe",
    "desktop": "row.desktopLogin",
    "note": "row.note",
    "document": "row.document",
    "identity": "row.identity",
    "bookmark": "row.websiteGlobe",
    "license": "row.note",
    "purchase": "row.note",
    "warranty": "row.document",
    "subscription": "row.note",
    # Secret-bearing kinds reuse existing canonical glyphs until dedicated
    # artwork lands in the sidebar bundle.
    "card": "header.lock",
    "bank_account": "header.lock",
    "ssh_key": "nav.securityRecovery",
    "api_key": "header.lock",
    "wifi": "nav.devicesConnections",
    "passkey": "nav.securityRecovery",
}


class UnsafeIconOrigin(ValueError):
    """The saved origin is not eligible for an explicit public HTTPS fetch."""


class IconDecodeError(ValueError):
    """Icon bytes are unsupported, malformed, or exceed a processing limit."""


def _public_addresses(
    host: str,
    port: int,
    *,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[tuple[int, str], ...]:
    """Resolve once and reject every non-public address returned by DNS.

    ``getaddrinfo`` has no portable cancellation API and can block inside the
    platform resolver.  Keep those calls in a small daemon pool so a stalled
    resolver cannot hold a fetch worker or prevent process exit.  The caller
    still receives a bounded result and the daemon resolver slot is released
    only when the platform call eventually returns.
    """

    if deadline is None:
        deadline = _monotonic() + MAX_DOWNLOAD_SECONDS
    if cancel_event is not None and cancel_event.is_set():
        raise TimeoutError("Website icon DNS lookup cancelled")
    remaining = deadline - _monotonic()
    if remaining <= 0 or not _DNS_RESOLVER_SLOTS.acquire(timeout=remaining):
        raise TimeoutError("Website icon DNS lookup timed out")

    completed = threading.Event()
    outcome: dict[str, Any] = {}

    def resolve() -> None:
        try:
            outcome["results"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except BaseException as exc:  # publish every resolver failure to waiter
            outcome["error"] = exc
        finally:
            _DNS_RESOLVER_SLOTS.release()
            completed.set()

    threading.Thread(
        target=resolve,
        name="lgk-icon-dns",
        daemon=True,
    ).start()
    while not completed.wait(timeout=min(0.05, max(0.0, deadline - _monotonic()))):
        if cancel_event is not None and cancel_event.is_set():
            raise TimeoutError("Website icon DNS lookup cancelled")
        if _monotonic() >= deadline:
            raise TimeoutError("Website icon DNS lookup timed out")
    if cancel_event is not None and cancel_event.is_set():
        raise TimeoutError("Website icon DNS lookup cancelled")
    error = outcome.get("error")
    if error is not None:
        if isinstance(error, TimeoutError):
            raise error
        raise UnsafeIconOrigin("The website host could not be resolved safely") from error
    results = outcome.get("results")
    if not isinstance(results, (list, tuple)):
        raise UnsafeIconOrigin("The website host could not be resolved safely")
    addresses: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for family, _socktype, _proto, _canonname, sockaddr in results:
        address = str(sockaddr[0]).split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise UnsafeIconOrigin("The website host resolved to an invalid address") from exc
        if not _public_address(parsed):
            raise UnsafeIconOrigin("Private or reserved website addresses are not allowed")
        item = (family, address)
        if item not in seen:
            seen.add(item)
            addresses.append(item)
    if not addresses:
        raise UnsafeIconOrigin("The website host has no usable address")
    return tuple(addresses)


_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")


def _public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for a global unicast address, judged by any IPv4 it embeds.

    ``::a.b.c.d`` (IPv4-compatible), ``::ffff:a.b.c.d`` (mapped) and NAT64
    ``64:ff9b::a.b.c.d`` reach the embedded IPv4 address, so that address
    decides; multicast and the deprecated IPv6 site-local range are refused
    although :attr:`is_global` accepts them.
    """
    if isinstance(address, ipaddress.IPv6Address):
        embedded: ipaddress.IPv4Address | None = address.ipv4_mapped or address.sixtofour
        if embedded is None and (address in _NAT64_PREFIX or address in _IPV4_COMPATIBLE):
            embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        if embedded is not None and not _public_address(embedded):
            return False
        if address.is_site_local:
            return False
    return address.is_global and not address.is_multicast


def validate_website_icon_origin(
    origin: str,
    *,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
    resolve: bool = True,
) -> str:
    """Return the canonical HTTPS origin allowed for an explicit icon action."""

    if not isinstance(origin, str) or len(origin) > 2048:
        raise UnsafeIconOrigin("Website origin is invalid")
    try:
        canonical = canonicalize_origin(origin, allow_local_http=False)
    except (OriginError, ValueError) as exc:
        raise UnsafeIconOrigin(str(exc)) from exc
    parsed = urlsplit(canonical)
    host = parsed.hostname
    if not host or "/" in host or parsed.username or parsed.password:
        raise UnsafeIconOrigin("Website origin is invalid")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        raise UnsafeIconOrigin("IP-literal website origins are not allowed")
    port = parsed.port or 443
    if resolve:
        _public_addresses(host, port, deadline=deadline, cancel_event=cancel_event)
    return canonical


def safe_icon_url(
    origin: str,
    *,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
    resolve: bool = True,
) -> str | None:
    """Return the one permitted URL, or ``None`` for an unsafe origin."""

    try:
        canonical = validate_website_icon_origin(
            origin, deadline=deadline, cancel_event=cancel_event, resolve=resolve)
    except (UnsafeIconOrigin, TimeoutError, ValueError, OSError):
        return None
    return canonical.rstrip("/") + "/favicon.ico"


def is_safe_icon_origin(origin: str) -> bool:
    return safe_icon_url(origin) is not None


@dataclass(frozen=True)
class CachedIcon:
    """A normalized source image and its bounded memory accounting."""

    image: Any
    size_bytes: int


@dataclass(frozen=True)
class IconResult:
    """One completed visible-row request, published by the UI polling thread."""

    request_id: str
    key: str
    origin: str
    profile_id: str | None
    generation: object
    image: Any | None = None
    error: BaseException | None = None
    stale: bool = False


@dataclass
class _IconJob:
    request_id: str
    key: str
    origin: str
    profile_id: str | None
    generation: object
    cancel_event: threading.Event
    lifecycle: int
    future: Future[Any] | None = None


class IconCache:
    """Small LRU cache bounded by both source count and decoded memory."""

    def __init__(self, *, max_sources: int = MAX_CACHED_SOURCES,
                 max_bytes: int = MAX_CACHE_BYTES) -> None:
        if max_sources <= 0 or max_bytes <= 0:
            raise ValueError("icon cache limits must be positive")
        self.max_sources = min(int(max_sources), MAX_CACHED_SOURCES)
        self.max_bytes = min(int(max_bytes), MAX_CACHE_BYTES)
        self._items: OrderedDict[str, CachedIcon] = OrderedDict()
        self._bytes = 0
        self._lock = threading.RLock()

    @property
    def bytes_used(self) -> int:
        with self._lock:
            return self._bytes

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def get(self, key: str) -> CachedIcon | None:
        with self._lock:
            value = self._items.get(str(key))
            if value is not None:
                self._items.move_to_end(str(key))
            return value

    def put(self, key: str, image: Any, *, size_bytes: int | None = None) -> bool:
        key = str(key)
        if size_bytes is None:
            size_bytes = _image_memory_size(image)
        size_bytes = int(size_bytes)
        if size_bytes <= 0 or size_bytes > self.max_bytes:
            return False
        with self._lock:
            old = self._items.pop(key, None)
            if old is not None:
                self._bytes -= old.size_bytes
            self._items[key] = CachedIcon(image, size_bytes)
            self._bytes += size_bytes
            while len(self._items) > self.max_sources or self._bytes > self.max_bytes:
                _evicted_key, evicted = self._items.popitem(last=False)
                self._bytes -= evicted.size_bytes
            return key in self._items

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._bytes = 0


def _image_memory_size(image: Any) -> int:
    width, height = getattr(image, "size", (0, 0))
    try:
        return max(0, int(width) * int(height) * 4)
    except (TypeError, ValueError):
        return 0


_ICO_MAGIC = b"\x00\x00\x01\x00"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_MAX_ICO_ENTRIES = 64


def _check_ico_entries(data: bytes) -> None:
    """Refuse an ICO whose embedded images are larger than the icon limits.

    Pillow trusts the directory sizes (at most 256 px) but decodes the
    embedded PNG or DIB at its own size, so a 10 KiB file claiming 16x16 can
    expand to over 100 MiB.  Every entry's real dimensions are read from its
    PNG IHDR or DIB header first.
    """
    if len(data) < 6:
        raise IconDecodeError("Website icon is truncated")
    count = int.from_bytes(data[4:6], "little")
    if not 1 <= count <= _MAX_ICO_ENTRIES or len(data) < 6 + 16 * count:
        raise IconDecodeError("Website icon directory is malformed")
    for index in range(count):
        entry = data[6 + 16 * index:22 + 16 * index]
        size = int.from_bytes(entry[8:12], "little")
        offset = int.from_bytes(entry[12:16], "little")
        if size <= 0 or offset < 6 + 16 * count or offset + size > len(data):
            raise IconDecodeError("Website icon directory is malformed")
        image = data[offset:offset + size]
        if image[:8] == _PNG_MAGIC:
            if len(image) < 24:
                raise IconDecodeError("Website icon is truncated")
            width, height = int.from_bytes(image[16:20], "big"), int.from_bytes(image[20:24], "big")
        else:
            if len(image) < 12:
                raise IconDecodeError("Website icon is truncated")
            width = abs(int.from_bytes(image[4:8], "little", signed=True))
            height = abs(int.from_bytes(image[8:12], "little", signed=True)) // 2  # XOR + AND masks
        if not 0 < width <= MAX_ICON_DIMENSION or not 0 < height <= MAX_ICON_DIMENSION \
                or width * height > MAX_ICON_PIXELS:
            raise IconDecodeError("Website icon dimensions exceed the limit")


def _decode_image(data: bytes) -> Any:
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0 or len(data) > MAX_DOWNLOAD_BYTES:
        raise IconDecodeError("Icon response exceeds the size limit")
    try:
        from PIL import Image
    except Exception as exc:  # pragma: no cover - Pillow is optional off Windows
        raise IconDecodeError("Native image decoding is unavailable") from exc
    try:
        if bytes(data[:4]) == _ICO_MAGIC:
            _check_ico_entries(bytes(data))
        # Only the three icon formats are even attempted; no other Pillow plugin parses website bytes.
        probe = Image.open(io.BytesIO(bytes(data)), formats=("PNG", "JPEG", "ICO"))
        if probe.format not in {"PNG", "JPEG", "ICO"}:
            raise IconDecodeError("Website icon format is unsupported")
        width, height = probe.size
        if width <= 0 or height <= 0 or width > MAX_ICON_DIMENSION or height > MAX_ICON_DIMENSION:
            raise IconDecodeError("Website icon dimensions exceed the limit")
        if width * height > MAX_ICON_PIXELS:
            raise IconDecodeError("Website icon pixel count exceeds the limit")
        # Animated images are not a safe bounded source for a static row icon.
        if getattr(probe, "n_frames", 1) != 1:
            raise IconDecodeError("Animated website icons are unsupported")
        image = probe.convert("RGBA")
        image.thumbnail((MAX_RETAINED_DIMENSION, MAX_RETAINED_DIMENSION), Image.Resampling.LANCZOS)
        return image
    except IconDecodeError:
        raise
    except Exception as exc:
        raise IconDecodeError("Website icon could not be decoded") from exc


def _read_bounded(response: Any, *, deadline: float,
                  cancel_event: threading.Event | None = None) -> bytes:
    content_length = response.getheader("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_DOWNLOAD_BYTES:
                raise IconDecodeError("Website icon response exceeds the size limit")
        except ValueError as exc:
            raise IconDecodeError("Website icon response length is invalid") from exc
    chunks: list[bytes] = []
    total = 0
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise TimeoutError("Website icon download cancelled")
        remaining = deadline - _monotonic()
        if remaining <= 0:
            raise TimeoutError("Website icon download timed out")
        try:
            response.fp.raw._sock.settimeout(remaining)  # type: ignore[attr-defined]
        except Exception:
            pass
        chunk = response.read(min(32 * 1024, MAX_DOWNLOAD_BYTES + 1 - total))
        if _monotonic() >= deadline:
            raise TimeoutError("Website icon download timed out")
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_DOWNLOAD_BYTES:
            raise IconDecodeError("Website icon response exceeds the size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _monotonic() -> float:
    import time
    return time.monotonic()


def fetch_website_icon(origin: str, *, cancel_event: threading.Event | None = None) -> Any:
    """Fetch one favicon over a pinned, public HTTPS connection.

    It is reached from the item list (``app.icons.IconProvider``) only when
    the person turned on "Show website icons" and strict offline mode is off;
    never by default, and never from search, unlock, hover, or selection
    alone.  Each call tells the site that this vault has an account there.
    It follows no redirects and sends no cookies, referrer, proxy
    credentials, or authentication headers.
    """

    deadline = _monotonic() + MAX_DOWNLOAD_SECONDS
    # Resolve once below after lexical origin validation.  ``safe_icon_url``
    # keeps its public validation semantics for ordinary callers.
    url = safe_icon_url(
        origin, deadline=deadline, cancel_event=cancel_event, resolve=False)
    if url is None:
        raise UnsafeIconOrigin("Website origin is not eligible for icon download")
    parsed = urlsplit(url)
    host = parsed.hostname
    assert host is not None
    port = parsed.port or 443
    addresses = _public_addresses(host, port, deadline=deadline, cancel_event=cancel_event)
    if cancel_event is not None and cancel_event.is_set():
        raise TimeoutError("Website icon download cancelled")
    last_error: Exception | None = None
    for family, address in addresses:
        if _monotonic() >= deadline:
            break
        if cancel_event is not None and cancel_event.is_set():
            raise TimeoutError("Website icon download cancelled")
        sock: socket.socket | None = None
        conn: http.client.HTTPSConnection | None = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(max(0.01, deadline - _monotonic()))
            sock.connect((address, port))
            context = ssl.create_default_context()
            wrapped = context.wrap_socket(sock, server_hostname=host)
            sock = None
            conn = http.client.HTTPSConnection(host, port, timeout=max(0.01, deadline - _monotonic()), context=context)
            conn.sock = wrapped
            conn.request("GET", "/favicon.ico", headers={"Host": parsed.netloc, "Accept": "image/png,image/jpeg,image/x-icon"})
            if _monotonic() >= deadline:
                raise TimeoutError("Website icon download timed out")
            response = conn.getresponse()
            if _monotonic() >= deadline:
                raise TimeoutError("Website icon download timed out")
            if cancel_event is not None and cancel_event.is_set():
                raise TimeoutError("Website icon download cancelled")
            if response.status < 200 or response.status >= 300:
                raise IconDecodeError("Website icon request was not successful")
            content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type and content_type not in {"image/png", "image/jpeg", "image/x-icon", "image/vnd.microsoft.icon"}:
                raise IconDecodeError("Website response is not an icon")
            data = _read_bounded(response, deadline=deadline, cancel_event=cancel_event)
            return _decode_image(data)
        except (IconDecodeError, UnsafeIconOrigin, TimeoutError):
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    raise TimeoutError("Website icon download failed safely") from last_error


def _is_local_windows_path(path: str | Path) -> bool:
    """Reject network/device paths before touching the filesystem.

    ``ExtractIconExW`` is a presentation helper, so a saved path must never
    turn an offline row render into a UNC/SMB probe.  Keep the lexical checks
    ahead of ``Path.is_file``/``stat`` and only accept a normal local drive.
    Reparse points are rejected as well because a local symlink/junction can
    otherwise resolve to a remote target after the drive check.
    """

    try:
        raw = os.fspath(path)
    except TypeError:
        return False
    if not isinstance(raw, str) or not raw:
        return False
    normalized = raw.replace("/", "\\")
    normalized_casefold = normalized.casefold()
    # UNC, Win32 device namespaces and NT object-manager paths are all
    # rejected without asking Windows to resolve them.
    if (
        normalized_casefold.startswith("\\\\")
        or normalized_casefold.startswith("\\??\\")
        or normalized_casefold.startswith("\\device\\")
        or normalized_casefold.startswith("\\globalroot\\")
    ):
        return False
    # Requiring an absolute drive path also prevents the process working
    # directory from being a hidden network share.
    if len(normalized) < 3 or normalized[1] != ":" or normalized[2] != "\\":
        return False
    drive_root = normalized[:3]
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        # DRIVE_REMOVABLE, DRIVE_FIXED and DRIVE_RAMDISK are local media.
        if int(get_drive_type(drive_root)) not in {2, 3, 6}:
            return False
        get_attributes = kernel32.GetFileAttributesW
        get_attributes.argtypes = [ctypes.c_wchar_p]
        get_attributes.restype = ctypes.c_uint32
        # Inspect every component before the final ``Path.is_file`` call.
        # A junction in a parent directory can redirect an otherwise local
        # drive into a remote target.
        current = drive_root.rstrip("\\")
        for component in normalized[3:].split("\\"):
            if not component:
                continue
            current += "\\" + component
            attributes = int(get_attributes(current))
            if attributes == 0xFFFFFFFF or attributes & 0x400:  # INVALID / REPARSE
                return False
    except Exception:
        return False
    return True


_VERSION_FOLDER = re.compile(r"^app-(\d+(?:\.\d+)*)$", re.IGNORECASE)


def current_versioned_executable(path: str | Path) -> str | Path:
    """Follow apps that install each update into a new ``app-<version>`` folder.

    Discord, Slack, Teams classic and other Squirrel-installed apps delete the
    old folder after updating, so a saved ``...\\app-1.0.9259\\Discord.exe``
    stops existing. When the saved file is gone, return the same executable
    from the newest sibling version folder; otherwise return ``path`` as is.
    Only a local, non-reparse parent folder is ever listed.
    """
    try:
        saved = Path(path)
        version_dir = saved.parent
        if not _VERSION_FOLDER.match(version_dir.name):
            return path
        install_root = version_dir.parent
        if not _is_local_windows_path(install_root):
            return path
        if _is_local_windows_path(saved) and saved.is_file():
            return path
        versions = []
        for child in install_root.iterdir():
            match = _VERSION_FOLDER.match(child.name)
            if match and child.is_dir() and (child / saved.name).is_file():
                versions.append((tuple(int(part) for part in match.group(1).split(".")), child / saved.name))
        return max(versions)[1] if versions else path
    except (OSError, ValueError, TypeError):
        return path


def extract_desktop_icon(path: str | Path, *, size: int = 22) -> Any | None:
    """Extract a bounded icon resource without executing the target file.

    ``ExtractIconExW`` asks the Windows shell for the image resource and does
    not launch the executable.  Every HICON, HBITMAP and temporary screen DC
    acquired below is released in ``finally``.  Any missing API, unreadable
    resource, optional Pillow dependency, or malformed bitmap returns the
    canonical fallback path's ``None`` signal.
    """

    if os.name != "nt":
        return None
    path = current_versioned_executable(path)
    # This must happen before ``Path.is_file`` or ``Path.stat``.  In
    # particular, a UNC path can block while Windows probes an SMB host.
    if not _is_local_windows_path(path):
        return None
    candidate = Path(path)
    try:
        if not candidate.is_file() or candidate.stat().st_size <= 0:
            return None
        target_size = max(8, min(MAX_RETAINED_DIMENSION, int(size)))
    except (OSError, TypeError, ValueError):
        return None

    try:
        from PIL import Image
    except Exception:
        return None

    hicon_large = ctypes.c_void_p()
    hicon_small = ctypes.c_void_p()
    icon_handles: list[int] = []
    icon_info = None
    hdc = None
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

        extracted = shell32.ExtractIconExW(
            str(candidate), 0, ctypes.byref(hicon_large), ctypes.byref(hicon_small), 1
        )
        if not extracted:
            return None
        for handle in (hicon_large.value, hicon_small.value):
            if handle:
                icon_handles.append(int(handle))
        if not icon_handles:
            return None
        selected = hicon_small.value if target_size <= 32 and hicon_small.value else hicon_large.value
        selected = selected or hicon_small.value or hicon_large.value
        if not selected:
            return None

        class _ICONINFO(ctypes.Structure):
            _fields_ = [
                ("fIcon", ctypes.c_uint32),
                ("xHotspot", ctypes.c_uint32),
                ("yHotspot", ctypes.c_uint32),
                ("hbmMask", ctypes.c_void_p),
                ("hbmColor", ctypes.c_void_p),
            ]

        class _BITMAP(ctypes.Structure):
            _fields_ = [
                ("bmType", ctypes.c_long),
                ("bmWidth", ctypes.c_long),
                ("bmHeight", ctypes.c_long),
                ("bmWidthBytes", ctypes.c_long),
                ("bmPlanes", ctypes.c_ushort),
                ("bmBitsPixel", ctypes.c_ushort),
                ("bmBits", ctypes.c_void_p),
            ]

        class _BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [
                ("biSize", ctypes.c_uint32),
                ("biWidth", ctypes.c_int32),
                ("biHeight", ctypes.c_int32),
                ("biPlanes", ctypes.c_uint16),
                ("biBitCount", ctypes.c_uint16),
                ("biCompression", ctypes.c_uint32),
                ("biSizeImage", ctypes.c_uint32),
                ("biXPelsPerMeter", ctypes.c_int32),
                ("biYPelsPerMeter", ctypes.c_int32),
                ("biClrUsed", ctypes.c_uint32),
                ("biClrImportant", ctypes.c_uint32),
            ]

        class _RGBQUAD(ctypes.Structure):
            _fields_ = [
                ("rgbBlue", ctypes.c_ubyte), ("rgbGreen", ctypes.c_ubyte),
                ("rgbRed", ctypes.c_ubyte), ("rgbReserved", ctypes.c_ubyte),
            ]

        class _BITMAPINFO(ctypes.Structure):
            _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", _RGBQUAD * 1)]

        # ctypes defaults to a C ``int`` return type and no argument
        # conversion.  Explicit pointer-width signatures avoid truncating
        # HICON/HBITMAP/HDC values on 64-bit Windows and make cleanup reliable.
        shell32.ExtractIconExW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint,
        ]
        shell32.ExtractIconExW.restype = ctypes.c_uint
        user32.GetIconInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ICONINFO)]
        user32.GetIconInfo.restype = ctypes.c_int
        user32.GetDC.argtypes = [ctypes.c_void_p]
        user32.GetDC.restype = ctypes.c_void_p
        user32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        user32.ReleaseDC.restype = ctypes.c_int
        user32.DestroyIcon.argtypes = [ctypes.c_void_p]
        user32.DestroyIcon.restype = ctypes.c_int
        gdi32.GetObjectW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        gdi32.GetObjectW.restype = ctypes.c_int
        gdi32.GetDIBits.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
        ]
        gdi32.GetDIBits.restype = ctypes.c_int
        gdi32.DeleteObject.argtypes = [ctypes.c_void_p]
        gdi32.DeleteObject.restype = ctypes.c_int

        icon_info = _ICONINFO()
        if not user32.GetIconInfo(ctypes.c_void_p(selected), ctypes.byref(icon_info)):
            return None
        color_bitmap = icon_info.hbmColor
        if not color_bitmap:
            return None
        bitmap = _BITMAP()
        if not gdi32.GetObjectW(color_bitmap, ctypes.sizeof(bitmap), ctypes.byref(bitmap)):
            return None
        width = abs(int(bitmap.bmWidth))
        height = abs(int(bitmap.bmHeight))
        if width <= 0 or height <= 0 or width > MAX_ICON_DIMENSION or height > MAX_ICON_DIMENSION:
            return None
        if width * height > MAX_ICON_PIXELS:
            return None

        info = _BITMAPINFO()
        info.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
        info.bmiHeader.biWidth = width
        # A negative height asks GDI for a top-down buffer and avoids a second
        # full-size image allocation for row inversion.
        info.bmiHeader.biHeight = -height
        info.bmiHeader.biPlanes = 1
        info.bmiHeader.biBitCount = 32
        info.bmiHeader.biCompression = 0  # BI_RGB
        pixels = (ctypes.c_ubyte * (width * height * 4))()
        hdc = user32.GetDC(None)
        if not hdc:
            return None
        copied = gdi32.GetDIBits(
            hdc, color_bitmap, 0, height, pixels, ctypes.byref(info), 0
        )
        if copied != height:
            return None
        image = Image.frombuffer("RGBA", (width, height), bytes(pixels), "raw", "BGRA", 0, 1).copy()
        resampling = getattr(Image, "Resampling", None)
        image.thumbnail((target_size, target_size), getattr(resampling, "LANCZOS", getattr(Image, "LANCZOS", 1)))
        return image
    except Exception:
        return None
    finally:
        if hdc:
            try:
                user32.ReleaseDC(None, hdc)  # type: ignore[name-defined]
            except Exception:
                pass
        if icon_info is not None:
            try:
                for bitmap_handle in (icon_info.hbmColor, icon_info.hbmMask):
                    if bitmap_handle:
                        gdi32.DeleteObject(bitmap_handle)  # type: ignore[name-defined]
            except Exception:
                pass
        try:
            for handle in icon_handles:
                user32.DestroyIcon(ctypes.c_void_p(handle))  # type: ignore[name-defined]
        except Exception:
            pass


def _normalise_origin_key(origin: str | None) -> str:
    """Canonicalise an origin for cache identity without doing DNS work."""

    value = str(origin or "")
    try:
        return canonicalize_origin(value, allow_local_http=False)
    except (OriginError, TypeError, ValueError):
        # Unsafe values are never fetched, but retaining a stable memory key
        # lets the row use the fallback without raising during listing.
        return value.strip().casefold()


def _normalise_executable_key(executable: str | None) -> str:
    try:
        value = os.fspath(executable) if executable else ""
    except TypeError:
        value = str(executable or "")
    if not isinstance(value, str):
        value = os.fsdecode(value)
    if not value:
        return ""
    # Cache-key construction must never touch the filesystem.  In particular,
    # source_for() can be called while rendering an offline row whose saved
    # executable is a UNC/device path.  Extraction performs the local-drive
    # and reparse checks before any stat/is_file operation.
    return value.replace("/", "\\").casefold()
