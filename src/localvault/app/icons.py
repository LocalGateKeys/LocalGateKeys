"""Icons for the item list, looked up in the background and kept in memory only (never in the vault).

* Desktop logins show their app's own icon, read from the executable's resources (no network, the app
  is never started; network and device paths are refused before any file access).
* Website logins show the icon the browser extension captured; without one, and while "Show website
  icons" (``website_icons``, off by default) is on and strict offline mode is off, the site's favicon
  is fetched over a pinned public HTTPS connection. Each fetch tells that site (and the network) that
  the vault has an account there, and nothing else: no username, password or vault data is sent.
"""
from __future__ import annotations

import base64
import io
import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .. import item_icons

_log = logging.getLogger(__name__)
ICON_SIZE = 32
_FAILED = ""  # remembered failure: not retried until cleared (lock, profile switch, offline change)


def _data_url(image: Any) -> str | None:
    if image is None:
        return None
    try:
        from PIL import Image

        image = image.convert("RGBA")
        if image.size != (ICON_SIZE, ICON_SIZE):
            image.thumbnail((ICON_SIZE, ICON_SIZE), Image.Resampling.LANCZOS)
        out = io.BytesIO()
        image.save(out, format="PNG", optimize=True)
        return "data:image/png;base64," + base64.b64encode(out.getvalue()).decode("ascii")
    except Exception:  # noqa: BLE001 - a broken icon just shows the logo or kind tile
        return None


class IconProvider:
    def __init__(self, *, offline: Callable[[], bool], on_ready: Callable[[], None],
                 extract: Callable[..., Any] = item_icons.extract_desktop_icon,
                 fetch: Callable[[str], Any] = item_icons.fetch_website_icon,
                 website_icons: Callable[[], bool] | None = None) -> None:
        self._offline = offline
        # The "Show website icons" setting. None leaves the gate to the caller
        # (HomeService checks the setting before asking for a website icon).
        self._website_icons = website_icons
        self._on_ready = on_ready
        self._extract = extract
        self._fetch = fetch
        self._lock = threading.Lock()
        self._icons: dict[tuple[str, str], str] = {}
        self._pending: set[tuple[str, str]] = set()
        self._generation = 0
        self._pool = ThreadPoolExecutor(max_workers=item_icons.MAX_IN_FLIGHT, thread_name_prefix="lgk-icons")
        self._notify_timer: threading.Timer | None = None

    def desktop(self, executable: str | None) -> str | None:
        key = item_icons._normalise_executable_key(executable)
        return self._get(("desktop", key), lambda: self._extract(executable, size=ICON_SIZE)) if key else None

    def website(self, origin: str | None) -> str | None:
        key = item_icons._normalise_origin_key(origin)
        if not key or self._offline():
            return None
        if self._website_icons is not None and not self._website_icons():
            return None
        return self._get(("web", key), lambda: self._fetch(key))

    def clear(self) -> None:
        with self._lock:
            self._generation += 1
            self._icons.clear()
            self._pending.clear()

    def _get(self, key: tuple[str, str], load: Callable[[], Any]) -> str | None:
        with self._lock:
            if key in self._icons:
                return self._icons[key] or None
            if key in self._pending:
                return None
            self._pending.add(key)
            generation = self._generation
        self._pool.submit(self._load, key, load, generation)
        return None

    def _load(self, key: tuple[str, str], load: Callable[[], Any], generation: int) -> None:
        try:
            url = _data_url(load())
        except Exception:  # noqa: BLE001 - unreachable site, unsafe origin, unreadable resource
            _log.debug("Icon lookup failed for %s", key[0], exc_info=True)
            url = None
        with self._lock:
            if generation != self._generation:
                return  # cleared meanwhile (lock, switch): drop the result
            self._pending.discard(key)
            self._icons[key] = url or _FAILED
        if url:
            self._notify()

    def _notify(self) -> None:
        """One list refresh for a burst of arriving icons."""
        with self._lock:
            if self._notify_timer is not None:
                return
            timer = self._notify_timer = threading.Timer(0.3, self._fire)
            timer.daemon = True
        timer.start()

    def _fire(self) -> None:
        with self._lock:
            self._notify_timer = None
        try:
            self._on_ready()
        except Exception:  # noqa: BLE001
            pass
