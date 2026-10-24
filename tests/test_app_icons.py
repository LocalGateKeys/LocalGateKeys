"""Icons for the item list: desktop app icons always, website icons only when strict offline mode is off."""
from __future__ import annotations

import threading
import time

from PIL import Image

from localvault.app.icons import IconProvider


def _wait(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    return predicate()


def test_a_desktop_app_icon_is_looked_up_once_then_served(tmp_path):
    calls, ready = [], threading.Event()
    provider = IconProvider(offline=lambda: True, on_ready=ready.set,
                            extract=lambda path, size: calls.append(path) or Image.new("RGBA", (32, 32), "red"),
                            fetch=lambda origin: None)
    assert provider.desktop(r"C:\Apps\example.exe") is None  # looked up in the background
    assert ready.wait(2)
    icon = provider.desktop(r"C:\Apps\example.exe")
    assert icon.startswith("data:image/png;base64,") and calls == [r"C:\Apps\example.exe"]


def test_website_icons_wait_for_strict_offline_mode_to_be_off():
    offline = [True]
    fetched = []
    provider = IconProvider(offline=lambda: offline[0], on_ready=lambda: None,
                            extract=lambda path, size: None,
                            fetch=lambda origin: fetched.append(origin) or Image.new("RGBA", (64, 64), "blue"))
    assert provider.website("https://example.com") is None
    time.sleep(0.1)
    assert fetched == []  # no network request in strict offline mode
    offline[0] = False
    provider.website("https://example.com")
    assert _wait(lambda: provider.website("https://example.com") is not None)
    assert fetched == ["https://example.com"]


def test_a_failed_lookup_is_not_retried_until_cleared():
    calls = []

    def broken(origin):
        calls.append(origin)
        raise TimeoutError("no answer")
    provider = IconProvider(offline=lambda: False, on_ready=lambda: None, extract=lambda p, s: None, fetch=broken)
    provider.website("https://slow.test")
    assert _wait(lambda: len(calls) == 1)
    time.sleep(0.05)
    assert provider.website("https://slow.test") is None and len(calls) == 1
    provider.clear()
    provider.website("https://slow.test")
    assert _wait(lambda: len(calls) == 2)


def test_a_burst_of_icons_refreshes_the_list_once():
    ready = []
    provider = IconProvider(offline=lambda: True, on_ready=lambda: ready.append(1),
                            extract=lambda path, size: Image.new("RGBA", (32, 32), "red"), fetch=lambda o: None)
    for n in range(5):
        provider.desktop(rf"C:\Apps\app{n}.exe")
    time.sleep(0.8)
    assert ready == [1]
