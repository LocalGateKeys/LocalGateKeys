"""``localgatekeys://install-licence/LGK1-...`` links: install a Pro licence from the licence page.

The licence page's "Install in LocalGateKeys" button opens this link; Windows starts
``LocalGateKeys.exe <link>``. The key is verified like a pasted one and installed only
after the user confirms. The worst a crafted link can do is offer a genuine, signed
licence, so nothing in the link is trusted beyond what the signature proves.

An app that is already running is told through a named event; it re-applies the plan.
"""
from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote

from . import licensing

_log = logging.getLogger(__name__)

SCHEME = "localgatekeys"
INSTALL_PREFIX = f"{SCHEME}://install-licence/"
# A licence key is well under 2 KB; anything far larger is not one.
MAX_LINK_CHARS = 16_384
EVENT_NAME = "Local\\LocalGateKeys.LicenceInstalled"


def _bad_link() -> licensing.LicenseError:
    return licensing.LicenseError("This is not a LocalGateKeys licence link.", reason="bad-link")


def find_link(args: list[str]) -> str | None:
    """The first ``localgatekeys:`` argument, if any."""
    for arg in args:
        if isinstance(arg, str) and arg.lower().startswith(f"{SCHEME}:"):
            return arg
    return None


def key_from_link(link: str) -> str:
    """The ``LGK1-`` key in an install link; raises ``LicenseError`` for anything else."""
    if not isinstance(link, str) or len(link) > MAX_LINK_CHARS:
        raise _bad_link()
    if not link.lower().startswith(INSTALL_PREFIX):
        raise _bad_link()
    key = unquote(link[len(INSTALL_PREFIX):]).strip().rstrip("/")
    if not key.startswith(licensing.PASTE_PREFIX):
        raise _bad_link()
    return key


@dataclass(frozen=True)
class Offer:
    key: str
    license: licensing.License
    replaces: licensing.License | None


def offer_from_link(link: str) -> Offer:
    """Parse and verify the link's licence without installing it."""
    key = key_from_link(link)
    lic = licensing.verify_bundle(licensing.parse_license_text(key))
    current = None
    try:
        installed = licensing.installed_bundle()
        if installed is not None:
            current = licensing.verify_bundle(installed)
    except Exception:  # noqa: BLE001 - an unreadable current licence is simply replaced
        current = None
    if current is not None and current.license_id == lic.license_id:
        current = None  # the same licence again: nothing is replaced
    return Offer(key=key, license=lic, replaces=current)


def _holder(lic: licensing.License) -> str:
    return lic.email if lic.name == lic.email else f"{lic.name} ({lic.email})"


def question(offer: Offer) -> str:
    text = f"Install the LocalGateKeys Pro licence for {_holder(offer.license)} on this device?"
    if offer.replaces is not None:
        text += f"\n\nThis replaces the licence for {_holder(offer.replaces)}."
    return text


def handle(link: str, ask: Callable[[str], bool], tell: Callable[[str], None]) -> bool:
    """Verify, confirm and install. Returns True when a licence was installed."""
    try:
        offer = offer_from_link(link)
    except licensing.LicenseError as exc:
        tell(f"The licence could not be installed: {exc}")
        return False
    if not ask(question(offer)):
        return False
    try:
        licensing.install_license(offer.key)
    except Exception:  # noqa: BLE001
        _log.warning("Licence from link could not be installed", exc_info=True)
        tell("The licence could not be installed. Open LocalGateKeys and paste the key from your licence page.")
        return False
    return True


# ------------------------------------------------------------ running-app signal
def signal_running_app() -> None:
    """Tell an already-running LocalGateKeys that a licence was installed (no-op if none listens)."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenEventW.restype = wintypes.HANDLE
    kernel32.SetEvent.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    event_modify_state = 0x0002
    handle = kernel32.OpenEventW(event_modify_state, False, EVENT_NAME)
    if handle:
        kernel32.SetEvent(handle)
        kernel32.CloseHandle(handle)


def watch_for_installs(on_install: Callable[[], None]) -> None:
    """Start a daemon thread that calls ``on_install`` each time another process installs a licence."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    handle = kernel32.CreateEventW(None, False, False, EVENT_NAME)  # auto-reset
    if not handle:
        _log.warning("Licence install signal not available")
        return

    def loop() -> None:
        infinite, signalled = 0xFFFFFFFF, 0
        while kernel32.WaitForSingleObject(handle, infinite) == signalled:
            try:
                on_install()
            except Exception:  # noqa: BLE001 - one failed refresh never stops the watcher
                _log.warning("Licence install refresh failed", exc_info=True)

    threading.Thread(target=loop, name="licence-link-watch", daemon=True).start()
