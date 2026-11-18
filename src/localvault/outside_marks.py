"""Small records kept outside the vault folder, so restoring or deleting that folder does not undo them.

Two users (audit 2026-11-10): the unlock throttle's high-water mark (``vault.UnlockThrottle``) and the copy of a
duress hold (``duress.trip``).  On Windows the values live in ``HKCU\\Software\\LocalGateKeys\\Marks`` (REG_SZ,
one per vault and purpose; the name is a hash of the purpose and the vault's absolute path, so it names no
folder).  Elsewhere there is no store: reads find nothing and writes are skipped, so the callers fall back to
their files.  Someone who can edit this Windows user's registry can still delete or change these values: the
same-user limit in ``SECURITY.md``.

Tests install a ``MemoryBackend`` (``tests/conftest.py``) and never touch the real registry.  So do the processes
they start, and the test-only scripts: ``LOCALGATEKEYS_OUTSIDE_MARKS=memory`` (set by tests/conftest.py for the
whole run) makes the store an in-memory one from the start.  Only that exact value, set explicitly, does it, and
only when running from source: a packaged (frozen) build ignores it.  The app never sets it.  (Whoever can set this user's environment can also delete the registry values: the same-user
limit above.)
"""
from __future__ import annotations

import hashlib
import os
import sys
import threading
from pathlib import Path
from typing import Protocol

__all__ = ["Backend", "MemoryBackend", "WindowsRegistry", "REGISTRY_KEY", "MAX_VALUE", "name_for", "read", "write",
           "delete", "set_backend", "backend", "name_for_id", "MEMORY_ENV"]

REGISTRY_KEY = r"Software\LocalGateKeys\Marks"
#: Tests and test-only scripts: ``memory`` keeps every value in this process (``MemoryBackend``).
MEMORY_ENV = "LOCALGATEKEYS_OUTSIDE_MARKS"
#: Longer values are not written, and are read as malformed.
MAX_VALUE = 4096


class Backend(Protocol):
    def read(self, name: str) -> str | None:
        """The value, or None when there is none; raises OSError when it cannot be read."""

    def write(self, name: str, value: str) -> None:
        """Store ``value``; raises OSError on failure."""

    def delete(self, name: str) -> None:
        """Remove the value (nothing when there is none); raises OSError on failure."""


class WindowsRegistry:
    """HKCU values under ``REGISTRY_KEY``.  In an MSIX package new HKCU keys are written unvirtualized
    (build-msix/AppxManifest.xml.in); either way this app reads back what it wrote."""

    def __init__(self, key: str = REGISTRY_KEY) -> None:
        self.key = key

    def read(self, name: str) -> str | None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key) as handle:
                value, kind = winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return None
        # Another type than a string is not ours: read it as malformed, never as missing.
        return value if kind == winreg.REG_SZ and isinstance(value, str) else ""

    def write(self, name: str, value: str) -> None:
        import winreg

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.key) as handle:
            winreg.SetValueEx(handle, name, 0, winreg.REG_SZ, value)

    def delete(self, name: str) -> None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key, 0, winreg.KEY_SET_VALUE) as handle:
                winreg.DeleteValue(handle, name)
        except FileNotFoundError:
            return


class MemoryBackend:
    """A dict standing in for the registry (tests).  ``fail_reads`` / ``fail_writes`` raise OSError."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail_reads = False
        self.fail_writes = False

    def read(self, name: str) -> str | None:
        if self.fail_reads:
            raise OSError("registry unreadable (test)")
        return self.values.get(name)

    def write(self, name: str, value: str) -> None:
        if self.fail_writes:
            raise OSError("registry not writable (test)")
        self.values[name] = value

    def delete(self, name: str) -> None:
        if self.fail_writes:
            raise OSError("registry not writable (test)")
        self.values.pop(name, None)


def _default_backend() -> Backend | None:
    # Only when running from source (tests, test-only scripts): a packaged build never turns its marks off.
    if os.environ.get(MEMORY_ENV) == "memory" and not getattr(sys, "frozen", False):
        return MemoryBackend()
    return WindowsRegistry() if sys.platform == "win32" else None


_LOCK = threading.Lock()
_BACKEND: Backend | None = _default_backend()


def set_backend(new: Backend | None) -> Backend | None:
    """Install another store (tests); returns the previous one."""
    global _BACKEND
    with _LOCK:
        previous, _BACKEND = _BACKEND, new
    return previous


def backend() -> Backend | None:
    return _BACKEND


def name_for(purpose: str, vault_path: Path | str) -> str:
    """The value name for ``purpose`` and the vault at ``vault_path`` (its absolute, case-folded path)."""
    text = os.path.normcase(str(Path(vault_path).absolute()))
    digest = hashlib.sha256(b"localgatekeys|outside-mark|v1|" + purpose.encode("ascii") + b"|"
                            + text.encode("utf-8")).hexdigest()[:32]
    return f"{purpose}-{digest}"


def name_for_id(purpose: str, identifier: str) -> str:
    """The value name for ``purpose`` and an identifier that does not depend on where the vault sits (its
    vault id), so a copy opened from another folder finds the same value."""
    digest = hashlib.sha256(b"localgatekeys|outside-mark-id|v1|" + purpose.encode("ascii") + b"|"
                            + identifier.encode("utf-8")).hexdigest()[:32]
    return f"{purpose}-{digest}"


def read(name: str) -> str | None:
    """The stored value, or None when there is none (or no store); raises OSError when it cannot be read."""
    store = _BACKEND
    if store is None:
        return None
    value = store.read(name)
    if value is not None and len(value) > MAX_VALUE:
        return ""
    return value


def write(name: str, value: str) -> bool:
    """Best effort: False when there is no store or the write failed."""
    store = _BACKEND
    if store is None or len(value) > MAX_VALUE:
        return False
    try:
        store.write(name, value)
    except OSError:
        return False
    return True


def delete(name: str) -> bool:
    """Best effort: False when there is no store or the delete failed."""
    store = _BACKEND
    if store is None:
        return False
    try:
        store.delete(name)
    except OSError:
        return False
    return True
