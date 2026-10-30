from __future__ import annotations

import ctypes
import os
import re
import threading
from collections.abc import Callable
from ctypes import wintypes


class HotkeyListener:
    """Register explicit Windows hotkeys using RegisterHotKey, never a key hook."""

    WM_HOTKEY = 0x0312
    WM_QUIT = 0x0012
    MOD_ALT = 0x0001
    MOD_CONTROL = 0x0002
    MOD_SHIFT = 0x0004
    VK_SPACE = 0x20
    VK_L = 0x4C
    QUICK_ID = 0x4C48

    FILL_ID = 0x4C56
    EMERGENCY_ID = 0x4C47

    def __init__(
        self,
        callback: Callable[[], None],
        emergency_callback: Callable[[], None] | None = None,
        quick_callback: Callable[[], None] | None = None,
        quick_hotkey: str = "Ctrl+Alt+K",
    ) -> None:
        self.quick_callback = quick_callback
        self.quick_hotkey = normalize_hotkey(quick_hotkey)
        self.callback = callback
        self.emergency_callback = emergency_callback
        self._thread: threading.Thread | None = None
        self._thread_id: int | None = None
        self._ready = threading.Event()
        self.error: str | None = None
        self.emergency_error: str | None = None
        self.quick_error: str | None = None

    def start(self) -> None:
        if os.name != "nt" or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="localgatekeys-hotkey", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=3)

    def stop(self) -> None:
        if os.name != "nt" or self._thread_id is None:
            return
        ctypes.windll.user32.PostThreadMessageW(self._thread_id, self.WM_QUIT, 0, 0)
        thread = self._thread
        if thread is not threading.current_thread():
            thread.join(timeout=1)
        self._thread = None
        self._thread_id = None
        self._ready.clear()

    def _run(self) -> None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        self._thread_id = int(kernel32.GetCurrentThreadId())

        fill_ok = bool(
            user32.RegisterHotKey(None, self.FILL_ID, self.MOD_CONTROL | self.MOD_SHIFT, self.VK_SPACE)
        )
        if not fill_ok:
            self.error = "Ctrl+Shift+Space is already registered by another application"

        emergency_ok = True
        if self.emergency_callback is not None:
            emergency_ok = bool(
                user32.RegisterHotKey(None, self.EMERGENCY_ID, self.MOD_CONTROL | self.MOD_ALT, self.VK_L)
            )
            if not emergency_ok:
                self.emergency_error = "Ctrl+Alt+L is already registered by another application"

        quick_modifiers, quick_vk = hotkey_parts(self.quick_hotkey, self)
        quick_ok = bool(
            self.quick_callback
            and user32.RegisterHotKey(None, self.QUICK_ID, quick_modifiers, quick_vk)
        )
        if self.quick_callback and not quick_ok:
            self.quick_error = f"{self.quick_hotkey} is already registered by another application"
        self._ready.set()
        message = wintypes.MSG()
        try:
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                if message.message != self.WM_HOTKEY:
                    continue
                try:
                    if message.wParam == self.QUICK_ID and quick_ok and self.quick_callback:
                        self.quick_callback()
                    elif message.wParam == self.FILL_ID and fill_ok:
                        self.callback()
                    elif message.wParam == self.EMERGENCY_ID and emergency_ok and self.emergency_callback:
                        self.emergency_callback()
                except Exception:
                    pass
        finally:
            if quick_ok: user32.UnregisterHotKey(None, self.QUICK_ID)
            if fill_ok:
                user32.UnregisterHotKey(None, self.FILL_ID)
            if self.emergency_callback is not None and emergency_ok:
                user32.UnregisterHotKey(None, self.EMERGENCY_ID)


_MODIFIER_ALIASES = {
    "ctrl": HotkeyListener.MOD_CONTROL,
    "control": HotkeyListener.MOD_CONTROL,
    "alt": HotkeyListener.MOD_ALT,
    "shift": HotkeyListener.MOD_SHIFT,
    "win": 0x0008,
    "windows": 0x0008,
    "meta": 0x0008,
}
_MODIFIER_ORDER = ("Ctrl", "Alt", "Shift", "Win")
_SPECIAL_KEYS = {
    "space": HotkeyListener.VK_SPACE,
    "tab": 0x09,
    "enter": 0x0D,
    "esc": 0x1B,
    "escape": 0x1B,
    "insert": 0x2D,
    "delete": 0x2E,
    "home": 0x24,
    "end": 0x23,
    "up": 0x26,
    "down": 0x28,
    "left": 0x25,
    "right": 0x27,
}


def _parse_hotkey(value: str) -> tuple[str, int, int]:
    if not isinstance(value, str):
        raise ValueError("Quick-access hotkey must be text")
    parts = [part.strip().casefold() for part in value.split("+") if part.strip()]
    if len(parts) < 2:
        raise ValueError("Quick-access hotkey needs a modifier and a key")
    modifier_names: list[str] = []
    modifiers = 0
    key: str | None = None
    for part in parts:
        if part in _MODIFIER_ALIASES:
            if part in modifier_names:
                raise ValueError("Quick-access hotkey repeats a modifier")
            modifier_names.append(part)
            modifiers |= _MODIFIER_ALIASES[part]
        elif key is None:
            key = part
        else:
            raise ValueError("Quick-access hotkey must contain one key")
    if not modifiers or key is None:
        raise ValueError("Quick-access hotkey needs a modifier and a key")
    if key in _SPECIAL_KEYS:
        vk = _SPECIAL_KEYS[key]
        display_key = "Space" if key == "space" else key.title()
    elif len(key) == 1 and key.isascii() and key.isalnum():
        vk = ord(key.upper())
        display_key = key.upper()
    elif re.fullmatch(r"f(?:[1-9]|1[0-2])", key):
        vk = 0x70 + int(key[1:]) - 1
        display_key = key.upper()
    else:
        raise ValueError("Quick-access hotkey key is unsupported")
    names = []
    for name in _MODIFIER_ORDER:
        if _MODIFIER_ALIASES[name.casefold()] & modifiers:
            names.append(name)
    return "+".join([*names, display_key]), modifiers, vk


def normalize_hotkey(value: str) -> str:
    """Return a canonical RegisterHotKey-compatible shortcut string."""
    return _parse_hotkey(value)[0]


def hotkey_parts(value: str, listener: HotkeyListener | None = None) -> tuple[int, int]:
    """Return modifier/VK values; listener is accepted for test-friendly API symmetry."""
    del listener
    _display, modifiers, vk = _parse_hotkey(value)
    return modifiers, vk


# --------------------------------------------------------------------------- main-window shortcuts
#
# One table drives the Tk bindings, the F1 cheat sheet and the Settings list so
# the three can never disagree about what a key does.

from dataclasses import dataclass as _dataclass

_TEXT_WIDGET_CLASSES = frozenset({"Entry", "TEntry", "Text", "TCombobox", "TSpinbox", "Spinbox"})


@_dataclass(frozen=True)
class MainWindowShortcut:
    keys: str
    label: str
    description: str
    method: str
    sequences: tuple[str, ...]
    # When True the shortcut is ignored while a text field has focus (used for
    # bare keys such as "?" that the user may legitimately type).
    guard_text_fields: bool = False


MAIN_WINDOW_SHORTCUTS: tuple[MainWindowShortcut, ...] = (
    MainWindowShortcut("Ctrl+K", "Search everything", "Search everything: items, actions and settings.",
                       "open_palette", ("<Control-k>",)),
    MainWindowShortcut("Ctrl+F", "Search", "Jump to the search box.", "_focus_search", ("<Control-f>",)),
    MainWindowShortcut("Ctrl+N", "New item", "Choose what to add: login, card, note, key and more.",
                       "new_item_shortcut", ("<Control-n>",)),
    MainWindowShortcut("Ctrl+Shift+C", "Copy username", "Copy the selected login's username.",
                       "copy_selected_username_clicked", ("<Control-Shift-C>",)),
    MainWindowShortcut("Ctrl+T", "Copy 2FA code", "Copy the selected login's current two-factor code.",
                       "copy_selected_totp_clicked", ("<Control-t>",)),
    MainWindowShortcut("Ctrl+,", "Settings", "Open Settings.", "settings_clicked", ("<Control-comma>",)),
    MainWindowShortcut("Ctrl+L", "Lock", "Lock the vault.", "lock", ("<Control-l>",)),
    MainWindowShortcut("F1 or ?", "Keyboard shortcuts", "Show this list of shortcuts.", "show_shortcuts_clicked",
                       ("<F1>", "<question>"), guard_text_fields=True),
)


def is_text_widget(widget: object) -> bool:
    """True for widgets where typing is expected (entries, text boxes, combos)."""
    try:
        return str(widget.winfo_class()) in _TEXT_WIDGET_CLASSES  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - foreign/destroyed widgets simply are not text fields
        return False


_SHORTCUT_DESCRIPTION_KEYS = {
    "Search everything: items, actions and settings.": "shortcuts.desc.searchAll",
    "Jump to the search box.": "shortcuts.desc.search",
    "Choose what to add: login, card, note, key and more.": "shortcuts.desc.newItem",
    "Copy the selected login's username.": "shortcuts.desc.copyUsername",
    "Copy the selected login's current two-factor code.": "shortcuts.desc.copyTotp",
    "Open Settings.": "shortcuts.desc.settings",
    "Lock the vault.": "shortcuts.desc.lock",
    "Show this list of shortcuts.": "shortcuts.desc.shortcuts",
}


def shortcut_settings_rows() -> list[tuple[str, str, str]]:
    """(title, description, keys) rows for the Settings > Keyboard shortcuts card."""
    return [(shortcut.label, shortcut.description, shortcut.keys) for shortcut in MAIN_WINDOW_SHORTCUTS]


def shortcut_cheat_sheet_rows(quick_access_hotkey: str = "Ctrl+Alt+K") -> list[tuple[str, str, str]]:
    """(group, keys, description) rows for the F1 cheat sheet dialog."""
    try:
        quick = normalize_hotkey(quick_access_hotkey)
    except ValueError:
        quick = "Ctrl+Alt+K"
    from .i18n import t

    main, items, anywhere = t("shortcuts.group.main"), t("shortcuts.group.items"), t("shortcuts.group.anywhere")
    rows: list[tuple[str, str, str]] = [
        (main, t("shortcuts.keys.f1") if shortcut.keys == "F1 or ?" else shortcut.keys,
         t(_SHORTCUT_DESCRIPTION_KEYS[shortcut.description]))
        for shortcut in MAIN_WINDOW_SHORTCUTS
    ]
    rows.extend([
        (items, t("shortcuts.keys.openItem"), t("shortcuts.desc.openSelected")),
        (items, t("shortcuts.keys.doubleClick"), t("shortcuts.desc.openPointer")),
        (items, "Ctrl+C", t("shortcuts.desc.copyPassword")),
        (items, "Delete", t("shortcuts.desc.delete")),
        (items, t("shortcuts.keys.downArrow"), t("shortcuts.desc.moveIntoResults")),
        (anywhere, "Ctrl+Alt+L", t("shortcuts.desc.emergencyLock")),
        (anywhere, quick, t("shortcuts.desc.quickAccess")),
        (anywhere, "Ctrl+Shift+Space", t("shortcuts.desc.fillBound")),
    ])
    return rows
