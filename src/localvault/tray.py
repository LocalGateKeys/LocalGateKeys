from __future__ import annotations

import os
import threading
from collections.abc import Callable

from .ui_assets import asset_root


class TrayController:
    """Small Windows tray facade. Imports GUI dependencies lazily."""

    def __init__(
        self,
        *,
        on_open: Callable[[], None],
        on_lock: Callable[[], None],
        on_unlock: Callable[[], None],
        on_toggle_browser: Callable[[], None],
        on_toggle_desktop: Callable[[], None],
        on_exit: Callable[[], None],
        state: Callable[[], dict[str, bool]],
        on_switch: Callable[[], None] | None = None,
        on_quick_access: Callable[[], None] | None = None,
        on_check_updates: Callable[[], None] | None = None,
    ) -> None:
        self.on_switch = on_switch or on_open
        self.on_quick_access = on_quick_access or on_open
        self.on_check_updates = on_check_updates or (lambda: None)
        self.on_open = on_open
        self.on_lock = on_lock
        self.on_unlock = on_unlock
        self.on_toggle_browser = on_toggle_browser
        self.on_toggle_desktop = on_toggle_desktop
        self.on_exit = on_exit
        self.state = state
        self.icon = None
        self.thread: threading.Thread | None = None
        self.available = False

    def start(self) -> None:
        if os.name != "nt" or self.thread is not None:
            return
        try:
            import pystray  # noqa: F401
            from PIL import Image  # noqa: F401
        except Exception:
            return
        self.thread = threading.Thread(target=self._run, name="localvault-tray", daemon=True)
        self.thread.start()
        self.available = True

    def stop(self) -> None:
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)
        self.thread = None
        self.icon = None
        self.available = False

    def refresh(self) -> None:
        if self.icon is not None:
            try:
                self.icon.update_menu()
                self.icon.title = self._title()
            except Exception:
                pass

    def _title(self) -> str:
        return "LocalGateKeys — unlocked" if self.state().get("unlocked") else "LocalGateKeys — locked"

    def _run(self) -> None:
        import pystray
        from PIL import Image

        def image() -> Image.Image:
            try:
                asset = asset_root() / "icons" / "app_256.png"
                return Image.open(asset).convert("RGBA")
            except Exception:
                return Image.new("RGBA", (64, 64), (7, 17, 31, 255))

        def ui(callback: Callable[[], None]) -> Callable[..., None]:
            def wrapped(*_args: object) -> None:
                callback()
            return wrapped

        menu = pystray.Menu(
            pystray.MenuItem("Open LocalGateKeys", ui(self.on_open), default=True),
            pystray.MenuItem("Unlock vault", ui(self.on_unlock), enabled=lambda _item: not self.state().get("unlocked", False)),
            pystray.MenuItem("Lock vault", ui(self.on_lock), enabled=lambda _item: self.state().get("unlocked", False)),
            pystray.MenuItem("Lock & switch person", ui(self.on_switch)),
            pystray.MenuItem("Quick access", ui(self.on_quick_access)),
            pystray.MenuItem("Check for updates", ui(self.on_check_updates)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Browser integration",
                ui(self.on_toggle_browser),
                checked=lambda _item: self.state().get("browser_enabled", True),
            ),
            pystray.MenuItem(
                "Desktop fill icons",
                ui(self.on_toggle_desktop),
                checked=lambda _item: self.state().get("desktop_enabled", True),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", ui(self.on_exit)),
        )
        self.icon = pystray.Icon("LocalGateKeys", image(), self._title(), menu)
        self.icon.run()
