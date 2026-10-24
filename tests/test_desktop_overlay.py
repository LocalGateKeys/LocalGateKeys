from localvault.desktop_overlay import (
    DesktopFieldOverlay,
    _asset_path,
    calculate_overlay_position,
    calculate_overlay_position_from_offset,
    choose_overlay_password_control,
    control_rect_relative_to_window,
    foreground_belongs_to_target,
    get_foreground_hwnd,
    overlay_logo_asset_size,
    overlay_render_metrics,
    resolve_native_toplevel_hwnd,
    set_overlay_owner,
)
from localvault.uia import ControlDescriptor


def control(index: int, *, password: bool, enabled: bool = True, visible: bool = True):
    return ControlDescriptor(
        index=index,
        name="",
        automation_id=f"field-{index}",
        class_name="Edit",
        framework_id="Win32",
        is_password=password,
        enabled=enabled,
        visible=visible,
        rectangle=(10, 10, 110, 30),
    )


def test_overlay_chooses_only_visible_enabled_protected_field() -> None:
    controls = [
        control(0, password=False),
        control(1, password=True, visible=False),
        control(2, password=True, enabled=False),
        control(3, password=True),
    ]
    assert choose_overlay_password_control(controls) is controls[3]


def test_overlay_stays_hidden_without_protected_field() -> None:
    assert choose_overlay_password_control([control(0, password=False)]) is None


def test_overlay_tracks_top_level_window_delta() -> None:
    # Password field was at 300..500 x 220..252 when the window was at 100,100.
    # Moving the top-level window by +75,+40 should move the LV affordance by
    # exactly the same delta without waiting for another UIA enumeration.
    position = calculate_overlay_position(
        (300, 220, 500, 252),
        (100, 100, 700, 600),
        (175, 140, 775, 640),
        size=28,
        gap=4,
    )
    assert position == (579, 262)


def test_foreground_guard_accepts_only_target_or_overlay_click_window() -> None:
    assert foreground_belongs_to_target(100, 100, 200)
    assert foreground_belongs_to_target(200, 100, 200)
    assert not foreground_belongs_to_target(300, 100, 200)
    assert not foreground_belongs_to_target(0, 100, 200)


def test_get_foreground_hwnd_is_safe_off_windows() -> None:
    # Portable regression check: non-Windows test runners must not try to load
    # user32 merely by importing the desktop overlay module.
    import os

    if os.name != "nt":
        assert get_foreground_hwnd() == 0


def test_overlay_tracking_interval_is_60fps_class() -> None:
    assert DesktopFieldOverlay.TRACK_MS <= 7


def test_overlay_has_native_density_assets_for_windows_scaling_targets() -> None:
    expected = {
        96: (32, 24, 24),
        120: (40, 30, 30),
        144: (48, 36, 36),
        168: (56, 42, 42),
        192: (64, 48, 48),
    }
    for dpi, (canvas, logo, asset) in expected.items():
        assert overlay_render_metrics(dpi)[:2] == (canvas, logo)
        assert overlay_logo_asset_size(dpi) == asset
        assert _asset_path(f"icons/field_fill_{asset}.png").is_file()


def test_native_toplevel_resolution_is_safe_off_windows() -> None:
    import os

    if os.name != "nt":
        assert resolve_native_toplevel_hwnd(12345) == 12345


def test_relative_anchor_tracks_even_if_uia_absolute_rect_goes_stale() -> None:
    # Capture a stable password-field offset while the app is at x=900.
    relative = control_rect_relative_to_window(
        (1180, 220, 1380, 252),
        (900, 100, 1500, 600),
    )
    assert relative == (280, 120, 480, 152)

    # The app then moves to x=100. The overlay must follow from the stable
    # relative anchor even if a Chromium/CEF UIA provider is still reporting
    # the old absolute control rectangle for a few frames.
    position = calculate_overlay_position_from_offset(
        relative,
        (100, 100, 700, 600),
        size=28,
        gap=4,
    )
    assert position == (584, 222)


def test_overlay_owner_helper_is_safe_off_windows() -> None:
    import os

    if os.name != "nt":
        # Must be importable/testable on non-Windows CI without touching user32.
        set_overlay_owner(12345, 67890)



# --- the Win32 button (no Tk) ---------------------------------------------------------------------
from types import SimpleNamespace  # noqa: E402

import localvault.desktop_overlay as overlay_module  # noqa: E402
from localvault.desktop_overlay import render_overlay_image  # noqa: E402


def _snapshot(*, pid=99999, exe=r"C:\Apps\Example\example.exe", controls=None, hwnd=500):
    return SimpleNamespace(pid=pid, exe_path=exe, hwnd=hwnd,
                           controls=controls if controls is not None else [control(1, password=True)])


def _probe_env(monkeypatch, *, foreground=500):
    monkeypatch.setattr(overlay_module, "resolve_native_toplevel_hwnd", lambda hwnd: hwnd)
    monkeypatch.setattr(overlay_module, "get_foreground_hwnd", lambda: foreground)
    monkeypatch.setattr(overlay_module, "get_window_rect", lambda hwnd: (100, 100, 700, 600))
    monkeypatch.setattr(overlay_module, "window_dpi", lambda hwnd: 96.0)
    item = DesktopFieldOverlay(on_click=lambda hwnd: None, ignored_executables={"chrome.exe"})
    item.enabled = True
    return item


def test_a_protected_field_in_the_foreground_app_becomes_the_target(monkeypatch) -> None:
    item = _probe_env(monkeypatch)
    item.finish_probe(_snapshot())
    assert item.target_hwnd == 500 and item.target_control_offset == (-90, -90, 10, -70)


def test_no_target_for_browsers_this_app_other_windows_or_when_off(monkeypatch) -> None:
    import os

    for snapshot in (_snapshot(exe=r"C:\Program Files\Google\Chrome\chrome.exe"), _snapshot(pid=os.getpid()),
                     _snapshot(controls=[control(0, password=False)]), None):
        item = _probe_env(monkeypatch)
        item.finish_probe(snapshot)
        assert item.target_hwnd is None
    item = _probe_env(monkeypatch, foreground=777)  # the user already switched away
    item.finish_probe(_snapshot())
    assert item.target_hwnd is None
    item = _probe_env(monkeypatch)
    item.set_enabled(False)
    item.finish_probe(_snapshot())
    assert item.target_hwnd is None


def test_a_click_hides_the_button_and_hands_over_only_the_window(monkeypatch) -> None:
    clicked = []
    item = _probe_env(monkeypatch)
    item.on_click = clicked.append
    item.finish_probe(_snapshot())
    item._clicked()
    assert clicked == [500] and item.target_hwnd is None
    item.finish_probe(_snapshot())
    item.set_busy(True)
    item._clicked()
    assert clicked == [500]  # a fill already running: the click is ignored


def test_the_button_image_has_transparent_corners_and_the_logo() -> None:
    image = render_overlay_image(32, 24)
    assert image.size == (32, 32) and image.mode == "RGBA"
    assert image.getpixel((0, 0))[3] < 64  # rounded corner
    assert image.getpixel((16, 16))[3] == 255
    assert render_overlay_image(32, 24, "hover").getpixel((3, 16)) != image.getpixel((3, 16))


def test_the_button_is_always_on_top_only_for_an_always_on_top_app(monkeypatch) -> None:
    calls = []

    class User32:
        def SetWindowPos(self, hwnd, after, x, y, w, h, flags):
            calls.append((after.value, x, y, flags))
    monkeypatch.setattr(overlay_module, "_user32", lambda: User32())
    monkeypatch.setattr(overlay_module.os, "name", "nt")
    overlay_module.position_overlay_window(10, 5, 6, 32, topmost=True)
    overlay_module.position_overlay_window(10, 5, 6, 32, topmost=False)
    import ctypes
    # HWND_TOPMOST and HWND_NOTOPMOST as real pointer-sized -1 and -2 (not truncated 32-bit numbers).
    assert [c[0] for c in calls] == [ctypes.c_void_p(-1).value, ctypes.c_void_p(-2).value]
    assert all(c[3] & 0x0010 for c in calls)  # never activates
