from __future__ import annotations

import argparse
import copy
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .access_policy import is_sign_in_label
from .signature import authenticode_info, file_sha256
from .win_input import clear_focused_control, input_blocked_by_uipi, type_unicode


class UIAutomationError(RuntimeError):
    pass


@dataclass
class ControlDescriptor:
    index: int
    name: str
    automation_id: str
    class_name: str
    framework_id: str
    is_password: bool
    enabled: bool
    visible: bool
    rectangle: tuple[int, int, int, int]
    wrapper: Any = field(repr=False, compare=False, default=None)

    def selector(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "automation_id": self.automation_id,
            "class_name": self.class_name,
            "framework_id": self.framework_id,
            "is_password": self.is_password,
        }

    def fingerprint(self) -> dict[str, Any]:
        return {
            "automation_id": self.automation_id,
            "class_name": self.class_name,
            "framework_id": self.framework_id,
            "is_password": self.is_password,
            "enabled": self.enabled,
            "visible": self.visible,
        }

    def public_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "automation_id": self.automation_id,
            "class_name": self.class_name,
            "framework_id": self.framework_id,
            "is_password": self.is_password,
            "enabled": self.enabled,
            "visible": self.visible,
            "rectangle": list(self.rectangle),
        }


@dataclass
class WindowSnapshot:
    hwnd: int
    pid: int
    title: str
    exe_path: str
    exe_sha256: str
    controls: list[ControlDescriptor]
    signer: dict[str, Any] | None
    buttons: list[ControlDescriptor] = field(default_factory=list)

    def control_fingerprint(self) -> list[dict[str, Any]]:
        return [control.fingerprint() for control in self.controls]

    def public_dict(self) -> dict[str, Any]:
        return {
            "hwnd": self.hwnd,
            "pid": self.pid,
            "title": self.title,
            "exe_path": self.exe_path,
            "exe_sha256": self.exe_sha256,
            "signer": self.signer,
            "edit_controls": [control.public_dict() for control in self.controls],
            "sign_in_buttons": [control.public_dict() for control in self.buttons],
        }


def _require_windows() -> None:
    if os.name != "nt":
        raise UIAutomationError("Desktop UI Automation is available only on Windows")


@lru_cache(maxsize=64)
def _cached_authenticode_for_digest(
    exe_path: str, exe_sha256: str
) -> dict[str, Any] | None:
    """Cache signer inspection by the executable's full-file digest.

    Authenticode inspection currently shells out to PowerShell and is far more
    expensive than hashing the executable. A fresh fill still hashes the full
    file; signer metadata is reused only when that cryptographic digest is
    identical, so a changed binary cannot inherit an old signer result.
    """

    del exe_sha256  # It intentionally participates in the cache key.
    return authenticode_info(exe_path)


@lru_cache(maxsize=32)
def _cached_executable_identity(
    exe_path: str, mtime_ns: int, size: int
) -> tuple[str, dict[str, Any] | None]:
    """Cache overlay/background identity checks until file metadata changes."""

    del mtime_ns, size  # They intentionally participate in the cache key.
    digest = file_sha256(exe_path)
    return digest, _cached_authenticode_for_digest(exe_path, digest)


def _executable_identity(
    exe_path: str, *, allow_cache: bool
) -> tuple[str, dict[str, Any] | None]:
    if not allow_cache:
        # Security-sensitive bind/fill operations still hash the entire current
        # executable every time. Only Authenticode metadata is cached, and only
        # for the exact full-file SHA-256 digest just recomputed above.
        digest = file_sha256(exe_path)
        return digest, _cached_authenticode_for_digest(exe_path, digest)
    try:
        stat = Path(exe_path).stat()
    except OSError as exc:
        raise UIAutomationError(f"Could not fingerprint the foreground executable: {exc}") from exc
    return _cached_executable_identity(exe_path, int(stat.st_mtime_ns), int(stat.st_size))


def scan_window(
    hwnd: int,
    *,
    allow_identity_cache: bool = False,
    include_identity: bool = True,
    include_buttons: bool = False,
    include_all_buttons: bool = False,
) -> WindowSnapshot:
    """Inspect edit-control metadata for one existing top-level Windows window.

    This never reads current edit-control values. Protected fields have their
    accessibility name discarded as an extra precaution. ``include_identity``
    may be disabled only for non-secret UI discovery (for example, deciding
    whether to show the LV affordance). Bind/fill operations leave it enabled.
    """

    _require_windows()
    import psutil  # type: ignore[import-not-found]
    import win32gui  # type: ignore[import-not-found]
    import win32process  # type: ignore[import-not-found]
    from pywinauto import Desktop  # type: ignore[import-not-found]

    hwnd = int(hwnd)
    if not hwnd or not bool(win32gui.IsWindow(hwnd)):
        raise UIAutomationError("The target window is no longer available")
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    title = str(win32gui.GetWindowText(hwnd))
    try:
        exe_path = str(Path(psutil.Process(pid).exe()).resolve())
    except (psutil.Error, OSError) as exc:
        raise UIAutomationError(f"Could not identify the target executable: {exc}") from exc

    try:
        window = Desktop(backend="uia").window(handle=hwnd)
        wrappers = window.descendants(control_type="Edit")
    except Exception as exc:  # noqa: BLE001 - UIA providers raise many COM-specific errors
        raise UIAutomationError(f"UI Automation could not inspect this window: {exc}") from exc

    controls: list[ControlDescriptor] = []
    for wrapper in wrappers:
        try:
            index = len(controls)
            element_info = wrapper.element_info
            element = element_info.element
            is_password = bool(getattr(element, "CurrentIsPassword", False))
            rect = element_info.rectangle
            controls.append(
                ControlDescriptor(
                    index=index,
                    # Do not retain even the accessibility Name for protected
                    # fields. Well-behaved providers expose a label here, but a
                    # buggy provider could accidentally surface sensitive text.
                    name="" if is_password else str(element_info.name or ""),
                    automation_id=str(element_info.automation_id or ""),
                    class_name=str(element_info.class_name or ""),
                    framework_id=str(element_info.framework_id or ""),
                    is_password=is_password,
                    enabled=bool(element_info.enabled),
                    visible=bool(element_info.visible),
                    rectangle=(int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)),
                    wrapper=wrapper,
                )
            )
        except Exception:
            continue

    buttons: list[ControlDescriptor] = []
    if include_buttons:
        # Only for explicit binding/fill, never in the high-frequency overlay loop.
        for wrapper in window.descendants(control_type="Button"):
            try:
                info = wrapper.element_info
                name = str(info.name or "").strip()
                if not name:
                    continue
                if not include_all_buttons and not is_sign_in_label(name):
                    continue
                rect = info.rectangle
                buttons.append(ControlDescriptor(
                    index=len(buttons), name=name,
                    automation_id=str(info.automation_id or ""), class_name=str(info.class_name or ""),
                    framework_id=str(info.framework_id or ""), is_password=False,
                    enabled=bool(info.enabled), visible=bool(info.visible),
                    rectangle=(rect.left, rect.top, rect.right, rect.bottom), wrapper=wrapper))
            except Exception:
                continue

    if include_identity:
        exe_sha256, signer = _executable_identity(
            exe_path, allow_cache=allow_identity_cache
        )
    else:
        # Showing the overlay is not authorization to release a secret. Avoid
        # expensive hashing/signature work here; the click/fill path performs
        # the full identity verification before any credential is released.
        exe_sha256, signer = "", None
    return WindowSnapshot(
        hwnd=hwnd,
        pid=int(pid),
        title=title,
        exe_path=exe_path,
        exe_sha256=exe_sha256,
        controls=controls,
        signer=signer,
        buttons=buttons,
    )


def scan_foreground_window(
    *,
    allow_identity_cache: bool = False,
    include_identity: bool = True,
    include_buttons: bool = False,
    include_all_buttons: bool = False,
) -> WindowSnapshot:
    _require_windows()
    import win32gui  # type: ignore[import-not-found]

    hwnd = int(win32gui.GetForegroundWindow())
    if not hwnd:
        raise UIAutomationError("No foreground window was found")
    return scan_window(
        hwnd,
        allow_identity_cache=allow_identity_cache,
        include_identity=include_identity,
        include_buttons=include_buttons,
        include_all_buttons=include_all_buttons,
    )


def scan_bound_window(entry: dict[str, Any], *, include_buttons: bool = False, include_all_buttons: bool = False) -> WindowSnapshot:
    """Find the one visible top-level window that still belongs to a saved desktop binding.

    This is used by explicit management actions such as Sign in button mapping.
    It avoids requiring the user to race a foreground-window countdown while
    LocalGateKeys itself currently owns focus.
    """

    _require_windows()
    import psutil  # type: ignore[import-not-found]
    import win32gui  # type: ignore[import-not-found]
    import win32process  # type: ignore[import-not-found]

    scope = entry.get("scope", {})
    expected_path = os.path.normcase(os.path.normpath(str(scope.get("exe_path", ""))))
    expected_title = _normalized_window_title(str(scope.get("window_title", "")))
    binding_mode = str(scope.get("binding_mode", "strict")).casefold()
    discord_stable = binding_mode == "discord_stable" and _is_discord_executable(expected_path)
    if not expected_path or (not expected_title and not discord_stable):
        raise UIAutomationError("Saved desktop binding has no stable app/window identity")

    candidates: list[int] = []

    def visit(hwnd: int, _extra: Any) -> bool:
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return True
            title = _normalized_window_title(str(win32gui.GetWindowText(hwnd)))
            if not discord_stable and title != expected_title:
                return True
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            exe_path = os.path.normcase(os.path.normpath(str(Path(psutil.Process(pid).exe()).resolve())))
            if (discord_stable and _is_discord_executable(exe_path)) or exe_path == expected_path:
                candidates.append(int(hwnd))
        except Exception:
            pass
        return True

    win32gui.EnumWindows(visit, None)
    if not candidates:
        raise UIAutomationError("Open the saved app login window and try again")

    matches: list[WindowSnapshot] = []
    errors: list[str] = []
    for hwnd in candidates:
        try:
            snap = scan_window(
                hwnd,
                include_buttons=include_buttons,
                include_all_buttons=include_all_buttons,
            )
            validate_desktop_entry(entry, snap)
            matches.append(snap)
        except UIAutomationError as exc:
            errors.append(str(exc))

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise UIAutomationError("More than one matching app login window is open; close the extra window and try again")
    raise UIAutomationError(errors[0] if errors else "The saved app window no longer matches this binding")


def choose_default_selectors(
    controls: list[ControlDescriptor],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    visible = [control for control in controls if control.enabled and control.visible]
    password_control = next((control for control in visible if control.is_password), None)
    if password_control is None:
        return None, None
    username_candidates = [control for control in visible if not control.is_password]
    before = [control for control in username_candidates if control.index < password_control.index]
    username_control = (
        before[-1]
        if before
        else (username_candidates[0] if username_candidates else None)
    )
    return (
        username_control.selector() if username_control else None,
        password_control.selector(),
    )


def _score_selector(control: ControlDescriptor, selector: dict[str, Any]) -> int:
    expected_password = selector.get("is_password")
    if isinstance(expected_password, bool) and control.is_password != expected_password:
        return -1

    score = 0
    automation_id = str(selector.get("automation_id", ""))
    name = str(selector.get("name", ""))
    class_name = str(selector.get("class_name", ""))
    framework_id = str(selector.get("framework_id", ""))
    if automation_id and control.automation_id == automation_id:
        score += 120
    if name and control.name == name:
        score += 40
    if class_name and control.class_name == class_name:
        score += 20
    if framework_id and control.framework_id == framework_id:
        score += 10
    try:
        selected_index = int(selector.get("index", -1))
    except (TypeError, ValueError):
        selected_index = -1
    if selected_index == control.index:
        score += 5
    return score


def resolve_control(
    controls: list[ControlDescriptor],
    selector: dict[str, Any] | None,
    *,
    minimum_score: int = 25,
) -> ControlDescriptor | None:
    if not selector:
        return None
    candidates = [control for control in controls if control.enabled and control.visible]
    if not candidates:
        return None
    scored = sorted(
        ((_score_selector(control, selector), control) for control in candidates),
        key=lambda item: item[0],
        reverse=True,
    )
    best_score, best = scored[0]
    if best_score < minimum_score:
        return None
    if len(scored) > 1 and scored[1][0] == best_score:
        return None
    return best


def _normalized_window_title(value: str) -> str:
    return " ".join(value.split()).casefold()


def _is_discord_executable(path: str) -> bool:
    """Identify the official versioned Discord desktop installation family."""
    try:
        candidate = Path(path).expanduser().resolve(strict=False)
        local_app_data = Path(
            os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        ).expanduser().resolve(strict=False)
        relative = candidate.relative_to(local_app_data / "Discord")
    except (OSError, ValueError):
        return False
    return (
        len(relative.parts) == 2
        and relative.parts[1].casefold() == "discord.exe"
        and re.fullmatch(r"app-\d+(?:\.\d+)*", relative.parts[0], re.IGNORECASE)
        is not None
    )


def _is_verified_discord_signer(signer: dict[str, Any] | None) -> bool:
    if not isinstance(signer, dict) or str(signer.get("status", "")).casefold() != "valid":
        return False
    subject = str(signer.get("subject", ""))
    return re.search(
        r"(?:^|,\s*)(?:O|CN)=Discord Inc\.(?:,|$)", subject, re.IGNORECASE
    ) is not None


def _restore_foreground(hwnd: int) -> None:
    import win32gui  # type: ignore[import-not-found]

    try:
        win32gui.ShowWindow(hwnd, 5)
        win32gui.SetForegroundWindow(hwnd)
        time.sleep(0.03)
        if int(win32gui.GetForegroundWindow()) != int(hwnd):
            raise UIAutomationError("Windows did not grant foreground focus to the target")
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, UIAutomationError):
            raise
        raise UIAutomationError(f"Could not return focus to the target window: {exc}") from exc


def _write_control(control: ControlDescriptor, value: str, hwnd: int,
                   guard: Callable[[], None] | None = None) -> None:
    def check() -> None:
        if guard: guard()
        import win32gui
        if not win32gui.IsWindow(hwnd) or int(win32gui.GetForegroundWindow()) != int(hwnd):
            raise UIAutomationError("The target lost foreground focus before input")
        if control.wrapper is None:
            raise UIAutomationError("The target control is unavailable")
        info = control.wrapper.element_info
        if not info.enabled or not info.visible:
            raise UIAutomationError("The intended field is no longer available")
    check()
    try:
        control.wrapper.set_edit_text(value)
        return
    except Exception:
        if guard: guard()  # Cancellation is not a reason to try a weaker input path.
    if input_blocked_by_uipi(hwnd):
        # SendInput to an elevated app is dropped without an error: never report that as a fill.
        raise UIAutomationError(
            "This app runs as administrator, so Windows blocks typing into it. "
            "Run it without administrator rights, or fill it by hand."
        )
    try:
        check()
        control.wrapper.set_focus()
        time.sleep(0.02)
        check()
        if not bool(control.wrapper.has_keyboard_focus()):
            raise UIAutomationError("The intended field does not have keyboard focus")
        clear_focused_control()
        def typing_check() -> None:
            check()
            if not bool(control.wrapper.has_keyboard_focus()):
                raise UIAutomationError("The target field lost focus while filling")
        type_unicode(value, guard=typing_check)
    except Exception:
        raise UIAutomationError("The intended control rejected input or the fill was cancelled") from None



def _resolve_dynamic_layout_controls(
    controls: list[ControlDescriptor],
    username_selector: dict[str, Any] | None,
    password_selector: dict[str, Any],
) -> tuple[ControlDescriptor | None, ControlDescriptor]:
    """Resolve a user-approved dynamic desktop login layout conservatively.

    This mode exists for desktop apps whose accessibility provider recreates
    edit controls or changes automation metadata between launches.

    We first attempt the ordinary saved-selector resolution.  If that fails:
    - a previously protected password field may fall back only when exactly one
      enabled/visible protected password edit control exists;
    - a saved username field may fall back only when exactly one enabled/visible
      non-password edit control exists before the resolved password field.

    No fallback is allowed for an originally unprotected password field and no
    guessing is performed when multiple candidates exist.
    """

    protected_password_expected = bool(password_selector.get("is_password", False))

    password_control = resolve_control(
        controls,
        password_selector,
        minimum_score=25 if protected_password_expected else 60,
    )

    if password_control is None and protected_password_expected:
        password_candidates = [
            control
            for control in controls
            if control.enabled and control.visible and control.is_password
        ]
        if len(password_candidates) == 1:
            password_control = password_candidates[0]

    if password_control is None:
        if protected_password_expected:
            raise UIAutomationError(
                "The dynamic desktop binding could not identify exactly one protected password field"
            )
        raise UIAutomationError(
            "The previously approved unprotected password field no longer matches strongly enough"
        )

    if protected_password_expected and not password_control.is_password:
        raise UIAutomationError("The resolved password target is no longer protected")

    username_control: ControlDescriptor | None = None
    if isinstance(username_selector, dict):
        username_control = resolve_control(controls, username_selector)
        if username_control is None:
            username_candidates = [
                control
                for control in controls
                if (
                    control.enabled
                    and control.visible
                    and not control.is_password
                    and control.index < password_control.index
                )
            ]
            if len(username_candidates) == 1:
                username_control = username_candidates[0]
            else:
                raise UIAutomationError(
                    "The dynamic desktop binding could not identify exactly one username field"
                )

    return username_control, password_control


def validate_desktop_entry(
    entry: dict[str, Any], snapshot: WindowSnapshot
) -> tuple[ControlDescriptor | None, ControlDescriptor]:
    """Validate a saved desktop binding against a fresh window snapshot.

    Returns the resolved username/password controls only after the app identity
    and selectors match. Discord is the one versioned-install exception: its
    versioned install path, hash, title, and layout may change between launches,
    but the current binary must still be signed by Discord Inc. No field value
    is read and no input is sent by this function.
    """

    current = snapshot
    scope = entry.get("scope")
    if not isinstance(scope, dict):
        raise UIAutomationError("Desktop entry has no scope")
    expected_path = os.path.normcase(os.path.abspath(str(scope.get("exe_path", ""))))
    actual_path = os.path.normcase(os.path.abspath(current.exe_path))
    binding_mode = str(scope.get("binding_mode", "strict")).casefold()
    discord_stable = (
        binding_mode == "discord_stable"
        and _is_discord_executable(expected_path)
        and _is_discord_executable(actual_path)
    )
    if not expected_path or (not discord_stable and expected_path != actual_path):
        raise UIAutomationError(
            f"Executable mismatch. Expected {scope.get('exe_path')!s}, got {current.exe_path!s}"
        )

    if binding_mode not in {"strict", "embedded_web_volatile", "dynamic_layout", "discord_stable"}:
        raise UIAutomationError("Desktop binding mode is invalid; rebind it")

    if discord_stable and not _is_verified_discord_signer(current.signer):
        raise UIAutomationError("The current Discord executable is not signed by Discord Inc.")

    expected_hash = str(scope.get("exe_sha256", "")).upper()
    if not discord_stable and (len(expected_hash) != 64 or any(ch not in "0123456789ABCDEF" for ch in expected_hash)):
        raise UIAutomationError("Desktop binding has no valid executable fingerprint; rebind it")
    if not discord_stable and (not current.exe_sha256 or current.exe_sha256.upper() != expected_hash):
        raise UIAutomationError("The executable binary no longer matches the saved binding")

    expected_fingerprint = scope.get("control_fingerprint")
    if not discord_stable and not isinstance(expected_fingerprint, list):
        raise UIAutomationError("Desktop binding has no control-layout fingerprint; rebind it")

    # Native desktop controls retain exact layout validation. Embedded
    # Chromium/CEF/WebView providers often change geometry, indexes, and
    # unrelated accessibility nodes between launches, so an explicitly
    # rebound embedded-web credential validates its saved field selectors
    # instead of requiring the whole layout fingerprint to remain identical.
    if not discord_stable and binding_mode == "strict" and current.control_fingerprint() != expected_fingerprint:
        raise UIAutomationError("The login control layout changed; rebind before filling")

    expected_title = _normalized_window_title(str(scope.get("window_title", "")))
    actual_title = _normalized_window_title(current.title)
    if not discord_stable and expected_title and expected_title != actual_title:
        raise UIAutomationError(
            f"Window title mismatch. Expected {scope.get('window_title')!s}, got {current.title!s}"
        )

    expected_signer = scope.get("signer")
    if not discord_stable and isinstance(expected_signer, dict) and expected_signer.get("thumbprint"):
        if str(expected_signer.get("status", "")).casefold() != "valid":
            raise UIAutomationError("The saved executable signature was not valid")
        actual_status = str((current.signer or {}).get("status", ""))
        if actual_status.casefold() != "valid":
            raise UIAutomationError("The current executable signature is not valid")
        actual_thumbprint = str((current.signer or {}).get("thumbprint", "")).upper()
        expected_thumbprint = str(expected_signer.get("thumbprint", "")).upper()
        if not actual_thumbprint or actual_thumbprint != expected_thumbprint:
            raise UIAutomationError("The executable signer no longer matches the saved binding")

    username_selector = scope.get("username_selector")
    password_selector = scope.get("password_selector")
    if not isinstance(password_selector, dict):
        raise UIAutomationError("Desktop entry has no password-field selector")

    if binding_mode == "embedded_web_volatile" and not discord_stable:
        framework = str(password_selector.get("framework_id", "")).casefold()
        class_name = str(password_selector.get("class_name", "")).casefold()
        combined = f"{framework} {class_name}"
        if not any(token in combined for token in ("cef", "chrome", "chromium", "webview")):
            raise UIAutomationError(
                "Volatile-layout mode is allowed only for an explicitly bound embedded web control"
            )

    protected_password_expected = bool(password_selector.get("is_password", False))

    if discord_stable or binding_mode == "dynamic_layout":
        return _resolve_dynamic_layout_controls(
            current.controls,
            username_selector if isinstance(username_selector, dict) else None,
            password_selector,
        )

    username_control = resolve_control(
        current.controls,
        username_selector if isinstance(username_selector, dict) else None,
    )
    password_control = resolve_control(
        current.controls,
        password_selector,
        minimum_score=25 if protected_password_expected else 60,
    )
    if password_control is None:
        if protected_password_expected:
            raise UIAutomationError(
                "No protected password control was exposed by this app. "
                "The prototype will not guess or capture a custom-rendered field."
            )
        raise UIAutomationError(
            "The previously approved unprotected password field no longer matches strongly enough. "
            "Rebind the app rather than risking a fill into the wrong control."
        )
    if protected_password_expected and not password_control.is_password:
        raise UIAutomationError("The resolved password target is no longer protected")

    return username_control, password_control


def updated_binary_binding(
    entry: dict[str, Any], snapshot: WindowSnapshot
) -> tuple[dict[str, Any], bool] | None:
    """Recognise an in-place update or UI change of a bound app.

    Returns ``(updated_entry, signer_verified)`` when the snapshot is the same
    executable path and the saved field selectors still resolve, adopting the
    current hash, window title and layout. An identical binary, or a new one
    whose pinned signer still matches, is verified; ``signer_verified`` is
    False only for a changed unsigned binary, which the user must confirm.
    A changed window title is never adopted silently, even for an identical
    binary: the caller asks first (app/desktop.py).
    """

    scope = entry.get("scope")
    if not isinstance(scope, dict):
        return None
    expected_path = os.path.normcase(os.path.abspath(str(scope.get("exe_path", ""))))
    if not scope.get("exe_path") or expected_path != os.path.normcase(os.path.abspath(snapshot.exe_path)):
        return None
    if not snapshot.exe_sha256:
        return None
    same_binary = snapshot.exe_sha256.upper() == str(scope.get("exe_sha256", "")).upper()
    saved_signer = scope.get("signer")
    signer_pinned = same_binary or (isinstance(saved_signer, dict) and bool(saved_signer.get("thumbprint")))
    candidate = copy.deepcopy(entry)
    candidate_scope = candidate["scope"]
    candidate_scope["exe_sha256"] = snapshot.exe_sha256.upper()
    candidate_scope["window_title"] = snapshot.title
    candidate_scope["control_fingerprint"] = snapshot.control_fingerprint()
    try:
        # A pinned signer stays in scope, so validation still enforces it.
        validate_desktop_entry(candidate, snapshot)
    except UIAutomationError:
        candidate_scope.clear()
        return None
    return candidate, signer_pinned


def desktop_entry_matches_snapshot(entry: dict[str, Any], snapshot: WindowSnapshot) -> bool:
    """Return True only when a saved desktop binding validates against this exact snapshot."""

    try:
        validate_desktop_entry(entry, snapshot)
    except UIAutomationError:
        return False
    return True


def resolve_sign_in_button(snapshot: WindowSnapshot, selector: dict[str, Any]) -> ControlDescriptor:
    explicit = bool(selector.get("explicit_user_mapping")) if isinstance(selector, dict) else False
    if not isinstance(selector, dict) or (
        not explicit and not is_sign_in_label(selector.get("name", ""))
    ):
        raise UIAutomationError("No verified Sign in button is bound")

    name = str(selector.get("name", "")).strip()
    if not name:
        raise UIAutomationError("The saved Sign in action has no accessible name")

    identity_mode = str(selector.get("identity_mode", "exact_metadata")).casefold()
    candidates = [
        button
        for button in snapshot.buttons
        if button.visible and button.enabled and button.name == name
    ]

    if identity_mode == "exact_metadata":
        automation_id = str(selector.get("automation_id", ""))
        class_name = str(selector.get("class_name", ""))
        framework_id = str(selector.get("framework_id", ""))
        if not (automation_id or class_name):
            raise UIAutomationError("The saved Sign in button has no stable automation/class identity")
        matches = [
            button
            for button in candidates
            if (
                button.automation_id == automation_id
                and button.class_name == class_name
                and button.framework_id == framework_id
            )
        ]
    elif identity_mode == "unique_name":
        if not explicit:
            raise UIAutomationError("Name-only Sign in mappings must be explicitly approved")
        # Executable, window, and desktop credential binding are already verified.
        # Never fall back to geometry, index, Enter, or coordinate clicks.
        matches = candidates
    else:
        raise UIAutomationError("The saved Sign in button identity mode is invalid")

    if len(matches) != 1:
        raise UIAutomationError("The saved Sign in button is ambiguous or changed")
    return matches[0]


def fill_desktop_entry(entry: dict[str, Any], snapshot: WindowSnapshot | None = None,
                       *, guard: Callable[[], None] | None = None, sign_in: bool = False) -> bool:
    _require_windows()
    if guard: guard()
    if snapshot is not None:
        validate_desktop_entry(entry, snapshot)  # Reject a known mismatch even before live OS access.
    hwnd = snapshot.hwnd if snapshot else None
    # A chooser/unlock dialog may have taken time: refresh the target immediately
    # before releasing credentials rather than trusting the earlier snapshot.
    current = scan_window(hwnd, include_buttons=sign_in, include_all_buttons=sign_in) if hwnd else scan_foreground_window(include_buttons=sign_in, include_all_buttons=sign_in)
    if guard: guard()
    username_control, password_control = validate_desktop_entry(entry, current)
    _restore_foreground(current.hwnd)
    if guard: guard()
    username = str(entry.get("username", ""))
    if username and username_control is not None:
        _write_control(username_control, username, current.hwnd, guard)
    _write_control(password_control, str(entry.get("password", "")), current.hwnd, guard)
    if not sign_in: return False
    selector = entry.get("scope", {}).get("sign_in_selector")
    if not isinstance(selector, dict): return False
    # The control tree can change as the app reacts to the newly filled fields.
    fresh = scan_window(current.hwnd, include_buttons=True, include_all_buttons=True)
    if guard: guard()
    validate_desktop_entry(entry, fresh)
    button = resolve_sign_in_button(fresh, selector)
    import win32gui
    if int(win32gui.GetForegroundWindow()) != current.hwnd:
        raise UIAutomationError("Sign-in cancelled because the target lost focus")
    if guard: guard()
    try:
        button.wrapper.iface_invoke.Invoke()
    except Exception:
        raise UIAutomationError("Fields were filled, but the Sign in button could not be invoked. Click it manually.") from None
    return True


def inspect_main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect only metadata for edit controls in the foreground Windows app."
    )
    parser.add_argument("--delay", type=float, default=3.0, help="Seconds to switch to the target")
    args = parser.parse_args()
    if args.delay > 0:
        print(
            f"Switch to the target login window; inspecting in {args.delay:g} seconds...",
            flush=True,
        )
        time.sleep(args.delay)
    snapshot = scan_foreground_window()
    print(json.dumps(snapshot.public_dict(), indent=2, ensure_ascii=False))
