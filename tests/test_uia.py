import pytest

import localvault.uia as uia
from localvault.uia import (
    ControlDescriptor,
    UIAutomationError,
    WindowSnapshot,
    fill_desktop_entry,
    resolve_control,
)


def control(
    index: int,
    *,
    name: str = "",
    automation_id: str = "",
    class_name: str = "Edit",
    framework_id: str = "Win32",
    is_password: bool = False,
) -> ControlDescriptor:
    return ControlDescriptor(
        index=index,
        name=name,
        automation_id=automation_id,
        class_name=class_name,
        framework_id=framework_id,
        is_password=is_password,
        enabled=True,
        visible=True,
        rectangle=(0, 0, 100, 20),
    )


def test_selector_requires_identity_not_only_field_type() -> None:
    controls = [control(0), control(1)]
    assert resolve_control(controls, {"is_password": False}) is None


def test_selector_prefers_exact_automation_id_and_type() -> None:
    controls = [
        control(0, automation_id="username"),
        control(1, automation_id="password", is_password=True),
    ]
    selected = resolve_control(
        controls,
        {
            "index": 1,
            "automation_id": "password",
            "class_name": "Edit",
            "framework_id": "Win32",
            "is_password": True,
        },
    )
    assert selected is controls[1]


def test_protected_selector_never_resolves_unprotected_control() -> None:
    controls = [control(0, automation_id="password", is_password=False)]
    assert (
        resolve_control(
            controls,
            {"automation_id": "password", "is_password": True},
        )
        is None
    )


def test_unprotected_password_mapping_requires_strong_match() -> None:
    controls = [control(0, name="Password", is_password=False)]
    selector = {
        "index": 0,
        "name": "Password",
        "class_name": "Edit",
        "framework_id": "Win32",
        "is_password": False,
    }
    assert resolve_control(controls, selector, minimum_score=60) is controls[0]


def test_fill_does_not_fall_back_to_only_protected_field(monkeypatch) -> None:
    monkeypatch.setattr(uia, "_require_windows", lambda: None)
    only_password = control(0, automation_id="changed", is_password=True)
    snapshot = WindowSnapshot(
        hwnd=1,
        pid=2,
        title="Sign in",
        exe_path="/apps/example.exe",
        exe_sha256="A" * 64,
        controls=[only_password],
        signer=None,
    )
    entry = {
        "username": "alice",
        "password": "secret",
        "scope": {
            "exe_path": "/apps/example.exe",
            "exe_sha256": "A" * 64,
            "window_title": "Sign in",
            "control_fingerprint": [only_password.fingerprint()],
            "username_selector": None,
            "password_selector": {
                "index": 99,
                "automation_id": "original",
                "class_name": "Unknown",
                "framework_id": "Unknown",
                "is_password": True,
            },
        },
    }
    with pytest.raises(UIAutomationError, match="No protected password control"):
        fill_desktop_entry(entry, snapshot)


def test_selector_resolution_rejects_ambiguous_equal_matches() -> None:
    controls = [
        control(0, class_name="Edit", framework_id="Win32"),
        control(1, class_name="Edit", framework_id="Win32"),
    ]
    selector = {
        "class_name": "Edit",
        "framework_id": "Win32",
        "is_password": False,
    }
    assert resolve_control(controls, selector, minimum_score=25) is None


def test_fill_rejects_changed_executable_hash(monkeypatch) -> None:
    monkeypatch.setattr(uia, "_require_windows", lambda: None)
    password = control(0, automation_id="password", is_password=True)
    snapshot = WindowSnapshot(
        hwnd=1,
        pid=2,
        title="Sign in",
        exe_path="/apps/example.exe",
        exe_sha256="B" * 64,
        controls=[password],
        signer=None,
    )
    entry = {
        "username": "alice",
        "password": "secret",
        "scope": {
            "exe_path": "/apps/example.exe",
            "exe_sha256": "A" * 64,
            "window_title": "Sign in",
            "control_fingerprint": [password.fingerprint()],
            "username_selector": None,
            "password_selector": password.selector(),
        },
    }
    with pytest.raises(UIAutomationError, match="binary no longer matches"):
        fill_desktop_entry(entry, snapshot)


def test_fill_rejects_changed_control_layout(monkeypatch) -> None:
    monkeypatch.setattr(uia, "_require_windows", lambda: None)
    password = control(0, automation_id="password", is_password=True)
    snapshot = WindowSnapshot(
        hwnd=1,
        pid=2,
        title="Sign in",
        exe_path="/apps/example.exe",
        exe_sha256="A" * 64,
        controls=[password],
        signer=None,
    )
    entry = {
        "username": "alice",
        "password": "secret",
        "scope": {
            "exe_path": "/apps/example.exe",
            "exe_sha256": "A" * 64,
            "window_title": "Sign in",
            "control_fingerprint": [
                {
                    **password.fingerprint(),
                    "automation_id": "old-password",
                }
            ],
            "username_selector": None,
            "password_selector": password.selector(),
        },
    }
    with pytest.raises(UIAutomationError, match="control layout changed"):
        fill_desktop_entry(entry, snapshot)


def test_desktop_entry_matches_only_exact_bound_snapshot() -> None:
    password = control(1, automation_id="password", is_password=True)
    username = control(0, automation_id="username")
    snapshot = WindowSnapshot(
        hwnd=1,
        pid=2,
        title="Sign in",
        exe_path="/apps/example.exe",
        exe_sha256="A" * 64,
        controls=[username, password],
        signer=None,
    )
    entry = {
        "username": "alice",
        "password": "secret",
        "scope": {
            "exe_path": "/apps/example.exe",
            "exe_sha256": "A" * 64,
            "window_title": "Sign in",
            "control_fingerprint": [username.fingerprint(), password.fingerprint()],
            "username_selector": username.selector(),
            "password_selector": password.selector(),
        },
    }
    assert uia.desktop_entry_matches_snapshot(entry, snapshot)

    changed = WindowSnapshot(
        hwnd=1,
        pid=2,
        title="Different window",
        exe_path="/apps/example.exe",
        exe_sha256="A" * 64,
        controls=[username, password],
        signer=None,
    )
    assert not uia.desktop_entry_matches_snapshot(entry, changed)


def test_strict_identity_rehashes_but_reuses_signer_for_identical_digest(monkeypatch) -> None:
    uia._cached_authenticode_for_digest.cache_clear()
    hashes = []
    signer_calls = []

    def fake_hash(path: str) -> str:
        hashes.append(path)
        return "C" * 64

    def fake_signer(path: str):
        signer_calls.append(path)
        return {"status": "Valid", "thumbprint": "D" * 40}

    monkeypatch.setattr(uia, "file_sha256", fake_hash)
    monkeypatch.setattr(uia, "authenticode_info", fake_signer)

    first = uia._executable_identity("/apps/example.exe", allow_cache=False)
    second = uia._executable_identity("/apps/example.exe", allow_cache=False)

    assert first == second
    assert len(hashes) == 2
    assert len(signer_calls) == 1


def _bound_entry(username, password, signer=None):
    scope = {
        "exe_path": "/apps/example.exe",
        "exe_sha256": "A" * 64,
        "window_title": "Sign in",
        "control_fingerprint": [username.fingerprint(), password.fingerprint()],
        "username_selector": username.selector(),
        "password_selector": password.selector(),
    }
    if signer:
        scope["signer"] = signer
    return {"username": "alice", "password": "secret", "scope": scope}


def _updated_snapshot(controls, *, exe_path="/apps/example.exe", signer=None, title="Sign in v2"):
    return WindowSnapshot(
        hwnd=1, pid=2, title=title, exe_path=exe_path,
        exe_sha256="B" * 64, controls=controls, signer=signer,
    )


def test_unsigned_app_update_is_recognised_but_needs_confirmation() -> None:
    username = control(0, automation_id="username")
    password = control(1, automation_id="password", is_password=True)
    extra = control(2, automation_id="remember")
    entry = _bound_entry(username, password)
    snapshot = _updated_snapshot([username, password, extra])
    assert not uia.desktop_entry_matches_snapshot(entry, snapshot)

    result = uia.updated_binary_binding(entry, snapshot)
    assert result is not None
    updated, signer_verified = result
    assert signer_verified is False
    assert updated["scope"]["exe_sha256"] == "B" * 64
    assert uia.desktop_entry_matches_snapshot(updated, snapshot)
    assert entry["scope"]["exe_sha256"] == "A" * 64


def test_signed_app_update_requires_same_signer() -> None:
    username = control(0, automation_id="username")
    password = control(1, automation_id="password", is_password=True)
    signer = {"status": "Valid", "thumbprint": "D" * 40}
    entry = _bound_entry(username, password, signer)

    same = uia.updated_binary_binding(entry, _updated_snapshot([username, password], signer=signer))
    assert same is not None and same[1] is True

    other = {"status": "Valid", "thumbprint": "E" * 40}
    assert uia.updated_binary_binding(entry, _updated_snapshot([username, password], signer=other)) is None
    assert uia.updated_binary_binding(entry, _updated_snapshot([username, password], signer=None)) is None


def test_update_is_rejected_for_other_path_or_missing_fields() -> None:
    username = control(0, automation_id="username")
    password = control(1, automation_id="password", is_password=True)
    entry = _bound_entry(username, password)
    assert uia.updated_binary_binding(entry, _updated_snapshot([username, password], exe_path="/apps/other.exe")) is None
    assert uia.updated_binary_binding(entry, _updated_snapshot([username])) is None


def test_same_binary_with_changed_window_is_adopted_without_confirmation() -> None:
    username = control(0, automation_id="username")
    password = control(1, automation_id="password", is_password=True)
    extra = control(2, automation_id="remember")
    entry = _bound_entry(username, password)
    snapshot = WindowSnapshot(
        hwnd=1, pid=2, title="DeCave", exe_path="/apps/example.exe",
        exe_sha256="A" * 64, controls=[username, password, extra], signer=None,
    )
    assert not uia.desktop_entry_matches_snapshot(entry, snapshot)

    result = uia.updated_binary_binding(entry, snapshot)
    assert result is not None
    updated, signer_verified = result
    assert signer_verified is True
    assert updated["scope"]["window_title"] == "DeCave"
    assert uia.desktop_entry_matches_snapshot(updated, snapshot)
