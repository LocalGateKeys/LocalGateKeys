import pytest

from localvault.uia import (
    ControlDescriptor,
    UIAutomationError,
    WindowSnapshot,
    validate_desktop_entry,
)


def ctrl(index, *, aid="", name="", cls="Edit", framework="Win32", password=False):
    return ControlDescriptor(
        index=index,
        name=name,
        automation_id=aid,
        class_name=cls,
        framework_id=framework,
        is_password=password,
        enabled=True,
        visible=True,
        rectangle=(10, 10 + 45 * index, 280, 40 + 45 * index),
        wrapper=None,
    )


def snap(controls):
    return WindowSnapshot(
        hwnd=11,
        pid=0,
        title="DeCave",
        exe_path=r"C:\Apps\DeCave\DeCave.exe",
        exe_sha256="A" * 64,
        signer=None,
        controls=controls,
        buttons=[],
    )


def selector(c):
    return {
        "index": c.index,
        "name": c.name,
        "automation_id": c.automation_id,
        "class_name": c.class_name,
        "framework_id": c.framework_id,
        "is_password": c.is_password,
    }


def saved_entry(original):
    return {
        "kind": "desktop",
        "scope": {
            "exe_path": original.exe_path,
            "exe_sha256": original.exe_sha256,
            "window_title": original.title,
            "control_fingerprint": original.control_fingerprint(),
            "username_selector": selector(original.controls[0]),
            "password_selector": selector(original.controls[1]),
            "binding_mode": "dynamic_layout",
        },
    }


def test_dynamic_layout_survives_recreated_field_metadata():
    original = snap([
        ctrl(0, aid="email-old", name="Email", cls="OldEdit"),
        ctrl(1, aid="password-old", cls="OldPassword", password=True),
    ])
    entry = saved_entry(original)

    # Same verified application/login role, but the accessibility provider has
    # recreated the controls with different ids/classes/indexes.
    current = snap([
        ctrl(7, aid="email-new", name="", cls="WebInput"),
        ctrl(8, aid="password-new", cls="WebInput", password=True),
    ])

    username, password = validate_desktop_entry(entry, current)
    assert username is not None
    assert username.index == 7
    assert password.index == 8
    assert password.is_password


def test_dynamic_layout_refuses_multiple_password_candidates():
    original = snap([
        ctrl(0, aid="email-old"),
        ctrl(1, aid="password-old", password=True),
    ])
    entry = saved_entry(original)
    current = snap([
        ctrl(4, aid="email-new"),
        ctrl(5, aid="password-a", password=True),
        ctrl(6, aid="password-b", password=True),
    ])
    with pytest.raises(UIAutomationError, match="exactly one protected password"):
        validate_desktop_entry(entry, current)


def test_dynamic_layout_refuses_ambiguous_username_candidates():
    original = snap([
        ctrl(0, aid="email-old"),
        ctrl(1, aid="password-old", password=True),
    ])
    entry = saved_entry(original)
    current = snap([
        ctrl(3, aid="first-text"),
        ctrl(4, aid="second-text"),
        ctrl(5, aid="password-new", password=True),
    ])
    with pytest.raises(UIAutomationError, match="exactly one username"):
        validate_desktop_entry(entry, current)


def test_dynamic_layout_does_not_fallback_for_unprotected_password():
    original = snap([
        ctrl(0, aid="email-old"),
        ctrl(1, aid="password-old", password=False),
    ])
    entry = saved_entry(original)
    current = snap([
        ctrl(3, aid="email-new"),
        ctrl(4, aid="password-new", password=False),
    ])
    with pytest.raises(UIAutomationError):
        validate_desktop_entry(entry, current)
