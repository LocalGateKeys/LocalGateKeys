import pytest

from localvault.uia import (
    ControlDescriptor,
    UIAutomationError,
    WindowSnapshot,
    resolve_sign_in_button,
)


def button(name: str, *, aid: str = "submit", cls: str = "Button", framework: str = "Chrome"):
    return ControlDescriptor(
        index=0,
        name=name,
        automation_id=aid,
        class_name=cls,
        framework_id=framework,
        is_password=False,
        enabled=True,
        visible=True,
        rectangle=(1, 1, 100, 30),
        wrapper=None,
    )


def snapshot(btns):
    return WindowSnapshot(
        hwnd=1,
        pid=2,
        title="DeCave",
        exe_path=r"C:\\Apps\\DeCave\\DeCave.exe",
        exe_sha256="A" * 64,
        controls=[],
        signer=None,
        buttons=btns,
    )


def test_explicitly_mapped_custom_login_label_is_allowed():
    current = button("Enter DeCave")
    selector = current.selector()
    selector["explicit_user_mapping"] = True
    assert resolve_sign_in_button(snapshot([current]), selector) is current


def test_custom_login_label_without_explicit_mapping_is_rejected():
    current = button("Enter DeCave")
    with pytest.raises(UIAutomationError, match="No verified Sign in button"):
        resolve_sign_in_button(snapshot([current]), current.selector())


def test_explicit_mapping_still_requires_exact_identity():
    current = button("Enter DeCave", aid="submit-current")
    selector = current.selector()
    selector["explicit_user_mapping"] = True
    selector["automation_id"] = "different"
    with pytest.raises(UIAutomationError, match="ambiguous or changed"):
        resolve_sign_in_button(snapshot([current]), selector)


def test_explicit_mapping_rejects_ambiguous_duplicates():
    a = button("Enter DeCave")
    b = button("Enter DeCave")
    selector = a.selector()
    selector["explicit_user_mapping"] = True
    with pytest.raises(UIAutomationError, match="ambiguous or changed"):
        resolve_sign_in_button(snapshot([a, b]), selector)
