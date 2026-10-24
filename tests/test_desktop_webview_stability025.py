import pytest

from localvault.uia import (
    ControlDescriptor,
    UIAutomationError,
    WindowSnapshot,
    validate_desktop_entry,
)


def c(index, aid, cls, framework, password=False, rect=(10,10,200,30)):
    return ControlDescriptor(index=index, name="" if password else aid, automation_id=aid,
        class_name=cls, framework_id=framework, is_password=password, enabled=True,
        visible=True, rectangle=rect, wrapper=None)

def snap(controls=None, exe_hash="A"*64, title="Sign in to DeCave"):
    return WindowSnapshot(hwnd=101,pid=999,title=title,exe_path=r"C:\Apps\DeCave\DeCave.exe",
        exe_sha256=exe_hash,signer=None,controls=controls or [
            c(0,"email","Chrome_RenderWidgetHostHWND","Chrome"),
            c(1,"password","Chrome_RenderWidgetHostHWND","Chrome",True)],buttons=[])

def sel(x):
    return {"index":x.index,"name":x.name,"automation_id":x.automation_id,
        "class_name":x.class_name,"framework_id":x.framework_id,"is_password":x.is_password}

def entry(s, mode):
    return {"kind":"desktop","scope":{"exe_path":s.exe_path,"exe_sha256":s.exe_sha256,
        "window_title":s.title,"control_fingerprint":s.control_fingerprint(),
        "username_selector":sel(s.controls[0]),"password_selector":sel(s.controls[1]),
        "binding_mode":mode}}

def test_embedded_tolerates_layout_geometry_churn():
    original=snap(); saved=entry(original,"embedded_web_volatile")
    changed=snap([c(7,"decor","Chrome_WidgetWin_0","Chrome",False,(1,1,2,2)),  # unrelated node
                  c(3,"email","Chrome_RenderWidgetHostHWND","Chrome",False,(500,100,700,140)),
                  c(4,"password","Chrome_RenderWidgetHostHWND","Chrome",True,(500,150,700,190))])
    user,password=validate_desktop_entry(saved,changed)
    assert user.automation_id=="email" and password.automation_id=="password"

def test_native_still_rejects_layout_change():
    original=snap([c(0,"email","Edit","Win32"),c(1,"password","Edit","Win32",True)])
    saved=entry(original,"strict")
    changed=snap([c(0,"email","Edit","Win32",False,(20,20,220,50)),
                  c(1,"password","Edit","Win32",True,(20,70,220,100)),
                  c(2,"extra","Edit","Win32",False,(20,120,220,150))])
    with pytest.raises(UIAutomationError,match="layout changed"):
        validate_desktop_entry(saved,changed)

def test_embedded_rejects_hash_change():
    original=snap(); saved=entry(original,"embedded_web_volatile")
    with pytest.raises(UIAutomationError):
        validate_desktop_entry(saved,snap(exe_hash="B"*64))

def test_embedded_rejects_title_change():
    original=snap(); saved=entry(original,"embedded_web_volatile")
    with pytest.raises(UIAutomationError):
        validate_desktop_entry(saved,snap(title="Different Window"))

def test_embedded_rejects_ambiguous_password():
    original=snap(); saved=entry(original,"embedded_web_volatile")
    changed=snap([c(2,"email","Chrome_RenderWidgetHostHWND","Chrome"),
                  c(3,"password","Chrome_RenderWidgetHostHWND","Chrome",True),
                  c(4,"password","Chrome_RenderWidgetHostHWND","Chrome",True)])
    with pytest.raises(UIAutomationError):
        validate_desktop_entry(saved,changed)

def test_volatile_mode_refuses_native_selector():
    original=snap([c(0,"email","Edit","Win32"),c(1,"password","Edit","Win32",True)])
    saved=entry(original,"embedded_web_volatile")
    with pytest.raises(UIAutomationError,match="embedded web"):
        validate_desktop_entry(saved,original)


def test_discord_stable_binding_ignores_version_hash_title_and_layout(monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
    original = snap()
    original.exe_path = r"C:\Users\test\AppData\Local\Discord\app-1.0.1\Discord.exe"
    saved = entry(original, "discord_stable")
    changed = WindowSnapshot(
        hwnd=202,
        pid=1000,
        title="discord.com/app?version=2",
        exe_path=r"C:\Users\test\AppData\Local\Discord\app-1.0.2\Discord.exe",
        exe_sha256="B" * 64,
        signer={"status": "Valid", "subject": "CN=Discord Inc., O=Discord Inc.", "thumbprint": "A"},
        controls=[
            c(4, "new-email", "Chrome_RenderWidgetHostHWND", "Chrome"),
            c(8, "new-password", "Chrome_RenderWidgetHostHWND", "Chrome", True),
        ],
        buttons=[],
    )
    user, password = validate_desktop_entry(saved, changed)
    assert user.automation_id == "new-email"
    assert password.automation_id == "new-password"


def test_discord_stable_requires_discord_executable():
    original = snap()
    original.exe_path = r"C:\Users\test\Discord\app-1.0.1\Discord.exe"
    saved = entry(original, "discord_stable")
    changed = snap()
    with pytest.raises(UIAutomationError, match="Executable mismatch"):
        validate_desktop_entry(saved, changed)


def test_discord_stable_requires_verified_discord_signer(monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
    original = snap()
    original.exe_path = r"C:\Users\test\AppData\Local\Discord\app-1.0.1\Discord.exe"
    saved = entry(original, "discord_stable")
    changed = snap()
    changed.exe_path = r"C:\Users\test\AppData\Local\Discord\app-1.0.2\Discord.exe"
    changed.signer = {"status": "Valid", "subject": "CN=Untrusted Publisher"}
    with pytest.raises(UIAutomationError, match="not signed by Discord Inc"):
        validate_desktop_entry(saved, changed)
