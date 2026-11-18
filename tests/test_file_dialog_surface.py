"""A file dialog asked for while the main window is hidden in the tray shows the window first (found 2026-11-13)."""
import sys
from types import SimpleNamespace

from localvault.web.window import FileDialogs


class FakeWindow:
    def __init__(self):
        self.calls = []

    def restore(self):
        self.calls.append("restore")

    def show(self):
        self.calls.append("show")

    def create_file_dialog(self, kind, **_kw):
        self.calls.append(("dialog", kind))
        return ["C:/x.lgk"]


def test_dialogs_show_hidden_window_first(monkeypatch):
    monkeypatch.setitem(sys.modules, "webview",
                        SimpleNamespace(FileDialog=SimpleNamespace(OPEN="open", SAVE="save", FOLDER="folder")))
    for call in (lambda d: d.open_file("t"), lambda d: d.save_file("t", "n.lgk"), lambda d: d.choose_folder("t")):
        window = FakeWindow()
        assert call(FileDialogs(window)) is not None
        assert window.calls[:2] == ["restore", "show"]
        assert window.calls[2][0] == "dialog"
