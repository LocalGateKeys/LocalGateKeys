from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = [
    *sorted((ROOT / "src").rglob("*.py")),
    *sorted((ROOT / "browser-extension").glob("*.js")),
]
BANNED_PRIMITIVES = {
    "SetWindowsHookEx": "global Windows hook",
    "WH_KEYBOARD": "keyboard hook",
    "GetAsyncKeyState": "global key-state polling",
    "ReadProcessMemory": "process-memory credential access",
    "GetClipboardData": "clipboard monitoring",
    "pyperclip": "clipboard library",
    "pynput": "global input listener",
    "keyboard.hook": "global keyboard hook",
    "ImageGrab": "screen capture",
    "BitBlt": "screen capture",
    "get_value(": "UI Automation value read",
    ".texts()": "UI Automation text extraction",
    "CurrentValue": "UI Automation value property read",
    "ValuePattern.Value": "UI Automation value property read",
}


def test_source_contains_no_generic_credential_capture_primitives() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in SOURCE_FILES)
    found = [description for token, description in BANNED_PRIMITIVES.items() if token in combined]
    assert not found, f"Unsafe capture primitives found: {found}"
