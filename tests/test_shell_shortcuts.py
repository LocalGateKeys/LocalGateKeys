"""Main-window keyboard shortcuts: binding table, cheat sheet and Ctrl+T."""
from __future__ import annotations



from localvault.hotkey import MAIN_WINDOW_SHORTCUTS, shortcut_cheat_sheet_rows


def _sequences() -> set[str]:
    return {sequence for shortcut in MAIN_WINDOW_SHORTCUTS for sequence in shortcut.sequences}


def test_binding_table_covers_required_shortcuts() -> None:
    sequences = _sequences()
    for required in ("<Control-k>", "<Control-f>", "<Control-l>", "<Control-n>", "<Control-Shift-C>",
                     "<Control-t>", "<Control-comma>", "<F1>", "<question>"):
        assert required in sequences, required
    by_keys = {shortcut.keys: shortcut for shortcut in MAIN_WINDOW_SHORTCUTS}
    assert by_keys["Ctrl+K"].method == "open_palette"
    assert by_keys["Ctrl+F"].method == "_focus_search"
    assert by_keys["Ctrl+N"].method == "new_item_shortcut"
    assert by_keys["Ctrl+Shift+C"].method == "copy_selected_username_clicked"
    assert by_keys["Ctrl+T"].method == "copy_selected_totp_clicked"
    assert by_keys["Ctrl+,"].method == "settings_clicked"
    for shortcut in MAIN_WINDOW_SHORTCUTS:
        assert shortcut.label and shortcut.description
    # The "?" key must never fire while the user is typing in a text field.
    assert by_keys["F1 or ?"].guard_text_fields is True


def test_cheat_sheet_lists_every_binding_and_global_hotkeys() -> None:
    rows = shortcut_cheat_sheet_rows("Ctrl+Alt+K")
    keys = {row[1] for row in rows}
    for shortcut in MAIN_WINDOW_SHORTCUTS:
        assert shortcut.keys in keys, shortcut.keys
    for required in ("Ctrl+Alt+L", "Ctrl+Alt+K", "Ctrl+Shift+Space", "Ctrl+C", "Delete"):
        assert required in keys, required
    groups = {row[0] for row in rows}
    assert {"Main window", "Saved items", "Anywhere in Windows"} <= groups
    assert all(len(row) == 3 and row[2] for row in rows)


