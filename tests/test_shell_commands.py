from types import SimpleNamespace

from localvault.shell.commands import COMMANDS, palette_results

MORE_MENU_METHODS = {"change_master_clicked", "security_health_clicked", "export_clicked", "emergency_lock",
    "show_shortcuts_clicked", "new_typed_item_clicked", "typed_items_clicked", "reminders_clicked", "trash_clicked",
    "activity_clicked", "connections_clicked", "sync_settings_clicked", "safe_workspace_clicked", "import_clicked",
    "transfer_clicked", "onboarding_clicked", "check_updates_clicked", "open_error_log_clicked"}


def test_every_more_menu_action_has_a_command():
    assert MORE_MENU_METHODS <= {c.method for c in COMMANDS}


def test_command_ids_unique():
    assert len({c.id for c in COMMANDS}) == len(COMMANDS)


def test_kwargs_use_known_keys_only():
    keys = {k for c in COMMANDS for k, _ in c.kwargs}
    assert keys <= {"allow_locked", "initial", "section"}
    assert keys == {"allow_locked", "initial", "section"}


def test_kwargs_values():
    by_title = {c.title: c for c in COMMANDS}
    assert dict(by_title["Back up now"].kwargs) == {"allow_locked": True}
    assert dict(by_title["Verify a backup"].kwargs) == {"initial": "verify"}
    assert dict(by_title["Restore from backup…"].kwargs) == {"initial": "restore"}
    assert dict(by_title["Write recovery kit"].kwargs) == {"initial": "kit"}
    sections = [dict(c.kwargs)["section"] for c in COMMANDS if "section" in dict(c.kwargs)]
    assert sections == ["locking", "unlocking", "privacy", "autofill", "appearance", "backups", "plan", "help"]
    assert all(c.method == "settings_clicked" and c.group == "Settings" for c in COMMANDS if "section" in dict(c.kwargs))


def test_unlock_free_commands():
    free = {c.method for c in COMMANDS if not c.requires_unlock}
    assert free == {"recovery_center_clicked", "profiles_clicked", "show_shortcuts_clicked",
                    "onboarding_clicked", "check_updates_clicked", "open_error_log_clicked"}
    assert [c.title for c in COMMANDS if c.method == "recovery_center_clicked" and not c.requires_unlock] == ["Back up now"]


def test_help_group():
    help_titles = {c.title for c in COMMANDS if c.group == "Help"}
    assert {"Keyboard shortcuts", "Show setup", "Open error log"} <= help_titles


def test_back_finds_backup_actions_first():
    rows = palette_results("back", [], unlocked=True)
    assert rows[0].title == "Back up now" and rows[0].group == "Actions"
    assert {"Verify a backup", "Restore from backup…", "Write recovery kit"} <= {r.title for r in rows}


def test_keyword_match():  # "2fa" reaches the security center via keywords
    assert any(r.ref.method == "security_health_clicked" for r in palette_results("2fa", [], unlocked=True))


def _item(i="1", title="Backblaze"):
    return SimpleNamespace(id=i, kind="web", title=title, username="me", tags=(), scope={}, favorite=False, updated_at=1)


def test_items_grouped_after_actions():
    rows = palette_results("back", [_item()], unlocked=True)
    assert [r.group for r in rows].index("Items") > [r.group for r in rows].index("Actions")
    item_row = next(r for r in rows if r.kind == "item")
    assert item_row.title == "Backblaze" and item_row.ref.id == "1"


def test_locked_never_searches_items():
    rows = palette_results("back", [_item()], unlocked=False)
    assert all(r.kind == "command" for r in rows)


def test_locked_only_offers_unlocked_safe_commands():
    rows = palette_results("", [], unlocked=False, limit=50)
    assert rows and all(not r.ref.requires_unlock for r in rows)
    assert "Back up now" in {r.title for r in rows}


def test_scope_settings_only():
    assert {r.group for r in palette_results("lock", [], unlocked=True, scope="settings")} == {"Settings"}


def test_empty_query_is_registry_order_capped():
    rows = palette_results("", [_item()], unlocked=True, limit=5)
    assert [r.ref.id for r in rows] == [c.id for c in COMMANDS[:5]]


def test_group_order_and_limit():
    rows = palette_results("a", [_item(str(i), f"a{i}") for i in range(30)], unlocked=True, limit=12)
    assert len(rows) <= 12
    order = ["Actions", "Items", "Settings", "Help"]
    idx = [order.index(r.group) for r in rows]
    assert idx == sorted(idx)


def test_broad_query_keeps_at_least_four_item_rows():
    items = [_item(str(i), f"a{i}") for i in range(30)]
    rows = palette_results("a", items, unlocked=True, limit=12)
    assert len(rows) <= 12
    assert sum(r.kind == "item" for r in rows) >= 4


def test_few_items_all_shown_within_limit():
    rows = palette_results("a", [_item("1", "a1"), _item("2", "a2")], unlocked=True, limit=12)
    assert sum(r.kind == "item" for r in rows) == 2 and len(rows) <= 12


def test_import_export_command_is_encrypted_transfer():
    transfer = next(c for c in COMMANDS if c.method == "transfer_clicked")
    assert transfer.title == "Encrypted transfer"
    assert {"transfer", "device", "package"} <= set(transfer.keywords)
    assert not any(c.title == "Import & export" for c in COMMANDS)
