"""Command registry and ranking for the Ctrl+K palette (no Tk)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ..app.catalog import (
    _summary_title,
    kind_label,
    parse_search_query,
    rank_search_results,
    search_fields,
    search_rank,
)

GROUP_ORDER = ("Actions", "Items", "Settings", "Help")


@dataclass(frozen=True)
class Command:
    """One action reachable by name.

    The palette invokes it as ``getattr(app, method)(*args, **dict(kwargs))``.
    """

    id: str
    title: str
    subtitle: str
    group: Literal["Actions", "Settings", "Help"]
    method: str
    args: tuple = ()
    kwargs: tuple[tuple[str, object], ...] = ()
    keywords: tuple[str, ...] = ()
    requires_unlock: bool = True


@dataclass(frozen=True)
class PaletteRow:
    kind: Literal["item", "command"]
    title: str
    subtitle: str
    group: str
    ref: object


def _c(id, title, subtitle, method, *, group="Actions", args=(), kwargs=(), keywords=(), requires_unlock=True):
    return Command(id, title, subtitle, group, method, args, kwargs, keywords, requires_unlock)


_SETTINGS_SECTIONS = (
    ("locking", "Locking", "Auto-lock and idle timeouts", ("lock", "timeout", "idle", "auto-lock")),
    ("unlocking", "Unlocking", "Windows Hello, face and passkey unlock", ("hello", "face", "passkey", "biometric")),
    ("privacy", "Privacy", "Clipboard and screen protection", ("clipboard", "screenshot")),
    ("autofill", "Autofill", "Browser and desktop filling", ("fill", "browser", "extension")),
    ("appearance", "Appearance", "Theme, density and text size", ("theme", "dark", "light", "density")),
    ("backups", "Backups", "Backup folder and schedule", ("backup", "schedule", "folder")),
    ("plan", "Plan & sync", "Licence, Pro and device sync", ("licence", "license", "pro", "upgrade", "sync")),
    ("help", "Help & diagnostics", "Shortcuts, setup guide and error log", ("diagnostics", "log", "support")),
)

COMMANDS: tuple[Command, ...] = (
    _c("backup-now", "Back up now", "Save an encrypted backup", "recovery_center_clicked",
       kwargs=(("allow_locked", True),), keywords=("backup", "save"), requires_unlock=False),
    _c("backup-verify", "Verify a backup", "Check that a backup opens", "recovery_center_clicked",
       kwargs=(("initial", "verify"),), keywords=("backup", "check")),
    _c("backup-restore", "Restore from backup…", "Bring items back from a backup", "recovery_center_clicked",
       kwargs=(("initial", "restore"),), keywords=("backup", "recover")),
    _c("recovery-kit", "Write recovery kit", "Print or save your recovery kit", "recovery_center_clicked",
       kwargs=(("initial", "kit"),), keywords=("backup", "recover", "emergency")),
    _c("generate-password", "Generate password", "Create a strong password", "password_generator_clicked",
       keywords=("passphrase", "random")),
    _c("new-item", "New item", "Add a login, card, note or other item", "new_typed_item_clicked",
       keywords=("add", "create", "login", "card", "note")),
    _c("quick-access", "Quick access", "Open the quick access window", "quick_access_clicked",
       keywords=("fill", "launcher")),
    _c("lock-now", "Lock now", "Lock the vault", "lock", keywords=("secure",)),
    _c("emergency-lock", "Emergency lock", "Lock and clear sensitive state", "emergency_lock",
       keywords=("panic", "lock")),
    _c("switch-profile", "Switch profile", "Open another vault profile", "profiles_clicked",
       keywords=("vault", "account"), requires_unlock=False),
    _c("change-master", "Change master password", "Choose a new master password", "change_master_clicked",
       keywords=("passphrase", "credentials")),
    _c("security-center", "Security center", "Weak, reused and 2FA-missing items", "security_health_clicked",
       keywords=("2fa", "health", "weak", "reused", "breach", "audit")),
    _c("export", "Export vault", "Save your items to a file", "export_clicked", keywords=("csv", "download")),
    _c("import", "Import items", "Bring in items from another manager", "import_clicked",
       keywords=("csv", "browser", "upload")),
    _c("encrypted-transfer", "Encrypted transfer", "Move items to another device as an encrypted package",
       "transfer_clicked", keywords=("transfer", "device", "package", "migrate")),
    _c("typed-items", "Typed items", "Cards, identities, notes and more", "typed_items_clicked",
       keywords=("cards", "identity", "notes")),
    _c("reminders", "Reminders", "Expiring and overdue items", "reminders_clicked",
       keywords=("expiry", "due", "rotate")),
    _c("trash", "Trash", "Recently deleted items", "trash_clicked", keywords=("deleted", "restore")),
    _c("activity", "Activity", "Recent vault activity", "activity_clicked", keywords=("log", "history", "audit")),
    _c("devices-sync", "Devices & connections", "Browser extension connection and diagnostics",
       "connections_clicked", keywords=("extension", "browser", "bridge")),
    _c("sync-settings", "Sync", "Wi-Fi and cloud-folder sync between your devices", "sync_settings_clicked",
       keywords=("sync", "cloud", "folder", "wifi", "pair", "qr", "devices")),
    _c("safe-workspace", "Safe workspace", "Open a protected workspace", "safe_workspace_clicked",
       keywords=("sandbox", "workspace")),
    _c("check-updates", "Check for updates", "Look for a newer version", "check_updates_clicked",
       keywords=("upgrade", "version"), requires_unlock=False),
    _c("settings", "Settings", "Open settings", "settings_clicked", group="Settings",
       keywords=("preferences", "options")),
    *(
        _c(f"settings-{name}", title, subtitle, "settings_clicked", group="Settings",
           kwargs=(("section", name),), keywords=("settings", *extra))
        for name, title, subtitle, extra in _SETTINGS_SECTIONS
    ),
    _c("shortcuts", "Keyboard shortcuts", "See every shortcut", "show_shortcuts_clicked", group="Help",
       keywords=("keys", "hotkeys", "help"), requires_unlock=False),
    _c("setup-guide", "Setup guide", "Walk through first-run setup", "onboarding_clicked", group="Help",
       keywords=("onboarding", "tour", "help"), requires_unlock=False),
    _c("error-log", "Open error log", "Show the diagnostic log", "open_error_log_clicked", group="Help",
       keywords=("diagnostics", "debug", "help"), requires_unlock=False),
)

_MIN_ITEM_ROWS = 4
_SCOPE_GROUPS = {"actions": "Actions", "items": "Items", "settings": "Settings", "help": "Help"}


def registered_section_commands() -> tuple[Command, ...]:
    """Ctrl+K rows for Settings sections registered after start-up (Licence, Sync, …)."""

    from .settings_sections import sections

    built_in = {name for name, *_rest in _SETTINGS_SECTIONS}
    return tuple(
        _c(f"settings-{item.key}", item.title, item.subtitle or "Settings", "settings_clicked",
           group="Settings", kwargs=(("section", item.key),), keywords=("settings", *item.keywords))
        for item in sections() if item.key not in built_in
    )


def _command_row(command: Command) -> PaletteRow:
    return PaletteRow("command", command.title, command.subtitle, command.group, command)


def _item_row(summary: Any) -> PaletteRow:
    subtitle = str(getattr(summary, "username", "") or "") or kind_label(str(getattr(summary, "kind", "") or ""))
    return PaletteRow("item", _summary_title(summary), subtitle, "Items", summary)


def palette_results(query: str, summaries: list, *, unlocked: bool, scope: str = "everything",
                    limit: int = 12) -> list[PaletteRow]:
    """Rows for the palette: Actions, Items, Settings, then Help, best match first."""

    group_filter = _SCOPE_GROUPS.get(str(scope or "").casefold())
    commands = [c for c in (*COMMANDS, *registered_section_commands()) if (unlocked or not c.requires_unlock)
                and (group_filter is None or c.group == group_filter)]
    if not str(query or "").strip():
        return [_command_row(c) for c in commands][:max(0, limit)]

    tokens = parse_search_query(query)
    ranked: list[tuple[int, int, Command]] = []
    for index, command in enumerate(commands):
        fields = {"title": command.title.casefold(), "keywords": " ".join(command.keywords).casefold()}
        rank = search_rank(fields, tokens)
        if rank is not None:
            ranked.append((rank, index, command))
    ranked.sort(key=lambda r: r[:2])

    by_group: dict[str, list[PaletteRow]] = {name: [] for name in GROUP_ORDER}
    for _rank, _index, command in ranked:
        by_group[command.group].append(_command_row(command))
    if unlocked and group_filter in (None, "Items"):
        rows = [(s, search_fields(s)) for s in summaries]
        by_group["Items"] = [_item_row(s) for s in rank_search_results(rows, query)]

    limit = max(0, limit)
    items = by_group["Items"]
    # Broad queries must not push every item row off the list: keep room for
    # up to _MIN_ITEM_ROWS items, and give items whatever commands leave unused.
    reserved = min(len(items), _MIN_ITEM_ROWS, limit)
    command_budget = limit - reserved
    out: list[PaletteRow] = []
    commands_taken = 0
    for name in GROUP_ORDER:
        if name == "Items":
            continue
        taken = by_group[name][:max(0, command_budget - commands_taken)]
        by_group[name] = taken
        commands_taken += len(taken)
    by_group["Items"] = items[:limit - commands_taken]
    for name in GROUP_ORDER:
        out.extend(by_group[name])
    return out
