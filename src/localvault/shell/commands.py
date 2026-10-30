"""Command registry and ranking for the Ctrl+K palette (no Tk)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ..i18n import t
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
    title_key: str  # a catalog key (or plain text); ``title`` is the text in the active language
    subtitle_key: str
    group: Literal["Actions", "Settings", "Help"]
    method: str
    args: tuple = ()
    kwargs: tuple[tuple[str, object], ...] = ()
    keywords: tuple[str, ...] = ()
    requires_unlock: bool = True

    @property
    def title(self) -> str:
        return t(self.title_key)

    @property
    def subtitle(self) -> str:
        return t(self.subtitle_key)


@dataclass(frozen=True)
class PaletteRow:
    kind: Literal["item", "command"]
    title: str
    subtitle: str
    group: str
    ref: object


def _c(id, title, subtitle, method, *, group="Actions", args=(), kwargs=(), keywords=(), requires_unlock=True):
    return Command(id, title, subtitle, group, method, args, kwargs, keywords, requires_unlock)


GROUP_KEYS = {"Actions": "palette.group.actions", "Items": "palette.group.items",
              "Settings": "palette.group.settings", "Help": "palette.group.help"}


def group_label(group: str) -> str:
    """The shown name of a palette group; the group id itself stays English."""
    return t(GROUP_KEYS.get(group, group))


_SETTINGS_SECTIONS = (
    ("locking", "command.settings-locking.title", "command.settings-locking.subtitle", ("lock", "timeout", "idle", "auto-lock")),
    ("unlocking", "command.settings-unlocking.title", "command.settings-unlocking.subtitle", ("hello", "face", "passkey", "biometric")),
    ("privacy", "command.settings-privacy.title", "command.settings-privacy.subtitle", ("clipboard", "screenshot")),
    ("autofill", "command.settings-autofill.title", "command.settings-autofill.subtitle", ("fill", "browser", "extension")),
    ("appearance", "command.settings-appearance.title", "command.settings-appearance.subtitle", ("theme", "dark", "light", "density")),
    ("backups", "command.settings-backups.title", "command.settings-backups.subtitle", ("backup", "schedule", "folder")),
    ("plan", "command.settings-plan.title", "command.settings-plan.subtitle", ("licence", "license", "pro", "upgrade", "sync")),
    ("help", "command.settings-help.title", "command.settings-help.subtitle", ("diagnostics", "log", "support")),
)

COMMANDS: tuple[Command, ...] = (
    _c("backup-now", "command.backup-now.title", "command.backup-now.subtitle", "recovery_center_clicked",
       kwargs=(("allow_locked", True),), keywords=("backup", "save"), requires_unlock=False),
    _c("backup-verify", "command.backup-verify.title", "command.backup-verify.subtitle", "recovery_center_clicked",
       kwargs=(("initial", "verify"),), keywords=("backup", "check")),
    _c("backup-restore", "command.backup-restore.title", "command.backup-restore.subtitle", "recovery_center_clicked",
       kwargs=(("initial", "restore"),), keywords=("backup", "recover")),
    _c("recovery-kit", "command.recovery-kit.title", "command.recovery-kit.subtitle", "recovery_center_clicked",
       kwargs=(("initial", "kit"),), keywords=("backup", "recover", "emergency")),
    _c("generate-password", "command.generate-password.title", "command.generate-password.subtitle", "password_generator_clicked",
       keywords=("passphrase", "random")),
    _c("scan-qr", "command.scan-qr.title", "command.scan-qr.subtitle", "scan_qr_clicked",
       keywords=("2fa", "totp", "qr", "authenticator", "two-factor", "import", "photo", "image", "webcam")),
    _c("new-item", "command.new-item.title", "command.new-item.subtitle", "new_typed_item_clicked",
       keywords=("add", "create", "login", "card", "note")),
    _c("quick-access", "command.quick-access.title", "command.quick-access.subtitle", "quick_access_clicked",
       keywords=("fill", "launcher")),
    _c("lock-now", "command.lock-now.title", "command.lock-now.subtitle", "lock", keywords=("secure",)),
    _c("emergency-lock", "command.emergency-lock.title", "command.emergency-lock.subtitle", "emergency_lock",
       keywords=("panic", "lock")),
    _c("switch-profile", "command.switch-profile.title", "command.switch-profile.subtitle", "profiles_clicked",
       keywords=("vault", "account"), requires_unlock=False),
    _c("change-master", "command.change-master.title", "command.change-master.subtitle", "change_master_clicked",
       keywords=("passphrase", "credentials")),
    _c("security-center", "command.security-center.title", "command.security-center.subtitle", "security_health_clicked",
       keywords=("2fa", "health", "weak", "reused", "breach", "audit")),
    _c("security-check", "command.security-check.title", "command.security-check.subtitle", "security_health_clicked",
       kwargs=(("initial", "health"),), keywords=("security", "check", "weak", "reused", "breach", "health")),
    _c("export", "command.export.title", "command.export.subtitle", "export_clicked", keywords=("csv", "download")),
    _c("import", "command.import.title", "command.import.subtitle", "import_clicked",
       keywords=("csv", "browser", "upload")),
    _c("encrypted-transfer", "command.encrypted-transfer.title", "command.encrypted-transfer.subtitle",
       "transfer_clicked", keywords=("transfer", "device", "package", "migrate")),
    _c("share-item", "command.share-item.title", "command.share-item.subtitle", "share_item_clicked",
       keywords=("share", "send", "airdrop", "qr", "lgkshare")),
    _c("receive-share", "command.receive-share.title", "command.receive-share.subtitle", "receive_share_clicked",
       keywords=("share", "receive", "incoming", "lgkshare")),
    _c("typed-items", "command.typed-items.title", "command.typed-items.subtitle", "typed_items_clicked",
       keywords=("cards", "identity", "notes")),
    _c("reminders", "command.reminders.title", "command.reminders.subtitle", "reminders_clicked",
       keywords=("expiry", "due", "rotate")),
    _c("trash", "command.trash.title", "command.trash.subtitle", "trash_clicked", keywords=("deleted", "restore")),
    _c("activity", "command.activity.title", "command.activity.subtitle", "activity_clicked", keywords=("log", "history", "audit")),
    _c("devices-sync", "command.devices-sync.title", "command.devices-sync.subtitle",
       "connections_clicked", keywords=("extension", "browser", "bridge")),
    _c("sync-settings", "command.sync-settings.title", "command.sync-settings.subtitle", "sync_settings_clicked",
       keywords=("sync", "cloud", "folder", "wifi", "pair", "qr", "devices")),
    _c("sync-status", "command.sync-status.title", "command.sync-status.subtitle", "sync_settings_clicked",
       kwargs=(("initial", "status"),), keywords=("sync", "devices", "last", "status")),
    _c("safe-workspace", "command.safe-workspace.title", "command.safe-workspace.subtitle", "safe_workspace_clicked",
       keywords=("sandbox", "workspace")),
    _c("check-updates", "command.check-updates.title", "command.check-updates.subtitle", "check_updates_clicked",
       keywords=("upgrade", "version"), requires_unlock=False),
    _c("settings", "command.settings.title", "command.settings.subtitle", "settings_clicked", group="Settings",
       keywords=("preferences", "options")),
    *(
        _c(f"settings-{name}", title, subtitle, "settings_clicked", group="Settings",
           kwargs=(("section", name),), keywords=("settings", *extra))
        for name, title, subtitle, extra in _SETTINGS_SECTIONS
    ),
    _c("shortcuts", "command.shortcuts.title", "command.shortcuts.subtitle", "show_shortcuts_clicked", group="Help",
       keywords=("keys", "hotkeys", "help"), requires_unlock=False),
    _c("show-setup", "command.show-setup.title", "command.show-setup.subtitle", "onboarding_clicked",
       group="Help", keywords=("onboarding", "setup", "guide", "tour", "help"), requires_unlock=False),
    _c("error-log", "command.error-log.title", "command.error-log.subtitle", "open_error_log_clicked", group="Help",
       keywords=("diagnostics", "debug", "help"), requires_unlock=False),
)

_MIN_ITEM_ROWS = 4
_SCOPE_GROUPS = {"actions": "Actions", "items": "Items", "settings": "Settings", "help": "Help"}


def registered_section_commands() -> tuple[Command, ...]:
    """Ctrl+K rows for Settings sections registered after start-up (Licence, Sync, …)."""

    from .settings_sections import sections

    built_in = {name for name, *_rest in _SETTINGS_SECTIONS}
    return tuple(
        _c(f"settings-{item.key}", item.title, item.subtitle or "command.settings.title", "settings_clicked",
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
