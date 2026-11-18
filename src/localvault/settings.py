from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .backup_schedule import DEFAULT_TIME, FREQUENCIES, KEEP_CHOICES, validated_time
from .config import atomic_write_json, data_dir, read_json
from .hotkey import normalize_hotkey
from .password_tools import normalize_generator_options

SETTINGS_VERSION = 8
UNLOCK_COUNT_CAP = 1000
# Older versions still load; each migration below names the version that introduced it.
LOADABLE_SETTINGS_VERSIONS = (1, 2, 3, 4, 5, 6, 7, SETTINGS_VERSION)

@dataclass
class AppSettings:
    # Inactivity and total unlocked time are intentionally independent.
    auto_lock_seconds: int = 300
    max_session_seconds: int = 8 * 3600
    idle_source: str = "computer"
    fill_and_sign_in: bool = False
    start_with_windows: bool = False
    browser_enabled: bool = True
    # Answer websites' passkey requests (WebAuthn) from the vault; off hands
    # every request to the browser's own authenticator.
    passkeys_enabled: bool = True
    # Serve passkeys to every Windows app through the operating system's plugin
    # passkey manager (LocalGateKeysPasskeyProvider.exe over the pipe scope
    # ``system_passkey``). Off by default; every system request is refused while off.
    windows_passkey_provider: bool = False
    desktop_overlay_enabled: bool = True
    minimize_to_tray: bool = True
    lock_on_session_lock: bool = True
    lock_on_sleep: bool = True
    # Ask Windows to leave this app's windows out of screenshots and screen sharing
    # (SetWindowDisplayAffinity).  The app itself never captures the screen.
    hide_from_capture: bool = True
    clipboard_clear_seconds: int = 30
    automatic_backup_count: int = 5
    # Scheduled encrypted .lgk backups (see backup_schedule). Off by default;
    # they also need a backup password, which lives only inside the vault.
    scheduled_backup_frequency: str = "off"
    scheduled_backup_time: str = DEFAULT_TIME
    scheduled_backup_weekday: int = 0
    scheduled_backup_keep: int = 2
    # Optional folder (e.g. a cloud client's sync folder) that receives a copy
    # of each scheduled encrypted backup. Empty means no mirror.
    backup_mirror_dir: str = ""
    # Weekly restore test of the newest scheduled backup into a scratch folder (sub-plan 12).
    restore_test_weekly: bool = True
    trash_retention_days: int = 30
    # Off keeps deleted items in the trash until they are deleted by hand.
    trash_auto_purge: bool = True
    # "Open file" on a document writes a decrypted copy to the profile's
    # "Opened documents" folder until the vault locks.  Off leaves only
    # "Save a copy…"; the one-time warning is remembered separately.
    document_open_enabled: bool = True
    document_open_warning_seen: bool = False
    breach_check_enabled: bool = False
    # This is a global, persisted safety default.  Explicit bookmark opening
    # may still use the normal browser after a visible warning; no feature may
    # infer consent from this setting or perform background network work.
    strict_offline_mode: bool = True
    # Download each website login's favicon for the item list. Off by default and
    # never in strict offline mode: every download tells that site, and the
    # network, that this vault holds an account for it. Files before v7 load off
    # (v6 turned it on for everyone without asking).
    website_icons: bool = False
    # ISO date until which the "this version is old, check for updates?"
    # reminder stays quiet after the user declined it ("" = not snoozed).
    update_reminder_snoozed_until: str = ""
    # Unlocks so far (capped); the one-time "rate us" prompt waits for the third.
    unlock_count: int = 0
    # Set once the user has answered the "rate us on the Microsoft Store?" prompt.
    rate_prompt_answered: bool = False
    # ISO date until which the installer build's "moved to the Microsoft Store"
    # notice stays quiet after "Later" ("" = show it at the next unlock).
    store_move_snoozed_until: str = ""
    quick_access_hotkey: str = "Ctrl+Alt+K"
    # The quick-access shortcut opens a small search window instead of the app's Quick access page.
    quick_access_palette: bool = True
    appearance: str = "light"
    # When Windows Hello is enrolled, start its prompt as soon as the unlock
    # dialog opens; cancelling it falls back to the master password.
    hello_auto_start: bool = True
    # Set once the user has answered the "unlock faster with Windows Hello?" offer.
    hello_offer_answered: bool = False
    # Password generator defaults (see password_tools.GeneratorOptions).  Saved by
    # the generator dialog and reused by the entry editor's "New" button.
    generator_preferences: dict[str, Any] = field(default_factory=lambda: normalize_generator_options({}).as_dict())
    # Ask (desktop confirm dialog) before every 2FA code released to the
    # browser extension. Off by default; see docs/TOTP_SECURITY_DESIGN.md.
    totp_confirm: bool = False
    # Accept the client-asserted user_gesture flag when no gesture_nonce is
    # presented. Off by default: every shipped extension presents a nonce. Files
    # before v8 load it off (v7 and earlier stored "on" without anyone choosing it);
    # the broker records a diagnostics warning on every legacy acceptance.
    legacy_gesture_compat: bool = False
    # This PC's Wi-Fi sync listener as "address:port" (a private or link-local
    # address).  Empty = Wi-Fi sync off: no listener.  Set from the Sync screen.
    sync_lan_endpoint: str = ""
    #: The endpoint the user typed or picked themselves; the pairing screen keeps it even when it is
    #: not on a gateway network (direct cable, hotspot, Hyper-V external switch).
    sync_lan_endpoint_confirmed: str = ""
    # Vault list order on this device (app.catalog.SORT_OPTIONS); never synced.
    # A typed search keeps its relevance order.
    list_sort: str = "title_asc"
    # "system" follows Windows; otherwise one of i18n.SUPPORTED.
    language: str = "system"
    list_favorites_first: bool = True
    # "Not now" on the empty-vault "Import your passwords" card; this device only.
    import_card_dismissed: bool = False
    # The Home "One-time codes" section is collapsed to its header; this device only.
    codes_collapsed: bool = False
    # Notes and login notes are shown with Markdown formatting (display only); this device only.
    notes_show_formatting: bool = True
    # Erase a profile's vault from this PC once a device it trusted signed that it was removed from
    # sync (app.device_removal; never on the ambiguous "maybe removed" sync issues).
    erase_on_sync_removal: bool = True
    # Developer pack, this device only. The SSH agent pipe (ssh_agent package) is off by default and offers only the
    # ssh_key item ids in ``developer_ssh_keys``. The setup actions keep the values they replaced (environment,
    # global Git config) in ``developer_saved_env`` / ``developer_saved_git`` so Undo can restore them.
    developer_ssh_agent: bool = False
    developer_ssh_keys: list[str] = field(default_factory=list)
    developer_saved_env: dict[str, Any] = field(default_factory=dict)
    developer_saved_git: dict[str, Any] = field(default_factory=dict)
    # "Command line access" for the lgk tool (cli_service): off by default; it serves only the item ids in
    # ``developer_cli_items`` (never a strict login).
    developer_cli: bool = False
    developer_cli_items: list[str] = field(default_factory=list)
    # "Allow AI agents to use LocalGateKeys" (agent_gate, ``lgk mcp``): Pro, off by default, this device only.
    # Every sign-in or read still needs the user's approval; with ``require_hello_for_agents`` also Windows Hello.
    agents_enabled: bool = False
    require_hello_for_agents: bool = False
    # "AI agents may use this item" for API keys, SSH keys and notes (run_with_secrets): the item ids, this device
    # only. Never exported or restored (a restore clears it); a transfer import drops the ids it writes.
    agent_items: list[str] = field(default_factory=list)
    # "Exposed to an AI agent" dismissals (agent_exposure): "<item id>@<unix time>", this device only. Never
    # exported; a restore clears it.
    agent_exposure_dismissed: list[str] = field(default_factory=list)
    # The last plain-secrets scan ({"count": found, "at": unix time}); empty before the first one. Feeds the
    # Security check's "Plain secrets found on this PC".
    developer_last_scan: dict[str, Any] = field(default_factory=dict)
    # KeePass-style unlock factors, this device only. ``unlock_keyfile_paths`` maps a vault_id to the key file's
    # path (never a copy of the file); "" means "Don't remember" for that vault. ``unlock_factors_always_ask``
    # turns Windows Hello, the security key and the camera off for vaults with a key file / YubiKey.
    unlock_keyfile_paths: dict[str, str] = field(default_factory=dict)
    unlock_factors_always_ask: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> AppSettings:
        try:
            raw = read_json(path or settings_path())
        except (OSError, ValueError):
            return cls()
        if raw.get("version", 1) not in LOADABLE_SETTINGS_VERSIONS:
            return cls()
        defaults = cls()
        args = {}
        for name, default in asdict(defaults).items():
            if isinstance(default, bool):
                args[name] = raw.get(name, default) if isinstance(raw.get(name, default), bool) else default
        args.update(
            auto_lock_seconds=_validated_timeout(raw.get("auto_lock_seconds", 300)),
            max_session_seconds=_validated_timeout(raw.get("max_session_seconds", 28800), default=28800),
            idle_source=raw.get("idle_source") if raw.get("idle_source") in ("computer", "vault") else "computer",
            clipboard_clear_seconds=_validated_clipboard_timeout(raw.get("clipboard_clear_seconds", 30)),
            automatic_backup_count=_validated_backup_count(raw.get("automatic_backup_count", 5)),
            trash_retention_days=_bounded(raw.get("trash_retention_days", 30), 1, 365, 30),
            scheduled_backup_frequency=_validated_frequency(raw.get("scheduled_backup_frequency")),
            scheduled_backup_time=validated_time(raw.get("scheduled_backup_time")),
            scheduled_backup_weekday=_bounded(raw.get("scheduled_backup_weekday", 0), 0, 6, 0),
            scheduled_backup_keep=_validated_keep(raw.get("scheduled_backup_keep")),
            backup_mirror_dir=_validated_mirror_dir(raw.get("backup_mirror_dir")),
            restore_test_weekly=raw.get("restore_test_weekly", True) is not False,
            sync_lan_endpoint=_validated_lan_endpoint(raw.get("sync_lan_endpoint")),
            sync_lan_endpoint_confirmed=_validated_lan_endpoint(raw.get("sync_lan_endpoint_confirmed")),
            unlock_count=_bounded(raw.get("unlock_count", 0), 0, UNLOCK_COUNT_CAP, 0),
            list_sort=_validated_list_sort(raw.get("list_sort")),
            language=_validated_language(raw.get("language")),
            developer_ssh_keys=validated_id_list(raw.get("developer_ssh_keys")),
            developer_saved_env=_validated_small_dict(raw.get("developer_saved_env")),
            developer_saved_git=_validated_small_dict(raw.get("developer_saved_git")),
            developer_cli_items=validated_id_list(raw.get("developer_cli_items")),
            agent_items=validated_id_list(raw.get("agent_items")),
            agent_exposure_dismissed=validated_id_list(raw.get("agent_exposure_dismissed")),
            developer_last_scan=validated_last_scan(raw.get("developer_last_scan")),
            unlock_keyfile_paths=validated_keyfile_paths(raw.get("unlock_keyfile_paths")),
        )
        version = raw.get("version", 1)
        # v7 turned website icons back off by default; v6 files stored "on"
        # without anyone choosing it.
        if version < 7:
            args["website_icons"] = defaults.website_icons
        # v8 turned the legacy gesture fallback off; earlier files stored the old
        # default ("on"), which no user chose (there is no switch for it).
        if version < 8:
            args["legacy_gesture_compat"] = defaults.legacy_gesture_compat
        # Missing in all pre-v5 files: new installs and old settings migrated
        # forward remain strict-offline by default.
        args["strict_offline_mode"] = (
            raw.get("strict_offline_mode", defaults.strict_offline_mode)
            if isinstance(raw.get("strict_offline_mode", defaults.strict_offline_mode), bool)
            else defaults.strict_offline_mode
        )
        snoozed = raw.get("update_reminder_snoozed_until", "")
        args["update_reminder_snoozed_until"] = (
            snoozed if isinstance(snoozed, str) and _is_iso_date(snoozed) else ""
        )
        store_snoozed = raw.get("store_move_snoozed_until", "")
        args["store_move_snoozed_until"] = (
            store_snoozed if isinstance(store_snoozed, str) and _is_iso_date(store_snoozed) else ""
        )
        try:
            args["appearance"] = _validated_appearance(raw.get("appearance", defaults.appearance))
        except ValueError:
            args["appearance"] = defaults.appearance
        try:
            args["quick_access_hotkey"] = normalize_hotkey(raw.get("quick_access_hotkey", "Ctrl+Alt+K"))
        except ValueError:
            args["quick_access_hotkey"] = cls().quick_access_hotkey
        args["generator_preferences"] = normalize_generator_options(raw.get("generator_preferences")).as_dict()
        return cls(**args)

    def save(self, path: Path | None = None) -> None:
        payload: dict[str, Any] = {"version": SETTINGS_VERSION, **asdict(self)}
        payload["auto_lock_seconds"] = _validated_timeout(self.auto_lock_seconds)
        payload["max_session_seconds"] = _validated_timeout(self.max_session_seconds, default=28800)
        payload["clipboard_clear_seconds"] = _validated_clipboard_timeout(self.clipboard_clear_seconds)
        payload["automatic_backup_count"] = _validated_backup_count(self.automatic_backup_count)
        payload["unlock_count"] = _bounded(self.unlock_count, 0, UNLOCK_COUNT_CAP, 0)
        payload["trash_retention_days"] = _bounded(self.trash_retention_days, 1, 365, 30)
        payload["scheduled_backup_frequency"] = _validated_frequency(self.scheduled_backup_frequency)
        payload["scheduled_backup_time"] = validated_time(self.scheduled_backup_time)
        payload["scheduled_backup_weekday"] = _bounded(self.scheduled_backup_weekday, 0, 6, 0)
        payload["scheduled_backup_keep"] = _validated_keep(self.scheduled_backup_keep)
        payload["backup_mirror_dir"] = _validated_mirror_dir(self.backup_mirror_dir)
        payload["restore_test_weekly"] = self.restore_test_weekly is not False
        payload["sync_lan_endpoint"] = _validated_lan_endpoint(self.sync_lan_endpoint)
        payload["sync_lan_endpoint_confirmed"] = _validated_lan_endpoint(self.sync_lan_endpoint_confirmed)
        payload["quick_access_hotkey"] = normalize_hotkey(self.quick_access_hotkey)
        payload["appearance"] = _validated_appearance(self.appearance)
        payload["list_sort"] = _validated_list_sort(self.list_sort)
        payload["language"] = _validated_language(self.language)
        payload["generator_preferences"] = normalize_generator_options(self.generator_preferences).as_dict()
        payload["developer_ssh_keys"] = validated_id_list(self.developer_ssh_keys)
        payload["developer_saved_env"] = _validated_small_dict(self.developer_saved_env)
        payload["developer_saved_git"] = _validated_small_dict(self.developer_saved_git)
        payload["developer_cli_items"] = validated_id_list(self.developer_cli_items)
        payload["agent_items"] = validated_id_list(self.agent_items)
        payload["agent_exposure_dismissed"] = validated_id_list(self.agent_exposure_dismissed)
        payload["developer_last_scan"] = validated_last_scan(self.developer_last_scan)
        payload["unlock_keyfile_paths"] = validated_keyfile_paths(self.unlock_keyfile_paths)
        atomic_write_json(path or settings_path(), payload)

def _validated_lan_endpoint(value: Any) -> str:
    """A private/link-local "address:port" for the Wi-Fi sync listener, or "" (off)."""
    if not isinstance(value, str) or not value.strip():
        return ""
    from .app.sync_view import validate_lan_endpoint

    normalized, _error = validate_lan_endpoint(value)
    return normalized or ""


MAX_ID_LIST = 1000
MAX_SMALL_DICT_BYTES = 16 * 1024


def validated_id_list(value: Any) -> list[str]:
    """A per-device allow-list of item ids: unique short strings without control characters."""
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if (isinstance(item, str) and 0 < len(item) <= 128 and item.isprintable() and item not in result
                and len(result) < MAX_ID_LIST):
            result.append(item)
    return result


MAX_KEYFILE_PATH = 4096


def validated_keyfile_paths(value: Any) -> dict[str, str]:
    """vault_id -> remembered key-file path ("" = don't remember): short printable ids, bounded paths."""
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for vault_id, path in value.items():
        if len(result) >= MAX_ID_LIST:
            break
        if (isinstance(vault_id, str) and 0 < len(vault_id) <= 128 and vault_id.isprintable()
                and isinstance(path, str) and len(path) <= MAX_KEYFILE_PATH and path.isprintable()):
            result[vault_id] = path
    return result


def validated_last_scan(value: Any) -> dict[str, Any]:
    """``{"count": n, "at": unix seconds}`` with non-negative whole numbers, else empty (no scan yet)."""
    if not isinstance(value, dict):
        return {}
    count, at = value.get("count"), value.get("at")
    if any(isinstance(n, bool) or not isinstance(n, int) for n in (count, at)):
        return {}
    if not 0 <= count <= 10**6 or not 0 <= at <= 10**11:
        return {}
    return {"count": count, "at": at}


def _validated_small_dict(value: Any) -> dict[str, Any]:
    """A small JSON object with text keys (values the developer setup replaced), else empty."""
    import json

    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        return {}
    try:
        text = json.dumps(value)
    except (TypeError, ValueError, RecursionError):
        return {}
    return json.loads(text) if len(text.encode("utf-8")) <= MAX_SMALL_DICT_BYTES else {}


def settings_path() -> Path:
    return data_dir() / "settings.json"

def _is_iso_date(value: str) -> bool:
    from datetime import date

    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return len(value) == 10


def _bounded(value: Any, low: int, high: int, default: int) -> int:
    # JSON true/false are ints in Python; they are never a valid number here.
    if isinstance(value, bool):
        return default
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError, OverflowError):
        return default

def _is_zero(value: Any) -> bool:
    """Only a real numeric 0 means "disabled"; JSON ``false`` (bool) does not."""
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value == 0

def _validated_timeout(value: Any, *, default: int = 300) -> int:
    if _is_zero(value): return 0
    return _bounded(value, 30, 86400, default)

def _validated_clipboard_timeout(value: Any) -> int:
    if _is_zero(value): return 0
    return _bounded(value, 5, 300, 30)

def _validated_backup_count(value: Any) -> int:
    return _bounded(value, 0, 20, 5)

def _validated_frequency(value: Any) -> str:
    return value if value in FREQUENCIES else "off"

LIST_SORTS = ("title_asc", "title_desc", "modified_desc", "created_desc")


def _validated_list_sort(value: Any) -> str:
    return value if value in LIST_SORTS else "title_asc"

def _validated_language(value: Any) -> str:
    from .i18n import PSEUDO, SUPPORTED, dev_enabled

    if value == PSEUDO and dev_enabled():
        return value
    return value if value in SUPPORTED + ("system",) else "system"


def _validated_keep(value: Any) -> int:
    return value if type(value) is int and value in KEEP_CHOICES else 2

def validated_mirror_dir(value: Any) -> str:
    """A local absolute folder path, or empty. Never a URL: the app stays offline."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > 1024 or "\x00" in value or "://" in value:
        return ""
    if not is_plain_directory_path(value):
        return ""
    return value if Path(value).is_absolute() else ""


_SLASHES = ("\\", "/")


def is_plain_directory_path(value: str) -> bool:
    """False for Win32 device/namespace paths and anything that is not a plain folder path.

    Local folders, mapped network drives and UNC shares (``\\\\nas\\backups``,
    a NAS mirror) are plain paths. ``\\\\?\\...`` and ``\\\\.\\...`` (and their
    forward-slash spellings) bypass Win32 path normalisation or name devices,
    pipes and volumes, so they are refused, as is a ``:`` anywhere but after
    the drive letter (an alternate data stream).
    """
    if len(value) >= 4 and value[0] in _SLASHES and value[1] in _SLASHES and value[2] in "?." \
            and value[3] in _SLASHES:
        return False
    if value[:4] in ("\\??\\", "/??/"):
        return False  # NT object-manager prefix
    rest = value[2:] if len(value) >= 2 and value[1] == ":" and value[0].isalpha() else value
    return ":" not in rest

_validated_mirror_dir = validated_mirror_dir

def _validated_appearance(value: Any) -> str:
    if value not in ("light", "dark", "system"):
        raise ValueError("Appearance must be light or dark, or system to follow Windows.")
    return value
