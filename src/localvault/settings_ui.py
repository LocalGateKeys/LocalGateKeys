"""Settings values: option labels and validation. No widgets live here.

The Settings page (``shell/settings_page.py``) shows these options and hands
each change to ``FeatureUI.apply_settings_change``, which validates it with
:func:`settings_candidate` and saves it at once.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from typing import Any

from .backup_schedule import WEEKDAYS, parse_time
from .hotkey import normalize_hotkey
from .settings import AppSettings, _validated_appearance, validated_mirror_dir

# Deliberately independent clocks. The helper preserves existing custom values.
TIMEOUTS = {'Never': 0, '1 minute': 60, '5 minutes': 300, '15 minutes': 900,
            '30 minutes': 1800, '1 hour': 3600, '2 hours': 7200, '4 hours': 14400,
            '8 hours': 28800, '12 hours': 43200, '24 hours': 86400}
ACTIVITY = {'Computer activity': 'computer', 'Vault activity': 'vault'}
SECTIONS = ('security', 'filling', 'desktop', 'privacy', 'backups')
FREQUENCY_LABELS = {'Off': 'off', 'Daily': 'daily', 'Weekly': 'weekly'}
WEEKDAY_LABELS = {name: index for index, name in enumerate(WEEKDAYS)}
KEEP_LABELS = {'Keep only the latest': 1, 'Keep latest + previous': 2}
APPEARANCE_LABELS = {'System': 'system', 'Light': 'light', 'Dark': 'dark'}
CLIPBOARD_LABELS = {'Never': 0, '5 seconds': 5, '15 seconds': 15, '30 seconds': 30, '1 minute': 60,
                    '2 minutes': 120, '5 minutes': 300}
TRASH_LABELS = {'7 days': 7, '14 days': 14, '30 days': 30, '90 days': 90}
BACKUP_COUNT_LABELS = {'Off': 0, '3 backups': 3, '5 backups': 5, '10 backups': 10, '20 backups': 20}
# Menu labels for every preference shown as a choice; values are what is stored.
CHOICE_LABELS: dict[str, dict[str, Any]] = {
    'auto_lock_seconds': TIMEOUTS, 'max_session_seconds': TIMEOUTS, 'idle_source': ACTIVITY,
    'appearance': APPEARANCE_LABELS, 'clipboard_clear_seconds': CLIPBOARD_LABELS,
    'trash_retention_days': TRASH_LABELS, 'automatic_backup_count': BACKUP_COUNT_LABELS,
    'scheduled_backup_frequency': FREQUENCY_LABELS, 'scheduled_backup_weekday': WEEKDAY_LABELS,
    'scheduled_backup_keep': KEEP_LABELS,
}
_CUSTOM_UNITS = {'trash_retention_days': 'days', 'automatic_backup_count': 'backups'}
BOOLEAN_KEYS = ('fill_and_sign_in', 'lock_on_session_lock', 'lock_on_sleep',
                'browser_enabled', 'desktop_overlay_enabled', 'start_with_windows',
                'minimize_to_tray', 'breach_check_enabled', 'strict_offline_mode',
                'hello_auto_start', 'totp_confirm', 'trash_auto_purge', 'passkeys_enabled',
                'document_open_enabled')
INTEGER_KEYS = ('auto_lock_seconds', 'max_session_seconds', 'clipboard_clear_seconds',
                'trash_retention_days', 'automatic_backup_count',
                'scheduled_backup_weekday', 'scheduled_backup_keep')


def settings_candidate(original: AppSettings, values: dict[str, Any]) -> AppSettings:
    """Validate a settings draft without writing a file or touching the vault."""
    candidate = replace(original)
    allowed = {*BOOLEAN_KEYS, *INTEGER_KEYS, 'idle_source', 'quick_access_hotkey', 'appearance',
               'scheduled_backup_frequency', 'scheduled_backup_time', 'backup_mirror_dir'}
    if set(values) - allowed:
        raise ValueError('Unknown preference in Settings.')
    for key, value in values.items():
        if key in BOOLEAN_KEYS and type(value) is not bool:
            raise ValueError(f'Invalid switch value for {key}.')
        if key in INTEGER_KEYS and type(value) is not int:
            raise ValueError(f'Invalid numeric value for {key}.')
        if key == 'quick_access_hotkey':
            try:
                value = normalize_hotkey(value)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        if key == 'appearance':
            try:
                value = _validated_appearance(value)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        if key == 'scheduled_backup_time':
            if not isinstance(value, str):
                raise ValueError('Invalid backup time.')
            hour, minute = parse_time(value)
            value = f'{hour:02d}:{minute:02d}'
        if key == 'scheduled_backup_frequency' and value not in FREQUENCY_LABELS.values():
            raise ValueError('Unknown backup frequency.')
        if key == 'backup_mirror_dir':
            if not isinstance(value, str) or (value.strip() and not validated_mirror_dir(value)):
                raise ValueError('Choose a local folder for backup copies.')
            value = value.strip()
        setattr(candidate, key, value)
    for key in ('auto_lock_seconds', 'max_session_seconds'):
        value = getattr(candidate, key)
        if value != 0 and not 30 <= value <= 86400:
            raise ValueError('Session limits must be Never or between 30 seconds and 24 hours.')
    if candidate.clipboard_clear_seconds != 0 and not 5 <= candidate.clipboard_clear_seconds <= 300:
        raise ValueError('Clipboard clearing must be Never or between 5 and 300 seconds.')
    if not 1 <= candidate.trash_retention_days <= 365:
        raise ValueError('Deleted-entry retention must be between 1 and 365 days.')
    if not 0 <= candidate.automatic_backup_count <= 20:
        raise ValueError('Keep between 0 and 20 rolling backups.')
    if not 0 <= candidate.scheduled_backup_weekday <= 6:
        raise ValueError('Unknown weekday.')
    if candidate.scheduled_backup_keep not in KEEP_LABELS.values():
        raise ValueError('Keep the latest backup, or the latest and the previous one.')
    if candidate.idle_source not in ACTIVITY.values():
        raise ValueError('Unknown activity source.')
    candidate.appearance = _validated_appearance(candidate.appearance)
    return candidate


def changed_preferences(original: AppSettings, candidate: AppSettings) -> list[str]:
    return [name for name, value in asdict(original).items() if getattr(candidate, name) != value]


def display_duration(seconds: int, options: dict[str, int]) -> str:
    for name, value in options.items():
        if seconds == value: return name
    if seconds % 3600 == 0: name = f'{seconds // 3600} hours'
    elif seconds % 60 == 0: name = f'{seconds // 60} minutes'
    else: name = f'{seconds} seconds'
    options[name] = seconds
    return name


def choice_options(key: str, current: Any) -> dict[str, Any]:
    """Labels → stored values for ``key``, keeping a custom stored value selectable.

    A value set outside the menu (an older build, an edited settings file) is
    shown under its own label instead of being silently reset.
    """
    options = dict(CHOICE_LABELS[key])
    if current in options.values():
        return options
    if key in ('auto_lock_seconds', 'max_session_seconds', 'clipboard_clear_seconds') and type(current) is int:
        display_duration(current, options)
    elif key in _CUSTOM_UNITS and type(current) is int:
        options[f'{current} {_CUSTOM_UNITS[key]}'] = current
    return options


def choice_label(key: str, current: Any) -> str:
    """The menu label for the stored value of ``key``."""
    options = choice_options(key, current)
    return next((label for label, value in options.items() if value == current), next(iter(options)))
