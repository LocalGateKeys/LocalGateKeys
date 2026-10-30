"""Settings values: option labels and validation. No widgets live here.

The Settings page (``shell/settings_page.py``) shows these options and hands
each change to ``FeatureUI.apply_settings_change``, which validates it with
:func:`settings_candidate` and saves it at once.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, replace
from typing import Any

from .backup_schedule import WEEKDAYS, parse_time
from .hotkey import normalize_hotkey
from .i18n import t
from .settings import AppSettings, _validated_appearance, validated_mirror_dir

class _Labels(Mapping):
    """Menu labels -> stored values, translated each time the table is read.

    Table keys are ``(catalog key, count)`` pairs, so labels follow the language
    that is active when the menu is built, not the one at import time.
    """

    def __init__(self, table: dict[tuple[str, int], Any]) -> None:
        self._table = table

    def _labels(self) -> dict[str, Any]:
        return {t(key, count=count): value for (key, count), value in self._table.items()}

    def __getitem__(self, label: str) -> Any:
        return self._labels()[label]

    def __iter__(self):
        return iter(self._labels())

    def __len__(self) -> int:
        return len(self._table)


_NEVER = ('settings.never', 0)
_MIN = 'settings.duration.minutes'
_HOUR = 'settings.duration.hours'
_SEC = 'settings.duration.seconds'


# Deliberately independent clocks. The helper preserves existing custom values.
TIMEOUTS = _Labels({_NEVER: 0, (_MIN, 1): 60, (_MIN, 5): 300, (_MIN, 15): 900, (_MIN, 30): 1800,
                    (_HOUR, 1): 3600, (_HOUR, 2): 7200, (_HOUR, 4): 14400, (_HOUR, 8): 28800,
                    (_HOUR, 12): 43200, (_HOUR, 24): 86400})
ACTIVITY = _Labels({('settings.activity.computer', 0): 'computer', ('settings.activity.vault', 0): 'vault'})
SECTIONS = ('security', 'filling', 'desktop', 'privacy', 'backups')
FREQUENCY_LABELS = _Labels({('settings.off', 0): 'off', ('settings.frequency.daily', 0): 'daily',
                            ('settings.frequency.weekly', 0): 'weekly'})
WEEKDAY_LABELS = _Labels({(f'settings.weekday.{index}', 0): index for index in range(len(WEEKDAYS))})
KEEP_LABELS = _Labels({('settings.keep.latest', 0): 1, ('settings.keep.latestPrevious', 0): 2})
APPEARANCE_LABELS = _Labels({('settings.appearance.system', 0): 'system', ('settings.appearance.light', 0): 'light',
                             ('settings.appearance.dark', 0): 'dark'})
CLIPBOARD_LABELS = _Labels({_NEVER: 0, (_SEC, 5): 5, (_SEC, 15): 15, (_SEC, 30): 30, (_MIN, 1): 60,
                            (_MIN, 2): 120, (_MIN, 5): 300})
TRASH_LABELS = _Labels({('settings.duration.days', n): n for n in (7, 14, 30, 90)})
BACKUP_COUNT_LABELS = _Labels({('settings.off', 0): 0, **{('settings.count.backups', n): n for n in (3, 5, 10, 20)}})
# Menu labels for every preference shown as a choice; values are what is stored.
CHOICE_LABELS: dict[str, Mapping[str, Any]] = {
    'auto_lock_seconds': TIMEOUTS, 'max_session_seconds': TIMEOUTS, 'idle_source': ACTIVITY,
    'appearance': APPEARANCE_LABELS, 'clipboard_clear_seconds': CLIPBOARD_LABELS,
    'trash_retention_days': TRASH_LABELS, 'automatic_backup_count': BACKUP_COUNT_LABELS,
    'scheduled_backup_frequency': FREQUENCY_LABELS, 'scheduled_backup_weekday': WEEKDAY_LABELS,
    'scheduled_backup_keep': KEEP_LABELS,
    'language': {},  # filled by language_labels(): the system label follows the language
}
_CUSTOM_UNITS = {'trash_retention_days': 'settings.duration.days', 'automatic_backup_count': 'settings.count.backups'}
BOOLEAN_KEYS = ('fill_and_sign_in', 'lock_on_session_lock', 'lock_on_sleep',
                'browser_enabled', 'desktop_overlay_enabled', 'start_with_windows',
                'minimize_to_tray', 'breach_check_enabled', 'strict_offline_mode',
                'hello_auto_start', 'totp_confirm', 'trash_auto_purge', 'passkeys_enabled',
                'document_open_enabled', 'hide_from_capture')
INTEGER_KEYS = ('auto_lock_seconds', 'max_session_seconds', 'clipboard_clear_seconds',
                'trash_retention_days', 'automatic_backup_count',
                'scheduled_backup_weekday', 'scheduled_backup_keep')


# Each language under its own name, so it can be found whatever language is showing.
LANGUAGE_NAMES = {'en': 'English', 'es': 'Español', 'it': 'Italiano', 'pl': 'Polski', 'zh-Hans': '简体中文',
                  'ja': '日本語', 'de': 'Deutsch', 'pt-BR': 'Português (Brasil)', 'ko': '한국어', 'nl': 'Nederlands'}


def language_labels() -> dict[str, str]:
    from . import i18n

    labels = {t('settings.language.system'): 'system', **{name: code for code, name in LANGUAGE_NAMES.items()}}
    if i18n.dev_enabled():
        labels['Pseudo'] = i18n.PSEUDO
    return labels


def language_codes() -> tuple[str, ...]:
    return tuple(language_labels().values())


def settings_candidate(original: AppSettings, values: dict[str, Any]) -> AppSettings:
    """Validate a settings draft without writing a file or touching the vault."""
    candidate = replace(original)
    allowed = {*BOOLEAN_KEYS, *INTEGER_KEYS, 'idle_source', 'quick_access_hotkey', 'appearance', 'language',
               'scheduled_backup_frequency', 'scheduled_backup_time', 'backup_mirror_dir'}
    if set(values) - allowed:
        raise ValueError(t('settings.error.unknownPreference'))
    for key, value in values.items():
        if key in BOOLEAN_KEYS and type(value) is not bool:
            raise ValueError(t('settings.error.invalidSwitch', setting=key))
        if key in INTEGER_KEYS and type(value) is not int:
            raise ValueError(t('settings.error.invalidNumber', setting=key))
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
        if key == 'language' and value not in language_codes():
            raise ValueError(t('settings.error.unknownLanguage'))
        if key == 'scheduled_backup_time':
            if not isinstance(value, str):
                raise ValueError(t('settings.error.invalidBackupTime'))
            hour, minute = parse_time(value)
            value = f'{hour:02d}:{minute:02d}'
        if key == 'scheduled_backup_frequency' and value not in FREQUENCY_LABELS.values():
            raise ValueError(t('settings.error.unknownFrequency'))
        if key == 'backup_mirror_dir':
            if not isinstance(value, str) or (value.strip() and not validated_mirror_dir(value)):
                raise ValueError(t('settings.error.backupFolder'))
            value = value.strip()
        setattr(candidate, key, value)
    for key in ('auto_lock_seconds', 'max_session_seconds'):
        value = getattr(candidate, key)
        if value != 0 and not 30 <= value <= 86400:
            raise ValueError(t('settings.error.sessionLimits'))
    if candidate.clipboard_clear_seconds != 0 and not 5 <= candidate.clipboard_clear_seconds <= 300:
        raise ValueError(t('settings.error.clipboardRange'))
    if not 1 <= candidate.trash_retention_days <= 365:
        raise ValueError(t('settings.error.trashRetention'))
    if not 0 <= candidate.automatic_backup_count <= 20:
        raise ValueError(t('settings.error.backupCount'))
    if not 0 <= candidate.scheduled_backup_weekday <= 6:
        raise ValueError(t('settings.error.unknownWeekday'))
    if candidate.scheduled_backup_keep not in KEEP_LABELS.values():
        raise ValueError(t('settings.error.keepScheduled'))
    if candidate.idle_source not in ACTIVITY.values():
        raise ValueError(t('settings.error.unknownActivity'))
    candidate.appearance = _validated_appearance(candidate.appearance)
    return candidate


def changed_preferences(original: AppSettings, candidate: AppSettings) -> list[str]:
    return [name for name, value in asdict(original).items() if getattr(candidate, name) != value]


def display_duration(seconds: int, options: dict[str, int]) -> str:
    for name, value in options.items():
        if seconds == value: return name
    if seconds % 3600 == 0: name = t('settings.duration.hours', count=seconds // 3600)
    elif seconds % 60 == 0: name = t('settings.duration.minutes', count=seconds // 60)
    else: name = t('settings.duration.seconds', count=seconds)
    options[name] = seconds
    return name


def choice_options(key: str, current: Any) -> dict[str, Any]:
    """Labels → stored values for ``key``, keeping a custom stored value selectable.

    A value set outside the menu (an older build, an edited settings file) is
    shown under its own label instead of being silently reset.
    """
    options = language_labels() if key == 'language' else dict(CHOICE_LABELS[key])  # translated now
    if current in options.values():
        return options
    if key in ('auto_lock_seconds', 'max_session_seconds', 'clipboard_clear_seconds') and type(current) is int:
        display_duration(current, options)
    elif key in _CUSTOM_UNITS and type(current) is int:
        options[t(_CUSTOM_UNITS[key], count=current)] = current
    return options


def choice_label(key: str, current: Any) -> str:
    """The menu label for the stored value of ``key``."""
    options = choice_options(key, current)
    return next((label for label, value in options.items() if value == current), next(iter(options)))
