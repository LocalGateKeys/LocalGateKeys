"""Portable model tests; no display, vault or Windows profile is touched."""
from dataclasses import asdict

import pytest

from localvault.settings import AppSettings
from localvault.settings_ui import (
    TIMEOUTS,
    changed_preferences,
    display_duration,
    settings_candidate,
)


def test_draft_preserves_all_values_and_does_not_mutate_original():
    original = AppSettings(auto_lock_seconds=420, max_session_seconds=21600,
                           clipboard_clear_seconds=0, trash_retention_days=17,
                           automatic_backup_count=8, fill_and_sign_in=True)
    before = asdict(original)
    draft = settings_candidate(original, {'auto_lock_seconds': 900})
    assert asdict(original) == before
    assert changed_preferences(original, draft) == ['auto_lock_seconds']
    for key, value in before.items():
        if key != 'auto_lock_seconds': assert getattr(draft, key) == value


def test_sign_in_still_defaults_off():
    assert settings_candidate(AppSettings(), {}).fill_and_sign_in is False


@pytest.mark.parametrize('value', ['light', 'dark'])
def test_appearance_draft_choice_is_validated_and_preserved(value):
    draft = settings_candidate(AppSettings(), {'appearance': value})
    assert draft.appearance == value
    assert settings_candidate(draft, {}).appearance == value


def test_maximum_and_inactivity_are_independent():
    draft = settings_candidate(AppSettings(), {'max_session_seconds': 28800, 'auto_lock_seconds': 900})
    assert draft.max_session_seconds == 8*3600
    assert draft.auto_lock_seconds == 15*60


@pytest.mark.parametrize('updates', [
    {'missing_key': True}, {'fill_and_sign_in': 1}, {'auto_lock_seconds': True},
    {'max_session_seconds': '28800'}, {'max_session_seconds': -1},
    {'max_session_seconds': 86401}, {'auto_lock_seconds': 5},
    {'idle_source':'browser'}, {'clipboard_clear_seconds': 301},
    {'trash_retention_days':0}, {'automatic_backup_count':21},
    {'appearance': 'sepia'}, {'appearance': None},
])
def test_invalid_draft_refused(updates):
    with pytest.raises(ValueError): settings_candidate(AppSettings(), updates)


@pytest.mark.parametrize('seconds', [0,60,300,900,28800,43200,86400,1200,75])
def test_custom_durations_round_trip_without_silent_reset(seconds):
    options=dict(TIMEOUTS)
    name=display_duration(seconds,options)
    assert options[name] == seconds


def test_disabled_timeouts_are_retained():
    data=settings_candidate(AppSettings(), {'max_session_seconds':0,'auto_lock_seconds':0,'clipboard_clear_seconds':0})
    assert not data.max_session_seconds and not data.auto_lock_seconds and not data.clipboard_clear_seconds
