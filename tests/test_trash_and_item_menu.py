"""Trash auto-purge switch, bulk purge, favorites and the item row menu (no Tk)."""
from __future__ import annotations


import pytest

from localvault.settings import AppSettings
from localvault.settings_ui import settings_candidate
from localvault.vault import _validate_catalog_payload, create_vault, unlock_vault

MASTER = 'Demo-only-master-trash!'
KDF = {'memory_cost_kib': 8192, 'time_cost': 1, 'parallelism': 1}


@pytest.fixture
def vault(tmp_path):
    session = create_vault(tmp_path / 'vault.json', MASTER, kdf_overrides=KDF)
    yield session
    session.lock()


def add(session, user):
    return session.upsert_web(origin='https://example.test', username=user,
                              password='Test-only-password-trash!', label=user)


def _age_trash(session, days):
    for record in session._require_payload()['trash']:
        record['deleted_at'] -= days * 86400


def test_auto_purge_setting_round_trips(tmp_path):
    path = tmp_path / 'settings.json'
    assert AppSettings().trash_auto_purge is True
    AppSettings(trash_auto_purge=False).save(path)
    assert AppSettings.load(path).trash_auto_purge is False
    assert settings_candidate(AppSettings(), {'trash_auto_purge': False}).trash_auto_purge is False
    with pytest.raises(ValueError):
        settings_candidate(AppSettings(), {'trash_auto_purge': 0})


def test_expired_trash_is_purged_only_while_auto_purge_is_on(vault):
    first = add(vault, 'alice')
    vault.delete(first)
    _age_trash(vault, 400)
    vault.trash_auto_purge = False
    add(vault, 'bob')  # any write runs the expiry pass
    assert [row['id'] for row in vault.trash_summaries()] == [first]
    vault.trash_auto_purge = True
    add(vault, 'carol')
    assert vault.trash_summaries() == []


def test_purge_deleted_many_removes_only_the_chosen_records(vault):
    ids = [add(vault, name) for name in ('alice', 'bob', 'carol')]
    for entry_id in ids:
        vault.delete(entry_id)
    assert vault.purge_deleted_many([ids[0], ids[2], 'missing']) == 2
    assert [row['id'] for row in vault.trash_summaries()] == [ids[1]]
    assert vault.purge_deleted_many([]) == 0


def test_set_favorite_changes_only_the_flag(vault):
    entry_id = add(vault, 'alice')
    vault.set_details(entry_id, tags=['work'], notes='keep me')
    vault.set_favorite(entry_id, True)
    entry = vault.get_entry(entry_id)
    assert entry['favorite'] is True and entry['tags'] == ['work'] and entry['notes'] == 'keep me'
    vault.set_favorite(entry_id, False)
    assert vault.get_entry(entry_id)['favorite'] is False


def _labels(rows):
    return [row[0] for row in rows if row is not None]


def _deleted_license_with_history(session):
    item_id = session.items.create_license('Old licence', license_value='Test-only-licence')
    assert session.items.update_license(item_id, notes='edited', expected_revision=1)
    assert session.items.delete_item(item_id)
    assert any(row['item_id'] == item_id for row in session._require_payload()['history'])
    return item_id


def test_auto_purge_drops_history_so_the_vault_still_unlocks(tmp_path):
    path = tmp_path / 'vault.json'
    session = create_vault(path, MASTER, kdf_overrides=KDF)
    item_id = _deleted_license_with_history(session)
    _age_trash(session, 400)
    add(session, 'bob')  # any write runs the expiry pass
    assert not any(row['item_id'] == item_id for row in session._require_payload()['history'])
    session.lock()
    reopened = unlock_vault(path, MASTER)
    assert reopened.items.trash_summaries() == []
    reopened.lock()


def test_bulk_purge_drops_history_of_purged_items(vault):
    item_id = _deleted_license_with_history(vault)
    assert vault.purge_deleted_many([item_id]) == 1
    assert not any(row['item_id'] == item_id for row in vault._require_payload()['history'])


def test_loading_prunes_history_left_behind_by_an_earlier_purge(vault):
    item_id = _deleted_license_with_history(vault)
    payload = vault._require_payload()
    payload['trash'] = []  # what older builds wrote to disk
    _validate_catalog_payload(payload)
    assert not any(row['item_id'] == item_id for row in payload['history'])
