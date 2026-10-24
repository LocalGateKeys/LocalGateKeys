"""Opening a stored document in its default app via a temporary decrypted copy (no Tk)."""
from __future__ import annotations

import os

import pytest

from localvault.attachments import (
    OPEN_COPIES_DIR_NAME,
    AttachmentError,
    _open_copy_name,
    can_open_externally,
    cleanup_open_copies,
)
from localvault.settings import AppSettings
from localvault.settings_ui import settings_candidate
from localvault.vault import create_vault

MASTER = 'Demo-only-master-open!'
KDF = {'memory_cost_kib': 8192, 'time_cost': 1, 'parallelism': 1}
CONTENT = b'%PDF-1.7 synthetic document bytes'


@pytest.fixture
def vault(tmp_path):
    session = create_vault(tmp_path / 'vault.json', MASTER, kdf_overrides=KDF)
    yield session
    session.lock()


def _document(session, tmp_path, name='taxes 2025.pdf', data=CONTENT):
    source = tmp_path / 'source' / name
    source.parent.mkdir(exist_ok=True)
    source.write_bytes(data)
    return session.documents.create(source, title='Taxes')


def _copies(tmp_path):
    root = tmp_path / OPEN_COPIES_DIR_NAME
    return sorted(root.rglob('*')) if root.exists() else []


def test_open_writes_a_named_copy_and_lock_deletes_it(vault, tmp_path):
    item_id = _document(vault, tmp_path)
    launched = []
    path = vault.documents.open_externally(item_id, launcher=launched.append)
    assert launched == [str(path)]
    assert path.name == 'taxes 2025.pdf'
    assert path.parent.parent == tmp_path / OPEN_COPIES_DIR_NAME
    assert path.read_bytes() == CONTENT
    second = vault.documents.open_externally(item_id, launcher=launched.append)
    assert second.parent != path.parent  # each open gets its own folder
    vault.lock()
    assert not path.exists() and not second.exists()
    assert not (tmp_path / OPEN_COPIES_DIR_NAME).exists()


def test_executable_types_are_refused_before_decrypting(vault, tmp_path):
    item_id = _document(vault, tmp_path, name='setup.exe', data=b'MZ synthetic')
    launched = []
    with pytest.raises(AttachmentError, match='Save a copy'):
        vault.documents.open_externally(item_id, launcher=launched.append)
    assert launched == [] and _copies(tmp_path) == []


def test_launch_failure_removes_the_copy(vault, tmp_path):
    item_id = _document(vault, tmp_path, name='notes.odt')

    def fail(_path):
        raise OSError('no association')

    with pytest.raises(AttachmentError, match='could not open'):
        vault.documents.open_externally(item_id, launcher=fail)
    assert [p for p in _copies(tmp_path) if p.is_file()] == []


@pytest.mark.parametrize(('name', 'allowed'), [
    ('archive.rar', False), ('scan.PDF', True), ('report.docx', True),
    ('run.exe', False), ('script.JS', False), ('link.lnk', False), ('page.hta', False),
    ('no-extension', False),
])
def test_can_open_externally(name, allowed):
    assert can_open_externally(name) is allowed


def test_open_copy_name_is_windows_safe():
    assert _open_copy_name('a:b?.pdf') == 'a_b_.pdf'
    assert _open_copy_name('CON.txt') == '_CON.txt'
    assert _open_copy_name('trailing. . ') == 'trailing'
    assert _open_copy_name(' ') == 'document'


@pytest.mark.skipif(os.name != 'nt', reason='Windows refuses to delete a file that is open')
def test_cleanup_reports_a_copy_still_in_use(tmp_path):
    folder = tmp_path / OPEN_COPIES_DIR_NAME / 'abc'
    folder.mkdir(parents=True)
    held = folder / 'held.pdf'
    held.write_bytes(b'x')
    (folder.parent / 'def').mkdir()
    (folder.parent / 'def' / 'free.pdf').write_bytes(b'y')
    with held.open('rb'):
        assert cleanup_open_copies(tmp_path) == [held]
    assert not (folder.parent / 'def').exists()
    assert cleanup_open_copies(tmp_path) == []
    assert not (tmp_path / OPEN_COPIES_DIR_NAME).exists()


def test_cleanup_without_a_folder_is_a_no_op(tmp_path):
    assert cleanup_open_copies(tmp_path) == []


def test_open_settings_round_trip(tmp_path):
    path = tmp_path / 'settings.json'
    assert AppSettings().document_open_enabled is True
    assert AppSettings().document_open_warning_seen is False
    AppSettings(document_open_enabled=False, document_open_warning_seen=True).save(path)
    loaded = AppSettings.load(path)
    assert loaded.document_open_enabled is False and loaded.document_open_warning_seen is True
    assert settings_candidate(AppSettings(), {'document_open_enabled': False}).document_open_enabled is False
    with pytest.raises(ValueError):
        settings_candidate(AppSettings(), {'document_open_warning_seen': True})


def test_favorite_toggle_works_for_documents_and_notes(vault, tmp_path):
    """Metadata changes must not hit the payload editors' kind restrictions."""
    document_id = _document(vault, tmp_path)
    service = vault.item_service
    assert service.set_metadata(document_id, favorite=True) is True
    assert service.get_item(document_id)['favorite'] is True
    assert service.set_metadata(document_id, favorite=False) is True
    assert service.get_item(document_id)['favorite'] is False
    note_id = service.create_note('Plain note', 'hello')
    assert service.set_metadata(note_id, favorite=True) is True
    assert service.get_item(note_id, include_protected=True)['payload']['body'] == 'hello'
