"""Security round 3 (2026-10-24), desktop: data-folder ACL (R-2, R-3), attachment decrypt fallback (R-7),
throttle key binding (R-8), disabled popup (R-9), history quota (CodeQL), private restore scratch (pentest #8)."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import config
from localvault import vault as V
from localvault.attachments import AttachmentStore
from localvault.history import HistoryQuotaError, HistoryService
from localvault.web import window as web_window

MASTER = "synthetic round three master password"
KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


@pytest.fixture(autouse=True)
def clean_throttle():
    V._reset_unlock_throttle_state_for_tests()
    yield
    V._reset_unlock_throttle_state_for_tests()


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".pytest-tmp" / f"round3-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ------------------------------------------------------------- R-2 / R-3 data folder ACL

def _fake_windows(monkeypatch, applied: list, *, already: bool = False) -> None:
    monkeypatch.setattr(config.os, "name", "nt")
    monkeypatch.setattr(config, "apply_owner_only_acl", applied.append)
    monkeypatch.setattr(config, "has_owner_only_acl", lambda path: already)


def test_data_dir_never_rewrites_an_existing_folder(tmp_path: Path, monkeypatch) -> None:
    # The native host calls data_dir() in a new process per browser message: no ACL rewrite there.
    folder = tmp_path / "existing"
    folder.mkdir()
    (folder / config.OWNED_MARKER).write_text("x", encoding="utf-8")
    applied: list = []
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(folder))
    _fake_windows(monkeypatch, applied)
    for _ in range(3):
        assert config.data_dir() == folder.resolve()
    assert applied == []


def test_a_folder_the_app_creates_is_marked_and_secured_at_once(tmp_path: Path, monkeypatch) -> None:
    folder = tmp_path / "new"
    applied: list = []
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(folder))
    _fake_windows(monkeypatch, applied)
    assert config.data_dir() == folder.resolve()
    assert (folder / config.OWNED_MARKER).is_file()
    assert applied == [folder.resolve()]


def test_main_app_secures_an_owned_folder_once_and_skips_a_correct_acl(tmp_path: Path, monkeypatch) -> None:
    folder = tmp_path / "owned"
    folder.mkdir()
    (folder / config.OWNED_MARKER).write_text("x", encoding="utf-8")
    applied: list = []
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(folder))
    _fake_windows(monkeypatch, applied)
    assert config.secure_data_dir_once() is True
    assert applied == [folder.resolve()]
    monkeypatch.setattr(config, "has_owner_only_acl", lambda path: True)
    assert config.secure_data_dir_once() is False
    assert applied == [folder.resolve()]


def test_an_override_folder_the_app_did_not_create_keeps_its_acl(tmp_path: Path, monkeypatch) -> None:
    # R-3: LOCALGATEKEYS_DATA_DIR pointed at someone's existing folder must not have its ACL replaced.
    folder = tmp_path / "foreign"
    folder.mkdir()
    applied: list = []
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(folder))
    _fake_windows(monkeypatch, applied)
    assert config.data_dir() == folder.resolve()
    assert config.secure_data_dir_once() is False
    assert applied == [] and not (folder / config.OWNED_MARKER).exists()


def test_default_folder_is_secured_without_a_marker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("LOCALGATEKEYS_DATA_DIR", raising=False)
    monkeypatch.setattr(config, "_local_appdata", lambda: tmp_path)
    applied: list = []
    _fake_windows(monkeypatch, applied)
    default = tmp_path / config.APP_DIR_NAME
    default.mkdir()
    assert config.secure_data_dir_once() is True
    assert applied == [default]


def test_secure_data_dir_once_is_a_no_op_off_windows(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config.os, "name", "posix")
    monkeypatch.setattr(config, "apply_owner_only_acl", lambda path: pytest.fail("no ACL off Windows"))
    assert config.secure_data_dir_once() is False


def test_native_host_and_pipe_code_never_secure_the_folder() -> None:
    src = Path(__file__).parents[1] / "src" / "localvault"
    for name in ("native_host.py", "pipe_transport.py", "browser_broker.py"):
        path = src / name
        if path.exists():
            assert "secure_data_dir_once" not in path.read_text(encoding="utf-8"), name
    assert "secure_data_dir_once" in (src / "web" / "main.py").read_text(encoding="utf-8")


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_owner_only_acl_is_detected_after_it_is_applied(case_dir: Path) -> None:
    folder = case_dir / "acl"
    folder.mkdir()
    config.apply_owner_only_acl(folder)
    assert config.has_owner_only_acl(folder) is True
    (folder / "file.txt").write_text("x", encoding="utf-8")
    assert config.has_owner_only_acl(folder) is True


# ------------------------------------------------------------- R-7 attachment decrypt fallback

class _NoDecryptInto:
    """AESGCM as in cryptography < 44: no decrypt_into."""

    def __init__(self, key):
        self._inner = AESGCM(bytes(key))

    def encrypt(self, nonce, data, aad):
        return self._inner.encrypt(nonce, data, aad)

    def decrypt(self, nonce, data, aad):
        return self._inner.decrypt(nonce, data, aad)


def test_attachment_reads_without_decrypt_into(case_dir: Path, monkeypatch) -> None:
    session = V.create_vault(case_dir / "vault.json", MASTER, kdf_overrides=KDF)
    try:
        store = AttachmentStore(session)
        attachment_id = store.add_bytes("notes.txt", b"synthetic attachment body", mime_type="text/plain")
        monkeypatch.setattr(V, "AESGCM", _NoDecryptInto)
        assert store.read_bytes(attachment_id) == b"synthetic attachment body"
    finally:
        session.lock()


# ------------------------------------------------------------- R-8 throttle key bound in the header

def _key_file(path: Path) -> Path:
    return V._unlock_throttle_key_path(path)


def _counter_file(path: Path) -> Path:
    return V._unlock_throttle_path(path)


def _fail(path: Path, times: int) -> None:
    for _ in range(times):
        try:
            V.unlock_vault(path, "wrong synthetic password")
        except V.InvalidMasterPassword:
            pass
        except V.UnlockThrottled:
            V._reset_unlock_throttle_state_for_tests()  # skip the in-process wait; the files keep the count


def _new_vault(case_dir: Path) -> Path:
    path = case_dir / "vault.json"
    V.create_vault(path, MASTER, kdf_overrides=KDF).lock()
    return path


def test_save_binds_the_throttle_key_in_the_authenticated_header(case_dir: Path) -> None:
    path = _new_vault(case_dir)
    header = json.loads(path.read_text())
    binding = header[V.THROTTLE_BINDING_FIELD]
    assert binding["location"] == V._throttle_location(path)
    assert _key_file(path).exists() and _counter_file(path).exists()
    assert json.loads(_key_file(path).read_text())["version"] == 2
    # The binding is covered by the catalog AAD: removing it makes the vault unopenable.
    del header[V.THROTTLE_BINDING_FIELD]
    path.write_text(json.dumps(header))
    with pytest.raises(V.VaultError):
        V.unlock_vault(path, MASTER)


def test_deleting_both_throttle_files_fails_closed(case_dir: Path) -> None:
    path = _new_vault(case_dir)
    _fail(path, 7)
    _key_file(path).unlink()
    _counter_file(path).unlink()
    V._reset_unlock_throttle_state_for_tests()
    throttle = V.UnlockThrottle(path)
    assert throttle.failures == V.THROTTLE_FAIL_CLOSED_FAILURES
    assert 0 < throttle.remaining_backoff_seconds() <= V.THROTTLE_MAX_SECONDS


def test_replacing_the_key_and_counter_fails_closed(case_dir: Path) -> None:
    path = _new_vault(case_dir)
    _fail(path, 7)
    _key_file(path).unlink()
    _counter_file(path).unlink()
    other = V.UnlockThrottle(path)
    other._write_key_record(os.urandom(32))  # an attacker's own key and a zero record under it
    other._store_failures(0, key=other._key(create=False))
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == V.THROTTLE_FAIL_CLOSED_FAILURES


def test_downgrading_the_key_to_version_1_fails_closed(case_dir: Path) -> None:
    path = _new_vault(case_dir)
    record = json.loads(_key_file(path).read_text())
    record["version"] = 1
    _key_file(path).write_text(json.dumps(record))
    _counter_file(path).unlink()
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == V.THROTTLE_FAIL_CLOSED_FAILURES


def test_fail_closed_is_a_delay_not_a_lock_out(case_dir: Path) -> None:
    path = _new_vault(case_dir)
    _key_file(path).unlink()
    _counter_file(path).unlink()
    V._reset_unlock_throttle_state_for_tests()
    with pytest.raises(V.UnlockThrottled):
        V.unlock_vault(path, MASTER)
    # Once the delay has passed (skipped here), the right password still opens the vault and rebinds.
    with V._THROTTLE_LOCK:
        V._THROTTLE_STATE[str(path.absolute())]["not_before"] = 0.0
    session = V.unlock_vault(path, MASTER)
    session.upsert_web(origin="https://example.test", username="u", password="synthetic-site-secret")
    session.lock()
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == 0


def test_a_copy_elsewhere_is_not_bound(case_dir: Path) -> None:
    # A restored or verified copy has no throttle files beside it: it keeps the previous behaviour.
    path = _new_vault(case_dir)
    copy_dir = case_dir / "copy"
    copy_dir.mkdir()
    copy = copy_dir / "vault.json"
    shutil.copyfile(path, copy)
    assert V.UnlockThrottle(copy).failures == 0
    V.unlock_vault(copy, MASTER).lock()


def test_a_vault_without_the_field_keeps_the_previous_behaviour(case_dir: Path) -> None:
    path = _new_vault(case_dir)
    _key_file(path).unlink()
    _counter_file(path).unlink()
    header = json.loads(path.read_text())
    header.pop(V.THROTTLE_BINDING_FIELD)
    path.write_text(json.dumps(header))
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == 0


def test_a_malformed_binding_is_refused(case_dir: Path) -> None:
    path = _new_vault(case_dir)
    header = json.loads(path.read_text())
    header[V.THROTTLE_BINDING_FIELD] = {"key_id": "not hex", "location": "x"}
    path.write_text(json.dumps(header))
    with pytest.raises(V.VaultError, match="binding is malformed"):
        V.unlock_vault(path, MASTER)


# ------------------------------------------------------------- R-9 disabled popup

def test_disabled_popup_show_returns_false_and_the_host_raises_the_main_window() -> None:
    from localvault.web.host import WebAgentHost

    shown: list = []
    popup = web_window.PopupWindow(NS(show=lambda: shown.append(1), hide=lambda: None))
    raised: list = []
    host = WebAgentHost.__new__(WebAgentHost)
    host._popup = popup
    host._window = NS(raise_window=lambda: raised.append(1))
    popup.disable()
    assert popup.show() is False and shown == []
    host.show_popup()
    assert raised == [1]


def test_disabling_the_popup_moves_its_prompts_to_the_main_window() -> None:
    from localvault.web.host import WebAgentHost
    from localvault.web.ui_port import WebUiPort

    emitted: list = []
    bus = NS(emit=lambda name, detail: emitted.append((name, detail)))
    port = WebUiPort(bus)
    popup = web_window.PopupWindow(NS(show=lambda: None, hide=lambda: None))
    controller = NS()
    host = WebAgentHost(controller, port, bus, window=NS(raise_window=lambda: emitted.append(("raised", {}))),
                        popup=popup)
    assert host.popup_port._surface == "popup"
    popup.disable()
    assert host.popup_port._surface is None
    assert host.popup_port._on_show == host.raise_window


def test_popup_already_disabled_at_construction_routes_to_the_main_window() -> None:
    from localvault.web.host import WebAgentHost
    from localvault.web.ui_port import WebUiPort

    bus = NS(emit=lambda name, detail: None)
    popup = web_window.PopupWindow(NS(show=lambda: None, hide=lambda: None))
    popup.disable()
    host = WebAgentHost(NS(), WebUiPort(bus), bus, window=NS(raise_window=lambda: None), popup=popup)
    assert host.popup_port._surface is None


# ------------------------------------------------------------- CodeQL: history quota near the limit

def test_history_quota_with_partial_per_item_history_raises_quota_error(case_dir: Path, monkeypatch) -> None:
    session = V.create_vault(case_dir / "vault.json", MASTER, kdf_overrides=KDF)
    try:
        item_id = session.items.create_note("Private", "first")
        assert session.items.update_item(item_id, body="second", expected_revision=1)
        history = HistoryService(session)
        rows_before = list(session._require_typed_catalog().get("history", []))
        assert 0 < len([r for r in rows_before if r.get("item_id") == item_id]) < history.max_versions
        monkeypatch.setattr(HistoryService, "_used_bytes", lambda self, rows: history.max_bytes + 1)
        item = next(i for i in session._require_typed_catalog()["items"] if i["id"] == item_id)
        with pytest.raises(HistoryQuotaError):
            history.record_before_change(item, change_type="update", persist=False)
        assert session._require_typed_catalog().get("history", []) == rows_before
    finally:
        session.lock()


# ------------------------------------------------------------- pentest #8 private restore scratch

def test_backup_snapshot_lives_in_a_private_directory(case_dir: Path) -> None:
    from localvault.app import recovery_center

    source = case_dir / "backup.lgk"
    source.write_bytes(b"synthetic backup bytes")
    digest = recovery_center.sha256_file(source)
    destination = case_dir / "dest"
    destination.mkdir()
    with recovery_center._backup_snapshot(source, destination, digest) as snapshot:
        assert snapshot.read_bytes() == b"synthetic backup bytes"
        scratch = snapshot.parent
        assert scratch.parent == destination and scratch.name.startswith(".lgk-restore-source-")
        assert [p.name for p in scratch.iterdir()] == [snapshot.name]
    assert not scratch.exists()


def test_backup_snapshot_refuses_a_changed_backup_and_cleans_up(case_dir: Path) -> None:
    from localvault.app import recovery_center

    source = case_dir / "backup.lgk"
    source.write_bytes(b"synthetic backup bytes")
    destination = case_dir / "dest"
    destination.mkdir()
    with pytest.raises(recovery_center.RecoveryError, match="changed"):
        with recovery_center._backup_snapshot(source, destination, "0" * 64):
            pass
    assert list(destination.iterdir()) == []
