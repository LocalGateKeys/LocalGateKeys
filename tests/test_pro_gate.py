"""Item-limit gate and licence wiring: stub objects only, no Tk windows."""
from __future__ import annotations

import types

import pytest

from localvault import licensing
from localvault.pro_gate import ProGateMixin
from localvault.vault import ItemLimitReached, create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


class _Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


def _bind(app, cls, name):
    setattr(app, name, types.MethodType(getattr(cls, name), app))


def _stub(**extra):
    prompts = []
    calls = []
    app = types.SimpleNamespace(root=None, prompts=prompts, calls=calls, status_var=_Var(""))
    app._show_upgrade_prompt = prompts.append
    for name in ("_handle_item_limit", "_item_slot_available", "_apply_item_limit",
                 "_licence_after_unlock", "_licence_changed"):
        _bind(app, ProGateMixin, name)
    app.ensure_unlocked = lambda: True
    app.show_home = lambda: None
    app.guard = types.SimpleNamespace(lease=lambda: calls.append("lease") or object())
    app.require_lease = lambda lease: None
    app._desktop_job = lambda *a, **k: calls.append("job")
    app.session = None
    for k, v in extra.items():
        setattr(app, k, v)
    return app


class _CountingSession:
    def __init__(self, count, limit):
        self.count, self.item_limit, self.is_unlocked = count, limit, True

    def live_item_count(self):
        return self.count


# --- Pro-only features (2026-10-19): sync, two-factor codes, attachments; desktop fill is free ---


def test_pro_only_features_and_free_desktop_fill():
    assert {f.value for f in licensing.Feature} == {"unlimited_items", "sync", "totp", "attachments"}
    assert not hasattr(licensing.Feature, "DESKTOP_FILL")
    assert not hasattr(ProGateMixin, "_pro_allowed")


# --- item slot check, upgrade prompt ---------------------------------------------------


def test_item_slot_available_cases():
    assert _stub(session=None)._item_slot_available() is True
    assert _stub(session=_CountingSession(99, None))._item_slot_available() is True
    assert _stub(session=_CountingSession(3, 4))._item_slot_available() is True
    app = _stub(session=_CountingSession(4, 4))
    assert app._item_slot_available() is False and len(app.prompts) == 1


def test_handle_item_limit_survives_prompt_failure():
    app = _stub()
    app._show_upgrade_prompt = lambda exc: (_ for _ in ()).throw(RuntimeError("ui"))
    app._handle_item_limit(ItemLimitReached(4, 4))  # logged, never raised
    assert "4 items" in app.status_var.get()


# --- licence wiring: limit applied after unlock / install / remove ---------------------


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    return create_vault(tmp_path / "v.json", "pro gate test password", kdf_overrides=KDF)


def test_apply_item_limit_sets_session_limit(monkeypatch, vault):
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: 4)
    app = _stub(session=vault)
    app._apply_item_limit()
    assert vault.item_limit == 4
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None)
    app._apply_item_limit()
    assert vault.item_limit is None
    _stub(session=None)._apply_item_limit()  # locked: nothing to do


def test_after_unlock_reconciles_then_applies_limit(monkeypatch, vault):
    order = []
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda s: order.append(("reconcile", s)))
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: order.append("limit") or 4)
    app = _stub(session=vault)
    app._licence_after_unlock()
    assert order == [("reconcile", vault), "limit"] and vault.item_limit == 4


def test_after_unlock_never_raises(monkeypatch, vault):
    monkeypatch.setattr(licensing, "reconcile_vault_copy",
                        lambda s: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: 4)
    app = _stub(session=vault)
    app._licence_after_unlock()
    assert vault.item_limit == 4


def test_licence_changed_unlocked_reconciles_and_refreshes(monkeypatch, vault):
    seen = []
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda s: seen.append("reconcile"))
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None)
    vault.item_limit = 4
    app = _stub(session=vault, _refresh_licence_status=lambda: seen.append("refresh"))
    app._licence_changed()
    assert seen == ["reconcile", "refresh"] and vault.item_limit is None


def test_licence_changed_locked_only_refreshes(monkeypatch):
    seen = []
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda s: seen.append("reconcile"))
    app = _stub(session=None, _refresh_licence_status=lambda: seen.append("refresh"))
    app._licence_changed()
    assert seen == ["refresh"]


# --- UI creation paths route ItemLimitReached to the upgrade prompt ---------------------


def test_trash_restore_stops_at_limit_and_reports_it(vault):
    from localvault.app.trash_restore import restore_trash_entries
    ids = [vault.upsert_web(origin=f"https://s{i}.example", username="u", password="p") for i in range(3)]
    for entry_id in ids:
        vault.delete(entry_id)
    vault.item_limit = 1
    result = restore_trash_entries(vault, ids, {i: "credential" for i in ids}, lambda: None)
    assert result.restored == 1
    assert isinstance(result.limit, ItemLimitReached)
    assert result.failed == []
    assert vault.live_item_count() == 1


def test_trash_restore_unlimited_restores_all(vault):
    from localvault.app.trash_restore import restore_trash_entries
    ids = [vault.upsert_web(origin=f"https://t{i}.example", username="u", password="p") for i in range(2)]
    for entry_id in ids:
        vault.delete(entry_id)
    result = restore_trash_entries(vault, ids, {i: "credential" for i in ids}, lambda: None)
    assert result.restored == 2 and result.limit is None and result.failed == []


