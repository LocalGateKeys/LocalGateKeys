"""Per-login edit tokens, duplicate-safe creation and atomic login saves."""

import json

import pytest

from localvault.item_service import ItemService
from localvault.vault import (
    PNG_SIGNATURE,
    DuplicateLoginError,
    LoginChangedError,
    VaultError,
    VaultLockedError,
    create_vault,
    unlock_vault,
)

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
TINY_PNG = PNG_SIGNATURE + b"\x00\x00\x00\x0dIHDR" + b"\x00" * 17


@pytest.fixture
def session(tmp_path):
    s = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    yield s
    if s.is_unlocked:
        s.lock()


def _save(session, entry_id, token, **overrides):
    values = dict(label="A", username="u", password=None, favorite=False, tags=[], notes="", totp=None,
                  recovery_codes=[], custom_fields=[], policy={}, urls=None)
    values.update(overrides)
    return session.save_login(entry_id, expected_token=token, **values)


def _disk_entry(session, entry_id):
    reopened = unlock_vault(session.path, MASTER)
    try:
        return reopened.get_entry(entry_id)
    finally:
        reopened.lock()


def test_errors_are_vault_errors_with_user_facing_messages():
    assert issubclass(LoginChangedError, VaultError)
    assert issubclass(DuplicateLoginError, VaultError)
    assert str(LoginChangedError()) == "This login was changed elsewhere."
    err = DuplicateLoginError("abc")
    assert err.existing_id == "abc"
    assert str(err) == "A login for this site and username already exists."


def test_token_ignores_other_items_and_icon_updates(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p1")
    b = session.upsert_web(origin="https://b.test", username="u", password="p2")
    token = session.login_edit_token(a)
    assert isinstance(token, str) and len(token) == 64
    session.update_entry_fields(b, label="B", username="u", password=None,
                                expected_revision=session.credential_detail(b)["revision"])
    assert session.set_entry_icon(a, TINY_PNG) is True
    assert session.login_edit_token(a) == token


def test_token_changes_when_the_login_or_its_urls_change(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p1")
    token = session.login_edit_token(a)
    session.item_service.set_web_urls(a, [{"url": "https://a.test", "match": "exact_origin"},
                                          {"url": "https://login.a.test", "match": "exact_origin"}])
    url_token = session.login_edit_token(a)
    assert url_token != token
    session.set_details(a, favorite=True)
    assert session.login_edit_token(a) != url_token


def test_token_for_unknown_login_raises(session):
    with pytest.raises(VaultError):
        session.login_edit_token("missing")


def test_save_login_rejects_a_changed_login(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p1")
    token = session.login_edit_token(a)
    new_token = _save(session, a, token, username="u2")
    assert new_token == session.login_edit_token(a)
    assert new_token != token
    with pytest.raises(LoginChangedError):
        _save(session, a, token, username="u3")
    assert session.get_entry(a)["username"] == "u2"


def test_save_login_applies_every_field(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p1")
    token = session.login_edit_token(a)
    _save(session, a, token, label="Renamed", username="me", favorite=True, tags=["work", " work ", "home"],
          notes="hello", totp={"secret": "JBSWY3DPEHPK3PXP"}, recovery_codes=["one", "two"],
          custom_fields=[{"name": "PIN", "value": "1234", "hidden": True}], policy={"sign_in": "never"},
          urls=[{"url": "https://a.test", "match": "exact_origin"}, {"url": "https://b.test/login", "match": "starts_with"}])
    entry = _disk_entry(session, a)
    assert entry["label"] == "Renamed" and entry["username"] == "me" and entry["password"] == "p1"
    assert entry["favorite"] is True and entry["tags"] == ["work", "home"] and entry["notes"] == "hello"
    assert entry["totp"]["secret"] == "JBSWY3DPEHPK3PXP"
    assert entry["recovery_codes"] == ["one", "two"]
    assert entry["custom_fields"] == [{"name": "PIN", "value": "1234", "hidden": True}]
    assert entry["policy"]["sign_in"] == "never"
    assert [row["url"] for row in entry["scope"]["urls"]] == ["https://a.test", "https://b.test/login"]


def test_save_login_keeps_password_when_none_and_records_history_on_change(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p1")
    token = _save(session, a, session.login_edit_token(a), password=None)
    assert session.credential_secret(a) == "p1"
    assert session.password_history(a) == []
    token = _save(session, a, token, password="p2")
    assert session.credential_secret(a) == "p2"
    assert [row["password"] for row in session.password_history(a)] == ["p1"]
    _save(session, a, token, password="p2")
    assert [row["password"] for row in session.password_history(a)] == ["p1"]


def test_save_login_with_desktop_login_and_no_urls(session):
    d = session.add_desktop(label="App", username="u", password="p", exe_path=r"C:\Apps\app.exe",
                            exe_sha256="A" * 64, window_title="App", control_fingerprint=[{"role": "edit"}],
                            username_selector=None, password_selector=None)
    _save(session, d, session.login_edit_token(d), label="App 2", username="v", notes="desk")
    entry = _disk_entry(session, d)
    assert (entry["label"], entry["username"], entry["notes"]) == ("App 2", "v", "desk")
    assert entry["scope"]["exe_path"].lower().endswith("app.exe")


def test_save_login_is_atomic(session, monkeypatch):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p1")
    token = session.login_edit_token(a)
    before = session.path.read_bytes()

    def boom(self, entry_id, urls):
        raise VaultError("simulated URL failure")

    monkeypatch.setattr(ItemService, "set_web_urls", boom)
    with pytest.raises(VaultError, match="simulated"):
        _save(session, a, token, username="changed", password="p2", notes="changed",
              urls=[{"url": "https://a.test", "match": "exact_origin"}])
    assert session.path.read_bytes() == before
    assert session.get_entry(a)["username"] == "u"
    assert session.login_edit_token(a) == token
    monkeypatch.undo()
    entry = _disk_entry(session, a)
    assert (entry["username"], entry["password"], entry.get("notes", "")) == ("u", "p1", "")


def test_save_login_rolls_back_urls_and_fields_when_details_fail(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p1")
    token = session.login_edit_token(a)
    before = session.path.read_bytes()
    with pytest.raises(VaultError, match="At most 20 tags"):
        _save(session, a, token, username="changed", password="p2", tags=[f"t{i}" for i in range(21)],
              urls=[{"url": "https://moved.test", "match": "exact_origin"}])
    assert session.path.read_bytes() == before
    entry = session.get_entry(a)
    assert (entry["username"], entry["password"], entry["scope"]["origin"]) == ("u", "p1", "https://a.test")
    assert session.login_edit_token(a) == token


def test_save_login_rejects_a_duplicate_username_for_the_site(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p")
    b = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="v", password="p")
    before = session.path.read_bytes()
    with pytest.raises(DuplicateLoginError) as err:
        _save(session, b, session.login_edit_token(b), username="u")
    assert err.value.existing_id == a
    assert session.path.read_bytes() == before


def test_save_login_rejects_a_duplicate_after_moving_the_site(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p")
    b = session.create_web_login(urls=[{"url": "https://b.test", "match": "exact_origin"}], username="u", password="p")
    with pytest.raises(DuplicateLoginError) as err:
        _save(session, b, session.login_edit_token(b), urls=[{"url": "https://a.test", "match": "exact_origin"}])
    assert err.value.existing_id == a


def test_save_login_can_rename_and_move_together(session):
    session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="v", password="p")
    b = session.create_web_login(urls=[{"url": "https://b.test", "match": "exact_origin"}], username="u", password="p")
    # (a.test, v) exists, but the final pair (c.test, v) is free.
    _save(session, b, session.login_edit_token(b), username="v",
          urls=[{"url": "https://c.test", "match": "exact_origin"}])
    entry = session.get_entry(b)
    assert entry["username"] == "v" and entry["scope"]["origin"] == "https://c.test"


def test_save_login_for_a_deleted_login_reports_a_change(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p")
    token = session.login_edit_token(a)
    session.delete(a)
    with pytest.raises(LoginChangedError):
        _save(session, a, token)


def test_create_web_login_refuses_duplicates(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p")
    before = session.path.read_bytes()
    with pytest.raises(DuplicateLoginError) as err:
        session.create_web_login(urls=[{"url": "https://a.test/login", "match": "exact_origin"}], username="u", password="q")
    assert err.value.existing_id == a
    assert session.path.read_bytes() == before
    assert session.credential_secret(a) == "p"


def test_create_web_login_applies_details_and_urls(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"},
                                       {"url": "https://a.test/app", "match": "starts_with"}],
                                 username="u", password="p", label="Alpha", favorite=True, tags=["x"], notes="n",
                                 recovery_codes=["c"], custom_fields=[{"name": "f", "value": "v", "hidden": False}],
                                 policy={"sign_in": "never"})
    entry = _disk_entry(session, a)
    assert entry["kind"] == "web" and entry["label"] == "Alpha" and entry["password"] == "p"
    assert entry["scope"]["origin"] == "https://a.test"
    assert len(entry["scope"]["urls"]) == 2
    assert entry["favorite"] is True and entry["tags"] == ["x"] and entry["notes"] == "n"
    assert entry["recovery_codes"] == ["c"] and entry["policy"]["sign_in"] == "never"
    assert entry["custom_fields"] == [{"name": "f", "value": "v", "hidden": False}]


def test_create_web_login_defaults_the_label_and_is_atomic(session, monkeypatch):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p")
    assert session.get_entry(a)["label"]
    before = session.path.read_bytes()
    count = len(session.all_entries())

    def boom(self, entry_id, urls):
        raise VaultError("simulated URL failure")

    monkeypatch.setattr(ItemService, "set_web_urls", boom)
    with pytest.raises(VaultError, match="simulated"):
        session.create_web_login(urls=[{"url": "https://b.test", "match": "exact_origin"}], username="u", password="p")
    assert session.path.read_bytes() == before
    assert len(session.all_entries()) == count


def test_create_web_login_rejects_invalid_details_without_writing(session):
    before = session.path.read_bytes()
    with pytest.raises(VaultError):
        session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u",
                                 password="p", tags=[str(i) for i in range(21)])
    assert session.path.read_bytes() == before
    assert session.all_entries() == []


def test_find_web_login_uses_the_upsert_matching_rule(session):
    a = session.upsert_web(origin="https://a.test", username="u", password="p")
    assert session.find_web_login("https://A.test:443/", "u") == a
    assert session.find_web_login("https://a.test", "U") is None
    assert session.find_web_login("https://b.test", "u") is None


def test_token_key_is_dropped_on_lock(session):
    a = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u", password="p")
    token = session.login_edit_token(a)
    session.lock()
    assert session._edit_token_key is None
    with pytest.raises(VaultLockedError):
        session.login_edit_token(a)
    reopened = unlock_vault(session.path, MASTER)
    try:
        assert reopened.login_edit_token(a) != token
        with pytest.raises(LoginChangedError):
            _save(reopened, a, token, username="later")
        assert reopened.get_entry(a)["username"] == "u"
    finally:
        reopened.lock()


def test_existing_upsert_and_update_behaviour_is_unchanged(session):
    a = session.upsert_web(origin="https://a.test", username="u", password="p1")
    assert session.upsert_web(origin="https://a.test", username="u", password="p2") == a
    assert [row["password"] for row in session.password_history(a)] == ["p1"]
    b = session.upsert_web(origin="https://a.test", username="v", password="p")
    with pytest.raises(VaultError, match="already has an entry for that username"):
        session.update_entry_fields(b, username="u")
    with pytest.raises(VaultError, match="This credential changed"):
        session.update_entry_fields(b, label="x", expected_revision=-1)
    assert json.loads(session.path.read_text(encoding="utf-8"))


def test_token_handles_unusual_text(session):
    a = session.upsert_web(origin="https://a.test", username="odd\ud800name", password="p")
    token = session.login_edit_token(a)
    assert token == session.login_edit_token(a)
    assert _save(session, a, token, username="odd\ud800name", label="Ünïcode ✓") != token


def test_create_web_login_reports_bad_urls_as_vault_errors(session):
    for urls in ([], [{"url": "ftp://a.test", "match": "exact_origin"}], [{"url": "https://a.test", "match": "bogus"}]):
        with pytest.raises(VaultError):
            session.create_web_login(urls=urls, username="u", password="p")
    assert session.all_entries() == []


# --- I3: the credential window's revision is per credential, not the whole-vault generation ---------------


def _sync_pair(tmp_path):
    """Vaults A and B in one cloud-folder group (cheap KDF), both synced once."""
    import time as _time

    from localvault.session_guard import StaleSession
    from localvault.sync import folder_transport as ft

    class Lease:
        valid = True

        def check(self):
            if not self.valid:
                raise StaleSession("locked")

    root = tmp_path / "OneDrive"
    root.mkdir()
    now = int(_time.time())
    cheap = (1024, 1, 1)
    a = create_vault(tmp_path / "sa.json", MASTER, kdf_overrides=KDF)
    b = create_vault(tmp_path / "sb.json", MASTER, kdf_overrides=KDF)
    la, lb = Lease(), Lease()
    pw = "correct horse battery staple 7!"
    ft.create_folder_group(root, a, la, pw, "A", install_id="ia", now=now, _kdf_override=cheap)
    ft.join_folder_group(root, b, lb, pw, "B", install_id="ib", now=now, _kdf_override=cheap)

    def sync(session, lease, install):
        return ft.FolderSync(root, install_id=install, _kdf_override=cheap).run_once(session, lease, now=now)

    return (a, lambda: sync(a, la, "ia")), (b, lambda: sync(b, lb, "ib"))


def test_credential_revision_survives_sync_metadata_saves_and_other_items(tmp_path):
    (a, sync_a), (b, sync_b) = _sync_pair(tmp_path)
    entry = a.upsert_web(origin="https://bank.test", username="me", password="pw-1")
    other = a.upsert_web(origin="https://other.test", username="me", password="pw-2")
    revision = a.credential_detail(entry)["revision"]
    token = a.login_edit_token(entry)
    generation = a._payload["generation"]
    assert type(revision) is int

    sync_a()  # writes sync_meta / sync_group only (B has nothing new)
    a.update_entry_fields(other, label="other renamed")  # another item
    assert a._payload["generation"] > generation, "the whole-vault generation moved"

    assert a.credential_detail(entry)["revision"] == revision
    assert a.login_edit_token(entry) == token
    assert a.credential_secret(entry, expected_revision=revision) == "pw-1"  # reveal still works
    assert a.update_entry_fields(entry, label="bank", expected_revision=revision) is True  # save still works
    sync_b()


def test_credential_revision_detects_a_concurrent_edit_of_the_same_credential(tmp_path):
    (a, sync_a), (b, sync_b) = _sync_pair(tmp_path)
    entry = a.upsert_web(origin="https://bank.test", username="me", password="pw-1")
    sync_a()
    sync_b()
    revision = a.credential_detail(entry)["revision"]
    b.update_entry_fields(entry, password="changed-on-b")  # a real edit of this credential elsewhere
    sync_b()
    sync_a()  # the edit arrives on A while A's credential window is open
    assert a.get_entry(entry)["password"] == "changed-on-b"
    with pytest.raises(VaultError, match="This credential changed"):
        a.credential_secret(entry, expected_revision=revision)
    with pytest.raises(VaultError, match="This credential changed"):
        a.update_entry_fields(entry, label="mine", expected_revision=revision)
    fresh = a.credential_detail(entry)["revision"]
    assert fresh != revision
    assert a.credential_secret(entry, expected_revision=fresh) == "changed-on-b"


def test_credential_revision_changes_on_a_local_edit_of_that_credential(session):
    entry = session.upsert_web(origin="https://bank.test", username="me", password="pw-1")
    revision = session.credential_detail(entry)["revision"]
    assert session.entry_revision(entry) == revision
    session.update_entry_fields(entry, username="me2")
    with pytest.raises(VaultError, match="This credential changed"):
        session.update_entry_fields(entry, label="x", expected_revision=revision)
    with pytest.raises(VaultError, match="This credential changed"):
        session.credential_secret(entry, expected_revision=True)  # a bool is never a revision
