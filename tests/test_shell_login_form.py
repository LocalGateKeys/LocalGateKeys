"""Pure (Tk-free) tests for the login form model."""
import inspect

import pytest

from localvault.shell import login_form as lf
from localvault.vault import VaultSession, create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
EXACT = [{"url": "https://example.com", "match": "exact_origin"}]


def _detail(**over):
    d = {"id": "abc", "kind": "web", "scope": {"origin": "https://example.com"}, "label": "example.com",
         "username": "me", "favorite": True, "tags": ["a"], "notes": "n", "totp": None,
         "recovery_codes": ["c1"], "custom_fields": [{"name": "pin", "value": "1", "hidden": True}],
         "policy": {"fill": "click"}}
    d.update(over)
    return d


def _draft(**over):
    d = lf.draft_from_detail(_detail(), EXACT)
    for k, v in over.items():
        setattr(d, k, v)
    return d


def _fields(d):
    return {e.field for e in lf.validate(d)}


def test_new_web_draft_defaults():
    d = lf.draft_for_new_web("pw123")
    assert d.kind == "web" and d.entry_id is None and d.password == "pw123"
    assert d.urls == [lf.UrlRow("", "exact_origin")]
    assert d.label_edited is False and d.desktop_binding is None


def test_effective_label_follows_url_until_edited():
    d = lf.draft_for_new_web("x")
    assert lf.effective_label(d) == "Untitled login"
    d.urls[0].url = "https://www.example.com/login"
    assert lf.effective_label(d) == "example.com"
    d.urls[0].url = "https://other.org"
    assert lf.effective_label(d) == "other.org"
    d.label, d.label_edited = "Mine", True
    d.urls[0].url = "https://third.org"
    assert lf.effective_label(d) == "Mine"


def test_draft_from_detail_never_reads_password_and_is_clean():
    d = lf.draft_from_detail(_detail(password="LEAK"), [{"url": "https://example.com", "match": "host"}])
    assert d.password is None and d.entry_id == "abc"
    assert d.urls == [lf.UrlRow("https://example.com", "host")]
    assert d.label_edited is False  # equals the derived label
    assert lf.is_dirty(d, lf.snapshot(d)) is False
    d2 = lf.draft_from_detail(_detail(label="Custom"), EXACT)
    assert d2.label_edited is True


def test_draft_from_detail_loads_totp():
    d = lf.draft_from_detail(_detail(totp={"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA256", "digits": 8,
                                           "period": 60}), [])
    assert d.totp_text == "JBSWY3DPEHPK3PXP" and (d.totp_algorithm, d.totp_digits, d.totp_period) == ("SHA256", 8, 60)
    assert lf.totp_config(d) == {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA256", "digits": 8, "period": 60}


@pytest.mark.parametrize("mutate", [
    lambda d: setattr(d, "username", "z"), lambda d: setattr(d, "password", "new"),
    lambda d: setattr(d, "favorite", False), lambda d: d.tags.append("b"), lambda d: setattr(d, "notes", "m"),
    lambda d: setattr(d, "label", "L") or setattr(d, "label_edited", True),
    lambda d: d.urls.append(lf.UrlRow("https://b.test", "host")),
    lambda d: setattr(d.urls[0], "match", "host"), lambda d: setattr(d, "totp_text", "JBSWY3DPEHPK3PXP"),
    lambda d: d.recovery_codes.append("c2"), lambda d: d.custom_fields[0].update(value="2"),
    lambda d: d.policy.update(fill="never"), lambda d: setattr(d, "totp_digits", 8),
])
def test_is_dirty_after_any_change(mutate):
    d = _draft()
    snap = lf.snapshot(d)
    mutate(d)
    assert lf.is_dirty(d, snap) is True


def test_valid_draft_has_no_errors():
    assert lf.validate(_draft()) == []


def test_validate_urls():
    assert _fields(_draft(urls=[])) == {"urls"}
    assert _fields(_draft(urls=[lf.UrlRow("", "host")])) == {"urls[0]"}
    d = _draft(urls=[lf.UrlRow("https://ok.test", "host"), lf.UrlRow("ftp://x", "host")])
    errs = lf.validate(d)
    assert [e.field for e in errs] == ["urls[1]"] and "http" in errs[0].message
    assert _fields(_draft(urls=[lf.UrlRow(f"https://h{i}.test", "host") for i in range(21)])) == {"urls"}
    assert _fields(_draft(urls=[lf.UrlRow(f"https://h{i}.test", "host") for i in range(20)])) == set()
    assert _fields(_draft(urls=[lf.UrlRow("http://remote.example.com", "host")])) == {"urls[0]"}


def test_exact_origin_row_with_path_is_normalised_not_an_error():
    d = _draft(urls=[lf.UrlRow("https://Example.com/login?x=1", "exact_origin")])
    assert lf.validate(d) == []
    assert lf.save_kwargs(d)["urls"] == [{"url": "https://example.com", "match": "exact_origin"}]
    assert d.urls[0].url == "https://Example.com/login?x=1"  # draft text untouched
    d = _draft(urls=[lf.UrlRow("https://example.com/a/b", "starts_with")])
    assert lf.save_kwargs(d)["urls"] == [{"url": "https://example.com/a/b", "match": "starts_with"}]


def test_validate_password_rules():
    assert _fields(lf.draft_for_new_web("")) == {"urls[0]", "password"}
    assert _fields(_draft(password=None)) == set()
    assert _fields(_draft(password="")) == {"password"}
    assert _fields(_draft(password="p" * 4096)) == set()
    assert _fields(_draft(password="p" * 4097)) == {"password"}
    new = lf.draft_for_new_web("x")
    new.urls[0].url = "https://a.test"
    new.password = None
    assert _fields(new) == {"password"}


def test_validate_text_limits():
    assert _fields(_draft(username="u" * 512)) == set()
    assert _fields(_draft(username="u" * 513)) == {"username"}
    assert _fields(_draft(label="l" * 513, label_edited=True)) == {"label"}
    assert _fields(_draft(notes="n" * 20001)) == {"notes"}
    assert _fields(_draft(recovery_codes=["c"] * 101)) == {"recovery_codes"}
    assert _fields(_draft(recovery_codes=["c" * 513])) == {"recovery_codes"}


def test_validate_tags():
    assert _fields(_draft(tags=[f"t{i}" for i in range(20)])) == set()
    assert _fields(_draft(tags=[f"t{i}" for i in range(21)])) == {"tags"}
    assert _fields(_draft(tags=["t" * 41])) == {"tags"}
    assert _fields(_draft(tags=["t" * 40, " ", "t" * 40])) == set()  # blanks and duplicates dropped


def test_validate_custom_fields():
    cf = [{"name": "ok", "value": "v", "hidden": False}, {"name": "", "value": "v", "hidden": True},
          {"name": "n" * 101, "value": "", "hidden": True}, {"name": "x", "value": "v" * 4097, "hidden": True}]
    errs = lf.validate(_draft(custom_fields=cf))
    assert [e.field for e in errs] == ["custom_fields[1]", "custom_fields[2]", "custom_fields[3]"]
    many = [{"name": f"n{i}", "value": "", "hidden": True} for i in range(51)]
    assert _fields(_draft(custom_fields=many)) == {"custom_fields"}
    # a fully blank row is ignored
    d = _draft(custom_fields=[{"name": "", "value": "", "hidden": True}])
    assert lf.validate(d) == [] and lf.save_kwargs(d)["custom_fields"] == []


def test_totp_accepts_uri_and_bare_key():
    assert lf.totp_config(_draft(totp_text="")) is None
    assert lf.totp_config(_draft(totp_text="   ")) is None
    bare = lf.totp_config(_draft(totp_text="jbsw y3dp-ehpk 3pxp"))
    assert bare == {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30}
    uri = "otpauth://totp/Ex:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60&issuer=Ex"
    assert lf.totp_config(_draft(totp_text=uri)) == {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA256",
                                                     "digits": 8, "period": 60}
    assert _fields(_draft(totp_text=uri)) == set()
    assert _fields(_draft(totp_text="!!notbase32!!")) == {"totp"}
    assert _fields(_draft(totp_text="otpauth://hotp/x?secret=AAAA")) == {"totp"}
    assert _fields(_draft(totp_text="JBSWY3DPEHPK3PXP", totp_digits=9)) == {"totp"}


def test_password_meta():
    m0 = lf.password_meta("", reuse_count=0)
    assert m0.segments == 0 and m0.reuse_text == "not used anywhere else"
    m1 = lf.password_meta("correct-horse-battery-staple-9Q!x", reuse_count=1)
    assert m1.segments == 4 and m1.label == "Very strong" and m1.reuse_text == "used by 1 other logins"
    m3 = lf.password_meta("password", reuse_count=3)
    assert m3.segments == 0 and m3.label == "Very weak" and m3.reuse_text == "used by 3 other logins"


def test_save_kwargs_matches_vault_signatures():
    d = _draft(tags=[" a ", "a", "b"], recovery_codes=["c1", " "], policy={"fill": "never", "junk": 1})
    kwargs = lf.save_kwargs(d)
    save = set(inspect.signature(VaultSession.save_login).parameters) - {"self", "entry_id", "expected_token"}
    create = set(inspect.signature(VaultSession.create_web_login).parameters) - {"self"}
    assert set(kwargs) == save == create
    assert kwargs["tags"] == ["a", "b"] and kwargs["recovery_codes"] == ["c1"]
    assert kwargs["label"] == "example.com" and kwargs["password"] is None
    assert kwargs["policy"]["fill"] == "never" and "junk" not in kwargs["policy"]
    assert kwargs["totp"] is None


def test_save_kwargs_refuses_invalid_draft():
    with pytest.raises(ValueError):
        lf.save_kwargs(_draft(username="u" * 600))


def test_desktop_draft_keeps_urls_none():
    d = lf.draft_from_detail(_detail(kind="desktop", scope={"exe_path": "C:/a.exe", "window_title": "A"},
                                     label="App"), [])
    assert d.kind == "desktop" and d.app_path == "C:/a.exe" and d.window_title == "A"
    assert lf.validate(d) == [] and lf.save_kwargs(d)["urls"] is None
    assert lf.effective_label(d) == "App"


def test_round_trip_through_real_vault(tmp_path):
    s = create_vault(tmp_path / "v.json", "correct horse battery staple", kdf_overrides=KDF)
    try:
        d = lf.draft_for_new_web("s3cret-Passw0rd-xyz")
        d.urls[0].url = "https://www.example.com/login"
        d.username = "me"
        d.totp_text = "JBSWY3DPEHPK3PXP"
        d.tags = ["x"]
        entry_id = s.create_web_login(**lf.save_kwargs(d))
        detail = s.credential_detail(entry_id)
        d2 = lf.draft_from_detail(detail, [{"url": "https://www.example.com", "match": "exact_origin"}])
        assert d2.password is None and lf.totp_config(d2)["secret"] == "JBSWY3DPEHPK3PXP"
        assert d2.tags == ["x"] and not lf.validate(d2)
        d2.notes = "changed"
        s.save_login(entry_id, expected_token=s.login_edit_token(entry_id), **lf.save_kwargs(d2))
        assert s.credential_detail(entry_id)["notes"] == "changed"
        assert s.credential_secret(entry_id) == "s3cret-Passw0rd-xyz"
    finally:
        s.lock()


@pytest.mark.parametrize("typed,match,expected", [
    ("example.com", "host", "https://example.com"),
    ("example.com", "exact_origin", "https://example.com"),
    ("www.example.com/login", "exact_origin", "https://www.example.com"),
    ("localhost:8080", "exact_origin", "https://localhost:8080"),
    ("http://localhost:8080", "exact_origin", "http://localhost:8080"),
])
def test_bare_domains_get_https(typed, match, expected):
    d = _draft(urls=[lf.UrlRow(typed, match)])
    assert lf.validate(d) == []
    assert lf.save_kwargs(d)["urls"] == [{"url": expected, "match": match}]
    assert d.urls[0].url == typed


def test_bare_domain_does_not_loosen_other_rules():
    assert _fields(_draft(urls=[lf.UrlRow("ftp://x", "host")])) == {"urls[0]"}
    assert _fields(_draft(urls=[lf.UrlRow("http://remote.example.com", "host")])) == {"urls[0]"}
