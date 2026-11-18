"""lgk:// references: parsing and resolution against allowed / not-allowed vault rows."""
from __future__ import annotations

import pytest

from localvault.lgk_refs import Ref, RefError, RefItem, find, parse, resolve


def _row(item_id, title, allowed=True, kind="web", listed=None, **fields):
    return RefItem(item_id, title, kind, allowed, (lambda field: fields.get(field)) if allowed else (lambda f: None),
                   listed=allowed if listed is None else listed)


def test_parse_valid_and_percent_encoded():
    assert parse("lgk://GitHub/password") == Ref("GitHub", "password")
    assert parse("lgk://Work%20mail%2FIMAP/username") == Ref("Work mail/IMAP", "username")
    assert parse("lgk://Caf%C3%A9/notes") == Ref("Café", "notes")
    assert parse("lgk://0f6c1b9e-1111-2222-3333-444455556666/private_key").field == "private_key"


@pytest.mark.parametrize("ref", ["lgk://a/b/c", "lgk://a", "lgk:///password", "lgk://a/", "GitHub/password",
                                 "https://a/b", "lgk://%ZZ%FF/x", "lgk://%FF/x", "lgk://a%00/x", None, 3,
                                 "lgk://" + "a" * 3000 + "/x"])
def test_parse_rejects_three_parts(ref):
    with pytest.raises(RefError) as caught:
        parse(ref)
    assert caught.value.code == "bad_reference"


def test_resolve_by_id_and_title():
    rows = [_row("id-1", "GitHub", password="pw-1", username="me"), _row("id-2", "Mail", password="pw-2")]
    assert resolve("lgk://id-2/password", rows) == "pw-2"
    assert resolve("lgk://GitHub/username", rows) == "me"
    assert resolve("lgk://github/password", rows) == "pw-1"  # case is ignored when nothing matches exactly
    # An id wins over a title that happens to equal it.
    rows.append(_row("Mail", "Other", password="pw-3"))
    assert resolve("lgk://Mail/password", rows) == "pw-3"
    with pytest.raises(RefError) as caught:
        resolve("lgk://Nope/password", rows)
    assert caught.value.code == "not_found"
    with pytest.raises(RefError) as caught:
        resolve("lgk://GitHub/nothing", rows)
    assert caught.value.code == "no_field" and "pw" not in caught.value.message


def test_resolve_ambiguous_lists_ids():
    rows = [_row("id-1", "AWS", key="k1"), _row("id-2", "AWS", key="k2"), _row("id-3", "AWS", allowed=False)]
    with pytest.raises(RefError) as caught:
        resolve("lgk://AWS/key", rows)
    error = caught.value
    assert error.code == "ambiguous"
    assert "id-1" in error.message and "id-2" in error.message
    assert "id-3" not in error.message  # a not-allowed item is never named
    assert "k1" not in error.message and "k2" not in error.message
    # One allowed match beside a not-allowed one with the same title resolves.
    assert resolve("lgk://AWS/key", rows[1:]) == "k2"


def test_resolve_strict_login_not_allowed():
    # An allow-listed strict login is listed but not allowed: not_allowed by id and by title.
    rows = [_row("id-1", "Bank", allowed=False, listed=True), _row("id-2", "Mail", password="pw")]
    for ref in ("lgk://id-1/password", "lgk://Bank/password", "lgk://bank/password"):
        with pytest.raises(RefError) as caught:
            resolve(ref, rows)
        assert caught.value.code == "not_allowed"
    assert find(parse("lgk://Mail/password"), rows).id == "id-2"


def test_title_outside_the_allow_list_is_not_found():
    # Any process can run lgk.exe: a title that only matches items outside the allow-list must look absent.
    rows = [_row("id-7", "Coinbase", allowed=False), _row("id-2", "Mail", password="pw")]
    for ref in ("lgk://Coinbase/password", "lgk://coinbase/password", "lgk://Nothing/password"):
        with pytest.raises(RefError) as caught:
            resolve(ref, rows)
        assert caught.value.code == "not_found" and "id-7" not in caught.value.message
    # An exact id reference still says not_allowed (the caller already knows the id).
    with pytest.raises(RefError) as caught:
        resolve("lgk://id-7/password", rows)
    assert caught.value.code == "not_allowed"


def test_resolve_typed_payload_field():
    rows = [_row("id-9", "Stripe", kind="api_key", key="sk_test_1", secret="whsec_2")]
    assert resolve(Ref("Stripe", "secret"), rows) == "whsec_2"
    assert resolve("lgk://id-9/key", rows) == "sk_test_1"
