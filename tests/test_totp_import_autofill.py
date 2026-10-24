from __future__ import annotations

import base64
import json
from urllib.parse import quote

import pytest
from test_release019 import KDF, MASTER, Broker  # noqa: F401  (shared broker double)

from localvault.totp import TotpError, generate_totp, match_migration_account, parse_migration_uri
from localvault.vault import create_vault

RFC_KEY = b"12345678901234567890"
RFC_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(number: int, value) -> bytes:
    if isinstance(value, int):
        return _varint(number << 3) + _varint(value)
    if isinstance(value, str):
        value = value.encode()
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _otp(secret=RFC_KEY, name="alice@example.test", issuer="Example", algorithm=1, digits=1, otp_type=2) -> bytes:
    return (_field(1, secret) + _field(2, name) + _field(3, issuer)
            + _field(4, algorithm) + _field(5, digits) + _field(6, otp_type))


def _uri(*otps: bytes, batch_size=1, batch_index=0, urlsafe=False) -> str:
    payload = b"".join(_field(1, o) for o in otps) + _field(2, batch_size) + _field(3, batch_index)
    data = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(payload).decode()
    return "otpauth-migration://offline?data=" + quote(data, safe="")


def test_migration_single_account_matches_rfc_vector():
    result = parse_migration_uri(_uri(_otp()))
    [acc] = result["accounts"]
    assert acc["secret"] == RFC_B32 and acc["issuer"] == "Example" and acc["label"] == "alice@example.test"
    assert (acc["algorithm"], acc["digits"], acc["period"]) == ("SHA1", 6, 30)
    assert generate_totp(acc["secret"], timestamp=59)[0] == "287082"


def test_migration_strips_issuer_prefix_and_handles_unescaped_plus_and_urlsafe():
    raw = _uri(_otp(name="Example:alice", secret=b"\xfb\xff" * 10))
    unescaped = raw.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
    for uri in (raw, unescaped, _uri(_otp(name="Example:alice", secret=b"\xfb\xff" * 10), urlsafe=True)):
        [acc] = parse_migration_uri(uri)["accounts"]
        assert acc["label"] == "alice"
        assert base64.b32decode(acc["secret"] + "=" * (-len(acc["secret"]) % 8)) == b"\xfb\xff" * 10


def test_migration_multiple_accounts_skips_hotp_and_reports_batch():
    result = parse_migration_uri(_uri(_otp(issuer="GitHub", algorithm=2, digits=2),
                                      _otp(issuer="Counter", otp_type=1),
                                      batch_size=2, batch_index=1))
    assert [a["issuer"] for a in result["accounts"]] == ["GitHub"]
    assert result["accounts"][0]["algorithm"] == "SHA256" and result["accounts"][0]["digits"] == 8
    assert result["skipped"][0]["issuer"] == "Counter" and "HOTP" in result["skipped"][0]["reason"]
    assert (result["batch_index"], result["batch_size"]) == (1, 2)


@pytest.mark.parametrize("bad", ["otpauth://totp/x?secret=" + RFC_B32, "otpauth-migration://offline?data=",
                                 "otpauth-migration://offline?data=%%%%", "otpauth-migration://offline?data=CgE",
                                 "https://example.test"])
def test_migration_rejects_malformed(bad):
    with pytest.raises(TotpError):
        parse_migration_uri(bad)


def test_match_account_by_issuer_or_host_and_refuses_ties():
    accounts = [{"issuer": "GitHub", "label": "a"}, {"issuer": "Google", "label": "b"}, {"issuer": "", "label": "x"}]
    assert match_migration_account(accounts, "My code", "https://github.com")["issuer"] == "GitHub"
    assert match_migration_account(accounts, "Google", "")["issuer"] == "Google"
    assert match_migration_account(accounts, "Bank", "https://bank.test") is None
    assert match_migration_account(accounts[:1], "anything") is accounts[0]


# ----------------------------------------------------------- browser broker

@pytest.fixture
def vault(tmp_path):
    s = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    yield s
    s.lock()


def _login(vault, user="alice", totp=True, origin="https://example.test", **policy):
    eid = vault.upsert_web(origin=origin, username=user, password="Test-only-password!", label=user)
    vault.set_details(eid, totp={"secret": RFC_B32} if totp else None, policy=policy or None)
    return eid


def test_totp_fill_releases_code_once_and_never_the_secret(vault):
    eid = _login(vault)
    _login(vault, "bob", totp=False)
    b = Broker(vault)
    start = b.request("begin_totp_browser", user_gesture=True)
    assert start["ok"] and [c["entry_id"] for c in start["choices"]] == [eid]
    assert RFC_B32 not in json.dumps(start)
    got = b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())
    assert got["ok"] and len(got["code"]) == 6 and got["code"].isdigit() and 1 <= got["remaining"] <= 30
    assert len(got["next_code"]) == 6 and RFC_B32 not in json.dumps(got)
    assert not b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())["ok"]


def test_totp_requires_gesture_exact_origin_and_fill_policy(vault):
    _login(vault, origin="https://example.test.evil.test")
    b = Broker(vault)
    assert b.request("begin_totp_browser")["error"] == "user_gesture_required"
    assert b.request("begin_totp_browser", user_gesture=True)["error"] == "totp_not_found"
    _login(vault, "carol", fill="never")
    assert b.request("begin_totp_browser", user_gesture=True)["error"] == "totp_not_found"


def test_totp_grant_bound_to_context_and_session(vault):
    eid = _login(vault)
    b = Broker(vault)
    start = b.request("begin_totp_browser", user_gesture=True)
    other = b.request("get_totp_browser", grant=start["grant"], entry_id=eid, context="tab-2-document-2-operation-2", gesture_nonce=b.nonce(context="tab-2-document-2-operation-2"))
    assert not other["ok"] and "code" not in other
    b.guard.invalidate()
    locked = b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())
    assert not locked["ok"] and "code" not in locked


def test_totp_master_password_policy_is_enforced(vault):
    eid = _login(vault, require_master_password=True)
    b = Broker(vault)
    b.reauthenticate = lambda *args: False
    start = b.request("begin_totp_browser", user_gesture=True)
    result = b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())
    assert result["error"] == "user_cancelled" and "code" not in result
