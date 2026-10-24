"""TOTP hardening: secret buffers are wiped, parsers are strict and robust,
and the browser fill path honours the per-code confirmation setting without
ever exposing the secret."""
from __future__ import annotations

import base64
import json
import logging
import random
from urllib.parse import quote

import pytest
from test_release019 import KDF, MASTER, Broker  # noqa: F401  (shared broker double)
from test_totp_import_autofill import _otp, _uri

from localvault import totp as totp_module
from localvault.settings import AppSettings
from localvault.totp import (
    MAX_SECRET_BYTES,
    TotpError,
    decode_secret,
    generate_totp,
    generate_totp_from_key,
    normalize_secret,
    parse_migration_uri,
    parse_otpauth_uri,
    requires_totp_confirmation,
    wipe,
)
from localvault.vault import create_vault

RFC_KEY = b"12345678901234567890"
RFC_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
URI = f"otpauth://totp/Example:alice@example.test?secret={RFC_B32}&issuer=Example&digits=8&period=30&algorithm=SHA1"


# ------------------------------------------------------------ memory handling

def test_wipe_zeroes_buffer_in_place():
    buf = bytearray(b"super secret")
    wipe(buf)
    assert buf == bytearray(len(b"super secret")) and len(buf) == 12
    wipe(bytearray())  # empty buffers are fine


def test_decode_secret_returns_mutable_bytearray():
    key = decode_secret(RFC_B32)
    assert isinstance(key, bytearray) and bytes(key) == RFC_KEY


def test_generate_totp_from_key_matches_rfc_vector_and_wipes_key():
    key = bytearray(RFC_KEY)
    code, remaining = generate_totp_from_key(key, timestamp=59, digits=8, period=30, algorithm="SHA1")
    assert code == "94287082" and remaining == 1
    assert key == bytearray(len(RFC_KEY)), "key buffer must be zeroed after use"
    assert len(key) == len(RFC_KEY)


def test_generate_totp_from_key_can_keep_key_for_a_second_code():
    key = bytearray(RFC_KEY)
    code, remaining = generate_totp_from_key(key, timestamp=59, digits=8, wipe_key=False)
    assert code == "94287082" and bytes(key) == RFC_KEY
    next_code, _ = generate_totp_from_key(key, timestamp=59 + remaining, digits=8)
    assert next_code == "37359152" and key == bytearray(len(RFC_KEY))


def test_generate_totp_wipes_key_even_when_hmac_fails(monkeypatch):
    seen: list[bytearray] = []
    real_decode = totp_module.decode_secret

    def spy(secret):
        key = real_decode(secret)
        seen.append(key)
        return key

    monkeypatch.setattr(totp_module, "decode_secret", spy)

    def boom(*args, **kwargs):
        raise RuntimeError("hmac unavailable")

    monkeypatch.setattr(totp_module.hmac, "new", boom)
    with pytest.raises(RuntimeError):
        generate_totp(RFC_B32, timestamp=59)
    assert len(seen) == 1 and seen[0] == bytearray(len(RFC_KEY))


def test_generate_totp_wipes_decoded_key_on_success(monkeypatch):
    seen: list[bytearray] = []
    real_decode = totp_module.decode_secret

    def spy(secret):
        key = real_decode(secret)
        seen.append(key)
        return key

    monkeypatch.setattr(totp_module, "decode_secret", spy)
    assert generate_totp(RFC_B32, timestamp=59, digits=8)[0] == "94287082"
    assert seen and all(k == bytearray(len(k)) and len(k) == len(RFC_KEY) for k in seen)


@pytest.mark.parametrize("key", [b"not a bytearray", RFC_KEY.decode(), memoryview(RFC_KEY)])
def test_generate_totp_from_key_rejects_immutable_keys(key):
    with pytest.raises(TotpError):
        generate_totp_from_key(key, timestamp=59)  # type: ignore[arg-type]


def test_generate_totp_from_key_rejects_empty_or_oversized_key():
    with pytest.raises(TotpError):
        generate_totp_from_key(bytearray(), timestamp=59)
    with pytest.raises(TotpError):
        generate_totp_from_key(bytearray(MAX_SECRET_BYTES + 1), timestamp=59)


# ------------------------------------------------------------ strict validation

def test_secret_length_is_bounded():
    assert MAX_SECRET_BYTES == 128
    ok = base64.b32encode(b"\x01" * MAX_SECRET_BYTES).decode().rstrip("=")
    assert normalize_secret(ok) == ok
    too_long = base64.b32encode(b"\x01" * (MAX_SECRET_BYTES + 1)).decode().rstrip("=")
    with pytest.raises(TotpError, match="too long"):
        normalize_secret(too_long)
    with pytest.raises(TotpError):
        parse_otpauth_uri(f"otpauth://totp/x?secret={too_long}")


@pytest.mark.parametrize("param,value", [
    ("digits", "5"), ("digits", "9"), ("digits", "abc"), ("digits", ""), ("digits", "6.0"), ("digits", "-6"),
    ("period", "14"), ("period", "121"), ("period", "x"), ("period", "999999999999999999999"),
    ("algorithm", "MD5"), ("algorithm", "SHA384"), ("algorithm", ""), ("algorithm", "sha1x"),
])
def test_parse_otpauth_rejects_out_of_range_parameters(param, value):
    uri = f"otpauth://totp/x?secret={RFC_B32}&{param}={quote(value)}"
    with pytest.raises(TotpError):
        parse_otpauth_uri(uri)


@pytest.mark.parametrize("bad", [
    None, 42, b"otpauth://totp/x?secret=" + RFC_B32.encode(), "", "otpauth://totp/x",
    "otpauth://totp/x?secret=", "otpauth://hotp/x?secret=" + RFC_B32, "otpauth://[totp/x?secret=" + RFC_B32,
    "http://totp/x?secret=" + RFC_B32, "otpauth://totp/x?secret=%ZZ", "otpauth://totp/x?secret=" + "A" * 5000,
    "otpauth://totp/x?secret=1189", "otpauth://totp/x?secret=" + RFC_B32 + "&digits=6&digits=7",
    "otpauth://totp/x?secret=" + RFC_B32 + "&secret=" + RFC_B32, "o" * (16 * 1024 + 1),
])
def test_parse_otpauth_rejects_malformed(bad):
    with pytest.raises(TotpError):
        parse_otpauth_uri(bad)  # type: ignore[arg-type]


def test_parse_otpauth_accepts_boundaries_and_lowercase_algorithm():
    for digits, period, alg in ((6, 15, "sha1"), (7, 60, "Sha256"), (8, 120, "SHA512")):
        res = parse_otpauth_uri(f"otpauth://totp/x?secret={RFC_B32}&digits={digits}&period={period}&algorithm={alg}")
        assert (res["digits"], res["period"], res["algorithm"]) == (digits, period, alg.upper())
        assert generate_totp(res["secret"], timestamp=59, digits=digits, period=period, algorithm=alg)[0].isdigit()


def test_generate_totp_rejects_bad_parameters():
    for kwargs in ({"digits": 5}, {"digits": 9}, {"period": 14}, {"period": 121}, {"algorithm": "MD5"},
                   {"timestamp": -1}, {"digits": "6"}, {"period": 30.0}, {"timestamp": 1.5}):
        with pytest.raises(TotpError):
            generate_totp(RFC_B32, **{"timestamp": 59, **kwargs})  # type: ignore[arg-type]


def test_migration_skips_oversized_secret_with_reason():
    big = _otp(secret=b"\x01" * (MAX_SECRET_BYTES + 1), issuer="Big")
    result = parse_migration_uri(_uri(_otp(), big))
    assert [a["issuer"] for a in result["accounts"]] == ["Example"]
    assert result["skipped"][0]["issuer"] == "Big" and "long" in result["skipped"][0]["reason"]


def test_migration_rejects_absurd_batch_values_and_nested_garbage():
    with pytest.raises(TotpError):
        parse_migration_uri(_uri(_otp(), batch_size=0))
    with pytest.raises(TotpError):
        parse_migration_uri(_uri(_otp(), batch_size=2, batch_index=5))
    with pytest.raises(TotpError):
        parse_migration_uri(_uri(_otp(), batch_size=10**9))


_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwxyz0123456789=&?/:%+-_.;,[]{}<>\\\"' \t\n\x00\xff"


def _mutate(rng: random.Random, text: str) -> str:
    for _ in range(rng.randint(1, 4)):
        op = rng.randint(0, 6)
        if not text:
            text = rng.choice(_ALPHABET)
        i = rng.randrange(len(text))
        if op == 0:
            text = text[:i] + text[i + 1:]
        elif op == 1:
            text = text[:i] + rng.choice(_ALPHABET) + text[i:]
        elif op == 2:
            text = text[:i] + rng.choice(_ALPHABET) + text[i + 1:]
        elif op == 3:
            text = text[:i]
        elif op == 4:
            j = rng.randrange(i, len(text) + 1)
            text = text[:j] + text[i:j] + text[j:]
        elif op == 5:
            text = text[:i] + text[i:][::-1]
        else:
            text = text[:i] + "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 40))) + text[i:]
    return text


def test_fuzz_otpauth_parser_raises_only_totp_error():
    rng = random.Random(20261005)
    seeds = [URI, f"otpauth://totp/x?secret={RFC_B32}", f"otpauth://totp/Ex:bob?secret={RFC_B32}&digits=6&period=15&algorithm=SHA256"]
    for _ in range(500):
        candidate = _mutate(rng, rng.choice(seeds))
        try:
            result = parse_otpauth_uri(candidate)
        except TotpError:
            continue
        assert result["digits"] in (6, 7, 8) and 15 <= result["period"] <= 120
        assert result["algorithm"] in ("SHA1", "SHA256", "SHA512")
        assert generate_totp(result["secret"], timestamp=59, digits=result["digits"],
                             period=result["period"], algorithm=result["algorithm"])[0].isdigit()


def test_fuzz_migration_parser_raises_only_totp_error():
    rng = random.Random(1975)
    seeds = [_uri(_otp()), _uri(_otp(issuer="GitHub", algorithm=2, digits=2), _otp(issuer="Counter", otp_type=1),
                               batch_size=2, batch_index=1), _uri(_otp(), urlsafe=True)]
    # Mutate both the URI text and the raw protobuf bytes behind it.
    payloads = [base64.b64decode(s.split("data=")[1].replace("%2B", "+").replace("%2F", "/")
                                 .replace("%3D", "=").replace("-", "+").replace("_", "/")) for s in seeds[:2]]
    for n in range(500):
        if n % 2:
            candidate = _mutate(rng, rng.choice(seeds))
        else:
            raw = bytearray(rng.choice(payloads))
            for _ in range(rng.randint(1, 6)):
                if raw and rng.random() < 0.7:
                    raw[rng.randrange(len(raw))] = rng.randrange(256)
                elif raw and rng.random() < 0.5:
                    del raw[rng.randrange(len(raw))]
                else:
                    raw.insert(rng.randrange(len(raw) + 1), rng.randrange(256))
            candidate = "otpauth-migration://offline?data=" + quote(base64.b64encode(bytes(raw)).decode(), safe="")
        try:
            result = parse_migration_uri(candidate)
        except TotpError:
            continue
        for acc in result["accounts"]:
            assert acc["digits"] in (6, 8) and acc["algorithm"] in ("SHA1", "SHA256", "SHA512")
            assert isinstance(acc["secret"], str) and normalize_secret(acc["secret"]) == acc["secret"]
            assert isinstance(acc["label"], str) and isinstance(acc["issuer"], str)


# ------------------------------------------------------------ totp_confirm setting

def test_totp_confirm_setting_defaults_off_and_round_trips(tmp_path):
    assert AppSettings().totp_confirm is False
    assert requires_totp_confirmation(AppSettings()) is False
    s = AppSettings(totp_confirm=True)
    assert requires_totp_confirmation(s) is True
    path = tmp_path / "settings.json"
    s.save(path)
    assert AppSettings.load(path).totp_confirm is True
    data = json.loads(path.read_text(encoding="utf-8"))
    data["totp_confirm"] = "yes"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert AppSettings.load(path).totp_confirm is False
    assert requires_totp_confirmation(None) is False
    assert requires_totp_confirmation(object()) is False


# ------------------------------------------------------------ browser broker

@pytest.fixture
def vault(tmp_path):
    s = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    yield s
    s.lock()


def _login(vault, user="alice", origin="https://example.test", **policy):
    eid = vault.upsert_web(origin=origin, username=user, password="Test-only-password!", label=user)
    vault.set_details(eid, totp={"secret": RFC_B32}, policy=policy or None)
    return eid


def test_totp_confirm_setting_asks_before_each_code(vault, monkeypatch):
    eid = _login(vault)
    b = Broker(vault)
    b.settings.totp_confirm = True
    asked: list[tuple] = []
    monkeypatch.setattr("broker_host.confirm", lambda *args: asked.append(args) or False)
    start = b.request("begin_totp_browser", user_gesture=True)
    denied = b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())
    assert denied == {"ok": False, "error": "user_cancelled"}
    assert len(asked) == 1 and "example.test" in asked[0][2] and "alice" in asked[0][2]
    assert RFC_B32 not in json.dumps([str(a) for a in asked])
    # Declining does not consume the grant; the user can confirm on retry.
    monkeypatch.setattr("broker_host.confirm", lambda *args: asked.append(args) or True)
    got = b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())
    assert got["ok"] and got["code"].isdigit() and len(asked) == 2
    # The grant is single-use once a code has been released.
    assert not b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())["ok"]


def test_totp_confirm_off_never_prompts(vault, monkeypatch):
    eid = _login(vault)
    b = Broker(vault)
    assert b.settings.totp_confirm is False
    monkeypatch.setattr("broker_host.confirm", lambda *args: pytest.fail("must not prompt"))
    start = b.request("begin_totp_browser", user_gesture=True)
    assert b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce())["ok"]


def test_totp_fill_responses_and_logs_never_contain_secret(vault, monkeypatch, caplog):
    eid = _login(vault)
    denied = _login(vault, "bob", fill="never")
    b = Broker(vault)
    b.settings.totp_confirm = True
    monkeypatch.setattr("broker_host.confirm", lambda *args: True)
    secret_forms = {RFC_B32, RFC_B32.lower(), RFC_KEY.hex(), RFC_KEY.decode()}
    with caplog.at_level(logging.DEBUG):
        responses = [b.request("begin_totp_browser", user_gesture=True)]
        start = responses[0]
        responses.append(b.request("get_totp_browser", grant=start["grant"], entry_id=denied, gesture_nonce=b.nonce()))
        responses.append(b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce()))
        responses.append(b.request("get_totp_browser", grant=start["grant"], entry_id=eid, gesture_nonce=b.nonce()))
        responses.append(b.request("get_totp_browser", grant="bogus", entry_id=eid, gesture_nonce=b.nonce()))
    released = responses[2]
    assert released["ok"] and set(released) == {"ok", "code", "next_code", "remaining", "session_id"}
    assert released["code"].isdigit() and released["next_code"].isdigit() and 1 <= released["remaining"] <= 30
    blob = json.dumps(responses) + "\n".join(r.getMessage() for r in caplog.records) + caplog.text
    for form in secret_forms:
        assert form not in blob
