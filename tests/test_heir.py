"""Sub-plan 08 Task 2: emergency-access heir shards, the signed ``.lgkheir`` package and the shard sheet."""
from __future__ import annotations

import base64
import hashlib
import json
import re

import pytest
import segno
from cryptography.hazmat.primitives.asymmetric import ed25519

import localvault.vault as vault_module
from localvault import envelope, heir, sss
from localvault.vault import (
    DEFAULT_KDF,
    RecoveryPhraseError,
    create_vault,
    entropy_from_phrase,
    unlock_vault,
    unlock_with_recovery_phrase,
)

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
NOW = 1_800_000_000
HOLDERS = ("Anna", "Ben", "Chris")


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "lgk-data"))
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


@pytest.fixture
def owner(tmp_path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    phrase = session.create_recovery_phrase(MASTER)
    return session, phrase


def _plan(session, phrase, *, k=2, n=3, holders=HOLDERS, wait_days=7, folder=None, reauth=None, **extra):
    calls = []

    def reauthenticate():
        calls.append(1)
        return True if reauth is None else reauth

    plan, packages = heir.create_plan(session, k=k, n=n, holders=holders, wait_days=wait_days, folder=folder,
                                      phrase=phrase, reauthenticate=reauthenticate, now=NOW, **extra)
    return plan, packages, calls


# ------------------------------------------------------------------------------------------------ the plan
def test_plan_makes_one_signed_package_per_holder(owner, tmp_path):
    session, phrase = owner
    plan, packages, calls = _plan(session, phrase, folder=tmp_path / "shared", owner="Ilias")
    assert calls == [1]
    assert (plan.k, plan.n, plan.wait_days, plan.created) == (2, 3, 7, NOW)
    assert plan.folder == tmp_path / "shared"
    assert [h.nickname for h in plan.holders] == list(HOLDERS)
    assert len(packages) == 3 and len({bytes(p) for p in packages}) == 3
    entropy = entropy_from_phrase(phrase)
    for index, (holder, data) in enumerate(zip(HOLDERS, packages, strict=True), start=1):
        shard = heir.read_package(data)
        assert shard.holder == holder and shard.plan_id == plan.plan_id and shard.index == index
        assert (shard.k, shard.n, shard.wait_days, shard.created) == (2, 3, 7, NOW)
        assert shard.owner == "Ilias" and shard.signer == plan.signer
        assert len(shard.share) == sss.SHARE_LEN and shard.share[0] == index
        # The clear package never holds the phrase or the entropy.
        assert entropy.hex() not in data.decode() and base64.b64encode(entropy).decode() not in data.decode()
        assert phrase.split()[0] + " " + phrase.split()[1] not in data.decode()
    for pair in ((0, 1), (0, 2), (1, 2)):
        shares = [heir.read_package(packages[i]).share for i in pair]
        assert sss.combine(shares) == entropy
        assert heir.combine_packages([packages[i] for i in pair]) == entropy
    assert heir.combine_packages(packages) == entropy


def test_plan_ids_and_package_ids_are_fresh(owner):
    session, phrase = owner
    first, packages_a, _ = _plan(session, phrase)
    second, packages_b, _ = _plan(session, phrase)
    assert first.plan_id != second.plan_id and first.signer != second.signer
    ids = {envelope.open_signed(p, heir.FORMAT, heir.VERSION, limit=heir.MAX_PACKAGE).id
           for p in packages_a + packages_b}
    assert len(ids) == 6


def test_free_session_raises_pro_required_before_reauthentication(owner):
    session, phrase = owner
    session.pro_features = frozenset()
    with pytest.raises(heir.ProRequired):
        _plan(session, phrase, reauth=True)
    calls = []
    with pytest.raises(heir.ProRequired):
        heir.create_plan(session, k=2, n=3, holders=HOLDERS, wait_days=7, folder=None, phrase=phrase,
                         reauthenticate=lambda: calls.append(1) or True, now=NOW)
    assert calls == [] and heir.load_plan(session) is None
    session.pro_features = frozenset({heir.FEATURE})
    assert _plan(session, phrase)[0].n == 3


def test_failed_reauthentication_raises_permission_error_and_stores_nothing(owner):
    session, phrase = owner
    with pytest.raises(PermissionError):
        _plan(session, phrase, reauth=False)
    with pytest.raises(PermissionError):  # anything but True is a refusal
        _plan(session, phrase, reauth="yes")
    assert heir.load_plan(session) is None


def test_wrong_phrase_is_refused(owner, tmp_path):
    session, _phrase = owner
    other = create_vault(tmp_path / "other.json", MASTER, kdf_overrides=TEST_KDF)
    other_phrase = other.create_recovery_phrase(MASTER)
    with pytest.raises(RecoveryPhraseError):
        _plan(session, other_phrase)
    assert heir.load_plan(session) is None


def test_vault_without_recovery_phrase_cannot_make_a_plan(tmp_path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    with pytest.raises(RecoveryPhraseError):
        heir.create_plan(session, k=2, n=2, holders=("A", "B"), wait_days=1, folder=None, phrase=None,
                         reauthenticate=lambda: True, now=NOW)


@pytest.mark.parametrize("kwargs", [
    {"k": 1, "n": 3}, {"k": 4, "n": 3}, {"k": 2, "n": 6, "holders": tuple("ABCDEF")},
    {"wait_days": 0}, {"wait_days": 31}, {"wait_days": True}, {"k": 2.0},
    {"holders": ("Anna", "Ben")}, {"holders": ("Anna", "anna ", "Chris")}, {"holders": ("Anna", "  ", "Chris")},
    {"holders": ("Anna", "B" * 33, "Chris")}, {"holders": ("Anna", "Ben\nX", "Chris")},
])
def test_bad_plan_parameters_are_refused_before_reauthentication(owner, kwargs):
    session, phrase = owner
    args = {"k": 2, "n": 3, "holders": HOLDERS, "wait_days": 7, **kwargs}
    calls = []
    with pytest.raises(heir.HeirError):
        heir.create_plan(session, folder=None, phrase=phrase, now=NOW,
                         reauthenticate=lambda: calls.append(1) or True, **args)
    assert calls == []


def test_holder_objects_and_five_of_five(owner):
    session, phrase = owner
    names = tuple(heir.Holder(n) for n in ("Ária", "Βασίλης", "陈", "D", "E"))
    plan, packages, _ = _plan(session, phrase, k=5, n=5, holders=names, wait_days=30)
    assert plan.holders == names
    assert heir.combine_packages(packages) == entropy_from_phrase(phrase)
    with pytest.raises(heir.HeirError) as raised:
        heir.combine_packages(packages[:4])
    assert raised.value.reason == "need-more" and raised.value.missing == 1


# -------------------------------------------------------------------------------- stored plan, entropy check
def test_plan_is_stored_in_the_vault_without_secrets(owner, tmp_path):
    session, phrase = owner
    plan, packages, _ = _plan(session, phrase, folder=tmp_path / "shared")
    assert heir.load_plan(session) == plan
    reopened = unlock_vault(session.path, MASTER)
    assert heir.load_plan(reopened) == plan
    record = json.dumps(reopened._read_prefs()[heir.PREF_KEY])
    entropy = entropy_from_phrase(phrase)
    for secret in (entropy.hex(), base64.b64encode(entropy).decode(), phrase.split()[3]):
        assert secret not in record
    for data in packages:  # no shard is kept by the owner
        assert base64.b64encode(heir.read_package(data).share).decode() not in record
    assert heir.holder_nicknames(reopened) == list(HOLDERS)
    heir.remove_plan(reopened)
    assert heir.load_plan(reopened) is None and heir.holder_nicknames(reopened) == []


def test_plan_signing_key_matches_the_packages(owner):
    session, phrase = owner
    plan, packages, _ = _plan(session, phrase)
    key = heir.plan_signing_key(session)
    raw = key.public_key().public_bytes_raw()
    assert raw == plan.signer == heir.read_package(packages[0]).signer


def test_entropy_check_is_salted_keyed_and_constant_time(owner, monkeypatch):
    session, phrase = owner
    plan, packages, _ = _plan(session, phrase)
    entropy = entropy_from_phrase(phrase)
    assert len(plan.check) == 32 and len(plan.check_salt) == 16
    assert plan.check not in (hashlib.sha256(entropy).digest(), hashlib.sha256(phrase.encode()).digest())
    assert heir.verify_entropy(plan, entropy) is True
    assert heir.verify_entropy(plan, bytes(32)) is False
    assert heir.verify_entropy(heir.read_package(packages[1]), entropy) is True
    compared = []
    real = heir.hmac.compare_digest
    monkeypatch.setattr(heir.hmac, "compare_digest", lambda a, b: compared.append(1) or real(a, b))
    heir.verify_entropy(plan, entropy)
    assert compared == [1]


def test_check_is_bound_to_the_plan_id(owner):
    session, phrase = owner
    entropy = entropy_from_phrase(phrase)
    salt = bytes(range(16))
    one = heir.entropy_check(entropy, plan_id="11111111-1111-4111-8111-111111111111", salt=salt)
    two = heir.entropy_check(entropy, plan_id="22222222-2222-4222-8222-222222222222", salt=salt)
    assert one != two and len(one) == 32


# -------------------------------------------------------------------------------------- combine refusals
def test_combine_refuses_too_few_duplicates_mixed_and_tampered(owner):
    session, phrase = owner
    _plan_a, packages, _ = _plan(session, phrase)
    _plan_b, others, _ = _plan(session, phrase)
    with pytest.raises(heir.HeirError) as raised:
        heir.combine_packages(packages[:1])
    assert raised.value.reason == "need-more" and raised.value.missing == 1
    with pytest.raises(heir.HeirError) as raised:
        heir.combine_packages([packages[0], packages[0]])
    assert raised.value.reason == "duplicate"
    with pytest.raises(heir.HeirError) as raised:
        heir.combine_packages([packages[0], others[1]])
    assert raised.value.reason == "mixed-plans"
    with pytest.raises(heir.HeirError) as raised:
        heir.combine_packages([])
    assert raised.value.reason == "need-more"


def _resign(data: bytes, mutate, key=None) -> bytes:
    """Re-sign a changed payload with a fresh key (a forger without the plan key)."""
    outer = json.loads(data)
    payload = json.loads(base64.b64decode(outer["payload"]))
    mutate(payload)
    return envelope.seal_signed(heir.FORMAT, heir.VERSION, package_id=outer["id"], sender=outer["sender"],
                                payload=payload, signing_key=key or ed25519.Ed25519PrivateKey.generate())


def test_forged_shard_with_another_key_is_refused(owner):
    session, phrase = owner
    _plan_a, packages, _ = _plan(session, phrase)

    def corrupt(payload):
        share = bytearray(base64.b64decode(payload["share"]))
        share[5] ^= 1
        payload["share"] = base64.b64encode(bytes(share)).decode()

    forged = _resign(packages[1], corrupt)
    heir.read_package(forged)  # self-consistent on its own
    with pytest.raises(heir.HeirError) as raised:
        heir.combine_packages([packages[0], forged])
    assert raised.value.reason == "mixed-plans"


def test_wrong_share_under_the_plan_key_fails_the_check(owner):
    """Even a holder of the plan key cannot slip in a wrong share: the entropy check catches it."""
    session, phrase = owner
    _plan_a, packages, _ = _plan(session, phrase)
    key = heir.plan_signing_key(session)

    def corrupt(payload):
        share = bytearray(base64.b64decode(payload["share"]))
        share[7] ^= 0x40
        payload["share"] = base64.b64encode(bytes(share)).decode()

    forged = _resign(packages[1], corrupt, key)
    with pytest.raises(heir.HeirError) as raised:
        heir.combine_packages([packages[0], forged])
    assert raised.value.reason == "check-failed"


def test_package_byte_tampering_is_refused(owner):
    session, phrase = owner
    _plan_a, packages, _ = _plan(session, phrase)
    data = bytearray(packages[0])
    outer = json.loads(bytes(data))
    payload = bytearray(base64.b64decode(outer["payload"]))
    payload[payload.index(b"Anna")] = ord("B")
    outer["payload"] = base64.b64encode(bytes(payload)).decode()
    with pytest.raises(heir.HeirError) as raised:
        heir.read_package(json.dumps(outer).encode())
    assert raised.value.reason == "bad-signature"
    with pytest.raises(heir.HeirError):
        heir.read_package(b"not json")
    with pytest.raises(heir.HeirError):
        heir.read_package(b"x" * (heir.MAX_PACKAGE + 1))


def test_payload_rules_are_checked_after_the_signature(owner):
    session, phrase = owner
    _plan_a, packages, _ = _plan(session, phrase)
    key = heir.plan_signing_key(session)
    cases = [
        lambda p: p.update(k=6), lambda p: p.update(index=4), lambda p: p.update(wait_days=0),
        lambda p: p.update(extra=1), lambda p: p.pop("check"), lambda p: p.update(kind="other"),
        lambda p: p.update(share=base64.b64encode(bytes([2]) + bytes(32)).decode()),  # index mismatch
        lambda p: p.update(plan_id="not-a-uuid"), lambda p: p.update(created=True),
    ]
    for mutate in cases:
        with pytest.raises(heir.HeirError) as raised:
            heir.read_package(_resign(packages[0], mutate, key))
        assert raised.value.reason == "malformed"


# ------------------------------------------------------------------------------------------- QR and sheet
def test_qr_text_round_trips_and_fits_one_code(owner):
    session, phrase = owner
    _plan_a, packages, _ = _plan(session, phrase, holders=("Ária Βασίλης", "陈 Chen", "C" * 32), owner="O" * 64)
    for data in packages:
        text = heir.shard_qr_text(data)
        assert text.startswith("lgkheir:") and re.fullmatch(r"lgkheir:[A-Za-z0-9_-]+", text)
        assert heir.package_from_qr_text(text) == data
        assert len(text) <= heir.QR_LIMIT
        segno.make(text, error="m", micro=False)
    with pytest.raises(heir.HeirError):
        heir.package_from_qr_text("lgkshare-code:abc")
    with pytest.raises(heir.HeirError):
        heir.package_from_qr_text("lgkheir:%%%")


def test_sheet_facts_keep_greek_and_every_script_exactly(owner):
    session, phrase = owner
    holders = ("Βασίλης", "Zoë (x) \\ y", "陈")
    plan, packages, _ = _plan(session, phrase, holders=holders, owner="Ηλίας")
    sheet = heir.sheet_facts(plan, list(reversed(packages)))
    assert sheet["owner"] == "Ηλίας" and sheet["plan_id"] == plan.plan_id
    assert (sheet["k"], sheet["n"], sheet["wait_days"], sheet["created"]) == (2, 3, 7, "2027-01-15")
    assert [page["holder"] for page in sheet["pages"]] == list(holders)
    assert [page["index"] for page in sheet["pages"]] == [1, 2, 3]
    entropy = entropy_from_phrase(phrase)
    assert entropy.hex() not in json.dumps(sheet) and "lgkheir:" not in json.dumps(sheet)
    for page, data in zip(sheet["pages"], packages, strict=True):
        assert page["package_id"] == heir.read_package(data).package_id
        # The QR path data redraws exactly the code of this package's QR text.
        code = segno.make(heir.shard_qr_text(data), error="m", micro=False)
        rows = [list(r) for r in code.matrix_iter(scale=1, border=4)]
        assert page["qr_size"] == len(rows)
        drawn = [[0] * len(rows) for _ in rows]
        for x, y, w in re.findall(r"M(\d+) (\d+)h(\d+)v1h-\3z", page["qr_path"]):
            for dx in range(int(w)):
                drawn[int(y)][int(x) + dx] = 1
        assert drawn == [[1 if v else 0 for v in r] for r in rows]


def test_sheet_facts_refuse_packages_of_another_plan(owner):
    session, phrase = owner
    plan, _packages, _ = _plan(session, phrase)
    _other, others, _ = _plan(session, phrase)
    with pytest.raises(heir.HeirError):
        heir.sheet_facts(plan, others)
    with pytest.raises(heir.HeirError):
        heir.sheet_facts(plan, others[:1])


def test_owner_name_must_be_printable(owner):
    session, phrase = owner
    for bad in ("Ili\nas", "Il​ias", "O" * 65):
        with pytest.raises(heir.HeirError):
            _plan(session, phrase, owner=bad)
    assert heir.load_plan(session) is None


def test_shard_bytes_differ_between_plans_of_the_same_entropy(owner):
    session, phrase = owner
    _a, first, _ = _plan(session, phrase)
    _b, second, _ = _plan(session, phrase)
    for one, two in zip(first, second, strict=True):
        assert heir.read_package(one).share != heir.read_package(two).share


def test_split_randomness_is_a_module_seam_not_an_argument(owner, monkeypatch):
    session, phrase = owner
    with pytest.raises(TypeError):
        _plan(session, phrase, rng=lambda size: bytes(size))
    calls = []
    monkeypatch.setattr(heir, "_rng", lambda size: calls.append(size) or bytes(size))
    _plan(session, phrase)
    assert calls == [32]


# ---------------------------------------------------------------------------------------- stale plans (M1)
def test_replacing_the_recovery_phrase_marks_the_plan_stale(owner):
    session, phrase = owner
    plan, packages, _ = _plan(session, phrase)
    assert plan.stale is False and heir.holder_nicknames(session) == list(HOLDERS)
    new_phrase = session.create_recovery_phrase(MASTER)
    assert session.last_recovery_phrase_change.get("heir_plan_stale") is True
    stale = heir.load_plan(session)
    assert stale.stale is True and stale.plan_id == plan.plan_id
    assert heir.holder_nicknames(session) == []  # the kit no longer lists holders of dead shards
    assert heir.load_plan(unlock_vault(session.path, MASTER)).stale is True
    # The old shards still combine to the old entropy, which no longer opens the vault.
    old = heir.combine_packages(packages[:2])
    with pytest.raises(RecoveryPhraseError):
        session._unwrap_recovery(old)
    # A new plan from the new phrase is current again.
    assert _plan(session, new_phrase)[0].stale is False
    assert heir.load_plan(session).stale is False


def test_removing_the_phrase_or_a_password_change_without_it_marks_the_plan_stale(owner, tmp_path):
    session, phrase = owner
    _plan(session, phrase)
    session.change_master_password(MASTER, "another master password 1", recovery_phrase=phrase)
    assert heir.load_plan(session).stale is False  # the phrase was kept
    session.change_master_password("another master password 1", "another master password 2")
    assert heir.load_plan(session).stale is True
    other = create_vault(tmp_path / "other.json", MASTER, kdf_overrides=TEST_KDF)
    other_phrase = other.create_recovery_phrase(MASTER)
    _plan(other, other_phrase)
    other.remove_recovery_phrase(MASTER)
    assert heir.load_plan(other).stale is True


def test_damaged_stale_flag_is_refused(owner):
    session, phrase = owner
    _plan(session, phrase)
    record = session.heir_plan_record()
    session.set_heir_plan_record({**record, "stale": "yes"})
    with pytest.raises(heir.HeirError):
        heir.load_plan(session)


# ------------------------------------------------------------------------------- vault.recovery_entropy
def test_recovery_entropy_requires_reauthentication(owner):
    session, phrase = owner
    calls = []
    assert session.recovery_entropy(phrase, reauthenticate=lambda: calls.append(1) or True) == \
        entropy_from_phrase(phrase)
    assert calls == [1]
    with pytest.raises(PermissionError):
        session.recovery_entropy(phrase, reauthenticate=lambda: False)
    with pytest.raises(PermissionError):
        session.recovery_entropy(phrase, reauthenticate=None)
    with pytest.raises(RecoveryPhraseError):
        session.recovery_entropy("abandon " * 23 + "art", reauthenticate=lambda: True)


def test_recovery_entropy_after_a_password_change_still_matches(owner):
    session, phrase = owner
    session.change_master_password(MASTER, "another master password 1", recovery_phrase=phrase)
    assert session.recovery_entropy(phrase, reauthenticate=lambda: True) == entropy_from_phrase(phrase)


def test_recovery_entropy_from_a_session_opened_with_the_phrase(owner):
    session, phrase = owner
    session.lock()
    recovered = unlock_with_recovery_phrase(session.path, phrase)
    assert recovered.recovery_entropy(None, reauthenticate=lambda: True) == entropy_from_phrase(phrase)
    with pytest.raises(PermissionError):
        recovered.recovery_entropy(None, reauthenticate=lambda: False)


def test_recovery_entropy_refused_when_locked(owner):
    session, phrase = owner
    session.lock()
    with pytest.raises(vault_module.VaultError):
        session.recovery_entropy(phrase, reauthenticate=lambda: True)


# -------------------------------------------------------------------------------------------- envelope
def test_signed_envelope_round_trip_and_strict_parse():
    key = ed25519.Ed25519PrivateKey.generate()
    data = envelope.seal_signed("localgatekeys-test", 1, package_id="0b5f0c43-7f6a-4c2a-9a55-7d3f9f2f9c11",
                                sender="Zoë", payload={"a": 1, "b": "ü"}, signing_key=key)
    opened = envelope.open_signed(data, "localgatekeys-test", 1, limit=4096)
    assert opened.payload == {"a": 1, "b": "ü"} and opened.sender == "Zoë"
    assert opened.signer == key.public_key().public_bytes_raw()
    outer = json.loads(data)
    assert set(outer) == {"format", "version", "id", "sender", "signer", "payload", "sig"}
    for change, reason in [({"format": "x"}, "malformed"), ({"version": 2}, "unsupported"),
                           ({"extra": 1}, "malformed"), ({"sender": "Zoe"}, "bad-signature"),
                           ({"id": "not-a-uuid"}, "malformed"), ({"sig": "AAAA"}, "malformed")]:
        with pytest.raises(envelope.EnvelopeError) as raised:
            envelope.open_signed(json.dumps({**outer, **change}).encode(), "localgatekeys-test", 1, limit=4096)
        assert raised.value.reason == reason, change
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_signed(data, "localgatekeys-test", 1, limit=len(data) - 1)
