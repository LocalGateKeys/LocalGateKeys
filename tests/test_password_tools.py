from __future__ import annotations

import math
import re

import pytest

from localvault.password_tools import (
    COMMON_PASSWORDS,
    DEFAULT_SYMBOLS,
    SEPARATORS,
    GeneratorOptions,
    assess_password,
    breach_scan,
    estimate_strength,
    generate_from_preferences,
    generate_passphrase,
    generate_password,
    generate_username,
    load_wordlist,
    normalize_generator_options,
    vault_health,
)


def test_password_generator_honors_length_and_groups() -> None:
    value = generate_password(24)
    assert len(value) == 24
    assert any(ch.islower() for ch in value)
    assert any(ch.isupper() for ch in value)
    assert any(ch.isdigit() for ch in value)
    assert any(not ch.isalnum() for ch in value)


def test_password_generator_custom_symbols_exclusions_and_minimums() -> None:
    for _ in range(20):
        value = generate_password(
            16, symbol_set="#!", exclude="aeiouAEIOU7", min_digits=3, min_symbols=2,
        )
        assert len(value) == 16
        assert not set(value) & set("aeiouAEIOU7")
        assert sum(ch.isdigit() for ch in value) >= 3
        symbols = [ch for ch in value if not ch.isalnum()]
        assert len(symbols) >= 2 and set(symbols) <= {"#", "!"}


def test_password_generator_rejects_impossible_requests() -> None:
    with pytest.raises(ValueError):
        generate_password(12, lowercase=False, uppercase=False, digits=False, symbols=False)
    with pytest.raises(ValueError):
        generate_password(12, symbols=True, symbol_set="")
    with pytest.raises(ValueError):
        generate_password(12, exclude="abcdefghijklmnopqrstuvwxyz", uppercase=False, digits=False, symbols=False)


def test_wordlist_ships_with_at_least_4096_unique_words() -> None:
    words = load_wordlist()
    assert len(words) >= 4096
    assert len(set(words)) == len(words)
    assert all(re.fullmatch(r"[a-z]{3,12}", word) for word in words)


def test_passphrase_defaults_to_six_words_and_supports_options() -> None:
    words = load_wordlist()
    phrase = generate_passphrase()
    assert phrase.count("-") == 5
    assert all(part in words for part in phrase.split("-"))
    spaced = generate_passphrase(4, separator=" ", capitalize=True)
    parts = spaced.split(" ")
    assert len(parts) == 4 and all(part[0].isupper() and part[1:].islower() for part in parts)
    numbered = generate_passphrase(3, separator="", append_number=True)
    assert re.fullmatch(r"[a-z]+\d+", numbered)
    assert set(SEPARATORS.values()) == {"-", " ", ".", "_", ""}
    with pytest.raises(ValueError):
        generate_passphrase(3, separator="++")


def test_passphrase_and_health() -> None:
    phrase = generate_passphrase(5)
    assert phrase.count("-") == 4
    assert assess_password("password123").score < 60 < assess_password(phrase).score


def test_username_generator_styles() -> None:
    word_style = generate_username()
    assert re.fullmatch(r"[a-z]+\d{2,4}", word_style)
    alias = generate_username(style="alias", domain="example.com", prefix="shop")
    assert re.fullmatch(r"shop\+[a-z0-9]{6,12}@example\.com", alias)
    alias_default = generate_username(style="alias", domain="Example.ORG")
    assert alias_default.endswith("@example.org") and "+" in alias_default
    with pytest.raises(ValueError):
        generate_username(style="alias", domain="")
    with pytest.raises(ValueError):
        generate_username(style="alias", domain="not a domain", prefix="x")


def test_generator_options_normalize_and_round_trip() -> None:
    defaults = normalize_generator_options({})
    assert defaults == GeneratorOptions()
    assert defaults.words == 6 and defaults.separator == "-" and defaults.length == 20
    options = normalize_generator_options({
        "mode": "passphrase", "words": 99, "separator": "|", "capitalize": "yes",
        "length": 4, "min_digits": -3, "symbol_set": "", "exclude": 42,
    })
    assert options.mode == "passphrase"
    assert options.words == 16  # clamped
    assert options.separator == "-"  # unknown separator falls back
    assert options.capitalize is False  # non-bool is ignored
    assert options.length == 8 and options.min_digits == 0
    assert options.symbol_set == DEFAULT_SYMBOLS and options.exclude == ""
    assert normalize_generator_options(options.as_dict()) == options
    assert normalize_generator_options("garbage") == GeneratorOptions()


def test_generate_from_preferences_follows_saved_mode() -> None:
    password = generate_from_preferences({"mode": "password", "length": 30, "symbols": False})
    assert len(password) == 30 and all(ch.isalnum() for ch in password)
    phrase = generate_from_preferences({"mode": "passphrase", "words": 4, "separator": "dot"})
    assert phrase.count(".") == 3


@pytest.mark.parametrize("weak", [
    "password", "123456", "qwerty", "letmein", "iloveyou", "abc123", "football",
])
def test_estimator_scores_common_passwords_zero(weak: str) -> None:
    estimate = estimate_strength(weak)
    assert estimate.score == 0
    assert estimate.guesses < 1e4
    assert any(match.pattern == "dictionary" for match in estimate.matches)


@pytest.mark.parametrize("value, pattern", [
    ("abcdefghij", "sequence"),
    ("9876543210", "sequence"),
    ("aaaaaaaaaaaa", "repeat"),
    ("abcabcabcabc", "repeat"),
    ("ertyuiop[", "spatial"),
    ("xcvbnm,./", "spatial"),
    ("19870423", "date"),
    ("12/25/1999", "date"),
    ("P@ssw0rd", "dictionary"),
    ("dr0w$$ap", "dictionary"),
])
def test_estimator_detects_patterns_and_keeps_them_weak(value: str, pattern: str) -> None:
    estimate = estimate_strength(value)
    assert pattern in {match.pattern for match in estimate.matches}, estimate.matches
    assert estimate.score <= 1


def test_estimator_scores_random_and_passphrases_high() -> None:
    assert estimate_strength(generate_password(20)).score == 4
    assert estimate_strength(generate_passphrase(6)).score == 4
    words_only = estimate_strength("correct-horse-battery-staple")
    assert words_only.score >= 3
    assert words_only.guesses > 1e12
    # The classic xkcd comparison: l33t-mangled word with a symbol stays weaker.
    assert estimate_strength("Tr0ub4dor&3").guesses < words_only.guesses


def test_estimator_reports_guesses_crack_time_and_feedback() -> None:
    estimate = estimate_strength("password1")
    assert estimate.guesses_log10 == pytest.approx(math.log10(estimate.guesses))
    assert estimate.crack_time_display  # human-readable text
    assert estimate.warning
    assert estimate_strength("").score == 0 and estimate_strength("").guesses == 1
    strong = estimate_strength(generate_password(32))
    assert strong.warning == "" and "years" in strong.crack_time_display or "centuries" in strong.crack_time_display


def test_assess_password_is_backed_by_the_estimator() -> None:
    weak = assess_password("password")
    strong = assess_password(generate_password(24))
    assert 0 <= weak.score < 35 and weak.label == "Very weak"
    assert strong.score >= 80
    assert strong.entropy_bits > 60
    assert weak.reasons


def test_common_password_list_is_sizeable_and_lowercase() -> None:
    assert len(COMMON_PASSWORDS) >= 300
    assert COMMON_PASSWORDS[0] == "123456"
    assert len(set(COMMON_PASSWORDS)) == len(COMMON_PASSWORDS)


def test_vault_health_detects_reuse_and_old_passwords() -> None:
    entries = [
        {"id": "a", "password": "same", "updated_at": 1},
        {"id": "b", "password": "same", "updated_at": 1},
        {"id": "c", "password": "LongUniquePassword!123", "updated_at": 9_999_999_999},
    ]
    report = vault_health(entries)
    assert report["reused_count"] == 2
    assert set(report["reused_ids"]) == {"a", "b"}
    assert report["old_count"] >= 2


def test_vault_health_categorizes_every_entry_once() -> None:
    now = 1_700_000_000
    entries = [
        {"id": "weak", "label": "Weak", "username": "u", "password": "password", "updated_at": now, "totp": {"secret": "A"}},
        {"id": "r1", "label": "Reuse 1", "username": "u", "password": "SharedSecret!2024xyz", "updated_at": now, "totp": None},
        {"id": "r2", "label": "Reuse 2", "username": "u", "password": "SharedSecret!2024xyz", "updated_at": now - 400 * 86400},
        {"id": "ok", "label": "Fine", "username": "u", "password": generate_password(24), "updated_at": now, "totp": {"secret": "B"}},
    ]
    report = vault_health(entries, now=now)
    findings = {row["id"]: row for row in report["rows"]}
    assert findings["weak"]["categories"] == ("weak",)
    assert findings["r1"]["categories"] == ("reused", "no_2fa")
    assert findings["r2"]["categories"] == ("reused", "no_2fa", "old")
    assert findings["ok"]["categories"] == ()
    assert report["no_2fa_ids"] == ["r1", "r2"]
    assert report["old_ids"] == ["r2"]
    assert findings["weak"]["score"] == 0 and findings["ok"]["score"] == 4
    assert "password" not in str(report)


def test_breach_scan_dedupes_rate_limits_and_reports_per_entry() -> None:
    calls: list[str] = []
    sleeps: list[float] = []

    def check(password: str, *, consent: bool, strict_offline: bool) -> int:
        assert consent and not strict_offline
        calls.append(password)
        return {"leaked": 42}.get(password, 0)

    results: list[tuple[str, int | None, str]] = []
    outcome = breach_scan(
        {"a": "leaked", "b": "safe", "c": "leaked"},
        check=check,
        sleep=sleeps.append,
        delay=1.5,
        report=lambda entry_id, count, note: results.append((entry_id, count, note)),
    )
    assert calls == ["leaked", "safe"]  # identical passwords are checked once
    assert sleeps == [1.5]  # one pause between two network requests
    assert sorted(results) == [("a", 42, ""), ("b", 0, ""), ("c", 42, "")]
    assert outcome == {"checked": 2, "exposed": 2, "errors": 0, "cancelled": False}


def test_breach_scan_respects_strict_offline_and_cancellation() -> None:
    with pytest.raises(ValueError):
        breach_scan({"a": "x"}, check=lambda *a, **k: 0, sleep=lambda _s: None, strict_offline=True)

    state = {"calls": 0}

    def check(password: str, *, consent: bool, strict_offline: bool) -> int:
        state["calls"] += 1
        return 0

    reported: list[str] = []
    outcome = breach_scan(
        {"a": "x", "b": "y", "c": "z"},
        check=check,
        sleep=lambda _s: None,
        cancelled=lambda: state["calls"] >= 1,
        report=lambda entry_id, count, note: reported.append(entry_id),
    )
    assert outcome["cancelled"] is True
    assert state["calls"] == 1 and reported == ["a"]


def test_breach_scan_records_errors_without_stopping() -> None:
    from localvault.breach_check import BreachCheckError

    def check(password: str, *, consent: bool, strict_offline: bool) -> int:
        if password == "bad":
            raise BreachCheckError("boom")
        return 0

    notes: dict[str, str] = {}
    outcome = breach_scan(
        {"a": "bad", "b": "fine"}, check=check, sleep=lambda _s: None,
        report=lambda entry_id, count, note: notes.__setitem__(entry_id, note),
    )
    assert outcome["errors"] == 1 and outcome["checked"] == 2
    assert notes["a"] and not notes["b"]
