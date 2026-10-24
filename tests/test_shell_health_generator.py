"""Password health screen, generator preferences and the totp_confirm switch."""
from __future__ import annotations

from pathlib import Path

from localvault.settings import AppSettings
from localvault.settings_ui import BOOLEAN_KEYS, settings_candidate
from localvault.totp import requires_totp_confirmation

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "localvault"


def _section(module: str, start: str) -> str:
    source = (SOURCE_ROOT / module).read_text(encoding="utf-8")
    body = source.split(start, 1)[1]
    return body.split("\n    def ", 1)[0]


def test_totp_confirm_is_a_security_switch_bound_to_the_broker_hook() -> None:
    assert "totp_confirm" in BOOLEAN_KEYS
    candidate = settings_candidate(AppSettings(), {"totp_confirm": True})
    assert candidate.totp_confirm is True
    assert requires_totp_confirmation(candidate) is True
    assert requires_totp_confirmation(AppSettings()) is False
    sections = (SOURCE_ROOT / "shell" / "settings_sections.py").read_text(encoding="utf-8")
    locking = sections.split("def build_locking", 1)[1].split("\ndef ", 1)[0]
    assert 'form.switch("totp_confirm", "Ask before releasing 2FA codes"' in locking
    unlocking = sections.split("def build_unlocking", 1)[1].split("\ndef ", 1)[0]
    assert '"change_master_clicked"' in unlocking


