"""Passkey approval dialog copy (text only; no Tk window is opened)."""
from __future__ import annotations

from localvault.passkey_dialog import dialog_text

ACCOUNT = {"id": "item-1", "title": "Example (ada)", "user_name": "ada"}


def test_create_copy() -> None:
    text = dialog_text("create", origin="https://login.example.com", rp_id="example.com",
                       profile_name="Personal", accounts=[{"id": None, "title": "Example", "user_name": "ada"}],
                       excluded=False)
    assert text["title"] == "Save a passkey?"
    assert text["approve_label"] == "Save in LocalGateKeys"
    assert text["browser_label"] == "Use browser or another device"
    assert text["cancel_label"] == "Cancel"
    for line in ("Site: example.com", "Page: https://login.example.com", "Profile: Personal", "Account: ada"):
        assert line in text["body"]
    assert "already has" not in text["body"]


def test_create_copy_when_excluded() -> None:
    text = dialog_text("create", origin="https://example.com", rp_id="example.com", profile_name="P",
                       accounts=[{"id": None, "title": "Example", "user_name": "ada"}], excluded=True)
    assert text["body"].endswith("This account already has a LocalGateKeys passkey on this site.")


def test_get_copy_names_a_single_account() -> None:
    text = dialog_text("get", origin="https://example.com", rp_id="example.com", profile_name="Work",
                       accounts=[ACCOUNT], excluded=False)
    assert text["title"] == "Sign in with a passkey?"
    assert text["approve_label"] == "Sign in"
    assert "Account: Example (ada)" in text["body"]
    assert "Profile: Work" in text["body"]


def test_get_copy_with_several_accounts_asks_to_choose() -> None:
    text = dialog_text("get", origin="https://example.com", rp_id="example.com", profile_name="Work",
                       accounts=[ACCOUNT, {**ACCOUNT, "id": "item-2", "title": "Example (bob)"}], excluded=False)
    assert "Account:" not in text["body"]
    assert "Choose an account" in text["body"]
