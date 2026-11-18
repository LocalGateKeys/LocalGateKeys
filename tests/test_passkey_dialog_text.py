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


def test_system_text_names_rp_and_app_without_browser_button() -> None:
    caller = {"image": "msedge.exe", "title": 'Sign in\nSite: evil.test "\u202e' + "x" * 200}
    text = dialog_text("create", origin="", rp_id="example.com", profile_name="Personal",
                       accounts=[{"id": None, "title": "Example", "user_name": "ada"}], excluded=False,
                       surface="system", caller=caller)
    lines = text["body"].split("\n")
    assert lines[0] == "Site: example.com"
    # The window title is quoted (its own quotes made single), so "Site: ..." inside it cannot pass for a line.
    assert lines[1].startswith("App: msedge.exe \"Sign in Site: evil.test '")
    assert lines[1].endswith('"') and lines[1].count('"') == 2
    assert len(lines[1]) <= len("App: ") + 80 + 3 + 80 and "\u202e" not in lines[1]
    title_only = dialog_text("get", origin="", rp_id="example.com", profile_name="P", accounts=[ACCOUNT],
                             excluded=False, surface="system", caller={"title": "Bank"})
    assert 'App: "Bank"' in title_only["body"].split("\n")
    assert "Profile: Personal" in lines and not any(line.startswith("Page:") for line in lines)
    assert text["browser_label"] == "" and text["approve_label"] == "Save in LocalGateKeys"
    # get, and no (or a malformed) caller: no App line.
    for bad in (None, "msedge.exe", {"image": 7}):
        text = dialog_text("get", origin="", rp_id="example.com", profile_name="P", accounts=[ACCOUNT],
                           excluded=False, surface="system", caller=bad)
        assert "App:" not in text["body"] and "Page:" not in text["body"] and text["browser_label"] == ""
    # The browser surface is unchanged.
    assert dialog_text("get", origin="https://example.com", rp_id="example.com", profile_name="P",
                       accounts=[ACCOUNT], excluded=False)["browser_label"] == "Use browser or another device"
