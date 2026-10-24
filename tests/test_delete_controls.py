from __future__ import annotations

from pathlib import Path

import pytest

from localvault.vault import create_vault, unlock_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "delete control test master password"


@pytest.mark.parametrize("kind", ["web", "desktop"])
def test_login_delete_persists_only_selected_record(tmp_path: Path, kind: str) -> None:
    path = tmp_path / f"{kind}.vault"
    session = create_vault(path, MASTER, kdf_overrides=KDF)

    try:
        if kind == "web":
            selected_id = session.upsert_web(
                origin="https://selected.example", username="selected-user",
                password="secret-value-must-not-appear", label="Selected login",
            )
            retained_id = session.upsert_web(
                origin="https://retained.example", username="retained-user",
                password="retained-secret", label="Retained login",
            )
        else:
            def add_desktop(label: str, exe_path: str) -> str:
                return session.add_desktop(
                    label=label,
                    username=f"{label}-user",
                    password=f"{label}-secret",
                    exe_path=exe_path,
                    exe_sha256="a" * 64,
                    window_title=label,
                    control_fingerprint=[{"control_type": "Edit", "name": "Username"}],
                    username_selector=None,
                    password_selector=None,
                )

            selected_id = add_desktop("Selected", r"C:\Apps\Selected.exe")
            retained_id = add_desktop("Retained", r"C:\Apps\Retained.exe")

        assert session.delete(selected_id)
    finally:
        session.lock()

    reopened = unlock_vault(path, MASTER)
    try:
        assert reopened.get_entry(selected_id) is None
        assert reopened.get_entry(retained_id) is not None
        assert [row["id"] for row in reopened.trash_summaries()] == [selected_id]
        assert "secret-value-must-not-appear" not in repr(reopened.trash_summaries())
    finally:
        reopened.lock()


def test_typed_item_delete_persists_only_selected_record(tmp_path: Path) -> None:
    path = tmp_path / "typed.vault"
    session = create_vault(path, MASTER, kdf_overrides=KDF)
    try:
        selected_id = session.items.create_note("Selected note", body="typed secret body")
        retained_id = session.items.create_note("Retained note", body="retained body")
        assert session.items.delete_item(selected_id)
    finally:
        session.lock()

    reopened = unlock_vault(path, MASTER)
    try:
        assert reopened.items.get_item(selected_id) is None
        assert reopened.items.get_item(retained_id) is not None
        assert [row["id"] for row in reopened.items.trash_summaries()] == [selected_id]
        assert "typed secret body" not in repr(reopened.items.trash_summaries())
        # The credential trash list must skip deleted typed items, not crash.
        assert reopened.trash_summaries() == []
    finally:
        reopened.lock()
