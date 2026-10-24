import json
from pathlib import Path

import pytest

from localvault.vault import InvalidMasterPassword, VaultError, create_vault, unlock_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"


def test_create_unlock_and_exact_origin_scope(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    entry_id = session.upsert_web(
        origin="https://Example.com:443/", username="alice@example.com", password="s3cret!"
    )
    session.lock()

    unlocked = unlock_vault(path, MASTER)
    matches = unlocked.find_web("https://example.com")
    assert len(matches) == 1
    assert matches[0]["id"] == entry_id
    assert matches[0]["password"] == "s3cret!"
    assert unlocked.find_web("https://sub.example.com") == []


def test_wrong_master_password_fails(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, "this is not the password")


def test_ciphertext_tampering_fails(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.lock()
    document = json.loads(path.read_text(encoding="utf-8"))
    ciphertext = document["cipher"]["ciphertext"]
    document["cipher"]["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)


def test_rejects_resource_exhaustion_kdf_parameters(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.lock()
    document = json.loads(path.read_text(encoding="utf-8"))
    document["kdf"]["memory_cost_kib"] = 2**31
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(VaultError, match="Invalid KDF parameters"):
        unlock_vault(path, MASTER)


def test_web_upsert_does_not_duplicate_same_username(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    first = session.upsert_web(origin="https://example.com", username="a", password="one")
    second = session.upsert_web(origin="https://example.com", username="a", password="two")
    assert first == second
    assert len(session.find_web("https://example.com")) == 1
    assert session.find_web("https://example.com")[0]["password"] == "two"


def test_desktop_entries_match_exact_executable_path(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.add_desktop(
        label="Steam",
        username="alice",
        password="pw",
        exe_path=str(tmp_path / "Steam" / "steam.exe"),
        exe_sha256="A" * 64,
        window_title="Steam Sign In",
        control_fingerprint=[{"class_name": "Edit", "is_password": True}],
        username_selector={"index": 0, "is_password": False},
        password_selector={"index": 1, "is_password": True},
    )
    assert len(session.find_desktop(str(tmp_path / "Steam" / "steam.exe"))) == 1
    assert session.find_desktop(str(tmp_path / "Other" / "steam.exe")) == []


def test_discord_desktop_entries_match_across_versioned_install_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.add_desktop(
        label="Discord",
        username="alice",
        password="pw",
        exe_path=str(tmp_path / "Discord" / "app-1.0.1" / "Discord.exe"),
        exe_sha256="A" * 64,
        window_title="discord.com/app",
        control_fingerprint=[{"class_name": "Edit", "is_password": True}],
        username_selector={"index": 0, "is_password": False},
        password_selector={"index": 1, "is_password": True},
        binding_mode="discord_stable",
    )
    assert len(session.find_desktop(str(tmp_path / "Discord" / "app-1.0.2" / "Discord.exe"))) == 1
    assert session.find_desktop(str(tmp_path / "Discord" / "app-1.0.2" / "Other.exe")) == []


def test_desktop_entry_requires_window_title(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    with pytest.raises(VaultError, match="window_title cannot be empty"):
        session.add_desktop(
            label="Untitled",
            username="alice",
            password="pw",
            exe_path=str(tmp_path / "app.exe"),
            exe_sha256="A" * 64,
            window_title="",
            control_fingerprint=[{"class_name": "Edit", "is_password": True}],
            username_selector=None,
            password_selector={"index": 0, "is_password": True},
        )


def test_desktop_embedded_fill_approval_is_encrypted_and_persistent(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    entry_id = session.add_desktop(
        label="Steam",
        username="alice",
        password="pw",
        exe_path=str(tmp_path / "steamwebhelper.exe"),
        exe_sha256="B" * 64,
        window_title="Sign in to Steam",
        control_fingerprint=[{"class_name": "Chrome_RenderWidgetHostHWND", "is_password": True}],
        username_selector={"index": 0, "is_password": False},
        password_selector={"index": 1, "is_password": True, "framework_id": "Chrome"},
    )
    assert session.set_desktop_embedded_fill_approval(entry_id, True)
    assert session.get_entry(entry_id)["scope"]["embedded_web_fill_approved"] is True
    session.lock()

    unlocked = unlock_vault(path, MASTER)
    assert unlocked.get_entry(entry_id)["scope"]["embedded_web_fill_approved"] is True


def test_web_vault_keeps_multiple_usernames_for_same_origin(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    first = session.upsert_web(
        origin="https://example.com", username="alice", password="alice-secret"
    )
    second = session.upsert_web(
        origin="https://example.com", username="bob", password="bob-secret"
    )
    assert first != second
    matches = session.find_web("https://example.com")
    assert {entry["username"] for entry in matches} == {"alice", "bob"}
    assert len(matches) == 2



def test_edit_entry_fields_preserves_password_when_omitted(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    entry_id = session.upsert_web(origin="https://example.com", username="alice", password="secret")
    assert session.update_entry_fields(entry_id, label="Example", username="alice2")
    entry = session.get_entry(entry_id)
    assert entry["label"] == "Example"
    assert entry["username"] == "alice2"
    assert entry["password"] == "secret"


def test_rebinding_desktop_resets_embedded_trust(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    entry_id = session.add_desktop(
        label="Steam",
        username="alice",
        password="pw",
        exe_path=str(tmp_path / "steamwebhelper.exe"),
        exe_sha256="B" * 64,
        window_title="Sign in to Steam",
        control_fingerprint=[{"class_name": "Edit", "is_password": True}],
        username_selector={"index": 0, "is_password": False},
        password_selector={"index": 1, "is_password": True, "framework_id": "Chrome"},
    )
    assert session.set_desktop_embedded_fill_approval(entry_id, True)
    assert session.update_desktop_binding(
        entry_id,
        exe_path=str(tmp_path / "steamwebhelper.exe"),
        exe_sha256="C" * 64,
        window_title="Sign in to Steam",
        control_fingerprint=[{"class_name": "Edit", "is_password": True}],
        username_selector={"index": 0, "is_password": False},
        password_selector={"index": 1, "is_password": True, "framework_id": "Chrome"},
    )
    assert "embedded_web_fill_approved" not in session.get_entry(entry_id)["scope"]


def test_browser_save_uses_short_name_and_keeps_user_renames(tmp_path: Path) -> None:
    from localvault.vault import friendly_origin_label
    assert friendly_origin_label("https://app.de-cave.com") == "de-cave.com"
    assert friendly_origin_label("https://www.google.com") == "google.com"
    assert friendly_origin_label("https://github.com") == "github.com"
    assert friendly_origin_label("http://localhost:8080") == "localhost"

    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    entry_id = session.upsert_web(origin="https://app.de-cave.com", username="me", password="one-Password-1")
    assert session.get_entry(entry_id)["label"] == "de-cave.com"
    session.update_entry_fields(entry_id, label="Wine club", username="me", password=None,
                                expected_revision=session.credential_detail(entry_id)["revision"])
    # A later password update from the browser must not undo the rename.
    session.upsert_web(origin="https://app.de-cave.com", username="me", password="two-Password-2")
    entry = session.get_entry(entry_id)
    assert entry["label"] == "Wine club" and entry["password"] == "two-Password-2"
    session.lock()


def test_site_icon_is_stored_encrypted_and_survives_unlock(tmp_path: Path) -> None:
    import io

    from PIL import Image

    from localvault.site_icon import IconDecodeError, normalize_site_icon

    raw = io.BytesIO()
    Image.new("RGBA", (128, 128), (200, 30, 30, 255)).save(raw, format="PNG")
    png = normalize_site_icon(raw.getvalue())
    assert Image.open(io.BytesIO(png)).size == (64, 64)
    with pytest.raises(IconDecodeError):
        normalize_site_icon(b"<svg></svg>")

    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    entry_id = session.upsert_web(origin="https://example.com", username="me", password="pw-Example-1")
    assert session.set_entry_icon(entry_id, png) is True
    assert session.set_entry_icon(entry_id, png) is False  # unchanged: no extra write
    session.lock()
    assert png not in path.read_bytes()
    session = unlock_vault(path, MASTER)
    assert session.entry_icon(entry_id) == png
    assert session.captured_site_icons() == {"https://example.com": png}
    with pytest.raises(VaultError):
        session.set_entry_icon(entry_id, b"not a png")
    session.lock()
