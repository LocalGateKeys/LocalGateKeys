import base64
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault import profiles
from localvault.profiles import ProfileError, ProfileManager


def test_profiles_are_isolated_and_switchable(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path)
    alice = manager.create_profile("Alice")
    bob = manager.create_profile("Bob")
    manager.set_active(alice.id)
    assert manager.active_profile().id == alice.id
    assert manager.vault_path(alice.id) != manager.vault_path(bob.id)
    manager.vault_path(alice.id).write_text("alice", encoding="utf-8")
    assert not manager.vault_path(bob.id).exists()
    manager.set_active(bob.id)
    assert manager.active_profile().id == bob.id


def test_profile_names_unique_case_insensitive(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path)
    manager.create_profile("Alice")
    with pytest.raises(ProfileError):
        manager.create_profile("alice")


def test_restored_profile_is_registered_only_after_vault_publication_and_keeps_active(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path)
    active = manager.create_profile("Current")
    pending = manager.allocate_restore_profile("From backup")
    target = manager.restore_profile_path(pending)

    assert not target.exists()
    assert [profile.id for profile in manager.list_profiles()] == [active.id]
    (target / "vault.json").parent.mkdir(parents=True)
    (target / "vault.json").write_text('{"encrypted":true}', encoding="utf-8")

    restored = manager.register_restored_profile(pending)

    assert restored.id == pending.id
    assert [profile.name for profile in manager.list_profiles()] == ["Current", "From backup"]
    assert manager.active_profile().id == active.id
    assert manager.restore_profile_path(pending, require_absent=False) == target


def test_restored_profile_registration_rechecks_duplicate_name_and_preserves_data(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path)
    pending = manager.allocate_restore_profile("Restored")
    target = manager.restore_profile_path(pending)
    target.mkdir()
    vault = target / "vault.json"
    vault.write_text("encrypted", encoding="utf-8")
    manager.create_profile("restored")

    with pytest.raises(ProfileError, match="already exists"):
        manager.register_restored_profile(pending)

    assert vault.read_text(encoding="utf-8") == "encrypted"
    assert all(profile.id != pending.id for profile in manager.list_profiles())


def test_restore_profile_allocation_rejects_existing_destination(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path)
    pending = manager.allocate_restore_profile("Restored")
    target = manager.restore_profile_path(pending)
    target.mkdir()

    with pytest.raises(ProfileError, match="no longer available"):
        manager.restore_profile_path(pending)


def test_restore_profile_path_rejects_windows_junctions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager = ProfileManager(tmp_path)
    pending = manager.allocate_restore_profile("Restored")
    profiles_root = manager.root / "Profiles"
    monkeypatch.setattr(profiles, "_is_reparse_point", lambda path: path == profiles_root)

    with pytest.raises(ProfileError, match="regular local directory"):
        manager.restore_profile_path(pending)


def test_reparse_point_helper_recognizes_junctions_without_path_api() -> None:
    path = SimpleNamespace(
        is_symlink=lambda: False,
        is_junction=lambda: True,
        lstat=lambda: SimpleNamespace(st_file_attributes=0),
    )

    assert profiles._is_reparse_point(path)


def test_delete_archives_profile_and_never_deletes_only_profile(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path)
    alice = manager.create_profile("Alice")
    with pytest.raises(ProfileError):
        manager.delete_profile(alice.id)
    manager.create_profile("Bob")
    manager.vault_path(alice.id).write_text("encrypted", encoding="utf-8")
    manager.delete_profile(alice.id)
    assert all(p.id != alice.id for p in manager.list_profiles())
    archived = list((tmp_path / "DeletedProfiles").glob(f"*-{alice.id}/vault.json"))
    assert len(archived) == 1
    assert archived[0].read_text(encoding="utf-8") == "encrypted"


def test_profile_edit_persists_photo_without_switching_active_profile(tmp_path: Path) -> None:
    image = pytest.importorskip("PIL.Image")
    manager = ProfileManager(tmp_path)
    alice = manager.create_profile("Alice")
    bob = manager.create_profile("Bob")
    manager.set_active(alice.id)
    before = next(row for row in manager._read_index()["profiles"] if row["id"] == bob.id)
    active_before = manager._read_index()["active_profile_id"]

    source = io.BytesIO()
    image.new("RGB", (48, 32), (18, 130, 220)).save(source, format="JPEG", quality=92)
    updated = manager.update_profile(bob.id, name="Bobby", color="#123ABC", photo=source.getvalue())

    assert updated.name == "Bobby"
    assert updated.color == "#123ABC"
    assert updated.photo_data
    assert manager.active_profile().id == alice.id
    after = next(row for row in manager._read_index()["profiles"] if row["id"] == bob.id)
    assert manager._read_index()["active_profile_id"] == active_before
    assert after["last_used_at"] == before["last_used_at"]
    assert "photo.jpg" not in json.dumps(after)

    restored = ProfileManager(tmp_path).list_profiles()
    record = next(item for item in restored if item.id == bob.id)
    decoded = base64.b64decode(record.photo_data or "", validate=True)
    with image.open(io.BytesIO(decoded)) as retained:
        assert retained.format == "PNG"
        assert retained.size == (48, 32)

    renamed = manager.rename_profile(bob.id, "Bobby renamed")
    assert renamed.photo_data == updated.photo_data
    activated = manager.set_active(bob.id)
    assert activated.photo_data == updated.photo_data
    cleared = manager.remove_profile_photo(bob.id)
    assert cleared.photo_data is None


def test_profile_photo_bounds_color_validation_and_malformed_fallback(tmp_path: Path) -> None:
    image = pytest.importorskip("PIL.Image")
    manager = ProfileManager(tmp_path)
    profile = manager.create_profile("Photo")
    with pytest.raises(ProfileError):
        manager.update_profile(profile.id, color="not-a-color")
    with pytest.raises(ProfileError):
        manager.update_profile(profile.id, photo=b"<svg></svg>")

    huge = io.BytesIO()
    image.new("RGB", (1025, 20), (1, 2, 3)).save(huge, format="PNG")
    with pytest.raises(ProfileError):
        manager.update_profile(profile.id, photo=huge.getvalue())

    raw = manager._read_index()
    raw["profiles"][0]["photo_data"] = "this-is-not-base64"
    manager._write_index(raw)
    assert manager.list_profiles()[0].photo_data is None


