"""Double-clicked .lgkshare files: noted by the starting process, taken by the running app once unlocked."""
from __future__ import annotations

from pathlib import Path

from localvault import share_open
from localvault.api.result import ApiError

ROOT = Path(__file__).resolve().parents[1]


def _file(tmp_path: Path, name: str = "item.lgkshare") -> Path:
    path = tmp_path / name
    path.write_text("{}", encoding="utf-8")
    return path


def test_find_share_file_takes_only_an_existing_lgkshare(tmp_path):
    shared = _file(tmp_path, "Item.LGKSHARE")
    assert share_open.find_share_file(["--background", str(tmp_path / "gone.lgkshare"), "x.txt"]) is None
    assert share_open.find_share_file(["localgatekeys://install-licence/x", str(shared)]) == shared.resolve()


def test_notes_wait_while_locked_and_arrive_after_unlock(tmp_path):
    first, second = _file(tmp_path, "a.lgkshare"), _file(tmp_path, "b.lgkshare")
    share_open.note(first)
    share_open.note(second)
    share_open.note(first)  # noted again: once, now the newest
    received: list[str] = []
    assert share_open.receive_pending(lambda: False, received.append) == (0, "")
    assert share_open.has_pending() and received == []
    assert share_open.receive_pending(lambda: True, received.append) == (2, "")
    assert received == [str(second), str(first)]
    assert not share_open.has_pending()


def test_a_refused_file_is_dropped_with_its_message(tmp_path):
    share_open.note(_file(tmp_path))

    def refuse(path: str) -> None:
        raise ApiError("already_opened", "This shared item was already opened on this device.")

    assert share_open.receive_pending(lambda: True, refuse) == (0, "This shared item was already opened on this device.")
    assert not share_open.has_pending()


def test_deleted_files_and_old_notes_are_skipped(tmp_path):
    paths = [_file(tmp_path, f"{i}.lgkshare") for i in range(share_open.MAX_PENDING + 2)]
    for path in paths:
        share_open.note(path)
    paths[-1].unlink()
    assert share_open.take() == paths[2:-1]


def test_pending_list_lives_in_the_isolated_data_folder(tmp_path):
    share_open.note(_file(tmp_path))
    import os

    from localvault import config

    assert (config.data_dir() / share_open.PENDING_NAME).is_file()
    assert Path(os.environ["LOCALGATEKEYS_DATA_DIR"]).resolve() == config.data_dir()  # never the real folder


def test_installers_associate_lgkshare_with_the_app():
    iss = (ROOT / "build-personal" / "LocalGateKeys-Personal.iss").read_text(encoding="utf-8")
    assert 'Subkey: "Software\\Classes\\.lgkshare"; ValueType: string; ValueName: ""; ValueData: "LocalGateKeys.Share"' in iss
    assert 'LocalGateKeys.Share\\shell\\open\\command"; ValueType: string; ValueName: ""; ValueData: ' \
           '"""{app}\\LocalGateKeys.exe"" ""%1"""' in iss
    assert "ChangesAssociations=yes" in iss
    manifest = (ROOT / "build-msix" / "AppxManifest.xml.in").read_text(encoding="utf-8")
    assert '<uap:FileTypeAssociation Name="lgkshare">' in manifest and "<uap:FileType>.lgkshare</uap:FileType>" in manifest
