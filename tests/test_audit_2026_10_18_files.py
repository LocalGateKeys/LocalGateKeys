"""2026-10-18 audit: "Open file" allow-list with Mark-of-the-Web, and revocation that survives a deleted cache."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import distribution, licensing, open_copy_watch, updates
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.documents import OPEN_WARNING_TITLE, DocumentService
from localvault.app.updates import UpdatesService
from localvault.attachments import (
    OPEN_COPIES_DIR_NAME,
    OPEN_NOT_ALLOWED_TEXT,
    AttachmentError,
    can_open_externally,
    mark_of_the_web,
)
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.vault import create_vault

MASTER = "Demo-only-master-audit!"
KDF = {"memory_cost_kib": 8192, "time_cost": 1, "parallelism": 1}

# ------------------------------------------------------------------ "Open file" allow-list

BLOCKED = [
    "connect.rdp", "disk.iso", "disk.img", "disk.vhd", "disk.vhdx", "sandbox.wsb", "addin.xll",
    "site.website", "macro.docm", "macro.xlsm", "macro.pptm", "macro.dotm", "macro.xltm",
    "addin.xlam", "addin.ppam", "db.ade", "db.adp", "db.mde", "db.accde", "conf.ins", "conf.isp",
    "scrap.shb", "scrap.shs", "archive.zip", "archive.rar", "image.svg", "page.html", "page.htm",
    "run.exe", "script.ps1", "link.lnk", "shortcut.url", "help.chm", "setup.msi", "query.search-ms",
    "report.pdf.exe", "no-extension", "", "trailing.rdp. ", "UPPER.RDP",
]
ALLOWED = [
    "scan.pdf", "SCAN.PDF", "photo.png", "photo.jpg", "photo.jpeg", "anim.gif", "pic.webp", "pic.bmp",
    "fax.tif", "fax.tiff", "phone.heic", "notes.txt", "readme.md", "table.csv", "data.json", "data.xml",
    "app.log", "letter.docx", "sheet.xlsx", "deck.pptx", "letter.odt", "sheet.ods", "deck.odp",
    "letter.rtf", "song.mp3", "clip.mp4", "voice.m4a", "sound.wav", "clip.mov", "trailing.pdf. ",
    "photo.heif", "clip.webm", "film.mkv", "old.avi", "clip.m4v", "song.flac", "song.ogg",
    "voice.aac", "book.epub", "letter.doc", "sheet.xls", "deck.ppt",
]


@pytest.mark.parametrize("name", BLOCKED)
def test_open_refuses_everything_outside_the_allow_list(name):
    assert can_open_externally(name) is False


@pytest.mark.parametrize("name", ALLOWED)
def test_open_allows_viewer_types(name):
    assert can_open_externally(name) is True


@pytest.fixture
def vault(tmp_path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    yield session
    session.lock()


def _document(session, tmp_path, name, data=b"synthetic document bytes"):
    source = tmp_path / "source" / name
    source.parent.mkdir(exist_ok=True)
    source.write_bytes(data)
    return session.documents.create(source, title="Doc")


@pytest.mark.parametrize("name", ["connect.rdp", "macro.docm", "disk.vhdx"])
def test_blocked_type_is_refused_before_decrypting(vault, tmp_path, name):
    item_id = _document(vault, tmp_path, name)
    launched = []
    with pytest.raises(AttachmentError) as refused:
        vault.documents.open_externally(item_id, launcher=launched.append)
    assert str(refused.value) == OPEN_NOT_ALLOWED_TEXT and "Save a copy" in OPEN_NOT_ALLOWED_TEXT
    root = tmp_path / OPEN_COPIES_DIR_NAME
    assert launched == [] and not (root.exists() and any(root.rglob("*")))


@pytest.mark.skipif(os.name != "nt", reason="alternate data streams are an NTFS feature")
def test_opened_copy_carries_mark_of_the_web(vault, tmp_path):
    item_id = _document(vault, tmp_path, "letter.docx")
    path = vault.documents.open_externally(item_id, launcher=lambda _p: None)
    with open(str(path) + ":Zone.Identifier", "rb") as stream:
        assert stream.read() == b"[ZoneTransfer]\r\nZoneId=3\r\n"
    assert path.read_bytes() == b"synthetic document bytes"


def test_mark_of_the_web_failure_is_ignored(tmp_path):
    assert mark_of_the_web(tmp_path / "missing-folder" / "x.pdf") is False


def test_shell_open_refuses_a_blocked_type_without_calling_windows(tmp_path):
    target = tmp_path / "connect.rdp"
    target.write_bytes(b"full address:s:example.invalid")
    with pytest.raises(PermissionError):
        open_copy_watch.shell_open(target)


class _Bus:
    def emit(self, name, detail):
        pass


class _Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class _Port:
    def __init__(self):
        self.asked = []

    def confirm(self, title, message):
        self.asked.append(title)
        return True

    def notify(self, kind, title, message):
        pass

    def show_upgrade(self, *, limit, message, on_enter):
        pass


class _Dialogs:
    def __init__(self, path):
        self.path = path

    def open_file(self, title):
        return self.path

    def save_file(self, title, name):
        return None


def test_webview_refuses_a_blocked_type_before_the_warning(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    settings = AppSettings(idle_source="vault")
    monkeypatch.setattr(settings, "save", lambda *a, **k: None)
    controller = WebController(profiles=profiles, settings=settings, bus=_Bus(), scheduler=_Sched(),
                               create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    source = tmp_path / "connect.rdp"
    source.write_text("full address:s:example.invalid", encoding="utf-8")
    port = _Port()
    service = DocumentService(controller, port, _Dialogs(source))
    ref = service.create("Remote", "")["ref"]
    settings.document_open_enabled = True
    settings.document_open_warning_seen = False
    with pytest.raises(ApiError) as refused:
        service.open_externally(ref)
    assert refused.value.code == "unsupported_type" and refused.value.message == OPEN_NOT_ALLOWED_TEXT
    assert OPEN_WARNING_TITLE not in port.asked and settings.document_open_warning_seen is False
    controller.lock()


# ------------------------------------------------------------------------ revocation

ISSUED = dt.date(2026, 10, 15)
REVOKED_ID = "lgk_" + "0" * 26
OTHER_ID = "lgk_" + "7" * 25 + "Z"


def _key(private):
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).digest()[:8].hex(), base64.b64encode(raw).decode()


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    licence_key = ed25519.Ed25519PrivateKey.generate()
    licence_id, licence_pub = _key(licence_key)
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {licence_id: licence_pub})
    publisher = ed25519.Ed25519PrivateKey.generate()
    pub_id, pub_b64 = _key(publisher)
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", "https://updates.example.test/stable.json")
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {pub_id: pub_b64})

    def install(license_id=REVOKED_ID):
        lic = {"format": 1, "license_id": license_id, "edition": "pro", "name": "Ada", "email": "ada@example.com",
               "issued_at": ISSUED.isoformat(), "updates_until": "9999-12-31"}
        sig = {"alg": "Ed25519", "key_id": licence_id,
               "signature": base64.b64encode(licence_key.sign(updates.canonical_json(lic))).decode()}
        licensing.install_license(licensing.encode_paste({"license": lic, "signature": sig}))

    def signed(revoked, published="2026-10-10T00:00:00Z"):
        manifest = {"format": 1, "published": published, "revoked": list(revoked)}
        return json.dumps({"manifest": manifest, "signature": {
            "alg": "Ed25519", "key_id": pub_id,
            "signature": base64.b64encode(publisher.sign(updates.canonical_json(manifest))).decode()}}).encode()

    return SimpleNamespace(install=install, signed=signed)


class _Response:
    status = 200
    headers: dict = {}

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size):
        return self.body[:size]


def _fetch(body):
    opener = SimpleNamespace(open=lambda request, timeout: _Response(body))
    return updates.fetch_revocations(opener_factory=lambda *_a: opener)


def _state():
    return licensing.status(build_date=ISSUED).state


def test_built_in_revocation_list_applies_without_any_cache(setup, monkeypatch):
    setup.install()
    assert _state() == "pro"
    monkeypatch.setattr(licensing, "REVOKED_LICENSE_IDS", frozenset({REVOKED_ID}))
    assert _state() == "revoked"
    assert licensing.status(build_date=ISSUED, revoked=()).state == "revoked"
    assert REVOKED_ID in licensing._cached_revoked_ids()


def test_built_in_revocation_list_ships_empty_and_well_formed():
    assert isinstance(licensing.REVOKED_LICENSE_IDS, frozenset)
    assert all(updates._LICENSE_ID_PATTERN.fullmatch(i) for i in licensing.REVOKED_LICENSE_IDS)


def test_deleting_the_cache_does_not_unrevoke(setup):
    setup.install()
    assert _fetch(setup.signed([REVOKED_ID])) == frozenset({REVOKED_ID})
    assert updates.revocation_memory_path().exists()
    assert updates.revocation_memory_path().parent == licensing.license_path().parent
    assert _state() == "revoked"
    updates.revocation_cache_path().unlink()
    assert _state() == "revoked"
    # Removing and reinstalling the licence does not help either.
    licensing.remove_license()
    setup.install()
    assert _state() == "revoked"


def test_an_older_list_cannot_replace_the_remembered_one_after_the_cache_is_deleted(setup):
    setup.install()
    _fetch(setup.signed([REVOKED_ID]))
    updates.revocation_cache_path().unlink()
    with pytest.raises(updates.UpdateCheckError):
        _fetch(setup.signed([], published="2026-09-01T00:00:00Z"))
    assert _state() == "revoked"


def test_a_newer_signed_list_can_lift_a_revocation(setup):
    setup.install()
    _fetch(setup.signed([REVOKED_ID]))
    assert _fetch(setup.signed([OTHER_ID], published="2026-10-12T00:00:00Z")) == frozenset({OTHER_ID})
    assert _state() == "pro"


def test_a_cache_from_an_older_build_is_copied_next_to_the_licence(setup):
    setup.install()
    updates.revocation_cache_path().write_bytes(setup.signed([REVOKED_ID]))
    assert not updates.revocation_memory_path().exists()
    assert _state() == "revoked"
    assert updates.revocation_memory_path().exists()
    updates.revocation_cache_path().unlink()
    assert _state() == "revoked"


def test_a_forged_remembered_copy_is_ignored(setup):
    setup.install()
    _fetch(setup.signed([REVOKED_ID]))
    memory = updates.revocation_memory_path()
    bundle = json.loads(memory.read_text("utf-8"))
    bundle["manifest"]["revoked"] = []
    memory.write_text(json.dumps(bundle), encoding="utf-8")
    assert _state() == "revoked"  # the cache still verifies, and the forged copy is rewritten from it
    updates.revocation_cache_path().unlink()
    assert _state() == "revoked"
    memory.write_text(json.dumps(bundle), encoding="utf-8")
    assert _state() == "pro"  # neither copy verifies: nothing to go on


def test_msix_builds_verify_and_fetch_revocations(setup, monkeypatch):
    setup.install()
    monkeypatch.setattr(distribution, "self_update_enabled", lambda: False)
    assert updates.release_configuration() is None
    assert _fetch(setup.signed([REVOKED_ID])) == frozenset({REVOKED_ID})
    assert _state() == "revoked"


def test_missing_network_never_blocks_a_valid_licence(setup):
    setup.install(OTHER_ID)

    class Offline:
        def open(self, *_a, **_k):
            raise OSError("offline")

    with pytest.raises(updates.UpdateCheckError):
        updates.fetch_revocations(opener_factory=lambda *_a: Offline())
    assert _state() == "pro"


@pytest.mark.parametrize(("strict", "expected"), [(False, 1), (True, 0)])
def test_managed_builds_refresh_revocations_only_without_strict_offline(strict, expected):
    controller = SimpleNamespace(settings=SimpleNamespace(strict_offline_mode=strict))
    calls = []
    service = UpdatesService(controller, SimpleNamespace(), configuration=lambda: None,
                             managed=lambda: "Microsoft Store", revocations=lambda: calls.append(1))
    result = service.check()
    assert result["message"] == "LocalGateKeys updates are installed by Microsoft Store."
    assert len(calls) == expected
