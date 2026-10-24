"""Security audit: untrusted-input parsers and secondary trust paths.

Each test is one attack attempt (docstring ``SEC-P<n>: <attack>``).  Tests that
assert a defence which holds pass; a CONFIRMED weakness asserts the secure
behaviour and is marked ``xfail(strict=True)`` so the fix flips it to a pass.
No test touches the network, the real clipboard, the registry or a real camera.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault.importers import ImporterError, bitwarden, detect, kdbx, onepassword
from localvault.sync import (
    AuthenticationError,
    DeviceIdentity,
    PairedDevice,
    PairingAuthenticationError,
    PairingCodeError,
    PairingReplayError,
    PairingSession,
    SecureChannel,
    complete_pairing,
    confirm_pairing_offer,
    create_pairing_offer,
    create_session_hello,
    verify_session_hello,
)
from localvault.sync.pairing import PAIRING_MAX_ATTEMPTS

FAST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "synthetic audit master password"


def _keepass_doc(doctype: str, title: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        f"{doctype}\n"
        "<KeePassFile><Root><Group><Name>Root</Name><Entry>"
        f"<String><Key>Title</Key><Value>{title}</Value></String>"
        "<String><Key>UserName</Key><Value>alice</Value></String>"
        "<String><Key>Password</Key><Value>pw</Value></String>"
        "</Entry></Group></Root></KeePassFile>"
    )


# --------------------------------------------------------------------------- XML importers
def test_keepass_xml_doctype_filter_cannot_be_bypassed_with_utf16() -> None:
    """SEC-P1: hide a DOCTYPE with internal entities from the byte-level filter by encoding the XML as UTF-16."""
    entities = '<!DOCTYPE KeePassFile [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
    data = _keepass_doc(entities, "&b;").encode("utf-16")
    assert b"<!DOCTYPE" not in data  # the filter in kdbx._parse_document only scans raw bytes
    with pytest.raises(ImporterError):
        kdbx.load_keepass_xml(data)


def test_keepass_xml_billion_laughs_fails_closed_quickly() -> None:
    """SEC-P2: billion-laughs entity expansion smuggled past the DOCTYPE filter via UTF-16."""
    levels = ['<!ENTITY l0 "LOLLOLLOLLOLLOLLOLLOLLOLLOLLOL">']
    for index in range(1, 10):
        ref = f"&l{index - 1};"
        levels.append(f'<!ENTITY l{index} "{ref * 10}">')
    doctype = "<!DOCTYPE KeePassFile [" + "".join(levels) + "]>"
    data = _keepass_doc(doctype, "&l9;").encode("utf-16")
    started = time.monotonic()
    with pytest.raises(ImporterError):
        kdbx.load_keepass_xml(data)
    # expat's amplification guard (expat >= 2.4) stops the expansion.
    assert time.monotonic() - started < 10


def test_keepass_xml_external_entity_never_discloses_local_files(tmp_path: Path) -> None:
    """SEC-P3: XXE - an external SYSTEM entity pointing at a local file, smuggled via UTF-16."""
    secret = tmp_path / "secret.txt"
    secret.write_text("SYNTHETIC-LOCAL-FILE-MARKER", encoding="utf-8")
    doctype = f'<!DOCTYPE KeePassFile [<!ENTITY x SYSTEM "{secret.as_uri()}">]>'
    data = _keepass_doc(doctype, "&x;").encode("utf-16")
    try:
        result = kdbx.load_keepass_xml(data)
    except ImporterError:
        return
    dumped = json.dumps([dataclasses.asdict(record) for record in result.records])
    assert "SYNTHETIC-LOCAL-FILE-MARKER" not in dumped


# --------------------------------------------------------------------------- JSON / zip importers
_DEEP_JSON = ('{"items":' + "[" * 200_000 + "]" * 200_000 + "}").encode("ascii")


def test_bitwarden_deeply_nested_json_fails_with_importer_error() -> None:
    """SEC-P4: a deeply nested JSON export raises RecursionError instead of an ImporterError."""
    with pytest.raises(ImporterError):
        bitwarden.parse_bitwarden_json(_DEEP_JSON)


def test_format_detection_deeply_nested_json_fails_with_importer_error() -> None:
    """SEC-P4: format detection on a deeply nested .json raises RecursionError (uncaught by the import UI)."""
    with pytest.raises(ImporterError):
        detect.detect_format("export.json", _DEEP_JSON)


def _patched_1pux(flag_bits: int, method: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("export.data")
        info.compress_type = zipfile.ZIP_STORED
        archive.writestr(info, b'{"accounts": []}')
    data = bytearray(buffer.getvalue())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = data.find(signature)
        data[position + offset:position + offset + 4] = flag_bits.to_bytes(2, "little") + method.to_bytes(2, "little")
    return bytes(data)


@pytest.mark.parametrize("flag_bits,method", [(0x1, 0), (0, 99)], ids=["zip-encrypted", "unsupported-method"])
def test_1pux_hostile_member_fails_with_importer_error(flag_bits: int, method: int) -> None:
    """SEC-P5: a 1PUX whose export.data is ZIP-encrypted or uses an unknown method escapes the error contract."""
    with pytest.raises(ImporterError):
        onepassword.read_export_data(_patched_1pux(flag_bits, method))


def test_1pux_zip_bomb_is_bounded() -> None:
    """SEC-P6: zip bomb - export.data that inflates past the 64 MiB bound."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("export.data", b"\x20" * (onepassword.MAX_EXPORT_DATA_BYTES + 1))
    blob = buffer.getvalue()
    assert len(blob) < 1024 * 1024
    with pytest.raises(ImporterError):
        onepassword.read_export_data(blob)


def test_full_backup_zip_slip_member_is_rejected_before_decryption(tmp_path: Path) -> None:
    """SEC-P7: zip-slip - a full-profile backup member named data/../../evil.bin."""
    from localvault import backup

    source = tmp_path / "hostile.lgkfull"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("header.json", b"{}")
        archive.writestr("manifest.bin", b"\x00" * 64)
        archive.writestr("data/00000000.bin", b"\x00" * 64)
        archive.writestr("data/../../evil.bin", b"MZ synthetic")
    entries: list[object] = []
    with pytest.raises(backup.BackupError, match="unsafe"):
        backup._full_read_container(source, "synthetic backup password", on_entry=lambda *args: entries.append(args))
    assert entries == []
    assert not (tmp_path.parent / "evil.bin").exists()


# --------------------------------------------------------------------------- opening things
@pytest.mark.parametrize("url", [
    "file:///C:/Windows/System32/calc.exe",
    "javascript:alert(1)",
    "ms-settings:privacy",
    "data:text/html,<script>alert(1)</script>",
    "\\\\attacker.example\\share\\payload.exe",
    "https://user:pass@example.test/",
    "https://example.test/\x00.exe",
    "https://example.test/ evil",
    "http:///no-host",
    "vbscript:msgbox(1)",
])
def test_open_website_rejects_non_http_and_credential_urls(url: str) -> None:
    """SEC-P8: an imported/synced item URL used to launch a local handler via "Open website"."""
    from localvault.item_schema import ItemSchemaError, validate_bookmark_url

    with pytest.raises(ItemSchemaError):
        validate_bookmark_url(url)


def test_attachment_preview_never_executes_and_case_tricks_stay_unsafe(tmp_path: Path, monkeypatch) -> None:
    """SEC-P9: an active attachment with an upper-case suffix and spoofed text/plain MIME, plus execute-on-open."""
    from localvault.attachments import AttachmentStore, DocumentPreviewService
    from localvault.vault import create_vault

    def _forbidden(*_args, **_kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("attachments must never be shell-executed")

    monkeypatch.setattr(os, "startfile", _forbidden, raising=False)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    # "Save a copy" makes the copy owner-only through export's icacls helpers
    # (L-25). That fixed-path ACL call is not an execution of the attachment;
    # stub only those helpers so any other process launch still fails.
    from localvault import export as export_module
    acl_calls: list[str] = []
    monkeypatch.setattr(export_module, "_restrict_permissions", lambda path: acl_calls.append("file") or True)
    monkeypatch.setattr(export_module, "_restrict_directory", lambda path: acl_calls.append("dir") or True)
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=FAST_KDF)
    store = AttachmentStore(session)
    previews = DocumentPreviewService(session)
    for name in ("Invoice.HTM", "update.EXE", "macro.DocX", "icon.SvG"):
        attachment_id = store.add_bytes(name, b"<script>synthetic()</script>", mime_type="text/plain")
        preview = previews.preview_attachment(attachment_id)
        assert preview["kind"] == "metadata" and preview["safe"] is False, name
    attachment_id = store.add_bytes("run.exe", b"MZ synthetic", mime_type="application/octet-stream")
    destination = tmp_path / "out" / "run.exe"
    destination.parent.mkdir()
    store.export(attachment_id, destination)
    assert destination.read_bytes() == b"MZ synthetic"
    assert "file" in acl_calls  # the copy was restricted to the owner before it landed


# --------------------------------------------------------------------------- update feed
def test_update_signature_key_confusion_between_trusted_keys_is_rejected(monkeypatch, tmp_path: Path) -> None:
    """SEC-P10: key confusion - a manifest signed by trusted key B but labelled with trusted key A's id."""
    from localvault import updates

    def publisher():
        private = ed25519.Ed25519PrivateKey.generate()
        raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return private, hashlib.sha256(raw).digest()[:8].hex(), base64.b64encode(raw).decode("ascii")

    _key_a, id_a, public_a = publisher()
    key_b, id_b, public_b = publisher()
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", "https://updates.example.test/stable.json")
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {id_a: public_a, id_b: public_b})
    monkeypatch.setattr(updates, "BUILD_DATE", "2026-10-05")
    monkeypatch.setattr(updates, "_LAST_VERIFIED", None)
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    manifest = {
        "format": "localgatekeys-release-manifest", "version": 1, "app_version": "9.9.9",
        "published": "2026-10-01T12:00:00Z", "min_supported_version": "9.9.9",
        "notes_url": "https://updates.example.test/notes", "artifacts": [], "sequence": 99,
    }
    body = json.dumps({"manifest": manifest, "signature": {
        "alg": "Ed25519", "key_id": id_a,
        "signature": base64.b64encode(key_b.sign(updates.canonical_json(manifest))).decode("ascii"),
    }}).encode("utf-8")

    class Response:
        status = 200
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, size: int) -> bytes:
            return body[:size]

    opener = SimpleNamespace(open=lambda _request, timeout: Response())
    with pytest.raises(updates.UpdateCheckError) as caught:
        updates.check_for_updates(opener_factory=lambda *_args: opener)
    assert caught.value.reason == "bad-signature"
    assert not updates.update_state_path().exists()


# --------------------------------------------------------------------------- LAN sync
def _paired():
    inviter = DeviceIdentity.generate("device-a")
    invitee = DeviceIdentity.generate("device-b")
    offer = create_pairing_offer(inviter, "group-1", "192.168.10.5", 43125, now=1000.0)
    confirmation = confirm_pairing_offer(offer, invitee, code=offer.code, pairing_secret=offer.pairing_secret,
                                         expected_fingerprint=offer.certificate_fingerprint, now=1001.0)
    peer_b = complete_pairing(offer, inviter, confirmation, code=offer.code,
                              pairing_secret=offer.pairing_secret, now=1002.0)
    peer_a = PairedDevice(inviter.device_id, "group-1", inviter.signing_public_key, inviter.exchange_public_key,
                          inviter.fingerprint, 1000.0, inviter.sign(b"enrollment"))
    return inviter, invitee, offer, confirmation, peer_a, peer_b


def _channels(inviter, invitee, peer_a, peer_b, session_id: bytes):
    hello_a = create_session_hello(inviter, "group-1", session_id)
    hello_b = create_session_hello(invitee, "group-1", session_id)
    channel_a = SecureChannel.from_paired_identities(inviter, peer_b, group_id="group-1", session_id=session_id,
                                                     role="initiator", local_hello=hello_a, remote_hello=hello_b)
    channel_b = SecureChannel.from_paired_identities(invitee, peer_a, group_id="group-1", session_id=session_id,
                                                     role="responder", local_hello=hello_b, remote_hello=hello_a)
    return channel_a, channel_b


def test_sync_hello_impersonating_a_paired_device_id_is_rejected() -> None:
    """SEC-P11: peer impersonation - an unpaired LAN host claims the paired device id and signs with its own key."""
    _inviter, _invitee, _offer, _confirmation, _peer_a, peer_b = _paired()
    mallory = DeviceIdentity.generate("device-b")
    forged = create_session_hello(mallory, "group-1", b"m" * 16, counter=10**9)
    with pytest.raises(AuthenticationError):
        verify_session_hello(forged, "group-1", peer_b)


def test_sync_reflected_and_cross_session_frames_are_rejected() -> None:
    """SEC-P12: replay - reflect an initiator frame back at it and replay a frame into a later session."""
    inviter, invitee, _offer, _confirmation, peer_a, peer_b = _paired()
    channel_a, channel_b = _channels(inviter, invitee, peer_a, peer_b, b"1" * 16)
    frame = channel_a.seal(b"opaque delta")
    with pytest.raises(AuthenticationError):
        channel_a.open(frame)
    assert channel_b.open(frame) == b"opaque delta"
    _later_a, later_b = _channels(inviter, invitee, peer_a, peer_b, b"2" * 16)
    with pytest.raises(AuthenticationError):
        later_b.open(frame)


def test_pairing_mitm_cannot_substitute_the_exchange_key() -> None:
    """SEC-P13: pairing MITM - swap the invitee's X25519 exchange key in the confirmation."""
    inviter, _invitee, offer, confirmation, _peer_a, _peer_b = _paired()
    mallory = DeviceIdentity.generate("mallory")
    swapped = dataclasses.replace(confirmation, exchange_public=mallory.exchange_public_key)
    with pytest.raises(PairingAuthenticationError):
        complete_pairing(offer, inviter, swapped, code=offer.code, pairing_secret=offer.pairing_secret, now=1002.0)


def test_pairing_code_brute_force_burns_the_offer() -> None:
    """SEC-P14: brute-force the 8-digit pairing code; after the attempt budget even the right code is refused."""
    inviter = DeviceIdentity.generate("device-a")
    invitee = DeviceIdentity.generate("device-b")
    offer = create_pairing_offer(inviter, "group-1", "10.0.0.10", 40000, now=10.0)
    session = PairingSession(offer, clock=lambda: 11.0)
    wrong = "00000000" if offer.code != "00000000" else "11111111"
    for _ in range(PAIRING_MAX_ATTEMPTS):
        with pytest.raises(PairingCodeError):
            session.confirm(invitee, code=wrong, pairing_secret=offer.pairing_secret)
    with pytest.raises(PairingReplayError):
        session.confirm(invitee, code=offer.code, pairing_secret=offer.pairing_secret)


# --------------------------------------------------------------------------- unlock policy
def _emergency_lock(profile_id: str) -> list[str]:
    """Run the WebView app's emergency lock against a stub controller (no vault, no UI)."""
    from localvault.app.lockmodes import LockModes

    locked: list[str] = []
    controller = SimpleNamespace(
        profiles=SimpleNamespace(active_profile=lambda: SimpleNamespace(id=profile_id)),
        lock=lambda status="": locked.append(status) or {},
    )
    LockModes(controller).emergency_lock()
    return locked


def test_emergency_lock_master_requirement_survives_restart(monkeypatch, tmp_path: Path) -> None:
    """SEC-P15: after an emergency lock, exit from the tray and relaunch to get Windows Hello / camera unlock back."""
    from localvault.unlock_policy import master_unlock_required

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    locked = _emergency_lock("profile-1")
    assert locked and "Master password required" in locked[0]
    # The requirement is a file in the data directory, so a relaunched process still sees it.
    assert master_unlock_required("profile-1") is True


def test_forged_face_failure_file_cannot_lift_an_active_block(monkeypatch, tmp_path: Path) -> None:
    """SEC-P16: reset the camera-unlock throttle by overwriting face-failures.json with a zero counter."""
    from localvault import config, face_unlock

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(face_unlock, "_FAILURES", {})
    record_id = "synthetic-face-record"
    now = time.time()
    for _ in range(3):
        face_unlock.record_failure(record_id, now=now)
    (config.data_dir() / "face-failures.json").write_text(
        json.dumps({record_id: {"count": 0, "blocked_until": 0}}), encoding="utf-8")
    with pytest.raises(face_unlock.FaceError, match="Too many"):
        face_unlock.check_attempt(record_id)


# --------------------------------------------------------------------------- executable resolution
@pytest.mark.skipif(os.name != "nt", reason="Windows executable search order")
def test_authenticode_check_does_not_resolve_powershell_from_search_path(monkeypatch) -> None:
    """SEC-P17: plant powershell.exe in the working directory to forge the Authenticode signer used by pins."""
    from localvault import signature

    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, "", "")

    monkeypatch.setattr(signature.subprocess, "run", fake_run)
    signature.authenticode_info(sys.executable)
    assert calls, "authenticode_info did not run a child process"
    assert all(Path(argv[0]).is_absolute() for argv in calls), calls


@pytest.mark.skipif(os.name != "nt", reason="Windows executable search order")
def test_bridge_repair_acl_tool_is_not_resolved_from_search_path(monkeypatch, tmp_path: Path) -> None:
    """SEC-P18: plant icacls.exe in the working directory; Repair bridge runs it while securing the data dir."""
    from localvault import browser_bridge

    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(browser_bridge.subprocess, "run", fake_run)
    browser_bridge._secure_data_directory(tmp_path)
    assert calls, "_secure_data_directory did not run a child process"
    assert all(Path(argv[0]).is_absolute() for argv in calls), calls


# --------------------------------------------------------------------------- clipboard / export
def test_clipboard_copy_is_cleared_on_lock_even_with_timer_disabled(monkeypatch) -> None:
    """SEC-P19: disable the clipboard timer (0 s) and rely on lock to leave the password on the clipboard."""
    import localvault.clipboard_guard as clip

    class Root:
        def __init__(self) -> None:
            self.text = ""
            self.jobs: list[object] = []

        def clipboard_clear(self) -> None:
            self.text = ""

        def clipboard_append(self, value: str) -> None:
            self.text = value

        def clipboard_get(self) -> str:
            return self.text

        def after(self, _ms: int, callback) -> None:
            self.jobs.append(callback)

    monkeypatch.setattr(clip, "os", SimpleNamespace(name="posix"))
    root = Root()
    guard = clip.ClipboardGuard(root, timeout_seconds=0)
    guard.copy("synthetic secret")
    assert root.jobs == [] and root.text == "synthetic secret"
    guard.clear()  # RuntimeActions.lock() calls this
    assert root.text == ""


def test_csv_export_carries_the_formula_injection_warning() -> None:
    """SEC-P20: CSV formula injection - an item titled =HYPERLINK(...) exported to CSV (accepted, warned risk)."""
    from localvault.export import ExportWarning, render_csv
    from localvault.importers import ImportedRecord

    record = ImportedRecord(kind="login", title='=HYPERLINK("https://evil.example","x")', username="alice",
                            password="pw", urls=["https://example.test"])
    rendered = render_csv([record], include_totp=False).decode("utf-8")
    # Values stay byte-exact for the destination password manager...
    assert '=HYPERLINK(' in rendered
    # ...so the defence is the mandatory warning shown before a CSV export.
    assert ExportWarning.SPREADSHEET in ExportWarning.for_format("csv", include_totp=False)


# --------------------------------------------------------------------------- follow-up hardening (info items)
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "iso-8859-1"])
def test_keepass_xml_any_doctype_is_rejected_in_every_encoding(encoding: str) -> None:
    """SEC-P1: an empty DOCTYPE (no entities) is still refused, whatever the document encoding."""
    data = _keepass_doc("<!DOCTYPE KeePassFile>", "plain").replace('encoding="UTF-16"', f'encoding="{encoding}"')
    with pytest.raises(ImporterError, match="DOCTYPE"):
        kdbx.load_keepass_xml(data.encode(encoding))


def test_keepass_xml_without_doctype_still_imports_from_utf16() -> None:
    """SEC-P1 regression: a normal UTF-16 KeePass XML export keeps importing."""
    result = kdbx.load_keepass_xml(_keepass_doc("", "Example").encode("utf-16"))
    assert [record.title for record in result.records] == ["Example"]


def test_keepass_key_file_with_doctype_is_rejected() -> None:
    """SEC-P1: the XML key-file parser shares the expat DOCTYPE guard."""
    keyfile = (b'<?xml version="1.0" encoding="utf-8"?><!DOCTYPE KeyFile [<!ENTITY k "QUJD">]>'
               b"<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>&k;</Data></Key></KeyFile>")
    with pytest.raises(ImporterError, match="DOCTYPE"):
        kdbx.keyfile_key(keyfile)


def test_1pux_deeply_nested_export_data_fails_with_importer_error() -> None:
    """SEC-P4: deep nesting inside export.data stays an ImporterError."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("export.data", _DEEP_JSON)
    with pytest.raises(ImporterError):
        onepassword.read_export_data(buffer.getvalue())


def test_kdbx_argon2_work_budget_refuses_stall_parameters_and_keeps_real_defaults() -> None:
    """Info: a hostile KDBX header asking for 1 GiB x 1000 Argon2 passes is refused before any derivation."""
    def argon(memory: int, iterations: int) -> dict[str, object]:
        return {"$UUID": kdbx.KDF_ARGON2D, "M": memory, "I": iterations, "P": 2, "S": b"s" * 32, "V": 0x13}

    with pytest.raises(kdbx.KdbxError):
        kdbx._check_kdf_limits(argon(kdbx.MAX_ARGON2_MEMORY, kdbx.MAX_ARGON2_ITERATIONS))
    kdbx._check_kdf_limits(argon(64 * 1024 * 1024, 2))      # KeePass default
    kdbx._check_kdf_limits(argon(64 * 1024 * 1024, 300))    # KeePassXC slow-unlock setting
    kdbx._check_kdf_limits(argon(1024 * 1024 * 1024, 16))   # 1 GiB, generous iterations


@pytest.mark.parametrize("document", [
    {"kdfType": 0, "kdfIterations": 10_000_000},
    {"kdfType": 1, "kdfIterations": 100, "kdfMemory": 1024, "kdfParallelism": 4},
    {"kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 64},
], ids=["pbkdf2-10M", "argon2-100-passes", "argon2-64-lanes"])
def test_bitwarden_kdf_parameters_beyond_bitwarden_limits_are_refused_quickly(document: dict) -> None:
    """Info: a crafted Bitwarden export cannot demand more KDF work than Bitwarden itself allows."""
    started = time.monotonic()
    with pytest.raises(bitwarden.BitwardenError):
        bitwarden.derive_export_keys("synthetic", {"salt": "synthetic-salt", **document})
    assert time.monotonic() - started < 1


def test_emergency_lock_marker_is_cleared_only_by_master_unlock(monkeypatch, tmp_path: Path) -> None:
    """SEC-P15: the persisted requirement is per profile and survives until explicitly cleared."""
    from localvault import unlock_policy

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    assert unlock_policy.master_unlock_required("profile-1") is False
    _emergency_lock("profile-1")
    assert unlock_policy.master_unlock_required("profile-1") is True
    assert unlock_policy.master_unlock_required("profile-2") is False
    # Any content (even an empty file) keeps the requirement: the marker fails closed.
    marker = next((tmp_path / "data" / "unlock-policy").iterdir())
    marker.write_bytes(b"")
    assert unlock_policy.master_unlock_required("profile-1") is True
    unlock_policy.clear_master_unlock_requirement("profile-1")
    assert unlock_policy.master_unlock_required("profile-1") is False


@pytest.mark.parametrize("raw,expected", [
    ({"auto_lock_seconds": False}, 300),
    ({"auto_lock_seconds": True}, 300),
    ({"auto_lock_seconds": 0}, 0),
    ({"auto_lock_seconds": 600}, 600),
    ({"max_session_seconds": False}, 8 * 3600),
    ({"clipboard_clear_seconds": False}, 30),
])
def test_settings_json_booleans_never_disable_or_shorten_timeouts(tmp_path: Path, raw: dict, expected: int) -> None:
    """Info: JSON false (a Python int subclass) in settings.json must not become 0 = auto-lock disabled."""
    from localvault.settings import AppSettings

    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"version": 1, **raw}), encoding="utf-8")
    name = next(iter(raw))
    assert getattr(AppSettings.load(path), name) == expected


@pytest.mark.parametrize("message,leaked", [
    ("login failed password=hunter2", "hunter2"),
    ('payload {"token": "ab12", "user": "bob"}', "ab12"),
    ("pin: 4821 rejected", "4821"),
    ("header Authorization: Bearer abc.def", "abc.def"),
    ("request ?api_key=sk_9&x=1 failed", "sk_9"),
])
def test_error_log_redacts_short_secrets_in_assignments(message: str, leaked: str) -> None:
    """Info: secrets shorter than 24 characters are redacted when they appear as a secret-named value."""
    from localvault.error_log import _scrub

    scrubbed = _scrub(message)
    assert leaked not in scrubbed and "[redacted]" in scrubbed


def test_error_log_keeps_ordinary_messages_and_redacts_named_secrets() -> None:
    """Info: diagnostics stay readable; values the caller names are redacted however short."""
    from localvault.error_log import _scrub

    plain = r"Invalid master password; token expired; could not open C:\Users\alice\vault.json"
    assert _scrub(plain) == plain
    assert _scrub("decrypt failed for horse9 in item", ["horse9"]) == "decrypt failed for [redacted] in item"


@pytest.mark.parametrize("body,unsafe", [
    (b"/OpenAction << /S /J#61vaScript /J#53 (app.alert(1)) >>", True),
    (b"/Names << /#45mbedded#46ile 3 0 R >>", True),
    (b"/Annots [ << /A << /S /L#61unch /F (calc.exe) >> >> ]", True),
    (b"/Type /Page /Annots [ << /A << /S /URI /URI (https://example.test) >> >> ]", False),
    (b"/Type /Page /Contents 4 0 R /JSTOR-like /AAPL", False),
])
def test_pdf_active_content_check_decodes_name_escapes(tmp_path: Path, body: bytes, unsafe: bool) -> None:
    """Info: ``#xx`` escapes in PDF names (``/J#61vaScript``) cannot hide active content from the preview check."""
    from localvault.attachments import AttachmentStore, DocumentPreviewService
    from localvault.vault import create_vault

    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=FAST_KDF)
    attachment_id = AttachmentStore(session).add_bytes("doc.pdf", b"%PDF-1.7\n" + body, mime_type="application/pdf")
    preview = DocumentPreviewService(session).preview_attachment(attachment_id)
    assert preview["safe"] is (not unsafe)
