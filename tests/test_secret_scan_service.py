"""Developer > secret scan service: job events, import, "Use references" (tmp_path only; vault and files are fakes)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault import backup, lgk_refs
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.health import plain_secrets_count
from localvault.app.secret_scan_service import SecretScanService
from localvault.cli_service import CliService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.shell.security_model import issues_for

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
VECTORS = Path(__file__).parent / "vectors" / "ssh"
SECRET = "sk_live_TESTVALUE_0123456789"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.upgrades = []

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append(limit)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    monkeypatch.setattr("localvault.settings.settings_path", lambda: tmp_path / "settings.json")
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    home = tmp_path / "home"
    home.mkdir()
    port = Port()
    service = SecretScanService(controller, port, bus, spawn=lambda fn: fn(), home=lambda: home)
    service.bus, service.home, service.port = bus, home, port
    return service, controller


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


def _populate(home: Path) -> dict[str, Path]:
    return {
        "key": _write(home / ".ssh" / "id_ed25519", (VECTORS / "ed25519.key").read_text(encoding="utf-8")),
        "enc": _write(home / ".ssh" / "id_enc", (VECTORS / "ed25519_enc.key").read_text(encoding="utf-8")),
        "env": _write(home / "proj" / ".env",
                      f"# prod\r\nexport STRIPE_KEY={SECRET}\r\nDB='postgres://u:p@h/db'\r\nPORT=3000 # port\r\n"),
    }


def _scan(service) -> list[dict]:
    service.start()
    done = [d for n, d in service.bus.events if n == "job.done"][-1]
    assert done["ok"], done
    return done["rows"]


def _snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_scan_job_reports_progress_rows_and_last_scan_without_values(env):
    service, controller = env
    _populate(service.home)
    rows = _scan(service)
    assert {r["name"] for r in rows} == {"id_ed25519", "id_enc", ".env"}
    env_row = next(r for r in rows if r["name"] == ".env")
    assert env_row["kind"] == "env_file" and env_row["var_count"] == 3
    names = [n for n, _d in service.bus.events if n.startswith("job.")]
    assert names[0] == "job.progress" and names[-1] == "job.done"
    assert SECRET not in json.dumps(service.bus.events)
    assert controller.settings.developer_last_scan["count"] == 3
    assert plain_secrets_count(controller.settings) == 3
    saved = json.loads((service.home.parent / "settings.json").read_text(encoding="utf-8"))
    assert saved["developer_last_scan"]["count"] == 3


def test_start_refuses_a_missing_folder_and_a_second_run(env, tmp_path):
    service, _controller = env
    with pytest.raises(ApiError):
        service.start([str(tmp_path / "nope")])
    with pytest.raises(ApiError):
        service.start("not a list")
    service._running = True
    with pytest.raises(ApiError) as caught:
        service.start()
    assert caught.value.code == "refused"


def test_chosen_folders_replace_the_default(env, tmp_path):
    service, _controller = env
    _populate(service.home)
    other = tmp_path / "other"
    _write(other / ".env", "A=1\n")
    service.start([str(other)])
    done = [d for n, d in service.bus.events if n == "job.done"][-1]
    assert [r["folder"] for r in done["rows"]] == [str(other)]


def test_locking_discards_findings(env):
    service, controller = env
    _populate(service.home)
    _scan(service)
    service._on_lock()
    with pytest.raises(ApiError):
        service.import_findings(["f1"])


def test_import_creates_items_never_deletes_files(env):
    service, controller = env
    files = _populate(service.home)
    before = _snapshot(service.home)
    rows = _scan(service)
    result = service.import_findings([r["id"] for r in rows])
    assert len(result["imported"]) == 3 and result["failed"] == 0
    assert _snapshot(service.home) == before  # no file deleted, moved or changed
    items = controller.session.item_service.list_items()
    by_title = {i["title"]: i for i in items}
    assert set(by_title) == {"id_ed25519", "id_enc", "proj/.env"}
    key = controller.session.item_service.get_item(by_title["id_ed25519"]["id"], include_protected=True)
    assert key["kind"] == "ssh_key"
    assert key["payload"]["public_key"].startswith("ssh-ed25519 ") and key["payload"]["public_key"].endswith(" id_ed25519")
    assert key["payload"]["fingerprint"].startswith("SHA256:")
    assert key["payload"]["private_key"] == files["key"].read_text(encoding="utf-8")
    encrypted = controller.session.item_service.get_item(by_title["id_enc"]["id"], include_protected=True)
    assert encrypted["payload"].get("public_key", "") == ""  # an encrypted key has no public half to read
    note = controller.session.item_service.get_item(by_title["proj/.env"]["id"], include_protected=True)
    assert note["kind"] == "note" and note["payload"]["body"] == files["env"].read_bytes().decode("utf-8")
    assert {f["name"] for f in note["payload"]["fields"]} == {"STRIPE_KEY", "DB"}  # PORT has an inline comment
    assert any(e[0] == "items.changed" for e in service.bus.events)
    assert service.import_findings([r["id"] for r in rows])["imported"] == []  # a second import adds nothing


def test_rewrite_adds_items_to_cli_allowlist(env):
    service, controller = env
    files = _populate(service.home)
    rows = _scan(service)
    env_id = next(r["id"] for r in rows if r["name"] == ".env")
    with pytest.raises(ApiError):
        service.rewrite_preview(env_id)  # import first: the references need the item
    imported = service.import_findings([env_id])
    item_id = controller.session.item_service.list_items()[0]["id"]
    preview = service.rewrite_preview(env_id)
    assert preview["rewrite_count"] == 2 and preview["skip_count"] == 1
    assert SECRET not in json.dumps(preview)
    assert files["env"].read_bytes().startswith(b"# prod\r\nexport STRIPE_KEY=" + SECRET.encode())  # not yet written
    result = service.rewrite_apply(env_id, preview["token"])
    ref = f"lgk://{item_id}/STRIPE_KEY"
    assert files["env"].read_bytes().decode("utf-8") == (
        f"# prod\r\nexport STRIPE_KEY={ref}\r\nDB='lgk://{item_id}/DB'\r\nPORT=3000 # port\r\n")
    assert controller.settings.developer_cli_items == [item_id]
    assert imported["imported"] == [env_id] and result["rewritten"] == 2
    # The rewritten lines resolve through the command line service's reader to the original values.
    note = controller.session.item_service.get_item(item_id, include_protected=True)
    rows_ = [lgk_refs.RefItem(item_id, "proj/.env", "note", True, CliService._item_reader(note), listed=True)]
    assert lgk_refs.resolve(ref, rows_) == SECRET
    assert lgk_refs.resolve(f"lgk://{item_id}/DB", rows_) == "postgres://u:p@h/db"
    # PORT (inline comment) is still plain, so the file is still reported; the count follows.
    assert [r["var_count"] for r in result["rows"] if r["name"] == ".env"] == [1]
    assert controller.settings.developer_last_scan["count"] == len(result["rows"])
    assert not [p for p in files["env"].parent.iterdir() if p.name != ".env"]  # no temp file left


def test_rewrite_drops_the_finding_when_nothing_plain_is_left(env):
    service, controller = env
    _write(service.home / "p" / ".env", "A=one\nB=two\n")
    rows = _scan(service)
    service.import_findings([rows[0]["id"]])
    result = service.rewrite_apply(rows[0]["id"], service.rewrite_preview(rows[0]["id"])["token"])
    assert result["rows"] == [] and controller.settings.developer_last_scan["count"] == 0
    assert plain_secrets_count(controller.settings) == 0


def test_rewrite_refuses_a_file_changed_after_the_preview(env):
    service, _controller = env
    path = _write(service.home / "p" / ".env", "A=one\n")
    rows = _scan(service)
    fid = rows[0]["id"]
    service.import_findings([fid])
    preview = service.rewrite_preview(fid)
    path.write_bytes(b"A=one\nNEW=added later\n")
    with pytest.raises(ApiError):
        service.rewrite_apply(fid, preview["token"])
    assert path.read_bytes() == b"A=one\nNEW=added later\n"


def test_rewrite_leaves_a_variable_edited_since_the_import(env):
    service, _controller = env
    path = _write(service.home / "p" / ".env", "A=one\nB=two\n")
    fid = _scan(service)[0]["id"]
    service.import_findings([fid])
    path.write_bytes(b"A=one\nB=edited\n")
    preview = service.rewrite_preview(fid)
    assert [(r["name"], r["action"]) for r in preview["rows"]] == [("A", "rewrite"), ("B", "skip")]
    service.rewrite_apply(fid, preview["token"])
    assert path.read_text().endswith("B=edited\n") and "lgk://" in path.read_text().splitlines()[0]


def test_rewrite_keeps_a_byte_order_mark(env):
    service, _controller = env
    path = service.home / "p" / ".env"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xef\xbb\xbfA=one\n")
    fid = _scan(service)[0]["id"]
    service.import_findings([fid])
    service.rewrite_apply(fid, service.rewrite_preview(fid)["token"])
    assert path.read_bytes().startswith(b"\xef\xbb\xbfA=lgk://")


def test_rewrite_refuses_a_non_utf8_file(env):
    service, _controller = env
    path = _write(service.home / "p" / ".env", "A=one\n")
    fid = _scan(service)[0]["id"]
    service.import_findings([fid])
    path.write_bytes(b"A=\xff\xfe\n")
    with pytest.raises(ApiError):
        service.rewrite_preview(fid)


def test_a_key_finding_cannot_be_rewritten(env):
    service, _controller = env
    _write(service.home / ".ssh" / "id", (VECTORS / "ed25519.key").read_text(encoding="utf-8"))
    fid = _scan(service)[0]["id"]
    with pytest.raises(ApiError):
        service.rewrite_preview(fid)


def test_unknown_finding_id_is_refused(env):
    service, _controller = env
    with pytest.raises(ApiError):
        service.rewrite_preview("f99")
    with pytest.raises(ApiError):
        service.import_findings(["../../etc/passwd"])


def test_plain_secrets_issue_is_mild_and_not_counted_in_the_score():
    health = {"rows": [{"id": "a", "label": "A"}], "weak_ids": [], "reused_ids": []}
    assert not issues_for(health, None)
    issue = {i.key: i for i in issues_for(health, None, 3)}["plain_secrets"]
    assert issue.count == 3 and issue.tone == "neutral" and issue.action.method == "developer_clicked"
    from localvault.shell.security_model import headline_for
    # Only breached/weak/reused count towards "needs fixing"; a plain-secrets issue alone leaves the headline fine.
    assert headline_for(100, "Excellent", (issue,)) == headline_for(100, "Excellent", ())


def test_last_scan_is_device_only_and_validated(tmp_path):
    assert AppSettings().developer_last_scan == {}
    assert "developer_last_scan" in backup.DEVICE_ONLY_SETTINGS
    from localvault.settings import validated_last_scan
    assert validated_last_scan({"count": 2, "at": 5}) == {"count": 2, "at": 5}
    assert validated_last_scan({"count": -1, "at": 5}) == {} and validated_last_scan({"count": True, "at": 1}) == {}
    assert validated_last_scan("x") == {}


def test_cli_reader_prefers_a_notes_custom_field_over_body():
    note = {"kind": "note", "payload": {"body": "whole file", "fields": [
        {"name": "body", "value": "var", "hidden": True}, {"name": "A", "value": "1", "hidden": True},
        {"name": "A", "value": "2", "hidden": True}]}}
    read = CliService._item_reader(note)
    assert (read("body"), read("A"), read("missing")) == ("var", "2", None)
    assert CliService._item_reader({"kind": "note", "payload": {"body": "text", "fields": []}})("notes") == "text"


def test_escaped_double_quoted_values_are_skipped_with_a_reason_but_still_imported(env):
    service, controller = env
    text = r'PEM="-----BEGIN KEY-----\nMIIE\n-----END KEY-----"' + "\nTOKEN=abc123\n"
    path = _write(service.home / "p" / ".env", text)
    fid = _scan(service)[0]["id"]
    service.import_findings([fid])
    note = controller.session.item_service.get_item(controller.session.item_service.list_items()[0]["id"],
                                                    include_protected=True)
    assert note["payload"]["body"] == text and [f["name"] for f in note["payload"]["fields"]] == ["TOKEN"]
    preview = service.rewrite_preview(fid)
    assert [(r["name"], r["action"], r.get("reason")) for r in preview["rows"]] == [
        ("PEM", "skip", "escaped"), ("TOKEN", "rewrite", None)]
    service.rewrite_apply(fid, preview["token"])
    assert path.read_bytes().decode().splitlines()[0] == text.splitlines()[0]


def test_import_validates_every_id_before_importing_anything(env):
    service, controller = env
    _populate(service.home)
    rows = _scan(service)
    with pytest.raises(ApiError):
        service.import_findings([rows[0]["id"], "f99"])
    assert controller.session.item_service.list_items() == []
    assert not [e for e in service.bus.events if e[0] == "items.changed"]
    service.import_findings([rows[0]["id"]])
    assert [e[0] for e in service.bus.events].count("items.changed") == 1  # through the injected bus


def test_a_rescan_does_not_forget_an_imported_file_and_reimport_is_refused(env):
    service, controller = env
    _write(service.home / "p" / ".env", "A=one\n")
    fid = _scan(service)[0]["id"]
    service.import_findings([fid])
    rows = _scan(service)  # same file, new scan
    assert rows[0]["imported"] is True
    assert service.import_findings([rows[0]["id"]])["imported"] == []
    assert len(controller.session.item_service.list_items()) == 1
    (service.home / "p" / ".env").write_bytes(b"A=changed\n")  # different content is a different file
    assert _scan(service)[0]["imported"] is False


def test_an_env_file_too_long_for_a_note_gets_its_own_reason(env):
    service, controller = env
    from localvault.item_schema import MAX_NOTE_BODY
    _write(service.home / "big" / ".env", "A=1\n" + "#" * MAX_NOTE_BODY + "\n")
    _write(service.home / "ok" / ".env", "A=1\n")
    rows = _scan(service)
    result = service.import_findings([r["id"] for r in rows])
    assert len(result["imported"]) == 1 and result["failed"] == 1
    assert result["failures"][0]["name"] == ".env" and "too long for a note" in result["failures"][0]["reason"]
    assert "too long for a note" in result["message"]


def test_hidden_note_fields_stay_out_of_the_detail_survive_body_edits_and_export_hidden(env):
    from localvault.app.typed import TypedService
    from localvault.export import item_to_record
    service, controller = env
    path = _write(service.home / "p" / ".env", f"TOKEN={SECRET}\n")
    fid = _scan(service)[0]["id"]
    service.import_findings([fid])
    items = controller.session.item_service
    item_id = items.list_items()[0]["id"]
    typed = TypedService(controller, service.port)
    ref = {"source": "typed", "id": item_id, "kind": "note"}
    detail = typed.detail(ref)
    assert SECRET not in json.dumps(detail)  # neither the body nor a custom field is in the detail view
    assert all(f["value"] is None for f in detail["fields"])
    typed.save(ref, "note", {"title": "proj/.env", "tags": [], "favorite": False, "values": {"body": "edited"},
                             "protected": {}, "clear": [], "revision": detail["revision"]})
    full = items.get_item(item_id, include_protected=True)
    assert full["payload"]["body"] == "edited" and full["payload"]["fields"][0]["value"] == SECRET
    assert item_to_record(full).custom_fields == [{"name": "TOKEN", "value": SECRET, "hidden": True}]
    assert "fields" not in items.get_item(item_id)["payload"]  # protected view drops them like the body


def test_a_name_with_different_duplicate_values_is_skipped_as_duplicate(env):
    service, controller = env
    text = "TOKEN=first\nTOKEN=second\nSAME=a\nSAME=a\nOTHER=z\n"
    path = _write(service.home / "p" / ".env", text)
    fid = _scan(service)[0]["id"]
    service.import_findings([fid])
    preview = service.rewrite_preview(fid)
    assert [(r["name"], r["action"], r.get("reason")) for r in preview["rows"]] == [
        ("TOKEN", "skip", "duplicate"), ("TOKEN", "skip", "duplicate"),
        ("SAME", "rewrite", None), ("SAME", "rewrite", None), ("OTHER", "rewrite", None)]
    service.rewrite_apply(fid, preview["token"])
    lines = path.read_bytes().decode().splitlines()
    assert lines[:2] == ["TOKEN=first", "TOKEN=second"] and lines[2].startswith("SAME=lgk://")
