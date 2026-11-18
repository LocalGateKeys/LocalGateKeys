"""CLI service: Command line access switch, allow-list, strict logins, unlock first, one approval per request."""
from __future__ import annotations

import copy
from types import SimpleNamespace as NS

from localvault import cli_service
from localvault.cli_service import CliService
from localvault.local_clients import Approvals, ClientIdentity
from localvault.settings import AppSettings

CLIENT = ClientIdentity(5150, r"C:\Program Files\LocalGateKeys\cli\lgk.exe", (), None, (77, 700))
SECRET = "JBSWY3DPEHPK3PXP"


def _login(entry_id, label, password, strict=False, totp=None):
    entry = {"id": entry_id, "kind": "web", "label": label, "username": f"user-{entry_id}", "password": password,
             "scope": {"origin": f"https://{entry_id}.example"}, "notes": f"notes-{entry_id}",
             "policy": {"require_master_password": strict}}
    if totp:
        entry["totp"] = totp
    return entry


class FakeItems:
    def __init__(self, items):
        self.items = items

    def list_items(self):
        return [{"id": i["id"], "kind": i["kind"], "title": i["title"], "payload": {}} for i in self.items]

    def get_item(self, item_id, *, include_protected=False):
        assert include_protected
        return copy.deepcopy(next((i for i in self.items if i["id"] == item_id), None))


class FakeSession:
    def __init__(self, entries, items):
        self.entries = entries
        self.item_service = FakeItems(items)
        self.reads = []

    def summaries(self):
        return [NS(id=e["id"], label=e["label"], kind=e["kind"]) for e in self.entries]

    def get_entry(self, entry_id):
        self.reads.append(entry_id)
        return copy.deepcopy(next((e for e in self.entries if e["id"] == entry_id), None))


class FakeHost:
    def __init__(self, *, enabled=True, allowed=("gh", "bank", "aws", "aws2", "stripe", "note", "pk"), locked=False,
                 answer=(True, False), unlock_result=True):
        self.settings = NS(developer_cli=enabled, developer_cli_items=list(allowed))
        self._session = FakeSession(
            [_login("gh", "GitHub", "pw-gh", totp={"secret": SECRET, "digits": 6, "period": 30}),
             _login("bank", "Bank", "pw-bank", strict=True),
             _login("aws", "AWS", "pw-aws-1"), _login("aws2", "AWS", "pw-aws-2"),
             _login("hidden", "Hidden", "pw-hidden")],
            [{"id": "stripe", "kind": "api_key", "title": "Stripe", "payload": {"key": "sk_1", "secret": "whsec"}},
             {"id": "pk", "kind": "passkey", "title": "Passkey",
              "payload": {"private_key": "pk-private", "user_name": "me@example.com"}},
             {"id": "note", "kind": "note", "title": "Env", "payload": {"body": "A=1"}}])
        self.locked = locked
        self.unlock_result = unlock_result
        self.unlocks = 0
        self.approvals = Approvals()
        self.answer = answer
        self.prompts = []

    @property
    def session(self):
        return None if self.locked else self._session

    def run_on_ui(self, fn, timeout=90.0):
        return fn()

    def ensure_unlocked(self):
        self.unlocks += 1
        if self.unlock_result:
            self.locked = False
        return self.unlock_result

    def approve_local_clients(self, requests):
        def ask(pending):
            self.prompts.append([(r.kind, r.item_id, r.item_title) for r in pending])
            return self.answer
        return self.approvals.check_or_ask_many(requests, ask, 1000.0)


def _call(host, **request):
    return CliService(host, deadline=5.0).dispatch(request, CLIENT)


def test_dispatch_requires_cli_enabled():
    host = FakeHost(enabled=False)
    assert _call(host, action="status") == {"ok": True, "unlocked": True, "cli_enabled": False}
    for request in ({"action": "list"}, {"action": "read", "ref": "lgk://GitHub/password"},
                    {"action": "totp", "ref": "GitHub"}, {"action": "resolve_many", "refs": ["lgk://gh/password"]}):
        reply = _call(host, **request)
        assert reply["ok"] is False and reply["error"] == "cli_disabled"
    assert host.prompts == [] and host._session.reads == [] and host.unlocks == 0
    assert _call(FakeHost(), action="get_credentials")["error"] == "unknown_action"


def test_list_shows_allowed_items_only_without_prompt():
    host = FakeHost()
    reply = _call(host, action="list")
    assert reply["ok"] is True
    assert {row["id"] for row in reply["items"]} == {"gh", "aws", "aws2", "stripe", "note", "pk"}  # no strict "bank", no "hidden"
    assert all(set(row) == {"id", "title", "kind"} for row in reply["items"])
    assert [row["id"] for row in _call(host, action="list", kind="api_key")["items"]] == ["stripe"]
    assert host.prompts == []


def test_read_fields_and_errors_without_values():
    host = FakeHost()
    assert _call(host, action="read", ref="lgk://GitHub/password") == {"ok": True, "value": "pw-gh"}
    assert _call(host, action="read", ref="lgk://gh/url")["value"] == "https://gh.example"
    assert _call(host, action="read", ref="lgk://Stripe/secret")["value"] == "whsec"
    assert _call(host, action="read", ref="lgk://Env/notes")["value"] == "A=1"
    for ref, code in (("lgk://Bank/password", "not_allowed"), ("lgk://hidden/password", "not_allowed"),
                      ("lgk://Hidden/password", "not_found"),
                      ("lgk://AWS/password", "ambiguous"), ("lgk://Nope/password", "not_found"),
                      ("lgk://GitHub/nope", "no_field"), ("lgk://a/b/c", "bad_reference")):
        reply = _call(host, action="read", ref=ref)
        assert reply["ok"] is False and reply["error"] == code, ref
        assert "pw-" not in reply["message"]
    assert "aws" in _call(host, action="read", ref="lgk://AWS/password")["message"]
    # Only resolvable reads were prompted for.
    assert all(len(prompt) == 1 for prompt in host.prompts) and len(host.prompts) == 4


def test_resolve_strict_login_not_allowed():
    host = FakeHost()
    reply = _call(host, action="resolve_many", refs=["lgk://gh/password", "lgk://bank/password"])
    assert reply["error"] == "not_allowed" and host.prompts == []
    assert "pw-bank" not in str(reply)


def test_resolve_many_single_approval():
    host = FakeHost(answer=(True, True))
    refs = ["lgk://gh/password", "lgk://GitHub/username", "lgk://Stripe/key", "lgk://gh/password"]
    reply = _call(host, action="resolve_many", refs=refs)
    assert reply == {"ok": True, "values": {"lgk://gh/password": "pw-gh", "lgk://GitHub/username": "user-gh",
                                            "lgk://Stripe/key": "sk_1"}}
    assert host.prompts == [[("cli_read", "gh", "GitHub"), ("cli_read", "stripe", "Stripe")]]
    # Each item was remembered on its own: one of them alone does not ask again; a new one asks for itself only.
    assert _call(host, action="read", ref="lgk://Stripe/secret")["value"] == "whsec"
    assert _call(host, action="resolve_many", refs=["lgk://gh/notes", "lgk://Env/notes"])["ok"] is True
    assert host.prompts[1:] == [[("cli_read", "note", "Env")]]


def test_denied_and_locked():
    host = FakeHost(answer=(False, False))
    assert _call(host, action="read", ref="lgk://gh/password")["error"] == "denied"
    host = FakeHost(locked=True, unlock_result=False)
    assert _call(host, action="read", ref="lgk://gh/password")["error"] == "locked"
    assert host.unlocks == 1 and host.prompts == []
    host = FakeHost(locked=True)
    assert _call(host, action="read", ref="lgk://gh/password")["value"] == "pw-gh"
    assert host.unlocks == 1
    assert _call(FakeHost(locked=True), action="status")["unlocked"] is False


def test_totp_uses_generate_totp(monkeypatch):
    calls = []

    def fake(secret, *, timestamp=None, digits=6, period=30, algorithm="SHA1"):
        calls.append((secret, timestamp, digits, period, algorithm))
        return "123456", 17
    monkeypatch.setattr(cli_service, "generate_totp", fake)
    host = FakeHost()
    service = CliService(host, deadline=5.0, now=lambda: 1_700_000_000)
    assert service.dispatch({"action": "totp", "ref": "GitHub"}, CLIENT) == {"ok": True, "code": "123456",
                                                                           "seconds_left": 17}
    assert service.dispatch({"action": "totp", "ref": "lgk://gh/totp"}, CLIENT)["code"] == "123456"
    assert service.dispatch({"action": "read", "ref": "lgk://gh/totp"}, CLIENT) == {"ok": True, "value": "123456"}
    assert calls[0] == (SECRET, 1_700_000_000, 6, 30, "SHA1")
    assert service.dispatch({"action": "totp", "ref": "Stripe"}, CLIENT)["error"] == "no_field"


def test_item_removed_from_allow_list_during_prompt_is_not_served():
    host = FakeHost()

    def approve(requests):
        host.settings.developer_cli_items = ["stripe"]
        return True
    host.approve_local_clients = approve
    reply = _call(host, action="read", ref="lgk://gh/password")
    assert reply["ok"] is False and reply["error"] == "not_allowed"


def test_resolve_many_rejects_bad_lists():
    host = FakeHost()
    for refs in ([], "lgk://gh/password", ["x"] * 101, [3]):
        reply = _call(host, action="resolve_many", refs=refs)
        assert reply["ok"] is False and reply["error"] in ("bad_request", "bad_reference")
    assert host.prompts == []


def test_cli_settings_default_off_and_device_only(tmp_path):
    from localvault.backup import DEVICE_ONLY_SETTINGS

    defaults = AppSettings()
    assert defaults.developer_cli is False and defaults.developer_cli_items == []
    path = tmp_path / "settings.json"
    AppSettings(developer_cli=True, developer_cli_items=["a", "a", "", "b"]).save(path)
    loaded = AppSettings.load(path)
    assert loaded.developer_cli is True and loaded.developer_cli_items == ["a", "b"]
    assert {"developer_cli", "developer_cli_items"} <= set(DEVICE_ONLY_SETTINGS)


def test_no_secret_in_logs(caplog):
    host = FakeHost()
    host.run_on_ui = lambda fn, timeout=90.0: (_ for _ in ()).throw(RuntimeError("pw-gh"))
    reply = _call(host, action="read", ref="lgk://gh/password")
    assert reply["error"] == "cli_failed" and "pw-gh" not in str(reply) and "pw-gh" not in caplog.text


def test_dispatch_from_pid_identifies_the_client(monkeypatch):
    import localvault.local_clients as local_clients

    seen = []
    monkeypatch.setattr(local_clients, "identify", lambda pid: seen.append(pid) or CLIENT)
    assert CliService(FakeHost()).dispatch_from_pid({"action": "status"}, 5150)["ok"] is True
    assert seen == [5150]


def test_passkey_private_key_is_never_served():
    host = FakeHost()
    reply = _call(host, action="read", ref="lgk://Passkey/private_key")
    assert reply["ok"] is False and reply["error"] == "no_field" and "pk-private" not in str(reply)
    reply = _call(host, action="resolve_many", refs=["lgk://Stripe/key", "lgk://pk/private_key"])
    assert reply["error"] == "no_field" and "pk-private" not in str(reply)
    assert host.prompts == []  # refused before any prompt
    assert _call(host, action="read", ref="lgk://Stripe/key")["value"] == "sk_1"
    assert _call(host, action="read", ref="lgk://Passkey/user_name")["value"] == "me@example.com"


def test_custom_fields_are_served_for_notes_only():
    fields = [{"name": "token", "value": "from-field", "hidden": True}]
    note = {"kind": "note", "payload": {"body": "b", "fields": fields}}
    other = {"kind": "api_key", "payload": {"key": "k1", "token": "top", "fields": fields}}
    assert CliService._item_reader(note)("token") == "from-field"
    assert CliService._item_reader(other)("token") == "top"
    assert CliService._item_reader({"kind": "api_key", "payload": {"fields": fields}})("token") is None
