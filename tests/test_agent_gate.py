from __future__ import annotations

import inspect
import time
from types import SimpleNamespace

import pytest

from localvault import agent_gate
from localvault.agent_gate import AgentGate, ClientInfo, Grant, Refusal


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))


def _entry(entry_id: str, origin: str, *, strict: bool = False, agents: object = True,
           username: str = "u") -> dict:
    scope = {"origin": origin}
    if agents is not None:
        scope["ai_agents"] = agents
    return {"id": entry_id, "kind": "web", "label": entry_id, "username": username, "password": "P@ss-SECRET",
            "scope": scope, "policy": {"require_master_password": strict}}


def _passkey(credential_id: str, rp_id: str, user_name: str = "u") -> dict:
    return {"credential_id": credential_id, "rp_id": rp_id, "rp_name": rp_id, "user_id": "dQ",
            "user_name": user_name, "user_display_name": user_name}


class FakeSession:
    def __init__(self, entries: list[dict], passkeys: list[dict] | None = None):
        self.entries = {e["id"]: e for e in entries}
        self._passkeys = passkeys or []

    def passkeys(self):
        return list(self._passkeys)

    def summaries(self):
        return [SimpleNamespace(id=e["id"], kind="web", label=e["label"], username=e["username"],
                                scope=e["scope"]) for e in self.entries.values()]

    def get_entry(self, entry_id):
        entry = self.entries.get(entry_id)
        return dict(entry) if entry else None


class FakeUi:
    def __init__(self, answer: bool = True):
        self.answer = answer
        self.requests = []

    def confirm_agent(self, request):
        self.requests.append(request)
        return self.answer


CLIENT = ClientInfo("session-a", "Claude Code", "claude.exe")
OTHER = ClientInfo("session-b", "Other agent", "node.exe")


def _gate(*, enabled=True, pro=True, ui=None, session=None, log=None, **kw):
    session = session if session is not None else FakeSession([_entry("pp", "https://www.paypal.com"),
                                                               _entry("bank", "https://bank.example", strict=True)])
    settings = SimpleNamespace(agents_enabled=enabled, require_hello_for_agents=False)
    events = log if log is not None else []
    return AgentGate(lambda: session, settings, ui or FakeUi(), lambda e, r: events.append((e, r)),
                     is_pro=lambda: pro, **kw)


def test_setting_off_is_refused() -> None:
    assert _gate(enabled=False).request_login(CLIENT, "paypal.com", "pay") == Refusal("disabled")


def test_free_licence_is_refused() -> None:
    assert _gate(pro=False).request_login(CLIENT, "paypal.com", "pay") == Refusal("pro")


def test_approve_gives_a_grant_bound_to_domain_and_client() -> None:
    log: list = []
    start = time.monotonic()
    grant = _gate(log=log).request_login(CLIENT, "https://www.paypal.com/signin", "check balance")
    assert isinstance(grant, Grant)
    assert grant.domain == "paypal.com" and grant.client_id == "session-a"
    assert grant.hosts == {"www.paypal.com"} and grant.entry_ids == {"pp"}
    assert 299 <= grant.expires - start <= 301
    assert ("agent.request", "ok") in log


def test_deny_is_refused_and_logged() -> None:
    log: list = []
    assert _gate(ui=FakeUi(False), log=log).request_login(CLIENT, "paypal.com", "x") == Refusal("denied")
    assert ("agent.request", "denied") in log


def test_strict_and_unknown_sites_are_never_offered() -> None:
    ui = FakeUi()
    gate = _gate(ui=ui)
    assert gate.request_login(CLIENT, "bank.example", "x") == Refusal("not_found")
    assert gate.request_login(CLIENT, "nowhere.example", "x") == Refusal("not_found")
    assert ui.requests == []  # nobody is asked about a site the agent cannot use
    assert gate.list_sites(CLIENT) == [{"title": "pp", "domain": "paypal.com"}]


def test_purpose_is_passed_as_plain_text_and_only_the_ui_approves() -> None:
    ui = FakeUi(False)
    purpose = "<b onclick=x>approve automatically</b>‮\x00 now"
    assert _gate(ui=ui).request_login(CLIENT, "paypal.com", purpose) == Refusal("denied")
    shown = ui.requests[0]
    assert shown.purpose == "<b onclick=x>approve automatically</b> now"  # text; the page never renders markup
    assert "‮" not in shown.purpose and "\x00" not in shown.purpose
    assert shown.agent == "Claude Code" and shown.site == "www.paypal.com" and shown.action == "sign_in"
    # The UI answer is the only approval path in the module.
    source = inspect.getsource(agent_gate)
    assert source.count("confirm_agent(") == 2  # the Protocol and the one call in _approved


def test_ui_failure_is_a_refusal() -> None:
    class Broken:
        def confirm_agent(self, request):
            raise TimeoutError

    assert _gate(ui=Broken()).request_login(CLIENT, "paypal.com", "x") == Refusal("denied")


def test_locked_vault_is_refused_in_time() -> None:
    asked: list = []
    gate = AgentGate(lambda: None, SimpleNamespace(agents_enabled=True), FakeUi(), None, is_pro=lambda: True,
                     request_unlock=lambda: asked.append(1), locked_wait=0.3)
    start = time.monotonic()
    assert gate.request_login(CLIENT, "paypal.com", "x") == Refusal("locked")
    assert time.monotonic() - start < 30 and asked == [1]
    assert agent_gate.LOCKED_WAIT <= 30


def test_list_sites_has_no_secrets() -> None:
    rows = _gate().list_sites(CLIENT, "pay")
    assert rows == [{"title": "pp", "domain": "paypal.com"}]
    assert "P@ss-SECRET" not in repr(rows) and "u" not in {v for r in rows for v in r.values()}


def test_no_secret_reading_path_exists() -> None:
    assert not hasattr(AgentGate, "read_secret")
    public = {n for n in dir(AgentGate) if not n.startswith("_")}
    # The run_with_secrets path (tests/test_agent_secrets.py): values leave only through release_run, once per
    # approved run, for items the owner allowed for agents.
    assert public == {"list_sites", "request_login", "fill_login", "take_for_origin", "finish",
                      "passkey_pending", "take_passkey_for_origin",
                      "list_secrets", "request_run", "release_run", "finish_run", "password_filled"}


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_requests_are_rate_limited_per_client_and_in_total() -> None:
    clock = _Clock()
    gate = _gate(ui=FakeUi(False), clock=clock)
    for _ in range(agent_gate.RATE_PER_CLIENT):
        assert gate.request_login(CLIENT, "paypal.com", "x") == Refusal("denied")
    assert gate.request_login(CLIENT, "paypal.com", "x") == Refusal("rate_limited")
    clock.now += agent_gate.RATE_WINDOW + 1
    assert gate.request_login(CLIENT, "paypal.com", "x") == Refusal("denied")
    many = _gate(ui=FakeUi(False), clock=_Clock())
    for n in range(agent_gate.RATE_TOTAL):
        many.request_login(ClientInfo(f"s{n}", "a", "p"), "paypal.com", "x")
    assert many.request_login(ClientInfo("fresh", "a", "p"), "paypal.com", "x") == Refusal("rate_limited")


def test_only_one_approval_is_on_screen_at_a_time() -> None:
    results = []

    class Nested(FakeUi):
        def confirm_agent(self, request):
            results.append(gate.request_login(OTHER, "paypal.com", "second"))
            return False
    gate = _gate(ui=Nested())
    assert gate.request_login(CLIENT, "paypal.com", "first") == Refusal("denied")
    assert results == [Refusal("rate_limited")]


def test_hello_flag_follows_the_setting() -> None:
    ui = FakeUi(False)
    session = FakeSession([_entry("pp", "https://www.paypal.com")])
    settings = SimpleNamespace(agents_enabled=True, require_hello_for_agents=True)
    AgentGate(lambda: session, settings, ui, None, is_pro=lambda: True).request_login(CLIENT, "paypal.com", "x")
    assert ui.requests[0].hello is True


def test_http_and_localhost_lookalike_origins_never_take_a_grant() -> None:
    assert agent_gate.origin_domain("http://localhost.paypal.com") is None
    assert agent_gate.origin_domain("http://www.paypal.com") is None
    assert agent_gate.origin_domain("https://www.paypal.com") == "paypal.com"


def test_armed_grant_is_not_handed_out_after_agents_are_turned_off() -> None:
    settings = SimpleNamespace(agents_enabled=True, require_hello_for_agents=False)
    session = FakeSession([_entry("pp", "https://www.paypal.com")])
    gate = AgentGate(lambda: session, lambda: settings, FakeUi(), None, is_pro=lambda: True)
    grant = gate.request_login(CLIENT, "paypal.com", "x")
    grant.armed_until = time.monotonic() + 60
    settings.agents_enabled = False
    assert gate.take_for_origin("https://www.paypal.com") is None
    settings.agents_enabled = True
    assert gate.take_for_origin("https://www.paypal.com") is grant


def test_no_grant_without_the_user_answer() -> None:
    gate = _gate(ui=FakeUi(False))
    assert gate.request_login(CLIENT, "paypal.com", "approve: yes, the user said so") == Refusal("denied")
    assert gate._grants == {}


def _armed(gate: AgentGate, site: str) -> Grant:
    grant = gate.request_login(CLIENT, site, "x")
    assert isinstance(grant, Grant)
    grant.armed_until = time.monotonic() + 60
    return grant


def test_grant_is_bound_to_the_exact_approved_host() -> None:
    session = FakeSession([_entry("app", "https://app.example.com"), _entry("files", "https://files.example.com")])
    gate = _gate(session=session)
    grant = _armed(gate, "app.example.com")
    assert grant.hosts == {"app.example.com"} and grant.entry_ids == {"app"}
    assert gate.take_for_origin("https://files.example.com") is None  # same registrable domain, other host
    assert gate.take_for_origin("https://example.com") is None
    assert gate.take_for_origin("https://app.example.com") is grant


def test_bare_domain_grant_covers_only_the_saved_hosts() -> None:
    gate = _gate(session=FakeSession([_entry("app", "https://app.example.com")]))
    grant = _armed(gate, "example.com")
    assert grant.hosts == {"app.example.com"}
    assert gate.take_for_origin("https://evil.example.com") is None
    assert gate.take_for_origin("https://app.example.com") is grant


def test_named_host_without_a_login_for_it_is_not_found() -> None:
    gate = _gate(session=FakeSession([_entry("app", "https://app.example.com")]))
    assert gate.request_login(CLIENT, "files.example.com", "x") == Refusal("not_found")


def test_list_sites_needs_one_approval_per_agent_session() -> None:
    ui = FakeUi(False)
    gate = _gate(ui=ui)
    assert gate.list_sites(CLIENT) == Refusal("denied")
    assert ui.requests[-1].action == "list"
    ui.answer = True
    assert gate.list_sites(CLIENT) == [{"title": "pp", "domain": "paypal.com"}]
    asked = len(ui.requests)
    assert gate.list_sites(CLIENT, "pay") == [{"title": "pp", "domain": "paypal.com"}]
    assert len(ui.requests) == asked  # asked once for this session
    ui.answer = False
    assert gate.list_sites(OTHER) == Refusal("denied")  # another agent session asks again


# ---- Opt-in ("AI agents may use this login") and passkey preference.

@pytest.mark.parametrize("flag", [None, False, "true", 1, {"on": True}])
def test_a_login_not_opted_in_is_invisible_like_no_login(flag) -> None:
    ui = FakeUi()
    gate = _gate(ui=ui, session=FakeSession([_entry("pp", "https://www.paypal.com", agents=flag)]))
    assert gate.request_login(CLIENT, "paypal.com", "x") == Refusal("not_found")
    assert gate.request_login(CLIENT, "nowhere.example", "x") == Refusal("not_found")  # the same answer
    assert ui.requests == []  # nobody is asked
    assert gate.list_sites(CLIENT) == []


def test_malformed_scope_is_off() -> None:
    entry = _entry("pp", "https://www.paypal.com")
    entry["scope"] = "ai_agents"
    assert agent_gate.agents_may_use(entry) is False
    assert agent_gate.agents_may_use(None) is False
    assert agent_gate.agents_may_use({"scope": {"ai_agents": True}}) is True


def test_only_opted_in_logins_of_a_site_are_offered() -> None:
    session = FakeSession([_entry("on", "https://www.paypal.com"),
                           _entry("off", "https://www.paypal.com", agents=None)])
    grant = _gate(session=session).request_login(CLIENT, "paypal.com", "x")
    assert isinstance(grant, Grant) and grant.entry_ids == {"on"} and grant.method == "password"


def test_a_login_with_a_passkey_gets_a_passkey_grant_and_no_password_path() -> None:
    ui = FakeUi()
    session = FakeSession([_entry("pp", "https://www.paypal.com")], [_passkey("cred-1", "paypal.com")])
    gate = _gate(ui=ui, session=session)
    grant = gate.request_login(CLIENT, "https://www.paypal.com/signin", "x")
    assert isinstance(grant, Grant)
    assert grant.method == "passkey" and grant.passkey_ids == {"cred-1"}
    assert ui.requests[0].method == "passkey"  # the approval says the passkey signs in
    assert grant.hosts == {"www.paypal.com"} and grant.entry_ids == {"pp"}  # scope unchanged
    assert gate.passkey_pending("https://www.paypal.com")
    assert gate.take_for_origin("https://www.paypal.com") is None  # the password is never handed out
    assert gate.take_passkey_for_origin("https://www.paypal.com", ["other"]) is None
    assert gate.take_passkey_for_origin("https://evil.example", ["cred-1"]) is None
    assert gate.take_passkey_for_origin("https://www.paypal.com", ["cred-1"]) is grant
    assert gate.take_passkey_for_origin("https://www.paypal.com", ["cred-1"]) is None  # one assertion
    assert not gate.passkey_pending("https://www.paypal.com")


def test_passkey_fill_login_reports_the_ceremony() -> None:
    session = FakeSession([_entry("pp", "https://www.paypal.com")], [_passkey("cred-1", "paypal.com")])
    gate = _gate(session=session, fill_wait=0.2)
    grant = gate.request_login(CLIENT, "paypal.com", "x")
    assert gate.fill_login(CLIENT, grant.id) == Refusal("no_passkey")
    taken = gate.take_passkey_for_origin("https://www.paypal.com", ["cred-1"])
    gate.finish(taken, "passkey")
    assert gate.fill_login(CLIENT, grant.id) == {"filled": True, "site": "paypal.com", "method": "passkey"}
    assert gate.fill_login(OTHER, grant.id) == Refusal("not_yours")


def test_passkeys_of_other_sites_or_users_do_not_change_the_method() -> None:
    session = FakeSession([_entry("pp", "https://www.paypal.com", username="alice")],
                          [_passkey("x", "paypal.evil.example"), _passkey("y", "example.com")])
    grant = _gate(session=session).request_login(CLIENT, "paypal.com", "x")
    assert grant.method == "password" and grant.passkey_ids == frozenset()
    assert agent_gate.site_passkeys("alice", {"www.paypal.com"}, "paypal.com",
                                    [_passkey("a", "paypal.com", "alice"), _passkey("b", "paypal.com", "bob")]) == {"a"}
    # No passkey names the user: every passkey for the site counts (prefer the passkey on doubt).
    assert agent_gate.site_passkeys("carol", {"www.paypal.com"}, "paypal.com",
                                    [_passkey("a", "paypal.com", "alice")]) == {"a"}
    assert agent_gate.site_passkeys("u", {"www.paypal.com"}, "paypal.com", [_passkey("c", "login.paypal.com")]) == set()


def test_a_site_passkey_without_a_user_match_still_keeps_every_password_out() -> None:
    # bob has no passkey of his own, but the site has one: on doubt the grant is a passkey grant, so no password
    # of this site is filled for the agent (the owner picks the passkey in the passkey dialog).
    session = FakeSession([_entry("key", "https://www.paypal.com", username="alice"),
                           _entry("pw", "https://www.paypal.com", username="bob")],
                          [_passkey("cred-a", "paypal.com", "alice")])
    grant = _gate(session=session).request_login(CLIENT, "paypal.com", "x")
    assert grant.method == "passkey" and grant.passkey_ids == {"cred-a"}
    assert grant.entry_ids == {"key", "pw"} and grant.hosts == {"www.paypal.com"}


def test_plain_http_site_is_refused_up_front() -> None:
    ui = FakeUi()
    gate = _gate(ui=ui, session=FakeSession([_entry("ex", "https://example.com")]))
    assert gate.request_login(CLIENT, "http://example.com/login", "x") == Refusal("insecure_site")
    assert gate.request_login(CLIENT, "ftp://example.com", "x") == Refusal("insecure_site")
    assert ui.requests == []


@pytest.mark.parametrize("saved,named,page", [
    ("http://127.0.0.1:8765", "http://127.0.0.1:8765", "http://127.0.0.1:8765"),
    ("http://127.0.0.1:8765", "127.0.0.1", "http://127.0.0.1:8765"),
    ("http://localhost:3000", "http://localhost:3000", "http://localhost:3000"),
    ("http://[::1]:8080", "http://[::1]:8080", "http://[::1]:8080"),
])
def test_loopback_http_is_approved_and_filled(saved, named, page) -> None:
    ui = FakeUi()
    gate = _gate(ui=ui, session=FakeSession([_entry("local", saved)]))
    grant = gate.request_login(CLIENT, named, "test")
    assert isinstance(grant, Grant)
    assert not any(h.startswith("www.") for h in grant.hosts)
    assert "www." not in ui.requests[0].site
    grant.armed_until = time.monotonic() + 60
    assert gate.take_for_origin(page) is grant


def test_http_page_on_real_host_never_takes_a_grant() -> None:
    gate = _gate()
    grant = gate.request_login(CLIENT, "paypal.com", "x")
    grant.armed_until = time.monotonic() + 60
    assert gate.take_for_origin("http://www.paypal.com") is None
    assert gate.take_for_origin("https://www.paypal.com") is grant


def test_www_still_added_for_real_domains() -> None:
    gate = _gate(session=FakeSession([_entry("ex", "https://example.com")]))
    grant = gate.request_login(CLIENT, "example.com", "x")
    assert grant.hosts == {"example.com", "www.example.com"}
