"""Local clients approval layer: caller identity and remembered approvals (fake process tables)."""
from __future__ import annotations

import threading
import time

from localvault.browser_ancestry import ProcessInfo
from localvault.local_clients import ApprovalRequest, Approvals, ClientIdentity, identify
from localvault.session_guard import SessionGuard

# pid -> (parent pid, image, created)
SSH = "C:/Windows/System32/OpenSSH/ssh.exe"


def _lookup(tree):
    def lookup(p):
        row = tree.get(p)
        return ProcessInfo(p, row[0], row[1], row[2]) if row else None
    return lookup


TERMINAL_TREE = {
    10: (9, SSH, 500),
    9: (8, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", 400),
    8: (7, "C:/Program Files/WindowsApps/WindowsTerminal.exe", 300),
    7: (6, "C:/Windows/explorer.exe", 100),
    6: (0, "C:/Windows/System32/userinit.exe", 50),
}


def test_identify_picks_terminal_session():
    ident = identify(10, lookup=_lookup(TERMINAL_TREE), signer=lambda image: "Microsoft Windows")
    assert ident.image == SSH and ident.signer == "Microsoft Windows"
    assert ident.session_key == (8, 300)
    assert [p.pid for p in ident.parent_chain][:3] == [9, 8, 7]
    assert ident.host_name == "WindowsTerminal.exe" and ident.program == "ssh.exe"
    assert ident.label == "ssh.exe (Microsoft Windows)"


def test_identify_falls_back_to_explorer():
    # Console from Start/Run: the session is the program explorer launched, not explorer itself.
    tree = {10: (9, SSH, 500), 9: (7, "C:/x/powershell.exe", 400), 7: (6, "C:/Windows/explorer.exe", 100),
            6: (0, "C:/x/userinit.exe", 50)}
    assert identify(10, lookup=_lookup(tree), signer=lambda i: None).session_key == (9, 400)
    # Two consoles launched from explorer are two sessions.
    tree2 = {**tree, 20: (19, SSH, 900), 19: (7, "C:/x/cmd.exe", 800)}
    assert identify(20, lookup=_lookup(tree2), signer=lambda i: None).session_key == (19, 800)
    # Launched by explorer directly: the client is its own session.
    direct = {10: (7, SSH, 500), 7: (6, "C:/Windows/explorer.exe", 100)}
    assert identify(10, lookup=_lookup(direct), signer=lambda i: None).session_key == (10, 500)
    # No terminal and no explorer: the client itself is its own session.
    assert identify(10, lookup=_lookup({10: (0, SSH, 500)}), signer=lambda i: None).session_key == (10, 500)


def test_identify_stops_at_recycled_parent_pid_and_unknown_process():
    # The terminal's pid now belongs to a process created after the client: not its parent.
    tree = {10: (8, SSH, 300), 8: (0, "C:/x/WindowsTerminal.exe", 500)}
    assert identify(10, lookup=_lookup(tree), signer=lambda i: None).session_key == (10, 300)
    unknown = identify(99, lookup=_lookup({}), signer=lambda i: None)
    assert unknown.image == "" and unknown.parent_chain == ()


def _client(image=SSH, key=(8, 300)):
    return ClientIdentity(10, image, (), None, key)


def _req(client=None, item="item-1", kind="ssh_sign"):
    return ApprovalRequest(kind, client or _client(), item, "Server key", "")


class Asker:
    def __init__(self, answer=(True, True)):
        self.answer, self.calls = answer, 0

    def __call__(self, req):
        self.calls += 1
        return self.answer


def test_remember_reuses_within_ttl():
    approvals, ask = Approvals(), Asker()
    assert approvals.check_or_ask(_req(), ask, 1000.0)
    assert approvals.check_or_ask(_req(), ask, 1599.0)
    assert ask.calls == 1
    # Another item or kind asks again; the image compares case-insensitively.
    assert approvals.check_or_ask(_req(item="item-2"), ask, 1100.0)
    assert approvals.check_or_ask(_req(kind="cli_read"), ask, 1100.0)
    assert ask.calls == 3
    assert approvals.check_or_ask(_req(_client(SSH.upper())), ask, 1100.0)
    assert ask.calls == 3


def test_remember_expires_after_600s():
    approvals, ask = Approvals(), Asker()
    approvals.check_or_ask(_req(), ask, 1000.0)
    approvals.check_or_ask(_req(), ask, 1601.0)  # the expiry counts from after the (real) prompt
    assert ask.calls == 2


def test_different_terminal_asks_again():
    approvals, ask = Approvals(), Asker()
    approvals.check_or_ask(_req(), ask, 1000.0)
    approvals.check_or_ask(_req(_client(key=(20, 900))), ask, 1001.0)
    assert ask.calls == 2


def test_denied_not_remembered():
    approvals, ask = Approvals(), Asker((False, True))
    assert not approvals.check_or_ask(_req(), ask, 1000.0)
    assert not approvals.check_or_ask(_req(), ask, 1001.0)
    assert ask.calls == 2
    # An approval without "remember" is used once; an unknown image is never remembered.
    once = Asker((True, False))
    assert approvals.check_or_ask(_req(), once, 1000.0) and approvals.check_or_ask(_req(), once, 1001.0)
    assert once.calls == 2
    anon = Asker()
    assert approvals.check_or_ask(_req(_client(image="")), anon, 1000.0)
    assert approvals.check_or_ask(_req(_client(image="")), anon, 1001.0)
    assert anon.calls == 2


def test_ask_error_denies():
    def boom(req):
        raise TimeoutError("not answered")
    assert not Approvals().check_or_ask(_req(), boom, 1.0)


def test_revoke_all_on_lock():
    from localvault.local_clients import default_approvals

    approvals = default_approvals()
    approvals.revoke_all()
    ask = Asker()
    approvals.check_or_ask(_req(), ask, 1000.0)
    approvals.check_or_ask(_req(), ask, 1001.0)
    assert ask.calls == 1
    SessionGuard("p1").invalidate()  # what lock, profile switch and unlock call
    approvals.check_or_ask(_req(), ask, 1002.0)
    assert ask.calls == 2
    approvals.revoke_all()


def test_revoke_during_prompt_denies():
    approvals = Approvals()

    def ask(req):
        approvals.revoke_all()  # the vault locked while the prompt was open
        return True, True
    assert not approvals.check_or_ask(_req(), ask, 1000.0)
    assert not approvals._remembered


def test_queue_serialises_asks():
    approvals = Approvals()
    log, first_in, release = [], threading.Event(), threading.Event()

    def slow(req):
        log.append("first-start")
        first_in.set()
        release.wait(5)
        log.append("first-end")
        return True, False

    def second(req):
        log.append("second-start")
        return True, False

    t1 = threading.Thread(target=approvals.check_or_ask, args=(_req(item="a"), slow, 1.0))
    t2 = threading.Thread(target=approvals.check_or_ask, args=(_req(item="b"), second, 1.0))
    t1.start()
    assert first_in.wait(5)
    t2.start()
    time.sleep(0.2)
    assert log == ["first-start"]  # the second ask has not started
    release.set()
    t1.join(5)
    t2.join(5)
    assert log == ["first-start", "first-end", "second-start"]


def test_queue_timeout_denies():
    approvals = Approvals()
    first_in, release = threading.Event(), threading.Event()

    def slow(req):
        first_in.set()
        release.wait(5)
        return True, False

    t1 = threading.Thread(target=approvals.check_or_ask, args=(_req(item="a"), slow, 1.0))
    t1.start()
    assert first_in.wait(5)
    ask = Asker()
    assert not approvals.check_or_ask(_req(item="b"), ask, 1.0, queue_timeout=0.2)
    assert ask.calls == 0
    release.set()
    t1.join(5)
    # The timed-out waiter left the queue: the next ask runs at once.
    assert approvals.check_or_ask(_req(item="c"), Asker(), 1.0, queue_timeout=0.2)


def test_host_approve_local_client_uses_popup_confirm_remember():
    from localvault.local_clients import default_approvals
    from localvault.web.host import WebAgentHost

    seen = {}

    class Port:
        def confirm_remember(self, title, message, label):
            seen.update(message=message, label=label)
            return {"approved": True, "remember": True}

    host = WebAgentHost.__new__(WebAgentHost)  # only the UI port matters here
    host.ui = Port()
    default_approvals().revoke_all()
    ident = identify(10, lookup=_lookup(TERMINAL_TREE), signer=lambda i: None)
    req = ApprovalRequest("cli_read", ident, "i1", "My login", "")
    assert host.approve_local_client(req) is True
    assert "ssh.exe" in seen["message"] and "WindowsTerminal.exe" in seen["message"] and "My login" in seen["message"]
    assert host.approve_local_client(req) is True  # remembered: no second prompt
    default_approvals().revoke_all()


def test_host_approval_for_several_items_uses_the_plural_prompt():
    from localvault.local_clients import default_approvals
    from localvault.web.host import WebAgentHost

    seen = []

    class Port:
        def confirm_remember(self, title, message, label):
            seen.append(message)
            return {"approved": True, "remember": False}

    host = WebAgentHost.__new__(WebAgentHost)
    host.ui = Port()
    default_approvals().revoke_all()
    ident = identify(10, lookup=_lookup(TERMINAL_TREE), signer=lambda i: None)
    reqs = [ApprovalRequest("cli_read", ident, "i1", "First", ""), ApprovalRequest("cli_read", ident, "i2", "Second", "")]
    assert host.approve_local_clients(reqs) is True
    assert "2 items" in seen[0] and "First, Second" in seen[0]
    default_approvals().revoke_all()


def test_remembered_expiry_counts_from_after_the_prompt(monkeypatch):
    from localvault.local_clients import approvals as approvals_module
    clock = [5000.0]
    monkeypatch.setattr(approvals_module.time, "monotonic", lambda: clock[0])
    approvals = Approvals()

    def slow_ask(req):
        clock[0] += 700.0  # the user took 700 seconds to answer
        return True, True

    assert approvals.check_or_ask(_req(), slow_ask, 1000.0)
    ask = Asker()
    # 1000 + 700 + 600 = 2300: still remembered at 2000 although 1000 + 600 would have expired.
    assert approvals.check_or_ask(_req(), ask, 2000.0)
    assert ask.calls == 0
