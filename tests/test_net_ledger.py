"""Network ledger: what is recorded, where, and that recording never breaks the connection."""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request

import pytest

from localvault import config, net_ledger


@pytest.fixture(autouse=True)
def _fresh_ledger():
    net_ledger._reset_for_tests()
    yield
    net_ledger.flush()
    net_ledger._reset_for_tests()


def _file() -> dict:
    net_ledger.flush()
    return json.loads((config.data_dir() / net_ledger.FILENAME).read_text(encoding="utf-8"))


class _Response:
    def __init__(self, status=200):
        self.status = status


class _Opener:
    def __init__(self, calls, outcome):
        self.calls, self.outcome = calls, outcome

    def open(self, request, timeout):
        self.calls.append(("open", request.full_url, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def _factory(calls, outcome):
    def build(*handlers):
        calls.append(("handlers", handlers))
        return _Opener(calls, outcome)
    return build


def test_open_url_records_host_only_and_returns_the_response_unchanged():
    calls = []
    response = _Response()
    handler = object()
    request = urllib.request.Request("https://api.pwnedpasswords.com/range/ABCDE?x=1")
    got = net_ledger.open_url(request, purpose=net_ledger.BREACH_RANGE, timeout=7,
                              handlers=(handler,), opener_factory=_factory(calls, response))
    assert got is response
    assert calls == [("handlers", (handler,)), ("open", request.full_url, 7)]
    data = _file()
    assert [(e["purpose"], e["host"], e["result"]) for e in data["entries"]] == [
        ("breach_range", "api.pwnedpasswords.com", "ok")]
    text = json.dumps(data)
    assert "ABCDE" not in text and "/range" not in text and "x=1" not in text


def test_open_url_records_http_errors_and_reraises_them():
    error = urllib.error.HTTPError("https://updates.example/stable.json", 404, "nf", {}, None)
    with pytest.raises(urllib.error.HTTPError):
        net_ledger.open_url(urllib.request.Request("https://updates.example/stable.json"),
                            purpose=net_ledger.UPDATE_CHECK, timeout=1, opener_factory=_factory([], error))
    with pytest.raises(urllib.error.URLError):
        net_ledger.open_url(urllib.request.Request("https://updates.example/revocations.json"),
                            purpose=net_ledger.REVOCATION_LIST, timeout=1,
                            opener_factory=_factory([], urllib.error.URLError(TimeoutError())))
    entries = net_ledger.view()["entries"]
    assert {(e["purpose"], e["result"]) for e in entries} == {("update_check", "http_404"),
                                                              ("revocation_list", "timeout")}


def test_site_hosts_stay_in_memory_and_the_file_keeps_only_a_count():
    net_ledger.record(net_ledger.WEBSITE_ICON, "secret-bank.example", "ok")
    net_ledger.record(net_ledger.WEBSITE_ICON, "other.example", "failed")
    raw = (json.dumps(_file()))
    assert "secret-bank" not in raw and "other.example" not in raw
    assert _file()["counts"] == {"website_icon": 2}
    shown = net_ledger.view()
    assert {e["host"] for e in shown["entries"]} == {"secret-bank.example", "other.example"}
    assert shown["earlier"] == []
    # A new run: the hosts are gone, the count is shown as earlier connections.
    net_ledger._reset_for_tests()
    assert net_ledger.view() == {"entries": [], "earlier": [{"purpose": "website_icon", "count": 2}]}


def test_lan_sync_never_keeps_the_address():
    net_ledger.record(net_ledger.LAN_SYNC, "192.168.1.20", "ok")
    assert _file()["entries"][0]["host"] == ""
    assert "192.168" not in json.dumps(_file())


def test_a_repeated_connection_is_counted_on_one_line():
    net_ledger.record(net_ledger.UPDATE_CHECK, "updates.example", "ok")
    for _ in range(40):
        net_ledger.record(net_ledger.LAN_SYNC, "192.168.1.20", "failed")
    net_ledger.record(net_ledger.LAN_SYNC, "192.168.1.20", "ok")
    entries = _file()["entries"]
    assert [(e["purpose"], e["result"], e.get("count", 1)) for e in entries] == [
        ("update_check", "ok", 1), ("lan_sync", "failed", 40), ("lan_sync", "ok", 1)]
    # The count survives a restart, and a repeated site is still counted once per connection.
    net_ledger._reset_for_tests()
    assert net_ledger.view()["entries"][1]["count"] == 40
    for _ in range(3):
        net_ledger.record(net_ledger.WEBSITE_ICON, "bank.example", "ok")
    assert _file()["counts"] == {"website_icon": 3}
    assert net_ledger.view()["earlier"] == []


def test_the_file_keeps_the_newest_500():
    for n in range(net_ledger.MAX_ENTRIES + 20):
        net_ledger.record(net_ledger.UPDATE_CHECK, f"h{n}.example", "ok")
    entries = _file()["entries"]
    assert len(entries) == net_ledger.MAX_ENTRIES
    assert entries[-1]["host"] == f"h{net_ledger.MAX_ENTRIES + 19}.example"
    assert entries[0]["host"] == "h20.example"


def test_unknown_purposes_and_odd_hosts_are_not_recorded_as_given():
    net_ledger.record("anything", "x.example", "ok")
    net_ledger.record(net_ledger.UPDATE_CHECK, "x.example/path?q", "weird result")
    assert [(e["host"], e["result"]) for e in net_ledger.view()["entries"]] == [("", "failed")]


def test_a_write_failure_never_breaks_the_connection(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("disk full")
    monkeypatch.setattr(config, "atomic_write_json", boom)
    response = _Response()
    got = net_ledger.open_url(urllib.request.Request("https://updates.example/stable.json"),
                              purpose=net_ledger.UPDATE_CHECK, timeout=1, opener_factory=_factory([], response))
    net_ledger.flush()
    assert got is response


def test_a_recording_failure_never_breaks_the_connection(monkeypatch):
    monkeypatch.setattr(net_ledger, "_path", lambda: (_ for _ in ()).throw(RuntimeError("no data folder")))
    response = _Response()
    assert net_ledger.open_url(urllib.request.Request("https://updates.example/stable.json"),
                               purpose=net_ledger.UPDATE_CHECK, timeout=1,
                               opener_factory=_factory([], response)) is response


class _Sock:
    def __init__(self, error=None):
        self.error, self.address = error, None

    def connect(self, address):
        self.address = address
        if self.error:
            raise self.error


def test_connect_records_the_name_not_the_address_and_reraises():
    sock = _Sock()
    net_ledger.connect(sock, ("93.184.216.34", 443), purpose=net_ledger.WEBSITE_ICON, host="example.com")
    assert sock.address == ("93.184.216.34", 443)
    with pytest.raises(socket.timeout):
        net_ledger.connect(_Sock(TimeoutError()), ("93.184.216.34", 443),
                           purpose=net_ledger.WEBSITE_ICON, host="example.com")
    entries = net_ledger.view()["entries"]
    assert sorted((e["host"], e["result"]) for e in entries) == [("example.com", "ok"), ("example.com", "timeout")]
    assert "93.184" not in json.dumps(net_ledger.view())


def test_damaged_file_starts_empty():
    (config.data_dir() / net_ledger.FILENAME).write_text("{not json", encoding="utf-8")
    assert net_ledger.view() == {"entries": [], "earlier": []}


def test_breach_check_goes_through_the_ledger_without_the_prefix(monkeypatch):
    from localvault import breach_check

    calls = []
    body = _Response()
    body.read = lambda n: b"0" * 35 + b":1\r\n"
    monkeypatch.setattr(urllib.request, "build_opener", _factory(calls, _Ctx(body)))
    breach_check._fetch("ABCDE")
    assert type(calls[0][1][0]).__name__ == "_NoRedirect" and calls[1][2] == 10
    assert [(e["purpose"], e["host"]) for e in net_ledger.view()["entries"]] == [
        ("breach_range", "api.pwnedpasswords.com")]
    assert "ABCDE" not in json.dumps(_file())


def test_update_and_revocation_fetches_are_told_apart(monkeypatch):
    from localvault import updates

    def opener(*handlers):
        assert type(handlers[0]).__name__ == "_SameOriginRedirectHandler"
        return _Opener([], urllib.error.URLError("offline"))
    for url, purpose in (("https://updates.example/stable.json", net_ledger.UPDATE_CHECK),
                         ("https://updates.example/revocations.json", net_ledger.REVOCATION_LIST)):
        with pytest.raises(updates.UpdateCheckError):
            updates._fetch_feed(url, opener, purpose=purpose)
    assert sorted(e["purpose"] for e in net_ledger.view()["entries"]) == ["revocation_list", "update_check"]


class _Ctx:
    def __init__(self, inner):
        self.inner, self.status = inner, 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n):
        return self.inner.read(n)


def test_lines_with_the_same_time_are_listed_newest_first(monkeypatch):
    monkeypatch.setattr(net_ledger, "_now", lambda: "2026-11-13T00:00:00Z")
    net_ledger.record(net_ledger.UPDATE_CHECK, "updates.example", "ok")
    net_ledger.record(net_ledger.LAN_SYNC, "192.168.1.20", "failed")
    net_ledger.record(net_ledger.LAN_SYNC, "192.168.1.20", "ok")
    assert [(e["purpose"], e["result"]) for e in net_ledger.view()["entries"]] == [
        ("lan_sync", "ok"), ("lan_sync", "failed"), ("update_check", "ok")]
