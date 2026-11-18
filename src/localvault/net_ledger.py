"""Network ledger: the one place the app opens an outbound connection, and a record of each one.

Every outbound connection the app itself makes goes through :func:`open_url` (HTTPS requests built on
``urllib``) or :func:`connect` / :func:`connect_ex` (a TCP socket the caller already created).  Each records
*when*, *what for* (a fixed purpose id), *which host* and *the result*; never a path, a query string, the
breach-check hash prefix or an item name.  ``tests/test_net_ledger_guard.py`` fails when any other module
opens a connection itself.

Where entries are kept:

- fixed services (update check, revocation list, breach range check): host and result in
  ``network-ledger.json`` in the data folder, newest :data:`MAX_ENTRIES` only;
- hosts that reveal a site the user saved (:data:`SITE_PURPOSES`, website icons): in memory for this run only;
  the file keeps the purpose and a count, never the host;
- LAN sync peers (:data:`LOCAL_PURPOSES`): the purpose and "local network", never the address.

Recording never breaks or slows the connection it records: the wrappers call the connection exactly as the
caller would (same handlers, timeout and socket), every recording error is swallowed, and the file is written
on a background thread.
"""
from __future__ import annotations

import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

UPDATE_CHECK = "update_check"
REVOCATION_LIST = "revocation_list"
BREACH_RANGE = "breach_range"
WEBSITE_ICON = "website_icon"
LAN_SYNC = "lan_sync"

#: Every purpose id the app records; anything else is not recorded.
PURPOSES = frozenset({UPDATE_CHECK, REVOCATION_LIST, BREACH_RANGE, WEBSITE_ICON, LAN_SYNC})
#: The host names a site the user saved: memory only, the file keeps a count.
SITE_PURPOSES = frozenset({WEBSITE_ICON})
#: A device on the user's own network: the address is never kept.
LOCAL_PURPOSES = frozenset({LAN_SYNC})

FILENAME = "network-ledger.json"
MAX_ENTRIES = 500
MAX_SESSION_ENTRIES = 500
_MAX_HOST = 253
_MAX_COUNT = 1_000_000

_lock = threading.Lock()
_flush_lock = threading.Lock()
_state: dict[str, Any] = {"path": None, "entries": [], "counts": {}, "dirty": False, "writer": None}
_session: list[dict[str, str]] = []


# ------------------------------------------------------------------------------------------- recording


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path() -> Path:
    from . import config

    return config.data_dir() / FILENAME


def _clean_host(host: Any) -> str:
    if not isinstance(host, str):
        return ""
    text = host.strip().lower().strip("[]")
    if not text or len(text) > _MAX_HOST or any(c in text for c in "/?#@\\ \t\r\n"):
        return ""
    return text


def _clean_result(result: Any) -> str:
    text = str(result)
    if text in {"ok", "failed", "timeout"}:
        return text
    if text.startswith("http_") and text[5:].isdigit() and len(text) == 8:
        return text
    return "failed"


def _load_locked(path: Path) -> None:
    """Point the in-memory copy at *path* (the data folder can change, e.g. between tests)."""
    if _state["path"] == path:
        return
    entries: list[dict[str, str]] = []
    counts: dict[str, int] = {}
    try:
        import json

        raw = json.loads(path.read_text(encoding="utf-8"))
        for item in raw.get("entries", [])[-MAX_ENTRIES:]:
            if (isinstance(item, dict) and item.get("purpose") in PURPOSES - SITE_PURPOSES
                    and isinstance(item.get("at"), str)):
                entries.append({"at": item["at"][:20], "purpose": item["purpose"],
                                "host": "" if item["purpose"] in LOCAL_PURPOSES else _clean_host(item.get("host")),
                                "result": _clean_result(item.get("result"))})
                count = item.get("count")
                if type(count) is int and 1 < count <= _MAX_COUNT:
                    entries[-1]["count"] = count
        for purpose, count in dict(raw.get("counts", {})).items():
            if purpose in SITE_PURPOSES and type(count) is int and count > 0:
                counts[purpose] = count
    except Exception:  # noqa: BLE001, S110 - a missing or damaged ledger starts empty
        pass
    _state.update(path=path, entries=entries, counts=counts, dirty=False)


def _append_locked(entries: list[dict[str, Any]], entry: dict[str, Any], limit: int) -> None:
    """Add *entry*, or count it on the newest line when that line is the same connection with the same result.

    A paired device that is switched off is retried again and again; without this, those lines would push the
    update and breach checks out of the newest :data:`MAX_ENTRIES`.
    """
    last = entries[-1] if entries else None
    if last is not None and all(last[key] == entry[key] for key in ("purpose", "host", "result")):
        last["at"] = entry["at"]
        last["count"] = min(int(last.get("count", 1)) + 1, _MAX_COUNT)
        return
    entries.append(entry)
    del entries[:-limit]


def record(purpose: str, host: Any, result: Any) -> None:
    """Record one outbound connection.  Never raises; unknown purposes are ignored."""
    try:
        if purpose not in PURPOSES:
            return
        entry = {"at": _now(), "purpose": purpose, "host": _clean_host(host), "result": _clean_result(result)}
        if purpose in LOCAL_PURPOSES:
            entry["host"] = ""
        path = _path()
        with _lock:
            _load_locked(path)
            if purpose in SITE_PURPOSES:
                _append_locked(_session, entry, MAX_SESSION_ENTRIES)
                _state["counts"][purpose] = int(_state["counts"].get(purpose, 0)) + 1
            else:
                _append_locked(_state["entries"], entry, MAX_ENTRIES)
            _state["dirty"] = True
            if _state["writer"] is None:
                writer = threading.Thread(target=_write_loop, name="net-ledger", daemon=True)
                _state["writer"] = writer
                writer.start()
    except Exception:  # noqa: BLE001, S110 - recording must never break a connection
        pass


def _write_loop() -> None:
    try:
        while True:
            with _lock:
                if not _state["dirty"]:
                    _state["writer"] = None
                    return
            flush()
    except Exception:  # noqa: BLE001
        with _lock:
            _state["writer"] = None


def flush() -> None:
    """Write pending entries now (the writer thread calls this; tests call it to wait).  Never raises."""
    with _flush_lock:
        try:
            with _lock:
                if not _state["dirty"] or _state["path"] is None:
                    return
                path = _state["path"]
                value = {"version": 1, "entries": [dict(e) for e in _state["entries"]],
                         "counts": dict(_state["counts"])}
                _state["dirty"] = False
            from . import config

            config.atomic_write_json(path, value)
        except Exception:  # noqa: BLE001, S110 - a full disk or locked file only loses ledger lines
            pass


def view() -> dict[str, Any]:
    """Newest first: the kept entries plus this run's site entries, and the per-purpose counts of earlier site
    connections (whose hosts were never written)."""
    with _lock:
        _load_locked(_path())
        merged = [dict(e) for e in _state["entries"]] + [dict(e) for e in _session]
        counts = dict(_state["counts"])
        this_run: dict[str, int] = {}
        for entry in _session:
            this_run[entry["purpose"]] = this_run.get(entry["purpose"], 0) + int(entry.get("count", 1))
    merged.reverse()  # lines with the same time stay newest first through the stable sort
    merged.sort(key=lambda e: e["at"], reverse=True)
    earlier = [{"purpose": p, "count": counts[p] - this_run.get(p, 0)} for p in sorted(counts)
               if counts[p] - this_run.get(p, 0) > 0]
    return {"entries": merged, "earlier": earlier}


def _reset_for_tests() -> None:
    with _lock:
        _state.update(path=None, entries=[], counts={}, dirty=False)
        _session.clear()


# ------------------------------------------------------------------------------------------- wrappers


def _failure(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"http_{exc.code:03d}" if 100 <= exc.code <= 999 else "failed"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, (TimeoutError, socket.timeout)):
        return "timeout"
    return "failed"


def open_url(request: urllib.request.Request, *, purpose: str, timeout: float,
             handlers: Iterable[Any] = (),
             opener_factory: Callable[..., Any] | None = None) -> Any:
    """``build_opener(*handlers).open(request, timeout=timeout)``, recorded.  Returns the response unchanged and
    re-raises any error unchanged; only the host of ``request`` is recorded."""
    try:
        host = urlsplit(request.full_url).hostname
    except Exception:  # noqa: BLE001
        host = ""
    builder = opener_factory or urllib.request.build_opener
    try:
        response = builder(*handlers).open(request, timeout=timeout)
    except BaseException as exc:
        record(purpose, host, _failure(exc))
        raise
    try:
        status = getattr(response, "status", None)
        if status is None:
            status = response.getcode()
        result = "ok" if isinstance(status, int) and 200 <= status < 300 else (
            f"http_{status:03d}" if isinstance(status, int) and 100 <= status <= 999 else "failed")
    except Exception:  # noqa: BLE001
        result = "ok"
    record(purpose, host, result)
    return response


def connect(sock: socket.socket, address: Any, *, purpose: str, host: str) -> None:
    """``sock.connect(address)``, recorded under *host* (the name, not the resolved address)."""
    try:
        sock.connect(address)
    except BaseException as exc:
        record(purpose, host, _failure(exc))
        raise
    record(purpose, host, "ok")


def connect_ex(sock: socket.socket, address: Any) -> int:
    """``sock.connect_ex(address)`` for a non-blocking connect; the caller records the outcome with
    :func:`record` once it is known (``sync.transport`` does, as ``LAN_SYNC``)."""
    return sock.connect_ex(address)
