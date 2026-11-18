"""Guard: only ``localvault.net_ledger`` opens an outbound connection, so the Network activity list is complete.

Scans every module under ``src/localvault`` (AST) for calls that open a connection and for imports of HTTP
client libraries.  A new caller must go through ``net_ledger.open_url`` / ``net_ledger.connect`` instead, or,
when it is not an outbound internet connection, get a commented entry in ``ALLOWED``.
"""
from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "localvault"
WRAPPER = "net_ledger.py"

#: Call names (function or method) that open a connection.
CONNECTING = frozenset({"urlopen", "build_opener", "OpenerDirector", "create_connection", "connect", "connect_ex",
                        "HTTPConnection", "HTTPSConnection", "open_connection", "urlretrieve"})
#: Names that open a connection even when only referenced (passed on, stored, used as a default).
REFERENCED = CONNECTING - {"connect", "connect_ex"}
#: HTTP client libraries the app must not use outside the wrapper.
CLIENT_LIBRARIES = frozenset({"requests", "httpx", "aiohttp", "urllib3", "ftplib", "smtplib", "telnetlib"})

#: (module path relative to src/localvault, call name) -> why it is not an outbound internet connection.
ALLOWED: dict[tuple[str, str], str] = {
    # The native messaging host's TCP fallback talks to the app on this PC: the state file is refused unless the
    # host is 127.0.0.1 (loopback, never leaves the machine).
    ("native_host.py", "create_connection"):
        "loopback only: native host -> app TCP fallback on 127.0.0.1",
    # Picks the outgoing interface: connect() on a UDP socket sends no packet, it only asks the routing table.
    ("sync/lan_interfaces.py", "connect"):
        "UDP route lookup, no packet is sent",
    # The TLS socket is already connected through net_ledger.connect (recorded); HTTPSConnection is given that
    # socket (conn.sock) and only speaks HTTP over it, it never connects itself.
    ("item_icons.py", "HTTPSConnection"):
        "wraps a socket already connected and recorded by net_ledger.connect",
}


def _calls() -> list[tuple[str, str, int]]:
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(PACKAGE).as_posix()
        if relative == WRAPPER:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else None
                through_wrapper = (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                                   and func.value.id == "net_ledger")
                if name in CONNECTING and not through_wrapper:
                    found.append((relative, name, node.lineno))
            elif isinstance(node, ast.Attribute) and node.attr in REFERENCED:
                # ``opener = urllib.request.build_opener`` then ``opener(...).open(...)`` is a connection too.
                found.append((relative, node.attr, node.lineno))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in CLIENT_LIBRARIES:
                        found.append((relative, alias.name, node.lineno))
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                if node.module.split(".")[0] in CLIENT_LIBRARIES:
                    found.append((relative, node.module, node.lineno))
                elif node.module == "urllib.request" and any(a.name in CONNECTING for a in node.names):
                    found.append((relative, "from urllib.request import", node.lineno))
    return found


def test_only_the_wrapper_opens_connections() -> None:
    offenders = [f"{module}:{line}: {name}" for module, name, line in _calls() if (module, name) not in ALLOWED]
    assert not offenders, ("Open outbound connections through localvault.net_ledger (or add a commented, "
                           "non-internet entry to ALLOWED):\n" + "\n".join(offenders))


def test_every_allow_list_entry_is_still_needed() -> None:
    used = {(module, name) for module, name, _line in _calls()}
    stale = sorted(set(ALLOWED) - used)
    assert not stale, f"Remove stale ALLOWED entries: {stale}"


def test_the_guard_sees_a_connection() -> None:
    tree = ast.parse("import urllib.request\nurllib.request.urlopen('https://x')\nsock.connect(addr)\n")
    names = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert {"urlopen", "connect"} <= names & CONNECTING
