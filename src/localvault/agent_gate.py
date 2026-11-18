"""Local Agent Gate: per-task, user-approved access for AI agents (MCP clients).

No tool reply carries a password, a one-time code or a private key: there is no reveal or copy path for agents.
An agent can list site titles and domains (after the user approved that once for its session), ask for a one-use
grant to sign in to one site (the user approves each request in the palette window; there is no "always" answer),
and have the browser extension offer that site's login when the user clicks the LocalGateKeys icon on the page.
The password is then written into the page, so the page, and any agent that automates that browser, can read it.
Logins that ask for the master password every time are never used.

Only logins the owner opted in ("AI agents may use this login": ``scope.ai_agents is True``, off by default and on
any missing or malformed value) exist for an agent; a site whose logins are all off looks like a site with no login.
A login that has a saved passkey for the approved site never has its password filled for an agent: the grant is a
passkey grant, and only one passkey assertion for those passkeys goes through the normal passkey path (the owner's
passkey dialog and user verification), so no reusable secret reaches the page.

Grants live five minutes, are used once, and are bound to the exact sign-in hosts and logins the user approved and
to the MCP client session that asked. Every call is written to the hash-chained activity log (``agent.*`` events,
no content).

Secrets for commands (``list_secrets`` / ``run_with_secrets``): only items of ``AGENT_SECRET_KINDS`` whose id the
owner switched on in ``settings.agent_items`` (this device only, never exported or restored) exist for an agent;
any other reference is ``not_found``, exactly like one to an item that does not exist. A run request names the
command line, the working folder and each ``lgk://`` reference; the user approves it once, and the approval
(a ``RunGrant``, one minute, one use, bound to the MCP session) releases the values to the ``lgk mcp`` process,
which starts the command with them in its environment. The command can send them anywhere: masking only hides them
in the output returned to the agent. The activity log gets each item id (``agent.request``, ``agent.read``,
``agent.complete``); the field names and the command line go to the run log (``run_log``), never a value.
"""
from __future__ import annotations

import ipaddress
import secrets
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .access_policy import enforced_policy
from .cli.run import (
    ENV_NAME as _ENV_NAME,
)
from .cli.run import (
    MAX_ARG,
    MAX_ARGV,
    MAX_COMMAND_LINE,
    MAX_REF,
    MAX_RUN_REFS,
    MAX_TIMEOUT,
    RESERVED_ENV,
    command_line,
    plain_text,
    unsafe_batch_command,
)
from .cli.run import (
    PREFIX as REF_PREFIX,
)
from .lgk_refs import Ref, RefError, RefItem, find, parse
from .origin import OriginError, _is_loopback, base_domain, canonicalize_origin, entry_urls, host_of

GRANT_TTL = 300.0
ARM_TTL = 60.0
LOCKED_WAIT = 30.0
FILL_WAIT = 60.0
MAX_PURPOSE = 300
MAX_SITE = 253
MAX_GRANTS = 32
MAX_LISTED = 50
RATE_WINDOW = 60.0
RATE_PER_CLIENT = 3  # approval requests per agent session per minute
RATE_TOTAL = 10  # approval requests from all agents per minute
# The per-login opt-in. It lives in the login's scope, which sync and the phone apps keep as is (unknown scope keys
# are preserved), so it syncs to the owner's devices; transfers and shares drop it (agent_scope_stripped).
AGENT_SCOPE_KEY = "ai_agents"
# Secrets for commands (run_with_secrets). Typed items have a strict schema with no room for a flag, so the switch
# is the device-only id list ``settings.agent_items``: never exported, cleared by a restore, dropped for items a
# transfer import writes. Only these kinds, and only these fields (a note: its body and its custom fields), exist for
# an agent. Cards, bank accounts, Wi-Fi and passkeys never do.
AGENT_SECRET_KINDS = frozenset({"api_key", "ssh_key", "note"})
_SECRET_FIELDS = {"api_key": ("key", "secret", "service"), "ssh_key": ("private_key", "passphrase", "public_key")}
RUN_TTL = 60.0  # between the approval and the release of the values (the same pipe request does both)
MAX_CWD = 1024
MAX_RUN_ID = 64
MAX_FIELDS_LISTED = 50
# The argv, environment and time limits, the batch-file rule and the "shown exactly" text check are the runner's
# (cli/run.py), so ``lgk mcp`` refuses the same requests before it asks; checked here again before the user is asked.
_plain = plain_text


def agent_item_allowed(settings: Any, item_id: Any) -> bool:
    """True only when ``item_id`` is in the owner's device-only list of items AI agents may use."""
    ids = getattr(settings, "agent_items", None)
    return isinstance(ids, list) and isinstance(item_id, str) and bool(item_id) and item_id in ids


def secret_value(item: Mapping[str, Any], name: str) -> str | None:
    """The value of one field an agent may use (non-empty text), else None. A note's custom field wins over its
    body, the last of a name first (the secret scan stores each .env variable as a custom field)."""
    kind = item.get("kind")
    payload = item.get("payload") if isinstance(item.get("payload"), Mapping) else {}
    value: Any = None
    if kind == "note":
        custom = payload.get("fields")
        if isinstance(custom, list):
            for row in reversed(custom):
                if isinstance(row, Mapping) and row.get("name") == name and isinstance(row.get("value"), str):
                    value = row["value"]
                    break
        if value is None and name == "body":
            value = payload.get("body")
    elif name in _SECRET_FIELDS.get(str(kind), ()):
        value = payload.get(name)
    return value if isinstance(value, str) and value else None


def secret_fields(item: Mapping[str, Any]) -> list[str]:
    """Names (never values) of the fields an agent may use on this item, sorted."""
    kind = item.get("kind")
    if kind not in AGENT_SECRET_KINDS:
        return []
    payload = item.get("payload") if isinstance(item.get("payload"), Mapping) else {}
    names: set[str] = set()
    if kind == "note":
        custom = payload.get("fields")
        if isinstance(custom, list):
            names.update(row["name"] for row in custom
                         if isinstance(row, Mapping) and isinstance(row.get("name"), str) and row["name"])
        names.add("body")
    else:
        names.update(_SECRET_FIELDS[str(kind)])
    return sorted(name for name in names if secret_value(item, name) is not None)[:MAX_FIELDS_LISTED]




def agents_may_use(entry: Any) -> bool:
    """True only when the owner turned on "AI agents may use this login"; missing or malformed is off."""
    try:
        scope = entry.get("scope")
    except Exception:  # noqa: BLE001 - not a login record: off
        return False
    return isinstance(scope, Mapping) and scope.get(AGENT_SCOPE_KEY) is True


def agent_scope_stripped(scope: Any) -> Any:
    """The scope without the opt-in: a login that leaves this vault (transfer, share) arrives with agents off."""
    if isinstance(scope, dict):
        scope.pop(AGENT_SCOPE_KEY, None)
    return scope


def _rp_covers(rp_id: Any, host: str, domain: str) -> bool:
    """WebAuthn's rule: a passkey for ``rp_id`` signs in on ``rp_id`` and its subdomains, inside one site."""
    if not isinstance(rp_id, str):
        return False
    rp = rp_id.strip().lower().rstrip(".")
    if not rp or registrable_domain(rp) != domain:
        return False
    return host == rp or host.endswith("." + rp)


def site_passkeys(username: Any, hosts: Iterable[str], domain: str,
                  passkeys: Iterable[Mapping[str, Any]]) -> frozenset[str]:
    """Credential ids of the saved passkeys a login has for these sign-in hosts (no key material is read).

    A passkey belongs to the site when its relying party covers one of the hosts. When some of them name the
    login's user name, only those count; otherwise every passkey for the site counts, so a doubtful match prefers
    the passkey (no password on the page) over the password.
    """
    hosts = [h for h in hosts if isinstance(h, str) and h]
    site = [p for p in passkeys if isinstance(p, Mapping) and isinstance(p.get("credential_id"), str)
            and p["credential_id"] and any(_rp_covers(p.get("rp_id"), h, domain) for h in hosts)]
    name = str(username or "").strip().casefold()
    same = [p for p in site if name and str(p.get("user_name") or "").strip().casefold() == name]
    return frozenset(str(p["credential_id"]) for p in (same or site))


@dataclass(frozen=True)
class ClientInfo:
    """Who is asking: the MCP session id (one per ``lgk mcp`` process), its client name and its process."""

    client_id: str
    name: str
    process: str


@dataclass
class Grant:
    id: str
    domain: str
    client_id: str
    expires: float
    hosts: frozenset[str] = frozenset()  # the exact page hosts the grant is good for
    entry_ids: frozenset[str] = frozenset()  # the logins the user approved
    # Credential ids of the approved logins' passkeys for the site. Non-empty: a passkey grant, never a password fill.
    passkey_ids: frozenset[str] = frozenset()
    agent: str = ""  # the agent's name as the approval showed it (the exposure log names it)
    used: bool = False
    armed_until: float = 0.0
    outcome: str = ""
    done: threading.Event = field(default_factory=threading.Event, repr=False, compare=False)

    @property
    def method(self) -> str:
        return "passkey" if self.passkey_ids else "password"


@dataclass(frozen=True)
class Refusal:
    reason: str  # disabled, pro, locked, not_found, denied, invalid, expired, used, not_yours, not_allowed, no_tab,
    # no_passkey


@dataclass(frozen=True)
class AgentRequest:
    """What the approval view shows. Every field is plain text; the page renders it as text, never markup."""

    action: str  # "sign_in", "read", "list" (list_sites/list_secrets, once per agent session) or "run"
    agent: str
    process: str
    site: str
    purpose: str
    hello: bool = False
    method: str = "password"  # sign_in: "passkey" (the passkey signs in) or "password" (filled into the page)
    # run: the exact command line, its working folder, (variable, item title, field) per value, and the time limit.
    command: str = ""
    cwd: str = ""
    secrets: tuple[tuple[str, str, str], ...] = ()
    timeout: int = 0


@dataclass(frozen=True)
class RunTarget:
    """One value a run asked for: the agent's reference, its variable, and the item and field it names."""

    ref: str
    variable: str
    item_id: str
    title: str
    field: str


@dataclass
class RunGrant:
    """One approved run: its values are released once, to the MCP session that asked, within ``RUN_TTL``."""

    id: str
    run_id: str
    client_id: str
    expires: float
    targets: tuple[RunTarget, ...]
    record: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    used: bool = False
    finished: bool = False

    @property
    def item_ids(self) -> list[str]:
        return list(dict.fromkeys(target.item_id for target in self.targets))


class AgentUi(Protocol):
    def confirm_agent(self, request: AgentRequest) -> bool: ...


def clean_text(value: Any, limit: int) -> str:
    """Plain, single-line text: control and bidi-override characters removed, length capped."""
    if not isinstance(value, str):
        return ""
    kept = []
    for char in value:
        category = unicodedata.category(char)
        if char in "\t\r\n":
            kept.append(" ")
        elif category in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            kept.append(char)
    return " ".join("".join(kept).split())[:limit]


def registrable_domain(site: Any) -> str | None:
    """``paypal.com`` for ``paypal.com``, ``https://www.paypal.com/x`` or ``login.paypal.com``; None if unusable."""
    if not isinstance(site, str) or not site.strip() or len(site) > MAX_SITE + 16:
        return None
    text = site.strip()
    if "://" not in text:
        text = "https://" + text
    try:
        host = host_of(text)
    except (OriginError, ValueError):
        return None
    domain = base_domain(host)
    return domain if domain and ("." in domain or _is_loopback(domain)) else None


def site_is_insecure(site: Any) -> bool:
    """True when the agent named a plain-http (or other non-https) URL on a non-loopback host."""
    if not isinstance(site, str) or "://" not in site:
        return False
    scheme = site.strip().split("://", 1)[0].lower()
    if scheme == "https":
        return False
    host = site_host(site)
    return not (scheme == "http" and host is not None and _is_loopback(host.strip("[]")))


def _is_ip_or_local(domain: str) -> bool:
    """IP literals and loopback names never get a ``www.`` sibling."""
    if _is_loopback(domain):
        return True
    try:
        ipaddress.ip_address(domain.strip("[]"))
        return True
    except ValueError:
        return False


def site_host(site: Any) -> str | None:
    """The lower-case host an agent named (``login.paypal.com`` for ``https://login.paypal.com/x``)."""
    if not isinstance(site, str) or not site.strip() or len(site) > MAX_SITE + 16:
        return None
    text = site.strip()
    if "://" not in text:
        text = "https://" + text
    try:
        return host_of(text).lower().rstrip(".") or None
    except (OriginError, ValueError):
        return None


def origin_domain(origin: str) -> str | None:
    """The registrable domain of a page origin; https qualifies, plain http only on loopback (like the extension's
    own fill, via ``canonicalize_origin``)."""
    try:
        canonical = canonicalize_origin(origin)
    except (OriginError, ValueError):
        return None
    if not canonical.startswith("https://"):
        host = site_host(canonical)
        if not (canonical.startswith("http://") and host is not None and _is_loopback(host.strip("[]"))):
            return None
    return registrable_domain(canonical)



def _hidden_ids(session: Any) -> frozenset[str]:
    """Travel-hidden ids of ``session``: the app's locked wrapper answers ``hidden_ids()``; a plain session is
    read directly. Unknown → empty (the wrapper's reads leave hidden items out as well)."""
    from .travel import hidden_id_set

    read = getattr(session, "hidden_ids", None)
    if callable(read):
        try:
            return frozenset(str(value) for value in read())
        except Exception:  # noqa: BLE001 - the wrapper's own reads still filter
            return frozenset()
    return hidden_id_set(session)


class AgentGate:
    def __init__(self, session: Callable[[], Any], settings: Callable[[], Any] | Any, ui: AgentUi,
                 activity: Callable[..., None] | None = None, *,
                 is_pro: Callable[[], bool] | None = None,
                 request_unlock: Callable[[], None] | None = None,
                 run_log: Callable[[dict[str, Any]], None] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 locked_wait: float = LOCKED_WAIT, fill_wait: float = FILL_WAIT) -> None:
        self._session = session
        self._settings = settings if callable(settings) else (lambda: settings)
        self._ui = ui
        self._activity = activity
        self._is_pro = is_pro or _licence_is_pro
        self._request_unlock = request_unlock
        self._run_log = run_log
        self._clock = clock
        self._locked_wait = float(locked_wait)
        self._fill_wait = float(fill_wait)
        self._lock = threading.Lock()
        self._grants: dict[str, Grant] = {}
        self._runs: dict[str, RunGrant] = {}
        self._asked: list[tuple[float, str]] = []
        self._asking = False
        self._listing_ok: set[str] = set()  # agent sessions the user let list sites and secrets

    # ------------------------------------------------------------------ checks
    def _log(self, event: str, result: str, item_id: str | None = None) -> None:
        if self._activity is None:
            return
        try:
            if item_id is None:
                self._activity(event, result)
            else:
                self._activity(event, result, item_id=item_id)
        except Exception:  # noqa: BLE001 - a log failure never releases or blocks anything by itself
            pass

    def _record_run(self, record: Mapping[str, Any], stage: str, **extra: Any) -> None:
        """One run-log row (agent, command line, folder, item ids and field names, outcome); never a value."""
        if self._run_log is None:
            return
        try:
            self._run_log({**record, "stage": stage, **extra})
        except Exception:  # noqa: BLE001, S110 - a log failure never releases or blocks anything by itself
            pass

    def _gate(self) -> Refusal | None:
        if getattr(self._settings(), "agents_enabled", False) is not True:
            return Refusal("disabled")
        if not self._is_pro():
            return Refusal("pro")
        return None

    def _unlocked(self) -> Any:
        """The open vault session, or None after the unlock prompt went unanswered for ``locked_wait`` seconds."""
        session = self._session()
        if session is not None:
            return session
        if self._request_unlock is not None:
            try:
                self._request_unlock()
            except Exception:  # noqa: BLE001
                pass
        deadline = time.monotonic() + self._locked_wait
        while time.monotonic() < deadline:
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
            session = self._session()
            if session is not None:
                return session
        return None

    def _ready(self, event: str) -> tuple[Any, Refusal | None]:
        refused = self._gate()
        if refused is not None:
            self._log(event, "denied")
            return None, refused
        session = self._unlocked()
        if session is None:
            self._log(event, "locked")
            return None, Refusal("locked")
        return session, None

    # ------------------------------------------------------------------ vault reads (no secrets)
    @staticmethod
    def _logins(session: Any) -> list[tuple[str, str, str, frozenset[str], str]]:
        """(id, title, registrable domain, URL hosts on it, user name) of each web login an agent may use: opted
        in by the owner, not strict, fill not "never". Every other login does not exist for an agent."""
        from .access_policy import has_rule, local_today

        rows: list[tuple[str, str, str, frozenset[str], str]] = []
        hidden = _hidden_ids(session)
        today = local_today()
        for summary in session.summaries():
            if getattr(summary, "kind", "") != "web" or str(summary.id) in hidden:
                continue
            entry = session.get_entry(summary.id)
            if not entry:
                continue
            try:
                if not agents_may_use(entry):
                    continue
                policy = enforced_policy(entry, today)
                # Any access rule on (contract 4.3) hides the login from agents, like strict and fill-never.
                if policy.get("require_master_password") or policy.get("fill") == "never" or has_rule(entry, today):
                    continue
                urls = [str(row.get("url", "")) for row in entry_urls(entry)]
                username = entry.get("username")
                username = username if isinstance(username, str) else ""
            finally:
                clear = getattr(entry, "clear", None)
                if callable(clear):
                    clear()
            by_domain: dict[str, set[str]] = {}
            for url in urls:
                domain, host = registrable_domain(url), site_host(url)
                if domain:
                    by_domain.setdefault(domain, set()).update({host} if host else set())
            for domain in sorted(by_domain):
                rows.append((str(summary.id), str(summary.label), domain, frozenset(by_domain[domain]), username))
        return rows

    @staticmethod
    def _passkeys(session: Any) -> list[Mapping[str, Any]]:
        """Names and credential ids of the saved passkeys (``passkey_metadata``: never key material).

        ``item_service.passkey_metadata`` leaves out travel-hidden passkeys itself (under the vault lock). Its rows
        carry no item id, so the filter that used to sit here (on a missing ``id`` key) never matched: finding
        W-L5."""
        read = getattr(session, "passkeys", None)
        rows = read() if callable(read) else []
        return [row for row in rows if isinstance(row, Mapping)] if isinstance(rows, list) else []

    # ------------------------------------------------------------------ tools
    def _listing_allowed(self, client: ClientInfo) -> Refusal | None:
        """The list of sign-in sites and allowed secrets is a private inventory: the user allows it once per agent
        session (one approval covers ``list_sites`` and ``list_secrets``)."""
        if client.client_id in self._listing_ok:
            return None
        if not self._take_turn(client):
            self._log("agent.search", "denied")
            return Refusal("rate_limited")
        try:
            request = AgentRequest("list", clean_text(client.name, 80) or "MCP client",
                                   clean_text(client.process, 80), "", "", hello=self._hello())
            if not self._approved(request):
                self._log("agent.search", "denied")
                return Refusal("denied")
            with self._lock:
                self._listing_ok.add(client.client_id)
            return None
        finally:
            with self._lock:
                self._asking = False

    def _hello(self) -> bool:
        return getattr(self._settings(), "require_hello_for_agents", False) is True

    def list_sites(self, client: ClientInfo, query: str = "") -> list[dict[str, str]] | Refusal:
        session, refused = self._ready("agent.search")
        if refused is not None:
            return refused
        refused = self._listing_allowed(client)
        if refused is not None:
            return refused
        needle = clean_text(query, 100).casefold()
        seen: set[tuple[str, str]] = set()
        out: list[dict[str, str]] = []
        for _id, title, domain, _hosts, _user in self._logins(session):
            if needle and needle not in title.casefold() and needle not in domain:
                continue
            if (title, domain) in seen:
                continue
            seen.add((title, domain))
            out.append({"title": title, "domain": domain})
            if len(out) >= MAX_LISTED:
                break
        self._log("agent.search", "ok")
        return out

    def request_login(self, client: ClientInfo, site: str, purpose: str) -> Grant | Refusal:
        if site_is_insecure(site):
            self._log("agent.request", "failed")
            return Refusal("insecure_site")
        domain, host = registrable_domain(site), site_host(site)
        if domain is None or host is None:
            self._log("agent.request", "failed")
            return Refusal("invalid")
        session, refused = self._ready("agent.request")
        if refused is not None:
            return refused
        matches = [row for row in self._logins(session) if row[2] == domain]
        if host != domain:
            # A named sign-in host: only that host, and only logins saved for it (or for the bare domain).
            matches = [row for row in matches if host in row[3] or domain in row[3]]
            hosts: frozenset[str] = frozenset({host})
        else:
            # A bare domain: the exact hosts the matching logins are saved for, never any other host on it.
            hosts = frozenset().union(*(row[3] for row in matches)) if matches else frozenset()
            if domain in hosts and not _is_ip_or_local(domain):
                hosts |= {"www." + domain}
        if not matches or not hosts:
            self._log("agent.request", "not_found")
            return Refusal("not_found")
        # A saved passkey for these hosts makes this a passkey grant: no password of the site is filled for an agent;
        # the site's passkey sign-in runs instead (site_passkeys prefers the passkey whenever in doubt).
        passkeys = self._passkeys(session)
        passkey_ids: frozenset[str] = frozenset().union(
            *(site_passkeys(row[4], hosts, domain, passkeys) for row in matches))
        if not self._take_turn(client):
            self._log("agent.request", "denied")
            return Refusal("rate_limited")
        try:
            return self._ask_and_grant(client, domain, purpose, hosts, frozenset(row[0] for row in matches),
                                       passkey_ids)
        finally:
            with self._lock:
                self._asking = False

    def _take_turn(self, client: ClientInfo) -> bool:
        """One approval on screen at a time, and at most a few per minute: an agent cannot flood the user."""
        now = self._clock()
        with self._lock:
            self._asked = [(at, who) for at, who in self._asked if now - at < RATE_WINDOW]
            mine = sum(1 for _at, who in self._asked if who == client.client_id)
            if self._asking or mine >= RATE_PER_CLIENT or len(self._asked) >= RATE_TOTAL:
                return False
            self._asked.append((now, client.client_id))
            self._asking = True
            return True

    def _ask_and_grant(self, client: ClientInfo, domain: str, purpose: str, hosts: frozenset[str],
                       entry_ids: frozenset[str], passkey_ids: frozenset[str] = frozenset()) -> Grant | Refusal:
        shown = ", ".join(sorted(hosts))
        if len(shown) > MAX_SITE:
            shown = shown[:MAX_SITE - 1] + "\u2026"
        request = AgentRequest("sign_in", clean_text(client.name, 80) or "MCP client",
                               clean_text(client.process, 80), shown, clean_text(purpose, MAX_PURPOSE),
                               hello=getattr(self._settings(), "require_hello_for_agents", False) is True,
                               method="passkey" if passkey_ids else "password")
        if not self._approved(request):
            self._log("agent.request", "denied")
            return Refusal("denied")
        expires = self._clock() + GRANT_TTL
        grant = Grant(secrets.token_urlsafe(18), domain, client.client_id, expires,
                      hosts=hosts, entry_ids=entry_ids, passkey_ids=passkey_ids, agent=request.agent)
        if passkey_ids:
            # The site's own passkey sign-in starts the ceremony (the agent or the user clicks it), so a passkey
            # grant is armed for its whole life; the owner's passkey dialog and verification still decide.
            grant.armed_until = expires
        with self._lock:
            self._expire()
            self._grants[grant.id] = grant
            while len(self._grants) > MAX_GRANTS:
                self._grants.pop(next(iter(self._grants)))
        self._log("agent.request", "ok")
        return grant

    def _approved(self, request: AgentRequest) -> bool:
        """The only way to approve: the user's answer in the approval view. A failure or timeout is a no."""
        try:
            return self._ui.confirm_agent(request) is True
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------ secrets for commands
    def _secret_items(self, session: Any) -> list[tuple[str, str, str, list[str]]]:
        """(id, title, kind, field names) of each item an agent may use: switched on by the owner on this device and
        of a kind that holds secrets. Every other item does not exist for an agent."""
        settings = self._settings()
        rows: list[tuple[str, str, str, list[str]]] = []
        for summary in session.items():
            item_id, kind = str(summary.get("id") or ""), summary.get("kind")
            if kind not in AGENT_SECRET_KINDS or not agent_item_allowed(settings, item_id):
                continue
            item = session.item(item_id)
            if not isinstance(item, dict) or item.get("kind") not in AGENT_SECRET_KINDS:
                continue
            try:
                rows.append((item_id, str(item.get("title") or ""), str(item["kind"]), secret_fields(item)))
            finally:
                _wipe(item)
        return rows

    def list_secrets(self, client: ClientInfo, query: str = "") -> list[dict[str, Any]] | Refusal:
        """Titles, kinds and field names of the items an agent may use in ``run_with_secrets``; never a value."""
        session, refused = self._ready("agent.search")
        if refused is not None:
            return refused
        refused = self._listing_allowed(client)
        if refused is not None:
            return refused
        needle = clean_text(query, 100).casefold()
        out: list[dict[str, Any]] = []
        for item_id, title, kind, fields in sorted(self._secret_items(session), key=lambda r: (r[1].casefold(), r[0])):
            if needle and needle not in title.casefold() and needle not in kind \
                    and not any(needle in name.casefold() for name in fields):
                continue
            out.append({"id": item_id, "title": title, "kind": kind, "fields": fields})
            if len(out) >= MAX_LISTED:
                break
        self._log("agent.search", "ok")
        return out

    def _run_targets(self, session: Any, env: Mapping[str, str]) -> list[RunTarget] | Refusal:
        """The item and field each reference names, among the allowed items only (``lgk_refs.find``)."""
        settings = self._settings()
        rows: list[RefItem] = []
        fields: dict[str, list[str]] = {}
        for item_id, title, kind, names in self._secret_items(session):
            rows.append(RefItem(item_id, title, kind, True, listed=True))
            fields[item_id] = names
        targets: list[RunTarget] = []
        for variable, text in env.items():
            try:
                ref: Ref = parse(text)
                row = find(ref, rows)
            except RefError as exc:
                codes = {"bad_reference": "invalid", "ambiguous": "ambiguous"}
                return Refusal(codes.get(exc.code, "not_found"))
            if ref.field not in fields.get(row.id, ()) or not agent_item_allowed(settings, row.id):
                return Refusal("not_found")
            targets.append(RunTarget(text, variable, row.id, row.title, ref.field))
        return targets

    def request_run(self, client: ClientInfo, run_id: Any, env: Any, command: Any, cwd: Any, timeout: Any,
                    purpose: Any) -> RunGrant | Refusal:
        """Ask the user to approve one run of ``command`` (an argv list) in ``cwd`` with the values ``env`` names
        (variable -> ``lgk://`` reference). Anything malformed is ``invalid``; a reference to anything but a field of
        an allowed item is ``not_found``, before the user is asked."""
        if not _valid_run(run_id, env, command, cwd, timeout):
            self._log("agent.request", "failed")
            return Refusal("invalid")
        session, refused = self._ready("agent.request")
        if refused is not None:
            return refused
        targets = self._run_targets(session, env)
        record: dict[str, Any] = {"run": run_id, "agent": clean_text(client.name, 80) or "MCP client",
                                  "process": clean_text(client.process, 80), "command": command_line(command),
                                  "cwd": cwd, "purpose": clean_text(purpose, MAX_PURPOSE), "timeout": int(timeout)}
        if isinstance(targets, Refusal):
            self._log("agent.request", "failed" if targets.reason == "invalid" else "not_found")
            self._record_run(record, "refused", result=targets.reason, items=[])
            return targets
        record["items"] = [{"variable": t.variable, "item_id": t.item_id, "field": t.field} for t in targets]
        if not self._take_turn(client):
            self._log("agent.request", "denied")
            self._record_run(record, "refused", result="rate_limited")
            return Refusal("rate_limited")
        try:
            request = AgentRequest("run", record["agent"], record["process"], "", record["purpose"],
                                   hello=self._hello(), command=record["command"], cwd=cwd,
                                   secrets=tuple((t.variable, clean_text(t.title, 120) or t.item_id, t.field)
                                                 for t in targets), timeout=int(timeout))
            grant = RunGrant(secrets.token_urlsafe(18), run_id, client.client_id, 0.0, tuple(targets), record)
            if not self._approved(request):
                for item_id in grant.item_ids:
                    self._log("agent.request", "denied", item_id)
                self._record_run(record, "denied")
                return Refusal("denied")
            grant.expires = self._clock() + RUN_TTL
            with self._lock:
                now = self._clock()
                for key in [k for k, g in self._runs.items() if g.expires <= now and (g.finished or not g.used)]:
                    self._runs.pop(key, None)
                self._runs[grant.id] = grant
                while len(self._runs) > MAX_GRANTS:
                    self._runs.pop(next(iter(self._runs)))
            for item_id in grant.item_ids:
                self._log("agent.request", "ok", item_id)
            self._record_run(record, "approved")
            return grant
        finally:
            with self._lock:
                self._asking = False

    def release_run(self, client: ClientInfo, grant_id: Any) -> dict[str, str] | Refusal:
        """The values of an approved run, keyed by reference: once, to the session that asked, before it expires.
        The items are read again, so a switch turned off since the approval is ``not_found``."""
        refused = self._gate()
        if refused is not None:
            self._log("agent.read", "denied")
            return refused
        if not isinstance(grant_id, str):
            return Refusal("invalid")
        with self._lock:
            grant = self._runs.get(grant_id)
            if grant is None:
                return Refusal("expired")
            if grant.client_id != client.client_id:
                return Refusal("not_yours")
            if grant.used:
                return Refusal("used")
            if grant.expires <= self._clock():
                self._runs.pop(grant_id, None)
                return Refusal("expired")
            grant.used = True
        session = self._session()
        if session is None:
            self._log("agent.read", "locked")
            return Refusal("locked")
        settings = self._settings()
        values: dict[str, str] = {}
        hidden = _hidden_ids(session)  # travel mode turned on after the approval: the item no longer exists
        for target in grant.targets:
            item = session.item(target.item_id)                 if agent_item_allowed(settings, target.item_id) and str(target.item_id) not in hidden else None
            try:
                value = secret_value(item, target.field) \
                    if isinstance(item, dict) and item.get("kind") in AGENT_SECRET_KINDS else None
            finally:
                _wipe(item)
            if value is None:
                values.clear()
                self._log("agent.read", "not_found")
                self._record_run(grant.record, "refused", result="not_found")
                return Refusal("not_found")
            values[target.ref] = value
        for item_id in grant.item_ids:
            self._log("agent.read", "ok", item_id)
        self._record_run(grant.record, "released")
        return values

    def finish_run(self, client: ClientInfo, run_id: Any, *, exit_code: Any, timed_out: Any, started: Any) -> None:
        """The ``lgk mcp`` process reports how the released run ended; logged once per run."""
        with self._lock:
            grant = next((g for g in self._runs.values() if g.run_id == run_id and g.client_id == client.client_id
                          and g.used and not g.finished), None)
            if grant is None:
                return
            grant.finished = True
        code = exit_code if type(exit_code) is int and -2**31 <= exit_code < 2**32 else None
        if timed_out is True:
            result = "cancelled"
        elif started is True and code == 0:
            result = "ok"
        else:
            result = "failed"
        for item_id in grant.item_ids:
            self._log("agent.complete", result, item_id)
        self._record_run(grant.record, "finished", result=result, exit_code=code, timed_out=timed_out is True,
                         started=started is True)

    # ------------------------------------------------------------------ grants
    def _expire(self) -> None:
        now = self._clock()
        for key in [k for k, g in self._grants.items() if g.expires <= now]:
            self._grants.pop(key, None)

    def _owned(self, client: ClientInfo, grant_id: Any) -> Grant | Refusal:
        if not isinstance(grant_id, str):
            return Refusal("invalid")
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                return Refusal("expired")
            if grant.client_id != client.client_id:
                return Refusal("not_yours")
            if grant.expires <= self._clock():
                self._grants.pop(grant_id, None)
                return Refusal("expired")
            if grant.passkey_ids:
                return grant  # armed since approval; fill_login only waits for (or reports) its one ceremony
            if grant.used or grant.armed_until:
                return Refusal("used")
            return grant

    def fill_login(self, client: ClientInfo, grant_id: str, tab_hint: str = "") -> dict[str, Any] | Refusal:
        """Arm the grant for the browser extension and wait until the sign-in page takes it.

        The extension asks (``fill_grant_browser``) only when the user clicks the LocalGateKeys icon in a sign-in
        field on an approved host; the user then picks the login in the picker. The reply says only whether the page
        took the grant, but the page itself receives the password once the user picks it.

        A passkey grant fills nothing: it waits for the site's passkey sign-in (``take_passkey_for_origin``), which
        the owner confirms in the passkey dialog, and reports whether it went through.
        """
        refused = self._gate()
        if refused is not None:
            self._log("agent.fill", "denied")
            return refused
        grant = self._owned(client, grant_id)
        if isinstance(grant, Refusal):
            self._log("agent.fill", "denied")
            return grant
        if grant.passkey_ids:
            if not grant.done.wait(self._fill_wait):
                self._log("agent.fill", "skipped")
                return Refusal("no_passkey")
            signed = grant.outcome == "passkey"
            self._log("agent.fill", "ok" if signed else "open")
            return {"filled": signed, "site": grant.domain, "method": "passkey",
                    **({} if signed else {"note": "The passkey sign-in did not complete. Ask again with "
                                                  "request_login."})}
        with self._lock:
            grant.armed_until = min(grant.expires, self._clock() + ARM_TTL)
        if not grant.done.wait(self._fill_wait):
            with self._lock:
                if not grant.used:
                    grant.armed_until = 0.0  # unarmed again: the agent may retry with the same grant
            if not grant.used:
                self._log("agent.fill", "skipped")
                return Refusal("no_tab")
        self._log("agent.fill", "ok" if grant.outcome == "filled" else "open")
        return {"filled": grant.outcome == "filled", "site": grant.domain, "method": "password",
                **({} if grant.outcome == "filled" else {"note": "The user picks the login on the page."})}

    def _page(self, origin: str) -> tuple[str, str | None] | None:
        """(registrable domain, exact host) of an https page, or None when agents are off, Pro ended or the origin
        does not qualify."""
        if self._gate() is not None:
            return None
        domain = origin_domain(origin)
        if domain is None:
            return None
        return domain, site_host(canonicalize_origin(origin))

    def _armed_for(self, page: tuple[str, str | None], *, passkey: bool) -> list[Grant]:
        """Armed, unused, unexpired grants of one kind whose approved hosts include this page's exact host.
        The caller holds the lock."""
        domain, host = page
        now = self._clock()
        return [grant for grant in self._grants.values()
                if grant.domain == domain and host in grant.hosts and not grant.used and grant.armed_until > now
                and grant.expires > now and bool(grant.passkey_ids) is passkey]

    def take_for_origin(self, origin: str) -> Grant | None:
        """The broker's side: the armed password grant whose approved hosts include this page's exact host, marked
        used. A passkey grant is never handed out here: its password is not filled.

        Nothing is handed out when agent access was turned off, or Pro ended, after the grant was approved.
        """
        page = self._page(origin)
        if page is None:
            return None
        with self._lock:
            for grant in self._armed_for(page, passkey=False):
                grant.used = True
                return grant
        return None

    def passkey_pending(self, origin: str) -> bool:
        """Whether a passkey grant waits for this page's passkey sign-in (the icon then says to use it)."""
        page = self._page(origin)
        if page is None:
            return False
        with self._lock:
            return bool(self._armed_for(page, passkey=True))

    def take_passkey_for_origin(self, origin: str, credential_ids: Iterable[str]) -> Grant | None:
        """The passkey broker's side: the passkey grant for this page whose passkeys include one of the offered
        credentials, marked used (one assertion). The broker then offers only the grant's passkeys, and the owner's
        passkey dialog and user verification run as for any passkey sign-in."""
        page = self._page(origin)
        if page is None:
            return None
        offered = frozenset(str(value) for value in credential_ids)
        with self._lock:
            for grant in self._armed_for(page, passkey=True):
                if grant.passkey_ids & offered:
                    grant.used = True
                    return grant
        return None

    def password_filled(self, grant: Grant, item_id: str) -> None:
        """The page received the password of the login the user picked for this agent grant: the activity log
        gets ``agent.fill`` / ``ok`` with that login's id and the run log a ``filled`` row with the agent's name
        (``agent_exposure`` reads both). Never a value; a passkey grant never gets here."""
        if grant.passkey_ids or not isinstance(item_id, str) or not item_id:
            return
        self._log("agent.fill", "ok", item_id)
        self._record_run({"agent": grant.agent, "items": [{"item_id": item_id}]}, "filled")

    @staticmethod
    def finish(grant: Grant, outcome: str) -> None:
        """``filled`` (one login, filled at once), ``picker`` (the user chooses on the page), ``passkey`` (the page
        received a passkey assertion) or ``none`` (nothing was offered or signed)."""
        grant.outcome = outcome
        grant.done.set()


def _valid_run(run_id: Any, env: Any, command: Any, cwd: Any, timeout: Any) -> bool:
    """Bounds and shapes of a run request. Everything shown in the approval must be shown exactly, so control,
    bidi and zero-width characters are refused rather than cleaned."""
    if not _plain(run_id, MAX_RUN_ID) or not _plain(cwd, MAX_CWD):
        return False
    if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT:
        return False
    if not isinstance(command, list) or not 1 <= len(command) <= MAX_ARGV:
        return False
    if not _plain(command[0], MAX_ARG) or not all(_plain(arg, MAX_ARG, empty=True) for arg in command[1:]):
        return False
    if len(command_line(command)) > MAX_COMMAND_LINE or unsafe_batch_command(command):
        return False
    if not isinstance(env, dict) or not 1 <= len(env) <= MAX_RUN_REFS:
        return False
    names: set[str] = set()
    for name, ref in env.items():
        if not isinstance(name, str) or not _ENV_NAME.match(name) or name.upper() in RESERVED_ENV:
            return False
        if name.upper() in names:  # Windows names ignore case: two would collide in the child's environment
            return False
        names.add(name.upper())
        if not _plain(ref, MAX_REF) or not ref.startswith(REF_PREFIX):
            return False
    return True


def _wipe(item: Any) -> None:
    """Drop our references to an item's values once read (Python cannot overwrite the strings themselves)."""
    if isinstance(item, dict):
        payload = item.get("payload")
        if isinstance(payload, dict):
            payload.clear()
        item.clear()


def _licence_is_pro() -> bool:
    try:
        from .licensing import Feature, is_pro

        return bool(is_pro(Feature.UNLIMITED_ITEMS))
    except Exception:  # noqa: BLE001 - fails closed
        return False
