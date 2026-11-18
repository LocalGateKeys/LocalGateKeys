"""What the ``lgk`` command line tool may do over the app pipe (requests in the ``cli`` scope).

Off by default ("Command line access" in Settings › Developer, this device only). It serves only the items in
``settings.developer_cli_items`` and never a login that asks for the master password every time. A locked vault
opens the compact unlock first. Every value leaves only after the user approved it in the popup (one prompt per
request, however many references ``lgk run``/``inject`` asked for; each approval is remembered on its own for ten
minutes). The whole request has one deadline, so ``lgk`` never hangs on a prompt nobody answers. Nothing here logs
values, references or item titles; error messages name ids and titles only.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from .access_policy import enforced_policy
from .lgk_refs import MAX_REFERENCE, PREFIX, Ref, RefError, RefItem, find, parse, resolve
from .local_clients import ApprovalRequest, ClientIdentity
from .totp import generate_totp

_log = logging.getLogger(__name__)
REQUEST_DEADLINE = 95.0
VAULT_LOCK_TIMEOUT = 5.0
MAX_REFS = 100
LOGIN_KINDS = frozenset({"web", "desktop"})
# Protected fields with no command line use (item_schema PROTECTED_FIELDS_BY_KIND): a passkey's private key only
# signs WebAuthn challenges inside the app. Card, bank, API key, SSH key and Wi-Fi fields stay readable.
CLI_REFUSED_FIELDS = frozenset({("passkey", "private_key")})
AGENT_ACTIONS = frozenset({"agent_list_sites", "agent_request_login", "agent_fill_login",
                           "agent_list_secrets", "agent_run_secrets", "agent_run_finished"})


def _ok(**values: Any) -> dict[str, Any]:
    return {"ok": True, **values}


def _error(code: str, message: str = "") -> dict[str, Any]:
    return {"ok": False, "error": code, "message": message or code}


def _login_totp(entry: dict[str, Any], now: int) -> tuple[str, int] | None:
    totp = entry.get("totp")
    if not isinstance(totp, dict) or not totp.get("secret"):
        return None
    return generate_totp(str(totp["secret"]), timestamp=now, digits=int(totp.get("digits", 6)),
                         period=int(totp.get("period", 30)), algorithm=str(totp.get("algorithm", "SHA1")))


def _login_url(entry: dict[str, Any]) -> str | None:
    scope = entry.get("scope") if isinstance(entry.get("scope"), dict) else {}
    origin = scope.get("origin")
    if isinstance(origin, str) and origin:
        return origin
    urls = scope.get("urls")
    if isinstance(urls, list) and urls and isinstance(urls[0], dict) and isinstance(urls[0].get("url"), str):
        return urls[0]["url"]
    return None


class CliService:
    def __init__(self, host: Any, *, deadline: float = REQUEST_DEADLINE,
                 clock: Callable[[], float] = time.monotonic, now: Callable[[], float] = time.time) -> None:
        self._host = host
        self._deadline = float(deadline)
        self._clock = clock
        self._now = now

    # ---------------------------------------------------------------- settings
    def _enabled(self) -> bool:
        return getattr(self._host.settings, "developer_cli", False) is True

    def _allowed_ids(self) -> set[str]:
        ids = getattr(self._host.settings, "developer_cli_items", None)
        return {value for value in ids if isinstance(value, str)} if isinstance(ids, list) else set()

    # ---------------------------------------------------------------- vault rows (call with the vault lock)
    def _rows(self) -> list[RefItem]:
        session = self._host.session
        if session is None:
            raise RefError("locked", "The vault is locked.")
        from .access_policy import has_rule, local_today
        from .travel import hidden_id_set

        hidden = hidden_id_set(session)
        allowed_ids = self._allowed_ids() - hidden
        today = local_today()
        rows: list[RefItem] = []
        for summary in session.summaries():
            if summary.id in hidden:
                continue
            allowed, read = False, (lambda _field: None)
            listed = summary.id in allowed_ids
            if listed:
                entry = session.get_entry(summary.id)
                if entry and not enforced_policy(entry, today).get("require_master_password")                         and not has_rule(entry, today):
                    allowed, read = True, self._login_reader(entry)
            rows.append(RefItem(summary.id, summary.label, summary.kind, allowed, read, listed=listed))
        items = session.item_service
        for item in items.list_items():
            item_id = str(item.get("id", ""))
            if item_id in hidden:
                continue
            allowed, read = False, (lambda _field: None)
            if item_id in allowed_ids:
                full = items.get_item(item_id, include_protected=True)
                if full:
                    allowed, read = True, self._item_reader(full)
            rows.append(RefItem(item_id, str(item.get("title") or ""), str(item.get("kind") or ""), allowed, read,
                                listed=item_id in allowed_ids))
        return rows

    def _login_reader(self, entry: dict[str, Any]) -> Callable[[str], str | None]:
        def read(field: str) -> str | None:
            if field in ("username", "password", "notes"):
                value = entry.get(field, "")
                return value if isinstance(value, str) else None
            if field == "url":
                return _login_url(entry)
            if field == "totp":
                code = _login_totp(entry, int(self._now()))
                return code[0] if code else None
            return None
        return read

    @staticmethod
    def _item_reader(item: dict[str, Any]) -> Callable[[str], str | None]:
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}

        def read(field: str) -> str | None:
            if (item.get("kind"), field) in CLI_REFUSED_FIELDS:
                return None
            # A note's custom fields (name -> value, the last of a name wins) come first: the secret scan stores
            # each .env variable there, and a variable may be called "body" or "notes".
            custom = payload.get("fields")
            if item.get("kind") == "note" and isinstance(custom, list):
                for row in reversed(custom):
                    if isinstance(row, dict) and row.get("name") == field and isinstance(row.get("value"), str):
                        return row["value"]
            key = "body" if field == "notes" and "notes" not in payload and item.get("kind") == "note" else field
            value = payload.get(key)
            return value if isinstance(value, str) else None
        return read

    # ---------------------------------------------------------------- waiting
    def _with_vault(self, fn: Callable[[], Any], deadline: float) -> Any:
        return self._host.run_on_ui(fn, timeout=max(0.0, min(VAULT_LOCK_TIMEOUT, deadline - self._clock())))

    def _until(self, deadline: float, fn: Callable[[], Any]) -> bool:
        """Run a wait for the user on its own thread; False when it is not True by the deadline."""
        remaining = deadline - self._clock()
        if remaining <= 0:
            return False
        result: list[Any] = []

        def run() -> None:
            try:
                result.append(fn())
            except Exception as exc:  # noqa: BLE001 - a failed prompt or unlock is a refusal
                _log.info("CLI wait failed: %s", type(exc).__name__)
        worker = threading.Thread(target=run, name="lgk-cli-wait", daemon=True)
        worker.start()
        worker.join(remaining)
        return bool(result) and result[0] is True and self._clock() < deadline

    # ---------------------------------------------------------------- dispatch
    def dispatch_from_pid(self, request: dict[str, Any], pid: int) -> dict[str, Any]:
        """The pipe's entry point: identify the lgk.exe process (its terminal session) and dispatch."""
        from .local_clients import identify

        return self.dispatch(request, identify(pid))

    def dispatch(self, request: dict[str, Any], client: ClientIdentity) -> dict[str, Any]:
        action = request.get("action")
        try:
            if action == "status":
                return _ok(unlocked=self._host.session is not None, cli_enabled=self._enabled())
            if isinstance(action, str) and action in AGENT_ACTIONS:
                # ``lgk mcp`` (AI agents): its own switch, Pro check and per-request approval (agent_gate).
                agents = getattr(self._host, "agent_gate_service", None)
                if agents is None:
                    return _error("unknown_action", "Unknown command.")
                return agents.dispatch(request, client)
            if action not in ("list", "read", "totp", "resolve_many"):
                return _error("unknown_action", "Unknown command.")
            if not self._enabled():
                return _error("cli_disabled", "Command line access is off in Settings › Developer.")
            deadline = self._clock() + self._deadline
            if self._host.session is None and not self._until(deadline, self._host.ensure_unlocked):
                return _error("locked", "The vault is locked.")
            if action == "list":
                return self._list(request, deadline)
            return self._release(action, request, client, deadline)
        except RefError as exc:
            return _error(exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - the client gets a plain failure, never details
            _log.warning("CLI request failed: %s", type(exc).__name__)
            return _error("cli_failed", "The request failed.")

    def _list(self, request: dict[str, Any], deadline: float) -> dict[str, Any]:
        kind = request.get("kind")
        if kind is not None and not isinstance(kind, str):
            return _error("bad_request", "The kind must be text.")
        rows = self._with_vault(self._rows, deadline)
        return _ok(items=[{"id": row.id, "title": row.title, "kind": row.kind} for row in rows
                          if row.allowed and (kind is None or row.kind == kind)])

    @staticmethod
    def _references(action: str, request: dict[str, Any]) -> list[tuple[str, Ref]]:
        if action == "resolve_many":
            refs = request.get("refs")
            if not isinstance(refs, list) or not refs or len(refs) > MAX_REFS:
                raise RefError("bad_request", f"Send 1 to {MAX_REFS} references.")
            return [(ref, parse(ref)) for ref in dict.fromkeys(ref if isinstance(ref, str) else "" for ref in refs)]
        ref = request.get("ref")
        if action == "totp":
            # ``lgk totp`` takes a whole reference (its field is ignored) or a bare item id or title.
            if isinstance(ref, str) and not ref.startswith(PREFIX) and 0 < len(ref) <= MAX_REFERENCE:
                return [(ref, Ref(ref, "totp"))]
            return [(ref, Ref(parse(ref).item, "totp"))]
        return [(ref, parse(ref))]

    def _release(self, action: str, request: dict[str, Any], client: ClientIdentity,
                 deadline: float) -> dict[str, Any]:
        refs = self._references(action, request)

        def targets() -> list[RefItem]:
            rows = self._rows()
            found = [find(ref, rows) for _text, ref in refs]
            for (_text, ref), row in zip(refs, found, strict=True):  # a missing field fails before the prompt
                if action == "totp":
                    self._totp(row.id)
                else:
                    resolve(ref, rows)
            return found
        # Unknown, ambiguous, not-allowed and missing-field references fail here, before anyone is asked.
        approved = self._with_vault(targets, deadline)
        approvals = list({row.id: ApprovalRequest("cli_read", client, row.id, row.title, "")
                          for row in approved}.values())
        if not self._until(deadline, lambda: self._host.approve_local_clients(approvals)):
            _log.info("CLI read not approved")
            return _error("denied", "Not approved.")

        def values() -> dict[str, Any]:
            # Again under the vault lock: still unlocked, still the same allowed items.
            rows = self._rows()
            out: dict[str, Any] = {}
            for (text, ref), row in zip(refs, approved, strict=True):
                if find(ref, rows).id != row.id:
                    raise RefError("not_allowed", "The items changed while the prompt was open.")
                out[text] = self._totp(row.id) if action == "totp" else resolve(ref, rows)
            return out
        released = self._with_vault(values, deadline)
        if self._clock() >= deadline:
            return _error("denied", "Not approved in time.")
        if action == "resolve_many":
            return _ok(values=released)
        (value,) = released.values()
        if action == "totp":
            return _ok(code=value[0], seconds_left=value[1])
        return _ok(value=value)

    def _totp(self, item_id: str) -> tuple[str, int]:
        session = self._host.session
        entry = session.get_entry(item_id) if session is not None else None
        code = _login_totp(entry, int(self._now())) if entry else None
        if code is None:
            raise RefError("no_field", f"{item_id} has no one-time code.")
        return code
