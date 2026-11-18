"""The app side of the Local Agent Gate: wires ``AgentGate`` to the running app.

``lgk mcp`` (cli/mcp_server.py) sends ``agent_*`` requests over the ``lgk`` pipe scope; ``CliService`` hands them
here. Approvals are asked in the quick-search palette window (the popup when the palette cannot show), vault reads
run under the vault lock, and every call is written to the hash-chained activity log.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
from typing import Any

from ..agent_gate import AgentGate, AgentRequest, ClientInfo, Grant, Refusal, clean_text
from ..agent_run_log import AgentRunLog, run_log_path
from ..i18n import t

_log = logging.getLogger(__name__)
VAULT_LOCK_TIMEOUT = 5.0
APPROVAL_TIMEOUT = 120.0  # an unanswered agent approval is a no; the agent may ask again
# Told to the agent with a passkey grant (MCP result text; agent-facing replies are English, like _refused).
PASSKEY_NOTE = ("This login signs in with a passkey; the password is not filled. Open the site's sign-in page and "
                "choose its passkey sign-in (for example 'Sign in with a passkey'). The user confirms it in "
                "LocalGateKeys. Call fill_login with the grant to learn whether it went through.")


class _LockedSession:
    """Session reads the gate makes, each one under the vault lock (the pipe thread does not hold it)."""

    def __init__(self, host: Any, session: Any) -> None:
        self._host = host
        self._session = session

    def _hidden(self) -> frozenset[str]:
        from ..travel import hidden_id_set

        return hidden_id_set(self._session)

    def hidden_ids(self) -> frozenset[str]:
        """Ids travel mode hides on this device right now: they do not exist for an agent (contract 2.3)."""
        return self._host.run_on_ui(self._hidden, timeout=VAULT_LOCK_TIMEOUT)

    def summaries(self) -> list[Any]:
        def visible() -> list[Any]:
            hidden = self._hidden()
            return [s for s in self._session.summaries() if str(getattr(s, "id", "")) not in hidden]

        return self._host.run_on_ui(visible, timeout=VAULT_LOCK_TIMEOUT)

    def get_entry(self, entry_id: str) -> Any:
        def read() -> Any:
            return None if str(entry_id) in self._hidden() else self._session.get_entry(entry_id)

        return self._host.run_on_ui(read, timeout=VAULT_LOCK_TIMEOUT)

    def passkeys(self) -> list[Any]:
        """Names and credential ids of the saved passkeys (never key material; travel-hidden ones left out)."""
        return self._host.run_on_ui(lambda: list(self._session.item_service.passkey_metadata()),
                                    timeout=VAULT_LOCK_TIMEOUT)

    def items(self) -> list[Any]:
        """Typed items without their protected fields (ids, kinds and titles are what the gate reads here)."""
        def visible() -> list[Any]:
            hidden = self._hidden()
            return [i for i in self._session.item_service.list_items() if str(i.get("id")) not in hidden]

        return self._host.run_on_ui(visible, timeout=VAULT_LOCK_TIMEOUT)

    def item(self, item_id: str) -> Any:
        """One typed item with its values: the gate calls it only for items the owner allowed for agents. A
        travel-hidden item reads as missing, also when travel mode was turned on after an approval (scan 3 L1)."""
        def read() -> Any:
            if str(item_id) in self._hidden():
                return None
            return self._session.item_service.get_item(item_id, include_protected=True)

        return self._host.run_on_ui(read, timeout=VAULT_LOCK_TIMEOUT)


class AgentGateService:
    def __init__(self, host: Any) -> None:
        self._host = host
        self.runs = AgentRunLog(lambda: run_log_path(getattr(host, "_controller", None)))
        self.gate = AgentGate(self._session, lambda: host.settings, self, self._record,
                              request_unlock=self._request_unlock, run_log=self.runs.append)

    # ------------------------------------------------------------------ gate hooks
    def _session(self) -> Any:
        session = self._host.session
        return None if session is None else _LockedSession(self._host, session)

    def _record(self, event: str, result: str, item_id: str | None = None) -> None:
        session = self._host.session
        if session is None:
            return
        if item_id is None:
            self._host.run_on_ui(lambda: session.activity.record(event, result=result), timeout=VAULT_LOCK_TIMEOUT)
        else:
            self._host.run_on_ui(lambda: session.activity.record(event, result=result, item_id=item_id),
                                 timeout=VAULT_LOCK_TIMEOUT)

    def _request_unlock(self) -> None:
        threading.Thread(target=self._host.ensure_unlocked, name="lgk-agent-unlock", daemon=True).start()

    def confirm_agent(self, request: AgentRequest) -> bool:
        """Ask in the palette window; with "Require Windows Hello for agents", Hello (or the master password) too."""
        host = self._host
        port = getattr(host, "_port", None)
        approved = False
        if request.action == "list":
            # list_sites/list_secrets: shown with the "read" layout, the item being the list itself.
            request = dataclasses.replace(request, action="read", site=t("agents.approve.listItems"))
        palette_ok = port is not None and hasattr(port, "surface_view") and host.show_palette()
        if palette_ok:
            view = port.surface_view("palette")
            approved = host.released_while_waiting(lambda: view.confirm_agent(request, timeout=APPROVAL_TIMEOUT))
        else:
            # No palette window: the popup shows the same text through its plain confirm, with the same deadline.
            approved = _confirm_with_deadline(host.ui, t("agents.approve.title"), self.describe(request))
        if approved and request.hello:
            lease = host._controller.guard.lease()
            approved = host.reauthenticate(t("agents.approve.hello"), lease, allow_hello=True)
        return approved is True

    @staticmethod
    def describe(request: AgentRequest) -> str:
        if request.action == "run":
            values = "\n".join(t("agents.approve.runValue", variable=variable, item=item, field=field)
                               for variable, item, field in request.secrets)
            return t("agents.approve.run", agent=request.agent, process=request.process or "?",
                     command=request.command, cwd=request.cwd, values=values, purpose=request.purpose or "-",
                     seconds=request.timeout)
        if request.action == "sign_in":
            key = "agents.approve.signInPasskey" if request.method == "passkey" else "agents.approve.signIn"
        else:
            key = "agents.approve.read"
        return t(key, agent=request.agent, process=request.process or "?", site=request.site,
                 purpose=request.purpose or "-")

    # ------------------------------------------------------------------ pipe requests
    def dispatch(self, request: dict[str, Any], client: Any) -> dict[str, Any]:
        action = request.get("action")
        info = ClientInfo(
            client_id=f"{getattr(client, 'pid', '')}:{clean_text(request.get('session'), 64)}",
            name=clean_text(request.get("client_name"), 80),
            process=_agent_process(client),
        )
        if not request.get("session"):
            return _refused(Refusal("invalid"))
        try:
            if action == "agent_list_sites":
                result: Any = self.gate.list_sites(info, request.get("query") or "")
                return _refused(result) if isinstance(result, Refusal) else {"ok": True, "sites": result}
            if action == "agent_request_login":
                result = self.gate.request_login(info, request.get("site"), request.get("purpose") or "")
                if isinstance(result, Grant):
                    reply = {"ok": True, "grant": result.id, "site": result.domain, "expires_in": 300,
                             "method": result.method}
                    if result.method == "passkey":
                        reply["note"] = PASSKEY_NOTE
                    return reply
                return _refused(result)
            if action == "agent_fill_login":
                result = self.gate.fill_login(info, request.get("grant"), clean_text(request.get("tab_hint"), 200))
                return _refused(result) if isinstance(result, Refusal) else {"ok": True, **result}
            if action == "agent_list_secrets":
                result = self.gate.list_secrets(info, request.get("query") or "")
                return _refused(result, SECRET_MESSAGES) if isinstance(result, Refusal) else \
                    {"ok": True, "secrets": result}
            if action == "agent_run_secrets":
                return self._run(info, request)
            if action == "agent_run_finished":
                self.gate.finish_run(info, request.get("run"), exit_code=request.get("exit_code"),
                                     timed_out=request.get("timed_out"), started=request.get("started"))
                return {"ok": True}
        except Exception as exc:  # noqa: BLE001 - the agent gets a plain failure, never details
            _log.warning("Agent request failed: %s", type(exc).__name__)
            return {"ok": False, "error": "failed", "message": "The request failed."}
        return {"ok": False, "error": "unknown_action", "message": "Unknown command."}

    def _run(self, info: ClientInfo, request: dict[str, Any]) -> dict[str, Any]:
        """``run_with_secrets``: approval, then the values (keyed by reference, as ``resolve_many`` answers) in the
        same reply to the ``lgk mcp`` process that asked; it starts the command and reports the end."""
        env, refs = request.get("env"), request.get("refs")
        if not isinstance(env, dict) or not isinstance(refs, list) \
                or not all(isinstance(value, str) for value in [*refs, *env.values()]) \
                or set(refs) != set(env.values()):
            return _refused(Refusal("invalid"), SECRET_MESSAGES)
        grant = self.gate.request_run(info, request.get("run"), env, request.get("command"), request.get("cwd"),
                                      request.get("timeout"), request.get("purpose") or "")
        if isinstance(grant, Refusal):
            return _refused(grant, SECRET_MESSAGES)
        values = self.gate.release_run(info, grant.id)
        if isinstance(values, Refusal):
            return _refused(values, SECRET_MESSAGES)
        return {"ok": True, "values": values}


def _confirm_with_deadline(ui: Any, title: str, message: str) -> bool:
    """The plain confirm, ended as a refusal after ``APPROVAL_TIMEOUT`` (the web UiPort supports a deadline)."""
    ask = getattr(ui, "_ask", None)
    if not callable(ask):
        return ui.confirm(title, message) is True
    try:
        return ask({"kind": "confirm", "title": title, "message": message}, timeout=APPROVAL_TIMEOUT) is True
    except TimeoutError:
        return False


def _agent_process(client: Any) -> str:
    """The program that started ``lgk mcp`` (its parent, from Windows, not from the request), else lgk itself."""
    import os

    chain = getattr(client, "parent_chain", ()) or ()
    image = getattr(chain[0], "image", "") if chain else getattr(client, "image", "")
    return clean_text(os.path.basename(str(image or "").replace("\\", "/")), 80)


SECRET_MESSAGES = {
    "not_found": "No item the agent may use has that id or title and field. Call list_secrets to see the items and "
                 "fields the user allowed for AI agents.",
    "ambiguous": "Several items the agent may use have this title. Use the item id from list_secrets.",
    "invalid": "The request is malformed.",
    "used": "The approval was already used.",
    "expired": "The approval expired. Ask again.",
}


def _refused(refusal: Refusal, override: dict[str, str] | None = None) -> dict[str, Any]:
    if override and refusal.reason in override:
        return {"ok": False, "error": refusal.reason, "message": override[refusal.reason]}
    messages = {
        "disabled": "AI agent access is off. Turn on Settings > Developer > Allow AI agents to use LocalGateKeys.",
        "pro": "AI agent access needs LocalGateKeys Pro.",
        "locked": "LocalGateKeys is locked. The user was asked to unlock it; try again after that.",
        "not_found": "No login the agent may use is saved for that site.",
        "denied": "The user did not approve this request.",
        "invalid": "The request is malformed.",
        "insecure_site": "Only https sites can be filled (plain http is allowed only for localhost, 127.0.0.1 "
                         "and [::1]).",
        "expired": "The grant expired or does not exist. Ask again with request_login.",
        "used": "The grant was already used. Ask again with request_login.",
        "not_yours": "The grant belongs to another agent session.",
        "rate_limited": "Too many requests. Wait a minute, and ask once the user answered the open request.",
        "no_tab": "No sign-in page for the approved site took the fill. Open the sign-in page and call fill_login again.",
        "no_passkey": "The site's passkey sign-in was not used yet. Choose the passkey sign-in on the approved site's "
                      "sign-in page, then call fill_login again.",
    }
    return {"ok": False, "error": refusal.reason, "message": messages.get(refusal.reason, refusal.reason)}
