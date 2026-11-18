"""Settings > Developer: the SSH agent switch, the vault's SSH keys, and the SSH_AUTH_SOCK / Git signing setup.

Every setup action is opt-in and reversible: the values it replaces go into ``developer_saved_env`` /
``developer_saved_git`` (this device only) and Undo puts them back, unless the user changed them again meanwhile.
The key list never runs the passphrase KDF: a key is judged from its stored format and public half, and only an
unencrypted-looking key without a stored passphrase is parsed (which stops before any KDF for an encrypted one).
"""
from __future__ import annotations

import logging
import threading
from urllib.parse import quote
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from .. import dev_setup, distribution, lgk_refs
from ..access_policy import enforced_policy
from ..api.result import ApiError
from ..i18n import t
from ..item_schema import ItemSchemaError
from ..ssh_keys import SshKeyError, _openssh_container, generate_ed25519, load_private_key
from ..vault import ItemLimitReached, VaultError
from .setting_links import clipboard_result

_log = logging.getLogger(__name__)
ENV_NAME = "SSH_AUTH_SOCK"
GIT_SSH = "C:/Windows/System32/OpenSSH/ssh.exe"
GIT_KEYGEN = "C:/Windows/System32/OpenSSH/ssh-keygen.exe"
GIT_KEYS = ("core.sshCommand", "gpg.format", "gpg.ssh.program", "user.signingkey", "commit.gpgsign")
SUPPORTED_TYPES = frozenset({"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ssh-rsa"})
_INTENT = "developer settings check whether an SSH key needs a passphrase"
MAX_SAVED = 16 * 1024
SIGNING_MIN_GIT = (2, 34)  # SSH commit signing
SECRET_FIELD_ORDER = ("password", "passphrase", "secret", "token", "api_key", "license")
REFUSED_FIELDS = frozenset({("passkey", "private_key")})


def default_pipe() -> str:
    from ..ssh_agent import default_pipe_name

    return default_pipe_name()


def _start_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="developer-agent", daemon=True).start()


def _public_type(line: Any) -> str:
    fields = line.split() if isinstance(line, str) else []
    return fields[0] if fields else ""


class DeveloperService:
    def __init__(self, controller: Any, port: Any, *, pipe: Callable[[], str] = default_pipe,
                 spawn: Callable[[Callable[[], None]], None] = _start_thread) -> None:
        self._controller = controller
        self._port = port
        self._pipe = pipe
        self._spawn = spawn
        # The web host (agent start/stop and status); set by the desktop wiring, absent in tests and tools.
        self.apply_agent: Callable[[], str] | None = None
        self.agent_status: Callable[[], str] | None = None

    # ------------------------------------------------------------ helpers
    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        return self._controller.session

    def _update(self, **changes: Any) -> None:
        controller = self._controller
        candidate = replace(controller.settings, **changes)
        try:
            candidate.save()
        except OSError:
            raise ApiError("invalid", t("settings.error.notSaved")) from None
        controller.settings = candidate

    def _ssh_item(self, session: Any, item_id: str) -> dict[str, Any]:
        item = session.item_service.get_item(item_id)
        if not item or item.get("kind") != "ssh_key":
            raise ApiError("not_found", t("typed.err.itemGone"))
        return item

    def _classify(self, session: Any, item: dict[str, Any]) -> tuple[str, str]:
        """("ok" | "needs_passphrase" | "unsupported", reason code); see the module note on the KDF."""
        payload = item.get("payload") or {}
        public = str(payload.get("public_key") or "")
        fmt = str(payload.get("key_format") or "")
        has_private = bool(payload.get("private_key_present"))
        has_passphrase = bool(payload.get("passphrase_present"))
        if fmt in ("putty", "ssh2"):
            return "unsupported", fmt
        if fmt == "pem-dsa":
            return "unsupported", "dsa"
        if public.strip():
            kind = _public_type(public)
            if kind.startswith("sk-"):
                return "unsupported", "sk"
            if kind not in SUPPORTED_TYPES:
                return "unsupported", "type"
        if not has_private:
            return "unsupported", "no_private"
        if public.strip() and has_passphrase:
            return "ok", ""  # a stored passphrase is not tried here: that would run the KDF
        try:
            text = session.item_service.reveal_secret(str(item["id"]), "private_key", intent=_INTENT)
            if fmt == "openssh":
                container_type, _encrypted = _openssh_container(text)
                if container_type.startswith("sk-"):
                    return "unsupported", "sk"
                if container_type not in SUPPORTED_TYPES:
                    return "unsupported", "type"
            if has_passphrase:
                return "unsupported", "unreadable"
            load_private_key(text, None)  # an encrypted key stops at needs_passphrase before any KDF
        except SshKeyError as exc:
            if exc.code == "needs_passphrase":
                return "needs_passphrase", ""
            return "unsupported", "format"
        except (ItemSchemaError, VaultError):
            return "unsupported", "unreadable"
        return "ok", ""

    def _key_rows(self, session: Any) -> list[dict[str, Any]]:
        offered = set(self._controller.settings.developer_ssh_keys)
        rows = []
        for item in session.item_service.list_items(kinds=["ssh_key"]):
            state, reason = self._classify(session, item)
            payload = item.get("payload") or {}
            rows.append({"id": item["id"], "title": str(item.get("title") or ""),
                         "fingerprint": str(payload.get("fingerprint") or ""),
                         "state": state, "reason": t(f"developer.reason.{reason}") if reason else "",
                         "offered": item["id"] in offered and state == "ok"})
        rows.sort(key=lambda row: (row["title"].casefold(), row["id"]))
        return rows

    def _env_state(self) -> dict[str, Any]:
        saved = self._controller.settings.developer_saved_env.get(ENV_NAME)
        try:
            current = dev_setup.get_user_env(ENV_NAME)
        except dev_setup.DevSetupError:
            current = None
        return {"name": ENV_NAME, "current": current or "", "pipe": self._pipe(), "applied": isinstance(saved, dict)}

    def _git_state(self) -> dict[str, Any]:
        version = dev_setup.git_version()
        return {"available": version is not None or dev_setup.git_available(),
                "signing_ok": version is None or version >= SIGNING_MIN_GIT,
                "version": ".".join(str(part) for part in version) if version else "",
                "applied": bool(self._controller.settings.developer_saved_git)}

    # ------------------------------------------------------------ status
    def status(self) -> dict[str, Any]:
        session = self._session()
        enabled = bool(self._controller.settings.developer_ssh_agent)
        status = self.agent_status() if self.agent_status is not None else ("off" if not enabled else "stopped")
        return {"agent": {"enabled": enabled, "status": status},
                "keys": self._key_rows(session),
                "env": self._env_state(),
                "git": self._git_state(),
                "cli": self._cli_state(session),
                "agents": {**self._agents_state(), "runs": self._agent_runs(session)}}

    # ------------------------------------------------------------ AI agents (lgk mcp, agent_gate)
    def _agents_state(self) -> dict[str, Any]:
        from ..agent_gate import _licence_is_pro

        settings = self._controller.settings
        return {"enabled": getattr(settings, "agents_enabled", False) is True,
                "hello": getattr(settings, "require_hello_for_agents", False) is True,
                "pro": _licence_is_pro(),
                # The Microsoft Store package runs the MCP server as `LocalGateKeysNativeHost.exe mcp`.
                "available": True, "packaged": distribution.is_packaged()}

    def set_agents(self, key: str, enabled: bool) -> dict[str, Any]:
        """``enabled`` (Allow AI agents) or ``hello`` (Require Windows Hello for each approval)."""
        self._session()
        if key == "enabled":
            from ..agent_gate import _licence_is_pro

            if enabled and not _licence_is_pro():
                raise ApiError("pro", t("agents.settings.proOnly"))
            self._update(agents_enabled=bool(enabled))
        elif key == "hello":
            self._update(require_hello_for_agents=bool(enabled))
        else:
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return self._agents_state()

    def _agent_runs(self, session: Any, limit: int = 10) -> list[dict[str, Any]]:
        """The newest ``run_with_secrets`` runs, one row each (its last stage), from the encrypted run log.
        Item titles come from the vault as it is now; the log keeps ids and field names only, never a value."""
        from ..agent_run_log import AgentRunLog, run_log_path

        titles = {str(item.get("id", "")): str(item.get("title") or "") for item in session.item_service.list_items()}
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for record in AgentRunLog(lambda: run_log_path(self._controller)).recent(200):
            if record.get("stage") == "filled":
                continue  # a password fill, not a run (kept for "Exposed to an AI agent")
            run = record.get("run") or f"#{len(rows)}-{record.get('at')}"
            if run in seen:
                continue
            seen.add(run)
            rows.append({key: record[key] for key in ("at", "stage", "agent", "process", "command", "cwd", "purpose",
                                                     "result", "exit_code", "timed_out", "started") if key in record}
                        | {"items": [{"variable": row["variable"], "field": row["field"],
                                      "title": titles.get(row["item_id"], "")} for row in record.get("items", [])]})
            if len(rows) >= limit:
                break
        return rows

    def agent_item(self, item_id: str) -> dict[str, Any]:
        """Whether a typed item can be offered to AI agents (its kind holds secrets) and whether it is."""
        from ..agent_gate import AGENT_SECRET_KINDS, agent_item_allowed

        session = self._session()
        item = session.item_service.get_item(item_id)
        available = bool(item) and item.get("kind") in AGENT_SECRET_KINDS
        return {"available": available,
                "allowed": available and agent_item_allowed(self._controller.settings, item_id)}

    def set_agent_item(self, item_id: str, on: bool) -> dict[str, Any]:
        """The per-item "AI agents may use this item" switch (``settings.agent_items``, this device only)."""
        from ..settings import MAX_ID_LIST

        ids = [i for i in self._controller.settings.agent_items if i != item_id]
        if on:
            if not self.agent_item(item_id)["available"]:
                raise ApiError("not_found", t("typed.err.itemGone"))
            ids = ids[: MAX_ID_LIST - 1] + [item_id]
        else:
            self._session()
        self._update(agent_items=ids)
        return {"allowed": bool(on)}

    # ------------------------------------------------------------ agent and keys
    def set_agent(self, enabled: bool) -> dict[str, Any]:
        """Save the switch and start/stop the pipe in the background (stopping can take a couple of seconds)."""
        self._session()
        self._update(developer_ssh_agent=bool(enabled))
        apply = self.apply_agent
        bus = self._controller._bus

        def work() -> None:
            try:
                if apply is not None:
                    apply()
            finally:
                bus.emit("developer.changed", {})

        self._spawn(work)
        return {"enabled": bool(enabled), "message": t("developer.agent.applying")}

    def toggle_key(self, item_id: str, on: bool) -> dict[str, Any]:
        session = self._session()
        item = self._ssh_item(session, item_id)
        ids = [i for i in self._controller.settings.developer_ssh_keys if i != item_id]
        if on:
            state, reason = self._classify(session, item)
            if state == "needs_passphrase":
                raise ApiError("invalid", t("developer.err.needsPassphrase"))
            if state != "ok":
                raise ApiError("invalid", t("developer.err.unsupported", reason=t(f"developer.reason.{reason}")))
            ids.append(item_id)
        self._update(developer_ssh_keys=ids)
        return {"offered": bool(on)}

    def generate_key(self, title: str = "") -> dict[str, Any]:
        """A new Ed25519 key item, offered to the agent at once (the user just asked for it here)."""
        session = self._session()
        name = " ".join(str(title or "").split())[:64] or t("developer.defaultKeyTitle")
        private, public = generate_ed25519("".join(ch for ch in name if ch.isprintable()))
        try:
            item_id = session.item_service.create_ssh_key(name, private_key=private, public_key=public)
        except ItemLimitReached as exc:
            self._port.show_upgrade(limit=exc.limit, message=str(exc), on_enter=lambda: None)
            raise ApiError("item_limit", str(exc)) from None
        except (ItemSchemaError, ValueError, VaultError) as exc:
            raise ApiError("invalid", str(exc)) from None
        ids = [i for i in self._controller.settings.developer_ssh_keys if i != item_id] + [item_id]
        self._update(developer_ssh_keys=ids)
        self._controller._bus.emit("items.changed", {})
        return {"id": item_id, "public_key": public, "message": t("developer.generated")}

    def copy_public_key(self, item_id: str) -> dict[str, Any]:
        item = self._ssh_item(self._session(), item_id)
        public = str((item.get("payload") or {}).get("public_key") or "").strip()
        if not public:
            raise ApiError("invalid", t("developer.err.noPublicKey"))
        self._controller.clipboard.copy(public)
        self._controller.touch()
        return clipboard_result(t("developer.publicKeyCopied"), self._controller.clipboard)

    # ------------------------------------------------------------ SSH_AUTH_SOCK
    def env_apply(self) -> dict[str, Any]:
        self._session()
        pipe = self._pipe()
        settings = self._controller.settings
        saved = dict(settings.developer_saved_env)
        try:
            previous = dev_setup.get_user_env(ENV_NAME)
            if not isinstance(saved.get(ENV_NAME), dict):  # keep the first previous value on a second Apply
                saved[ENV_NAME] = {"previous": previous, "applied": pipe}
            else:
                saved[ENV_NAME] = {**saved[ENV_NAME], "applied": pipe}
            dev_setup.set_user_env(ENV_NAME, pipe)
        except dev_setup.DevSetupError:
            raise ApiError("invalid", t("developer.err.envFailed")) from None
        self._update(developer_saved_env=saved)  # only after the registry accepted it
        return {"message": t("developer.env.applied")}

    def agent_pipe_status(self, status: str) -> None:
        """The agent's pipe status changed. "taken" (another account's process holds the name): remove the
        SSH_AUTH_SOCK this app set, so ssh and git stop talking to that process. "running": put it back."""
        saved = dict(self._controller.settings.developer_saved_env)
        entry = saved.get(ENV_NAME)
        if not isinstance(entry, dict) or not isinstance(entry.get("applied"), str):
            return
        try:
            current = dev_setup.get_user_env(ENV_NAME)
            if status == "taken" and not entry.get("suspended"):
                if current != entry["applied"]:
                    return  # changed by the user since: not ours to remove
                dev_setup.restore_user_env(ENV_NAME, None)
                saved[ENV_NAME] = {**entry, "suspended": True}
            elif status == "running" and entry.get("suspended"):
                if current is None:
                    dev_setup.set_user_env(ENV_NAME, entry["applied"])
                saved[ENV_NAME] = {k: v for k, v in entry.items() if k != "suspended"}
            else:
                return
            self._update(developer_saved_env=saved)
        except (dev_setup.DevSetupError, ApiError):
            _log.warning("SSH_AUTH_SOCK could not be updated for the agent pipe status")

    def env_undo(self) -> dict[str, Any]:
        self._session()
        saved = dict(self._controller.settings.developer_saved_env)
        entry = saved.get(ENV_NAME)
        if not isinstance(entry, dict):
            raise ApiError("invalid", t("developer.err.nothingToUndo"))
        try:
            current = dev_setup.get_user_env(ENV_NAME)
            # Removed while another account held the pipe name: still ours to put back.
            kept = current != entry.get("applied") and not (entry.get("suspended") and current is None)
            if not kept:
                dev_setup.restore_user_env(ENV_NAME, entry.get("previous"))
        except dev_setup.DevSetupError:
            raise ApiError("invalid", t("developer.err.envFailed")) from None
        saved.pop(ENV_NAME, None)
        self._update(developer_saved_env=saved)
        return {"message": t("developer.env.changedSince") if kept else t("developer.env.undone")}

    # ------------------------------------------------------------ Git
    def git_plan(self, item_id: str) -> list[tuple[str, str | None, str]]:
        """(key, current value, new value) for the five Git settings that sign commits with this key."""
        session = self._session()
        item = self._ssh_item(session, item_id)
        state, reason = self._classify(session, item)
        public = " ".join(str((item.get("payload") or {}).get("public_key") or "").split()[:2])
        if state != "ok" or not public:
            raise ApiError("invalid", t("developer.err.unsupported", reason=t(f"developer.reason.{reason or 'unreadable'}")))
        if item_id not in self._controller.settings.developer_ssh_keys:
            raise ApiError("invalid", t("developer.err.notOffered"))
        version = dev_setup.git_version()
        if version is None:
            raise ApiError("invalid", t("developer.err.gitMissing"))
        if version < SIGNING_MIN_GIT:
            raise ApiError("invalid", t("developer.err.gitOld", version=".".join(str(part) for part in version)))
        new = {"core.sshCommand": GIT_SSH, "gpg.format": "ssh", "gpg.ssh.program": GIT_KEYGEN,
               "user.signingkey": f"key::{public}", "commit.gpgsign": "true"}
        return [(key, dev_setup.git_config_get(key), new[key]) for key in GIT_KEYS]

    def git_preview(self, item_id: str) -> dict[str, Any]:
        return {"rows": [{"key": key, "current": current, "new": new}
                         for key, current, new in self.git_plan(item_id)]}

    def git_apply(self, item_id: str) -> dict[str, Any]:
        plan = self.git_plan(item_id)
        settings = self._controller.settings
        saved = dict(settings.developer_saved_git)
        for key, current, new in plan:
            earlier = saved.get(key)
            saved[key] = {"previous": earlier["previous"] if isinstance(earlier, dict) else current, "applied": new}
        self._update(developer_saved_git=saved)
        try:
            for key, _current, new in plan:
                dev_setup.git_config_set(key, new)
        except dev_setup.DevSetupError:
            try:
                self._git_restore()  # put back what was already changed
            except dev_setup.DevSetupError:
                pass
            raise ApiError("invalid", t("developer.err.gitFailed")) from None
        return {"message": t("developer.git.applied")}

    def _git_restore(self) -> int:
        """Restore every saved key whose value is still the one we set; returns how many were left alone."""
        saved = dict(self._controller.settings.developer_saved_git)
        kept = 0
        for key, entry in saved.items():
            if not isinstance(entry, dict):
                continue
            if dev_setup.git_config_get(key) == entry.get("applied"):
                dev_setup.git_config_set(key, entry.get("previous"))
            else:
                kept += 1
        self._update(developer_saved_git={})
        return kept

    def git_undo(self) -> dict[str, Any]:
        self._session()
        if not self._controller.settings.developer_saved_git:
            raise ApiError("invalid", t("developer.err.nothingToUndo"))
        if not dev_setup.git_available():
            raise ApiError("invalid", t("developer.err.gitMissing"))
        try:
            kept = self._git_restore()
        except dev_setup.DevSetupError:
            raise ApiError("invalid", t("developer.err.gitFailed")) from None
        return {"message": t("developer.git.changedSince") if kept else t("developer.git.undone")}

    # ------------------------------------------------------------ command line access (lgk.exe)
    @staticmethod
    def _strict_login(session: Any, item_id: str) -> bool:
        entry = session.get_entry(item_id)
        return bool(entry and enforced_policy(entry).get("require_master_password"))

    def _cli_rows(self, session: Any) -> list[dict[str, Any]]:
        listed = set(self._controller.settings.developer_cli_items)
        rows = [{"id": s.id, "title": s.label, "kind": s.kind, "listed": s.id in listed,
                 "strict": self._strict_login(session, s.id)} for s in session.summaries()]
        for item in session.item_service.list_items():
            item_id = str(item.get("id", ""))
            rows.append({"id": item_id, "title": str(item.get("title") or ""), "kind": str(item.get("kind") or ""),
                         "listed": item_id in listed, "strict": False})
        rows.sort(key=lambda row: (row["title"].casefold(), row["id"]))
        return rows

    def _cli_state(self, session: Any) -> dict[str, Any]:
        # The Microsoft Store package may declare one alias (the browser bridge's), so there lgk runs as
        # `LocalGateKeysNativeHost.exe lgk ...`; "packaged" lets the page show that command.
        return {"enabled": self._controller.settings.developer_cli is True, "available": True,
                "packaged": distribution.is_packaged(), "items": self._cli_rows(session)}

    def cli_enabled(self) -> dict[str, Any]:
        return {"enabled": self._controller.settings.developer_cli is True}

    def set_cli(self, enabled: bool) -> dict[str, Any]:
        self._session()
        self._update(developer_cli=bool(enabled))
        return {"enabled": bool(enabled)}

    def toggle_cli_item(self, item_id: str, on: bool) -> dict[str, Any]:
        session = self._session()
        ids = [i for i in self._controller.settings.developer_cli_items if i != item_id]
        if on:
            row = next((r for r in self._cli_rows(session) if r["id"] == item_id), None)
            if row is None:
                raise ApiError("not_found", t("typed.err.itemGone"))
            if row["strict"]:
                raise ApiError("invalid", t("developer.cli.strictReason"))
            ids.append(item_id)
        self._update(developer_cli_items=ids)
        return {"listed": bool(on)}

    @staticmethod
    def _reference_field(session: Any, item_id: str, field: str) -> str:
        """The caller's field, else a login's password or a typed item's first secret-looking field."""
        field = " ".join(str(field or "").split())
        if field:
            return field
        if session.get_entry(item_id):
            return "password"
        item = session.item_service.get_item(item_id) or {}
        names = [key.removesuffix("_present") for key in (item.get("payload") or {})]
        names = [n for n in names if (item.get("kind"), n) not in REFUSED_FIELDS and n != "fields"]
        for preferred in SECRET_FIELD_ORDER:
            if preferred in names:
                return preferred
        if names:
            return names[0]
        raise ApiError("invalid", t("developer.cli.noField"))

    def copy_reference(self, item_id: str, field: str = "") -> dict[str, Any]:
        """Copy ``lgk://<id>/<field>`` as text (never a secret). The id is stable; a title breaks on rename."""
        session = self._session()
        if not session.get_entry(item_id) and not session.item_service.get_item(item_id):
            raise ApiError("not_found", t("typed.err.itemGone"))
        name = self._reference_field(session, item_id, field)
        reference = f"{lgk_refs.PREFIX}{quote(item_id, safe='')}/{quote(name, safe='')}"
        try:
            lgk_refs.parse(reference)
        except lgk_refs.RefError:
            raise ApiError("invalid", t("developer.cli.noField")) from None
        self._controller.clipboard.copy(reference)
        self._controller.touch()
        return clipboard_result(t("developer.cli.referenceCopied"), self._controller.clipboard)
