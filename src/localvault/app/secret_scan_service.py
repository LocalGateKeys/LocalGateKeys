"""Developer > "Scan for plain secrets": find SSH private keys and .env files, import them, use references.

The scan runs only when pressed, on a worker thread, reads files under the chosen folders only and reports paths,
kinds and variable counts (never a value). Findings are kept here under short ids and every later call names a
finding id, never a path from the page. Import copies into the vault and never touches the file; "Use references"
is the only call that writes a file (one ``.env``, after a preview, atomically). Nothing is ever deleted.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import lgk_refs, secret_scan
from ..api.result import ApiError
from ..i18n import t
from ..item_schema import MAX_NOTE_BODY, ItemSchemaError
from ..secret_scan import Finding
from ..settings import MAX_ID_LIST
from ..ssh_keys import SshKeyError, load_private_key
from ..vault import ItemLimitReached, VaultError

JOB = "secret_scan"
MAX_ROOTS = 8
MASK = "••••••"


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True, name="lgk-secret-scan").start()


class SecretScanService:
    def __init__(self, controller: Any, port: Any, bus: Any, *, spawn: Callable[[Callable[[], None]], None] = _thread,
                 home: Callable[[], Path] = Path.home) -> None:
        self._controller = controller
        self._port = port
        self._bus = bus
        self._spawn = spawn
        self._home = home
        self._findings: dict[str, Finding] = {}
        self._imported: dict[str, str] = {}  # finding id -> item id
        # (path, SHA-256 of the file as imported) -> item id; survives a new scan of the same files (cleared on lock)
        self._marks: dict[tuple[str, str], str] = {}
        self._running = False
        self._cancel = threading.Event()
        self._state_lock = threading.RLock()
        controller.on_lock.append(self._on_lock)

    def _on_lock(self) -> None:
        with self._state_lock:
            self._cancel.set()
            self._findings = {}
            self._imported = {}
            self._marks = {}

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        return self._controller.session

    def _finding(self, finding_id: str) -> Finding:
        with self._state_lock:
            finding = self._findings.get(finding_id)
        if finding is None:
            raise ApiError("not_found", t("secret_scan.err.gone"))
        return finding

    def _row(self, finding_id: str, finding: Finding) -> dict[str, Any]:
        return {"id": finding_id, "name": finding.path.name, "folder": str(finding.path.parent),
                "path": str(finding.path), "kind": finding.kind, "var_count": finding.var_count,
                "key_format": finding.key_format, "imported": finding_id in self._imported}

    @staticmethod
    def _mark_key(finding: Finding) -> tuple[str, str] | None:
        try:
            return str(finding.path), hashlib.sha256(finding.path.read_bytes()).hexdigest()
        except OSError:
            return None

    def _rows(self) -> list[dict[str, Any]]:
        return [self._row(fid, f) for fid, f in self._findings.items()]

    def _save_scan(self, count: int) -> None:
        controller = self._controller
        candidate = replace(controller.settings, developer_last_scan={"count": count, "at": int(time.time())})
        try:
            candidate.save()
        except OSError:
            return  # the list is still shown; only the Security check's count is not updated
        controller.settings = candidate

    # ------------------------------------------------------------------ scan
    def _roots(self, roots: Any) -> list[Path]:
        if roots is None or roots == []:
            return [self._home()]
        if not isinstance(roots, list) or len(roots) > MAX_ROOTS or not all(isinstance(r, str) and r for r in roots):
            raise ApiError("invalid", t("secret_scan.err.folders"))
        paths = [Path(r) for r in roots]
        if not all(p.is_dir() for p in paths):
            raise ApiError("invalid", t("secret_scan.err.folders"))
        return paths

    def start(self, roots: Any = None) -> dict[str, Any]:
        self._session()
        paths = self._roots(roots)
        with self._state_lock:
            if self._running:
                raise ApiError("refused", t("secret_scan.err.running"))
            self._running = True
            cancel = self._cancel = threading.Event()
        lease = self._controller.guard.lease()

        def stopped() -> bool:
            return cancel.is_set() or not self._controller.guard.valid(lease)

        def progress(seen: int) -> None:
            self._bus.emit("job.progress", {"job": JOB, "text": t("secret_scan.progress", count=seen)})

        def worker() -> None:
            try:
                found = secret_scan.scan(paths, cancel=_Stop(stopped), progress=progress)
                with self._state_lock:
                    committed = not stopped()
                    if committed:
                        self._findings = {f"f{i}": f for i, f in enumerate(found, 1)}
                        self._imported = {}
                        for fid, f in self._findings.items():
                            key = self._mark_key(f)
                            if key is not None and key in self._marks:
                                self._imported[fid] = self._marks[key]
                if not committed:
                    self._bus.emit("job.done", {"job": JOB, "ok": False, "message": t("secret_scan.cancelled")})
                    return
                self._save_scan(len(found))
                self._bus.emit("job.done", {"job": JOB, "ok": True, "rows": self._rows(), "message": (
                    t("secret_scan.done", count=len(found)) if found else t("secret_scan.none"))})
            except Exception:  # noqa: BLE001 - surfaced to the user, never silently lost; no paths or values
                self._bus.emit("job.done", {"job": JOB, "ok": False, "message": t("secret_scan.failed")})
            finally:
                with self._state_lock:
                    self._running = False

        self._bus.emit("job.progress", {"job": JOB, "text": t("secret_scan.starting")})
        self._spawn(worker)
        return {"job": JOB}

    def cancel(self) -> dict[str, Any]:
        self._cancel.set()
        return {}

    # ---------------------------------------------------------------- import
    def _import_ssh(self, session: Any, finding: Finding) -> str:
        text = secret_scan.read_text(finding.path)
        if text is None or not secret_scan.regular_file(finding.path):
            raise ItemSchemaError("unreadable")
        public, fingerprint = "", ""
        try:
            key = load_private_key(text, None)
            public, fingerprint = key.public_line(finding.path.name), key.fingerprint()
        except SshKeyError:
            pass  # encrypted or a format the agent cannot use: stored as it is, without a public half
        return session.item_service.create_ssh_key(finding.path.name, private_key=text, public_key=public,
                                                   fingerprint=fingerprint)

    @staticmethod
    def _env_title(finding: Finding) -> str:
        return f"{finding.path.parent.name or 'env'}/{finding.path.name}"

    def _import_env(self, session: Any, finding: Finding) -> str:
        text = secret_scan.read_text(finding.path)
        if text is None or not secret_scan.regular_file(finding.path):
            raise ItemSchemaError("unreadable")
        if len(text) > MAX_NOTE_BODY:
            raise _TooLong
        title = self._env_title(finding)
        # One custom field per variable so lgk://<id>/<NAME> resolves (CliService serves a note's fields).
        fields = [{"name": name, "value": value, "hidden": True} for name, value in secret_scan.referenceable(text).items()]
        service = session.item_service
        try:
            return service.create_note(title, text, fields=fields)
        except ItemSchemaError:
            if not fields:
                raise
            return service.create_note(title, text)  # e.g. a control character in a value

    def import_findings(self, ids: Any) -> dict[str, Any]:
        session = self._session()
        if not isinstance(ids, list) or not ids or len(ids) > 500 or not all(isinstance(i, str) for i in ids):
            raise ApiError("invalid", t("bridge.invalidSelection"))
        wanted = [(finding_id, self._finding(finding_id)) for finding_id in dict.fromkeys(ids)]  # all ids first
        done, failures = [], []
        for finding_id, finding in wanted:
            with self._state_lock:
                if finding_id in self._imported:
                    continue
            mark = self._mark_key(finding)
            with self._state_lock:
                if mark is not None and mark in self._marks:  # this very file was imported before
                    self._imported[finding_id] = self._marks[mark]
                    continue
            try:
                item_id = (self._import_ssh if finding.kind == "ssh_private_key" else self._import_env)(session, finding)
            except ItemLimitReached as exc:
                self._port.show_upgrade(limit=exc.limit, message=str(exc), on_enter=lambda: None)
                if done:
                    break
                raise ApiError("item_limit", str(exc)) from None
            except _TooLong:
                failures.append({"id": finding_id, "name": finding.path.name,
                                 "reason": t("secret_scan.err.tooLong", max=f"{MAX_NOTE_BODY:,}")})
                continue
            except (ItemSchemaError, VaultError, ValueError, OSError):
                failures.append({"id": finding_id, "name": finding.path.name, "reason": t("secret_scan.err.importOne")})
                continue
            with self._state_lock:
                self._imported[finding_id] = item_id
                if mark is not None:
                    self._marks[mark] = item_id
            done.append(finding_id)
        if done:
            self._bus.emit("items.changed", {})
        message = t("secret_scan.imported", count=len(done))
        if failures:
            message += " " + " ".join(f"{f['name']}: {f['reason']}" for f in failures)
        return {"imported": done, "failed": len(failures), "failures": failures, "rows": self._rows(),
                "message": message}

    # ---------------------------------------------------------------- use references
    def _env_item(self, session: Any, finding_id: str, finding: Finding) -> tuple[str, dict[str, str]]:
        if finding.kind != "env_file":
            raise ApiError("invalid", t("secret_scan.err.notEnv"))
        item_id = self._imported.get(finding_id)
        item = session.item_service.get_item(item_id, include_protected=True) if item_id else None
        if not item or item.get("kind") != "note":
            raise ApiError("invalid", t("secret_scan.err.importFirst"))
        rows = (item.get("payload") or {}).get("fields") or []
        fields = {str(r.get("name")): str(r.get("value")) for r in rows if isinstance(r, dict)}
        return str(item_id), fields

    @staticmethod
    def _read(path: Path) -> tuple[bytes, str, bool]:
        """(raw bytes, text, has a BOM); a file that is not a plain UTF-8 file under 1 MiB is refused."""
        if not secret_scan.regular_file(path):
            raise ApiError("invalid", t("secret_scan.err.unreadable"))
        try:
            data = path.read_bytes()
            return data, data.decode("utf-8-sig"), data.startswith(b"\xef\xbb\xbf")
        except (OSError, UnicodeDecodeError):
            raise ApiError("invalid", t("secret_scan.err.unreadable")) from None

    @staticmethod
    def _plan(text: str, item_id: str, fields: dict[str, str]) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """(name -> reference to write, preview rows). A name is rewritten only while the file still holds the
        value stored in the item; rows carry the variable name and the new text, never a value."""
        referenceable = secret_scan.referenceable(text)
        refs: dict[str, str] = {}
        for name, value in referenceable.items():
            ref = f"{lgk_refs.PREFIX}{quote(item_id, safe='')}/{quote(name, safe='')}"
            try:
                parsed = lgk_refs.parse(ref)
            except lgk_refs.RefError:
                continue
            if parsed.item == item_id and parsed.field == name and fields.get(name) == value:
                refs[name] = ref
        rows: list[dict[str, Any]] = []
        duplicated = secret_scan.conflicting_duplicates(text)
        line_no = 0
        for line in secret_scan.parse_env(text):
            first = line_no + 1
            line_no += line.raw.count("\n") + (0 if line.raw.endswith("\n") else 1)
            if not line.key or not line.value or line.value.startswith("lgk://"):
                continue
            if line.key in refs and not line.trailing and not line.escaped:
                rows.append({"line": first, "name": line.key, "action": "rewrite", "before": MASK,
                             "after": refs[line.key]})
            else:
                reason = ("escaped" if line.escaped else "comment" if line.trailing
                          else "duplicate" if line.key in duplicated
                          else "changed" if line.key in referenceable else "other")
                rows.append({"line": first, "name": line.key, "action": "skip", "reason": reason})
        return refs, rows

    def rewrite_preview(self, finding_id: str) -> dict[str, Any]:
        session = self._session()
        finding = self._finding(finding_id)
        item_id, fields = self._env_item(session, finding_id, finding)
        data, text, _bom = self._read(finding.path)
        refs, rows = self._plan(text, item_id, fields)
        if not refs:
            raise ApiError("invalid", t("secret_scan.err.nothingToRewrite"))
        return {"token": hashlib.sha256(data).hexdigest(), "path": str(finding.path), "rows": rows,
                "rewrite_count": sum(1 for r in rows if r["action"] == "rewrite"),
                "skip_count": sum(1 for r in rows if r["action"] == "skip"),
                "cli_enabled": self._controller.settings.developer_cli is True}

    def rewrite_apply(self, finding_id: str, token: Any) -> dict[str, Any]:
        session = self._session()
        finding = self._finding(finding_id)
        item_id, fields = self._env_item(session, finding_id, finding)
        data, text, bom = self._read(finding.path)
        if not isinstance(token, str) or hashlib.sha256(data).hexdigest() != token:
            raise ApiError("invalid", t("secret_scan.err.changed"))
        refs, _rows = self._plan(text, item_id, fields)
        if not refs:
            raise ApiError("invalid", t("secret_scan.err.nothingToRewrite"))
        out = secret_scan.rewrite_env(text, refs).encode("utf-8")
        try:
            secret_scan.write_atomic(finding.path, (b"\xef\xbb\xbf" if bom else b"") + out)
        except OSError:
            raise ApiError("invalid", t("secret_scan.err.notWritten")) from None
        self._allow_in_cli(item_id)
        remaining = secret_scan.describe_file(finding.path)
        with self._state_lock:
            if remaining is None:
                self._findings.pop(finding_id, None)
            else:
                self._findings[finding_id] = remaining
            count = len(self._findings)
        self._save_scan(count)
        return {"rewritten": len(refs), "rows": self._rows(), "item_id": item_id, "message": t(
            "secret_scan.rewritten", count=len(refs)), "cli_enabled": self._controller.settings.developer_cli is True}

    def _allow_in_cli(self, item_id: str) -> None:
        controller = self._controller
        ids = [i for i in controller.settings.developer_cli_items if i != item_id][: MAX_ID_LIST - 1] + [item_id]
        candidate = replace(controller.settings, developer_cli_items=ids)
        try:
            candidate.save()
        except OSError:
            raise ApiError("invalid", t("settings.error.notSaved")) from None
        controller.settings = candidate


class _TooLong(Exception):
    """The .env text is longer than a note body can hold."""


class _Stop:
    """An Event-like object whose ``is_set`` also covers a lock (the scan stops when the vault locks)."""

    def __init__(self, stopped: Callable[[], bool]) -> None:
        self._stopped = stopped

    def is_set(self) -> bool:
        return self._stopped()
