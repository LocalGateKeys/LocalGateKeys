"""Import and export for the WebView UI.

The pure helpers moved here from ``feature_ui`` (re-exported there), plus the
services the bridge calls. Every path comes from a Python dialog; passwords
are used for one call and dropped; review rows are masked.
"""
from __future__ import annotations

from typing import Any

from ..export import EXPORT_FORMATS
from ..importers.chrome import MAPPING_TARGETS
from ..secret_text import SecretText, as_secret, secrets_match
from ..i18n import t

EXPORT_MIN_PASSWORD = 12
_MAPPING_NONE = "importExport.notImported"
_MAPPING_LABELS = {
    "title": "importSheet.colName", "url": "typed.identity.website", "username": "loginEditor.username", "password": "typed.field.wifi.password", "notes": "typed.field.purchase.notes",
    "totp": "importExport.oneTimePassword", "folder": "importExport.folderCollection", "favorite": "typedEditor.favorite",
}


def import_decision_for(status: str, mode: str) -> str:
    """Map a toolbar choice onto the decision the plan accepts for ``status``."""
    if mode == "skip":
        return "skip"
    if mode == "keep_both":
        return "skip" if status == "new" else "keep_both"
    if status == "new":
        return "add"
    if status == "conflict":
        return "merge" if mode == "merge" else "replace"
    return "skip"


def import_mapping_defaults(source: Any) -> dict[str, str]:
    """``{target: column}`` for the column-mapping step, prefilled from the guess."""
    guessed = {}
    for pair in getattr(source, "mapping", ()) or ():
        target, _sep, column = str(pair).partition(":")
        guessed[target] = column
    return {target: guessed.get(target, "") for target in MAPPING_TARGETS}


def import_summary_text(plan: Any, written: int) -> str:
    counts = plan.summary()
    lines = [t("importExport.recordsWritten", count=written),
             t("importExport.countsSummary", add=counts.get('add', 0), replace=counts.get('replace', 0),
               merge=counts.get('merge', 0), keepBoth=counts.get('keep_both', 0), skip=counts.get('skip', 0),
               total=counts.get('total', 0))]
    if counts.get("limited"):
        note = plan.limit_note() if callable(getattr(plan, "limit_note", None)) else ""
        lines.append(f"{note}." if note else t("importExport.rowsNeedPro", count=counts['limited']))
    if counts.get("skipped_rows"):
        lines.append(t("importExport.sourceRowsUnreadable", count=counts['skipped_rows']))
    diagnostics = tuple(getattr(plan, "diagnostics", ()) or ())
    if diagnostics:
        lines.append("")
        lines.append(t("importExport.diagnosticsHeading"))
        lines.extend(f"• {line}" for line in diagnostics[:40])
        if len(diagnostics) > 40:
            lines.append(t("importExport.diagnosticsMore", count=len(diagnostics) - 40))
    return "\n".join(lines)


def _secret_length(value: str | SecretText | None) -> int:
    if isinstance(value, SecretText):
        return value.char_count
    return len(value or "")


def export_request_issue(export_format: str, password: str | SecretText,
                         confirm_password: str | SecretText) -> str | None:
    """Validate the export form; ``None`` means the request can proceed."""
    if export_format not in EXPORT_FORMATS:
        return t("importExport.chooseAnExportFormat")
    if export_format != "kdbx":
        return None
    if _secret_length(password) < EXPORT_MIN_PASSWORD:
        return t("importExport.kdbxPasswordMin", min=EXPORT_MIN_PASSWORD)
    if not secrets_match(password or "", confirm_password or ""):
        return t("importExport.theKdbxPasswordsDoNot")
    return None


def _kdbx_password(password: str | SecretText) -> str:
    """The KDBX writer needs a ``str``; it is made from the wipeable buffer at the last moment."""
    secret, owned = as_secret(password)
    try:
        return secret.buffer.decode("utf-8")
    finally:
        if owned:
            secret.wipe()


def export_summary_text(summary: Any) -> str:
    lines = [t("importExport.exportRecordsWritten", count=summary.count, path=summary.path),
             t("importExport.exportFormat", label=getattr(summary, 'label', summary.format))]
    if getattr(summary, "skipped", 0):
        lines.append(t("importExport.exportSkipped", count=summary.skipped))
    if getattr(summary, "encrypted", False):
        lines.append(t("importExport.theFileIsEncryptedWith"))
    else:
        lines.append(t("importExport.theFileIsPlainText"))
    for warning in getattr(summary, "warnings", ()) or ():
        lines.append(str(warning))
    return "\n".join(lines)


# ---------------------------------------------------------------- services
import secrets as _secrets  # noqa: E402
import threading as _threading  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

from ..api.result import ApiError  # noqa: E402

IMPORT_SUBTITLE = ("importExport.recordsLocalOnlyNothingIs")
EXPORT_INTRO = ("importExport.writesACopyOfEvery")


def _session_lease(controller: Any) -> tuple[Any, Any]:
    if not controller.is_unlocked():
        raise ApiError("locked", t("error.lockedProfile"))
    lease = controller.guard.lease()
    controller.require_lease(lease)
    return controller.session, lease


def _summary_line(plan: Any) -> str:
    counts = plan.summary()
    note = plan.limit_note()
    return (t("importExport.planSummary", add=counts['add'], replace=counts['replace'], merge=counts['merge'],
              keepBoth=counts.get('keep_both', 0), skip=counts['skip'], total=counts['total'])
            + (t("importExport.unreadableRows", count=counts['skipped_rows']) if counts.get("skipped_rows") else "")
            + (f" · {note}" if note else ""))


class ImportService:
    def __init__(self, controller: Any, port: Any, dialogs: Any, bus: Any) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._bus = bus
        self._pending: dict[str, dict[str, Any]] = {}
        self._lock = _threading.Lock()
        controller.on_lock.append(self._drop_all)

    def _drop_all(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, {}
        for entry in pending.values():
            entry["cancel"].set()
            plan = entry.get("plan")
            if plan is not None:
                try:
                    plan.cancel()
                except Exception:  # noqa: BLE001, S110
                    pass

    def _entry(self, handle: str) -> dict[str, Any]:
        entry = self._pending.get(str(handle))
        if entry is None:
            raise ApiError("expired", t("importExport.thisImportWasClosedStart"))
        return entry

    def open(self) -> dict[str, Any]:
        from ..import_workflow import ImportWorkflowError, inspect_source
        from ..importers import ImporterError
        from ..vault import VaultError

        _session_lease(self._controller)
        path = self._dialogs.open_file(t("importSheet.titleStart"))
        if not path:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        try:
            source = inspect_source(_Path(path))
        except (ImporterError, ImportWorkflowError, VaultError, OSError, ValueError) as exc:
            raise ApiError("import_unavailable", str(exc)) from None
        handle = _secrets.token_urlsafe(12)
        with self._lock:
            self._pending[handle] = {"path": _Path(path), "source": source, "plan": None,
                                     "cancel": _threading.Event(), "applying": False}
        mapping = None
        if source.is_csv and source.unmapped:
            defaults = import_mapping_defaults(source)
            mapping = {"subtitle": (t("importExport.pickColumns", label=source.label, columns=len(source.fields), rows=source.row_count)),
                       "targets": [{"key": target, "label": t(_MAPPING_LABELS[target]) if target in _MAPPING_LABELS else target.title(),
                                    "value": defaults.get(target) or ""} for target in MAPPING_TARGETS],
                       "columns": list(source.fields), "none": t(_MAPPING_NONE),
                       "unmapped": t("importExport.notRecognisedAutomatically") + ", ".join(source.unmapped)}
        return {"handle": handle, "label": source.label, "needs_password": bool(source.needs_password),
                "password_text": t("importExport.sourceEncrypted", label=source.label), "mapping": mapping}

    def plan(self, handle: str, password: str | None, mapping: dict[str, str] | None) -> dict[str, Any]:
        from ..import_workflow import ImportWorkflowError, build_import_plan
        from ..importers import ImporterError, ImportFormatError, ImportPasswordError, ImportPasswordRequired
        from ..session_guard import StaleSession
        from ..vault import VaultError

        session, lease = _session_lease(self._controller)
        entry = self._entry(handle)
        source = entry["source"]
        column_mapping = None
        if mapping is not None:
            column_mapping = {k: v for k, v in mapping.items() if v and k in MAPPING_TARGETS}
            if "password" not in column_mapping and "notes" not in column_mapping:
                raise ApiError("invalid", t("importExport.chooseThePasswordColumnOr"))
            if len(set(column_mapping.values())) != len(column_mapping):
                raise ApiError("invalid", t("importExport.eachCsvColumnCanFeed"))
            if any(v not in source.fields for v in column_mapping.values()):
                raise ApiError("invalid", t("importExport.chooseColumnsFromThisFile"))
        try:
            plan = build_import_plan(session, entry["path"], password=password or None,
                                     source_format=source.source_format, column_mapping=column_mapping)
        except ImportPasswordRequired:
            raise ApiError("password_required", t("importExport.enterThePasswordThatOpens")) from None
        except ImportPasswordError as exc:
            raise ApiError("wrong_password", t("importExport.tryPasswordAgain", error=exc)) from None
        except StaleSession:
            raise ApiError("session_changed", t("importExport.sessionChangedOrExpiredImport")) from None
        except (ImportFormatError, ImporterError, ImportWorkflowError, VaultError, OSError, ValueError) as exc:
            raise ApiError("import_unavailable", str(exc)) from None
        finally:
            password = ""
        with self._lock:
            still_open = self._pending.get(str(handle)) is entry
            if still_open:
                entry["plan"] = plan
        if not still_open:
            plan.cancel()  # the import was closed while this plan was built: drop it now
            raise ApiError("expired", t("importExport.thisImportWasClosedStart"))
        self._controller.require_lease(lease)
        return self.review(handle)

    def review(self, handle: str) -> dict[str, Any]:
        from .catalog import kind_label

        entry = self._entry(handle)
        plan = entry["plan"]
        if plan is None:
            raise ApiError("invalid", t("importExport.prepareTheImportFirst"))
        source = entry["source"]
        return {
            "handle": handle,
            "subtitle": t(IMPORT_SUBTITLE, label=source.label, count=len(plan.rows)),
            "rows": [{"row": r.row, "name": r.label, "website": r.origin, "username": r.username,
                      "kind": kind_label("web" if r.kind == "login" else r.kind), "status": r.status,
                      "decision": t("importExport.needsPro") if getattr(r, "limited", False) else r.decision}
                     for r in plan.rows],
            "summary": _summary_line(plan), "diagnostics": list(plan.diagnostics or ()),
            "applying": entry["applying"],
        }

    def decide(self, handle: str, rows: list[int], mode: str) -> dict[str, Any]:
        from ..import_workflow import ImportWorkflowError

        if mode not in {"skip", "apply", "merge", "keep_both"}:
            raise ApiError("invalid", t("importExport.unknownDecision"))
        entry = self._entry(handle)
        plan = entry["plan"]
        if plan is None or entry["applying"]:
            raise ApiError("invalid", t("importExport.thisImportCannotBeChanged"))
        wanted = {int(r) for r in rows}
        for row in plan.rows:
            if row.row in wanted:
                try:
                    plan.set_decision(row, import_decision_for(row.status, mode))
                except ImportWorkflowError:
                    continue
        return self.review(handle)

    def decide_all(self, handle: str, action: str) -> dict[str, Any]:
        presets = {"add-new": ("add", ("new",)), "replace-conflicts": ("replace", ("conflict",)),
                   "skip-all": ("skip", None)}
        if action not in presets:
            raise ApiError("invalid", t("importExport.unknownDecision"))
        entry = self._entry(handle)
        plan = entry["plan"]
        if plan is None or entry["applying"]:
            raise ApiError("invalid", t("importExport.thisImportCannotBeChanged"))
        decision, statuses = presets[action]
        plan.set_all(decision, statuses=statuses)
        return self.review(handle)

    def _upgrade(self, limit: Any) -> None:
        self._port.show_upgrade(limit=limit.limit, message=str(limit), on_enter=lambda: None)

    def apply(self, handle: str) -> dict[str, Any]:
        from ..import_workflow import ImportCancelled, ImportWorkflowError, item_limit_cause
        from ..importers import ImporterError
        from ..session_guard import StaleSession
        from ..vault import VaultError
        from .transfer_controller import notify_item_limit

        session, lease = _session_lease(self._controller)
        entry = self._entry(handle)
        plan = entry["plan"]
        if plan is None or entry["applying"]:
            raise ApiError("invalid", t("importExport.thisImportCannotBeApplied"))
        count = sum(r.decision != "skip" and not r.limited for r in plan.rows)
        limited = plan.summary()["limited"]
        if not count and limited:
            notify_item_limit(self._upgrade, plan.limit_summary())
            raise ApiError("item_limit", plan.limit_note() or t("importExport.theFreePlanIsFull"))
        if not count:
            raise ApiError("nothing_selected", t("importExport.chooseAddReplaceOrMerge"))
        extra = t("importExport.limitedExtra", count=limited) if limited else ""
        if not self._port.confirm(t("importExport.applyImport"), t("importExport.writeRecords", count=count, extra=extra)):
            raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)
        with self._lock:
            if self._pending.get(str(handle)) is not entry or entry["cancel"].is_set():
                raise ApiError("import_cancelled", t("importExport.importCancelledNothingWasWritten"))
            entry["applying"] = True
        self._bus.emit("import.progress", {"handle": handle, "text": t("importExport.importingYouCanCancelUntil")})
        try:
            plan.review()
            written = plan.apply(session, cancel=lambda: entry["cancel"].is_set()
                                 or not self._controller.guard.valid(lease))
        except ImportCancelled:
            self.close(handle)
            raise ApiError("import_cancelled", t("importExport.importCancelledNothingWasWritten")) from None
        except Exception as exc:  # noqa: BLE001 - mapped below; never leaks a traceback
            limit = item_limit_cause(exc)
            if limit is not None:
                self._upgrade(limit)
                raise ApiError("item_limit", str(limit)) from None
            if isinstance(exc, StaleSession):
                raise ApiError("session_changed", t("importExport.sessionChangedOrExpiredImport")) from None
            if isinstance(exc, (ImportWorkflowError, ImporterError, VaultError, OSError, ValueError)):
                raise ApiError("import_failed", str(exc) or t("importExport.importFailed")) from None
            raise ApiError("import_failed", t("importExport.importFailed")) from None
        finally:
            entry["applying"] = False
            self._bus.emit("import.progress", {"handle": handle, "text": ""})
        text = import_summary_text(plan, written)
        limits = plan.limit_summary()
        self.close(handle)
        self._controller.touch()
        self._bus.emit("items.changed", {})
        notify_item_limit(self._upgrade, limits)
        return {"title": t("importExport.importComplete"), "message": text, "status": t("importExport.importedRecords", count=written)}

    def cancel(self, handle: str) -> dict[str, Any]:
        with self._lock:
            entry = self._pending.get(str(handle))
            applying = entry is not None and entry["applying"]
            if applying:
                entry["cancel"].set()
        if applying:
            return {"text": t("importExport.cancelling")}
        self.close(handle)
        return {}

    def close(self, handle: str) -> dict[str, Any]:
        with self._lock:
            entry = self._pending.pop(str(handle), None)
        if entry is not None:
            entry["cancel"].set()
            plan = entry.get("plan")
            if plan is not None:
                try:
                    plan.cancel()
                except Exception:  # noqa: BLE001, S110
                    pass
        return {}


class ExportService:
    def __init__(self, controller: Any, port: Any, dialogs: Any) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._auth = SecretService(controller, port)

    @staticmethod
    def formats(fmt: str = "kdbx", include_totp: bool = False) -> dict[str, Any]:
        from ..export import ExportWarning

        return {"intro": t(EXPORT_INTRO),
                "formats": [{"key": k, "label": t(v)} for k, v in EXPORT_FORMATS.items()],
                "warnings": list(ExportWarning.for_format(fmt, include_totp=include_totp))
                if fmt in EXPORT_FORMATS else [],
                "min_password": EXPORT_MIN_PASSWORD}

    def export(self, fmt: str, include_totp: bool, password: str | SecretText,
               confirm: str | SecretText) -> dict[str, Any]:
        """Export the vault. The KDBX password may be a ``SecretText`` (the bridge passes one and wipes it);
        it becomes a ``str`` only inside the KDBX writer call, which needs one."""
        from ..export import EXPORT_SUFFIXES, ExportError, ExportWarning, export_records
        from ..session_guard import StaleSession
        from ..vault import VaultError

        session, lease = _session_lease(self._controller)
        try:
            issue = export_request_issue(fmt, password, confirm)
            if issue:
                raise ApiError("invalid", issue)
            # Every format writes every secret (a KDBX password protects the file, not this vault), so the
            # master password is asked each time: no Windows Hello, no routine grace window.
            self._auth.reauthenticate(t("importExport.confirmToExportPasswords"), lease, allow_hello=False)
            self._controller.require_lease(lease)
            suffix = EXPORT_SUFFIXES[fmt]
            target = self._dialogs.save_file(t("importExport.saveExportAs"), f"localgatekeys-export{suffix}")
            if not target:
                raise ApiError("cancelled", t("recovery.noFileWasChosen"))
            path = _Path(target)
            if path.suffix.lower() != suffix:
                path = path.with_suffix(suffix)
            warnings = "\n\n".join(ExportWarning.for_format(fmt, include_totp=include_totp))
            if not self._port.confirm(t("importExport.exportNow"), warnings + "\n\n" + t("importExport.writeFileQuestion", name=path.name)):
                raise ApiError("cancelled", t("error.cancelled"))
            self._controller.require_lease(lease)
            try:
                summary = export_records(session, path, fmt, include_totp=include_totp,
                                         password=_kdbx_password(password) if fmt == "kdbx" else None,
                                         overwrite=True)
            except (ExportError, StaleSession, VaultError, OSError, ValueError) as exc:
                raise ApiError("export_failed", str(exc) or t("importExport.exportFailed")) from None
        finally:
            password = confirm = ""
        self._controller.touch()
        return {"title": t("importExport.exportComplete"), "message": export_summary_text(summary),
                "status": t("importExport.exportedRecords", count=summary.count)}
