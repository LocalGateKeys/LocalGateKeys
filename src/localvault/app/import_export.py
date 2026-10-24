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

EXPORT_MIN_PASSWORD = 12
_MAPPING_NONE = "(not imported)"
_MAPPING_LABELS = {
    "title": "Name", "url": "Website", "username": "Username", "password": "Password", "notes": "Notes",
    "totp": "One-time password", "folder": "Folder / collection", "favorite": "Favorite",
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
    lines = [f"{written} record(s) written.",
             f"Added {counts.get('add', 0)}, replaced {counts.get('replace', 0)}, merged {counts.get('merge', 0)}, "
             f"kept both {counts.get('keep_both', 0)}, skipped {counts.get('skip', 0)} of {counts.get('total', 0)} rows."]
    if counts.get("limited"):
        note = plan.limit_note() if callable(getattr(plan, "limit_note", None)) else ""
        lines.append(f"{note}." if note else f"{counts['limited']} row(s) need Pro.")
    if counts.get("skipped_rows"):
        lines.append(f"{counts['skipped_rows']} source row(s) could not be read.")
    diagnostics = tuple(getattr(plan, "diagnostics", ()) or ())
    if diagnostics:
        lines.append("")
        lines.append("Diagnostics:")
        lines.extend(f"• {line}" for line in diagnostics[:40])
        if len(diagnostics) > 40:
            lines.append(f"… and {len(diagnostics) - 40} more.")
    return "\n".join(lines)


def _secret_length(value: str | SecretText | None) -> int:
    if isinstance(value, SecretText):
        return value.char_count
    return len(value or "")


def export_request_issue(export_format: str, password: str | SecretText,
                         confirm_password: str | SecretText) -> str | None:
    """Validate the export form; ``None`` means the request can proceed."""
    if export_format not in EXPORT_FORMATS:
        return "Choose an export format."
    if export_format != "kdbx":
        return None
    if _secret_length(password) < EXPORT_MIN_PASSWORD:
        return f"The KDBX password needs at least {EXPORT_MIN_PASSWORD} characters."
    if not secrets_match(password or "", confirm_password or ""):
        return "The KDBX passwords do not match."
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
    lines = [f"{summary.count} record(s) written to {summary.path}.",
             f"Format: {getattr(summary, 'label', summary.format)}."]
    if getattr(summary, "skipped", 0):
        lines.append(f"{summary.skipped} record(s) were skipped as not exportable.")
    if getattr(summary, "encrypted", False):
        lines.append("The file is encrypted with the password you chose.")
    else:
        lines.append("The file is plain text: import it into the destination now, then delete it.")
    for warning in getattr(summary, "warnings", ()) or ():
        lines.append(str(warning))
    return "\n".join(lines)


# ---------------------------------------------------------------- services
import secrets as _secrets  # noqa: E402
import threading as _threading  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

from ..api.result import ApiError  # noqa: E402

IMPORT_SUBTITLE = ("{label} · {count} records. Local only; nothing is written until you choose Import. New records "
                   "default to Add; duplicates and conflicts default to Skip (Keep both saves the imported copy too). "
                   "Passwords are never shown here.")
EXPORT_INTRO = ("Writes a copy of every login and exportable item in this profile to a file you choose. Nothing leaves "
                "this PC unless you move the file.")


def _session_lease(controller: Any) -> tuple[Any, Any]:
    if not controller.is_unlocked():
        raise ApiError("locked", "Unlock this profile first.")
    lease = controller.guard.lease()
    controller.require_lease(lease)
    return controller.session, lease


def _summary_line(plan: Any) -> str:
    counts = plan.summary()
    note = plan.limit_note()
    return (f"Add {counts['add']} · Replace {counts['replace']} · Merge {counts['merge']} · "
            f"Keep both {counts.get('keep_both', 0)} · Skip {counts['skip']} of {counts['total']}"
            + (f" · {counts['skipped_rows']} unreadable row(s)" if counts.get("skipped_rows") else "")
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
            raise ApiError("expired", "This import was closed. Start it again.")
        return entry

    def open(self) -> dict[str, Any]:
        from ..import_workflow import ImportWorkflowError, inspect_source
        from ..importers import ImporterError
        from ..vault import VaultError

        _session_lease(self._controller)
        path = self._dialogs.open_file("Import passwords and items")
        if not path:
            raise ApiError("cancelled", "No file was chosen.")
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
            mapping = {"subtitle": (f"{source.label}: {len(source.fields)} columns, {source.row_count} rows. Pick "
                                    "which column feeds each field; at least the password column is required."),
                       "targets": [{"key": t, "label": _MAPPING_LABELS.get(t, t.title()),
                                    "value": defaults.get(t) or ""} for t in MAPPING_TARGETS],
                       "columns": list(source.fields), "none": _MAPPING_NONE,
                       "unmapped": "Not recognised automatically: " + ", ".join(source.unmapped)}
        return {"handle": handle, "label": source.label, "needs_password": bool(source.needs_password),
                "password_text": f"{source.label} is encrypted.\nEnter the password that opens it (it is used once "
                                 "and not stored):", "mapping": mapping}

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
            column_mapping = {k: v for k, v in mapping.items() if v and v != _MAPPING_NONE and k in MAPPING_TARGETS}
            if "password" not in column_mapping and "notes" not in column_mapping:
                raise ApiError("invalid", "Choose the password column (or a notes column for secure notes).")
            if len(set(column_mapping.values())) != len(column_mapping):
                raise ApiError("invalid", "Each CSV column can feed only one field.")
            if any(v not in source.fields for v in column_mapping.values()):
                raise ApiError("invalid", "Choose columns from this file.")
        try:
            plan = build_import_plan(session, entry["path"], password=password or None,
                                     source_format=source.source_format, column_mapping=column_mapping)
        except ImportPasswordRequired:
            raise ApiError("password_required", "Enter the password that opens this file.") from None
        except ImportPasswordError as exc:
            raise ApiError("wrong_password", f"{exc}\nTry the password again.") from None
        except StaleSession:
            raise ApiError("session_changed", "Session changed or expired. Import cancelled.") from None
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
            raise ApiError("expired", "This import was closed. Start it again.")
        self._controller.require_lease(lease)
        return self.review(handle)

    def review(self, handle: str) -> dict[str, Any]:
        from .catalog import kind_label

        entry = self._entry(handle)
        plan = entry["plan"]
        if plan is None:
            raise ApiError("invalid", "Prepare the import first.")
        source = entry["source"]
        return {
            "handle": handle,
            "subtitle": IMPORT_SUBTITLE.format(label=source.label, count=len(plan.rows)),
            "rows": [{"row": r.row, "name": r.label, "website": r.origin, "username": r.username,
                      "kind": kind_label("web" if r.kind == "login" else r.kind), "status": r.status,
                      "decision": "needs Pro" if getattr(r, "limited", False) else r.decision}
                     for r in plan.rows],
            "summary": _summary_line(plan), "diagnostics": list(plan.diagnostics or ()),
            "applying": entry["applying"],
        }

    def decide(self, handle: str, rows: list[int], mode: str) -> dict[str, Any]:
        from ..import_workflow import ImportWorkflowError

        if mode not in {"skip", "apply", "merge", "keep_both"}:
            raise ApiError("invalid", "Unknown decision.")
        entry = self._entry(handle)
        plan = entry["plan"]
        if plan is None or entry["applying"]:
            raise ApiError("invalid", "This import cannot be changed now.")
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
            raise ApiError("invalid", "Unknown decision.")
        entry = self._entry(handle)
        plan = entry["plan"]
        if plan is None or entry["applying"]:
            raise ApiError("invalid", "This import cannot be changed now.")
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
            raise ApiError("invalid", "This import cannot be applied now.")
        count = sum(r.decision != "skip" and not r.limited for r in plan.rows)
        limited = plan.summary()["limited"]
        if not count and limited:
            notify_item_limit(self._upgrade, plan.limit_summary())
            raise ApiError("item_limit", plan.limit_note() or "The free plan is full.")
        if not count:
            raise ApiError("nothing_selected", "Choose Add, Replace or Merge for at least one row.")
        extra = f" {limited} record(s) need Pro and will not be imported." if limited else ""
        if not self._port.confirm("Apply import?", f"Write {count} record(s) to this profile?{extra} Replace and "
                                  "merge keep the previous password in encrypted history. Protect and delete the "
                                  "source file afterwards."):
            raise ApiError("cancelled", "Cancelled.")
        self._controller.require_lease(lease)
        with self._lock:
            if self._pending.get(str(handle)) is not entry or entry["cancel"].is_set():
                raise ApiError("cancelled", "Import cancelled. Nothing was written.")
            entry["applying"] = True
        self._bus.emit("import.progress", {"handle": handle, "text": "Importing… you can cancel until it finishes."})
        try:
            plan.review()
            written = plan.apply(session, cancel=lambda: entry["cancel"].is_set()
                                 or not self._controller.guard.valid(lease))
        except ImportCancelled:
            self.close(handle)
            raise ApiError("cancelled", "Import cancelled. Nothing was written.") from None
        except Exception as exc:  # noqa: BLE001 - mapped below; never leaks a traceback
            limit = item_limit_cause(exc)
            if limit is not None:
                self._upgrade(limit)
                raise ApiError("item_limit", str(limit)) from None
            if isinstance(exc, StaleSession):
                raise ApiError("session_changed", "Session changed or expired. Import cancelled.") from None
            if isinstance(exc, (ImportWorkflowError, ImporterError, VaultError, OSError, ValueError)):
                raise ApiError("import_failed", str(exc) or "Import failed") from None
            raise ApiError("import_failed", "Import failed") from None
        finally:
            entry["applying"] = False
            self._bus.emit("import.progress", {"handle": handle, "text": ""})
        text = import_summary_text(plan, written)
        limits = plan.limit_summary()
        self.close(handle)
        self._controller.touch()
        self._bus.emit("items.changed", {})
        notify_item_limit(self._upgrade, limits)
        return {"title": "Import complete", "message": text, "status": f"Imported {written} record(s)."}

    def cancel(self, handle: str) -> dict[str, Any]:
        with self._lock:
            entry = self._pending.get(str(handle))
            applying = entry is not None and entry["applying"]
            if applying:
                entry["cancel"].set()
        if applying:
            return {"text": "Cancelling…"}
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

        return {"intro": EXPORT_INTRO,
                "formats": [{"key": k, "label": v} for k, v in EXPORT_FORMATS.items()],
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
            self._auth.reauthenticate("Confirm to export passwords", lease, allow_hello=False)
            self._controller.require_lease(lease)
            suffix = EXPORT_SUFFIXES[fmt]
            target = self._dialogs.save_file("Save export as", f"localgatekeys-export{suffix}")
            if not target:
                raise ApiError("cancelled", "No file was chosen.")
            path = _Path(target)
            if path.suffix.lower() != suffix:
                path = path.with_suffix(suffix)
            warnings = "\n\n".join(ExportWarning.for_format(fmt, include_totp=include_totp))
            if not self._port.confirm("Export now?", warnings + f"\n\nWrite {path.name}?"):
                raise ApiError("cancelled", "Cancelled.")
            self._controller.require_lease(lease)
            try:
                summary = export_records(session, path, fmt, include_totp=include_totp,
                                         password=_kdbx_password(password) if fmt == "kdbx" else None,
                                         overwrite=True)
            except (ExportError, StaleSession, VaultError, OSError, ValueError) as exc:
                raise ApiError("export_failed", str(exc) or "Export failed.") from None
        finally:
            password = confirm = ""
        self._controller.touch()
        return {"title": "Export complete", "message": export_summary_text(summary),
                "status": f"Exported {summary.count} record(s)."}
