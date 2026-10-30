"""Typed items for the WebView UI: per-kind schema, detail, edit, save, reveal and copy.

Behaviour follows the Tk ``TypedItemEditor`` / ``typed_item_details``
(docs/superpowers/specs/2026-10-17-webview-items-dataflow.md §1). Protected
values never leave Python except through an explicit, re-authenticated
``reveal``. Bookmark URL/notes and identity fields are shown in the detail view
without re-auth, exactly as the Tk app does. A secure note's body is hidden: it
is shown, copied or opened for editing only after the master password.
"""
from __future__ import annotations

import time
from typing import Any

from ..api.result import ApiError
from ..item_schema import IDENTITY_FIELDS, PROTECTED_FIELDS_BY_KIND, ItemSchemaError
from ..shell.overview_model import age_text
from ..vault import ItemLimitReached, VaultError
from .setting_links import clipboard_result
from ..i18n import catalog, t
from .typed_schema import (
    IDENTITY_LABELS,
    KIND_LABELS,
    kind_title,
    PURCHASE_LIKE,
    SECRET_FORM_HIDDEN_FIELDS,
    SECRET_KIND_CHOICES,
    SECRET_KIND_FIELDS,
    SECRET_KIND_NOTES,
)

PARITY_PLAIN_KINDS = frozenset({"note", "bookmark", "identity"})
# Fields that stay editable in plain view but are hidden in the detail view behind the master password.
MASTER_HIDDEN_FIELDS = {"note": frozenset({"body"})}
REVEAL_SECONDS = 30
_CONTROL_TYPES = {"text": "text", "multiline": "multiline", "choice": "select", "bool": "checkbox"}

_SAFE_FIELDS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "note": (("body", "typed.field.note.body", "multiline"),),
    "bookmark": (("url", "typed.field.bookmark.url", "text"), ("notes", "typed.field.bookmark.notes", "multiline")),
    "document": (("description", "typed.field.document.description", "text"),),
    "license": (
        ("product", "typed.field.license.product", "text"), ("vendor", "typed.field.license.vendor", "text"),
        ("license_value", "typed.field.license.license_value", "text"),
        ("purchase_date", "typed.field.license.purchase_date", "date"),
        ("expiration_date", "typed.field.license.expiration_date", "date"), ("notes", "typed.field.license.notes", "multiline"),
    ),
}
_PURCHASE_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("product", "typed.field.purchase.product", "text"), ("vendor", "typed.field.purchase.vendor", "text"), ("provider", "typed.field.purchase.provider", "text"),
    ("purchase_date", "typed.field.purchase.purchase_date", "date"),
    ("expiration_date", "typed.field.purchase.expiration_date", "date"),
    ("renewal_date", "typed.field.purchase.renewal_date", "date"),
    ("amount_minor", "typed.field.purchase.amount_minor", "number"), ("currency", "typed.field.purchase.currency", "text"),
    ("active", "typed.field.purchase.active", "checkbox"), ("notes", "typed.field.purchase.notes", "multiline"),
)
_KIND_NOTES = {
    **SECRET_KIND_NOTES,
    "bookmark": "typed.note.bookmark",
    "identity": "typed.note.identity",
    "document": "typed.note.document",
}


def _fields_for(kind: str, *, short: bool = False) -> list[dict[str, Any]]:
    """Field descriptors with labels in the active language (``short``: the detail view's label)."""
    protected = set(PROTECTED_FIELDS_BY_KIND.get(kind, ()))
    if kind in SECRET_KIND_FIELDS:
        rows = [(name, label, _CONTROL_TYPES.get(control, "text")) for name, label, control in SECRET_KIND_FIELDS[kind]]
        rows.append(("notes", "typed.field.notes", "multiline"))
        if kind == "card":
            rows.append(("billing_address_id", "typed.field.card.billing_address_id", "identity_ref"))
    elif kind == "identity":
        rows = [(name, IDENTITY_LABELS.get(name, name), "text") for name in sorted(IDENTITY_FIELDS)]
    elif kind in PURCHASE_LIKE:
        rows = list(_PURCHASE_FIELDS)
    else:
        rows = list(_SAFE_FIELDS.get(kind, ()))
    out = []
    for name, label, control in rows:
        text = t(label + ".short") if short and (label + ".short") in catalog() else t(label)
        field: dict[str, Any] = {
            "name": name, "label": text, "type": control,
            # Parity: note/bookmark/identity values are protected at rest but editable in plain view.
            "protected": name in protected and kind not in PARITY_PLAIN_KINDS,
        }
        if control == "select":
            field["options"] = list(SECRET_KIND_CHOICES.get(name, ()))
        out.append(field)
    return out


class TypedService:
    def __init__(self, controller: Any, port: Any) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._auth = SecretService(controller, port)

    # ---------------------------------------------------------------- schema
    def schema(self) -> dict[str, Any]:
        return {"kinds": [{"kind": kind, "label": kind_title(kind), "fields": _fields_for(kind),
                           "new_title": t(f"typed.title.new.{kind}"), "edit_title": t(f"typed.title.edit.{kind}"),
                           "note": t(_KIND_NOTES[kind]) if kind in _KIND_NOTES else ""}
                          for kind in KIND_LABELS]}

    # ---------------------------------------------------------------- helpers
    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("typed.err.unlockFirst"))
        return self._controller.session

    @staticmethod
    def _typed_ref(ref: dict[str, Any]) -> str:
        if ref.get("source") != "typed":
            raise ApiError("invalid", t("typed.err.chooseTyped"))
        return ref["id"]

    def _item(self, session: Any, item_id: str, *, protected: bool) -> dict[str, Any]:
        item = session.item_service.get_item(item_id, include_protected=protected)
        if item is None:
            raise ApiError("not_found", t("typed.err.itemGone"))
        return item

    # ---------------------------------------------------------------- detail
    def detail(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        item_id = self._typed_ref(ref)
        kind = None
        item = self._item(session, item_id, protected=False)
        kind = str(item.get("kind"))
        hidden = MASTER_HIDDEN_FIELDS.get(kind, frozenset())
        plain = self._item(session, item_id, protected=True) if kind in PARITY_PLAIN_KINDS else None
        try:
            payload = (plain or item).get("payload") or {}
            fields = []
            for field in _fields_for(kind, short=True):
                name = field["name"]
                if name in hidden:
                    if payload.get(name):
                        fields.append({"name": name, "label": field["label"], "value": None,
                                       "protected": True, "present": True})
                elif field["protected"]:
                    present = bool(item["payload"].get(f"{name}_present") or item["payload"].get(name))
                    fields.append({"name": name, "label": field["label"], "value": None, "protected": True,
                                   "present": present})
                else:
                    value = payload.get(name)
                    if value in (None, ""):
                        continue
                    fields.append({"name": name, "label": field["label"],
                                   "value": value if isinstance(value, (bool, int, float)) else str(value),
                                   "protected": False, "present": True})
            result = {"kind": kind, "title": str(item.get("title") or "Untitled"),
                      "subtitle": self._subtitle(item, kind), "fields": fields,
                      "tags": [str(t) for t in item.get("tags") or []], "favorite": bool(item.get("favorite")),
                      "revision": item.get("revision")}
            if kind == "document":
                try:
                    record = session.documents.attachment_for(item_id)
                    result["document"] = {"name": record.get("name"), "mime": record.get("mime_type"),
                                          "size": record.get("size")}
                except Exception as exc:  # noqa: BLE001 - shown as the Tk text does
                    result["document"] = {"error": f"Attachment unavailable: {exc}"}
            return result
        finally:
            if plain is not None:
                (plain.get("payload") or {}).clear()

    @staticmethod
    def _subtitle(item: dict[str, Any], kind: str) -> str:
        parts = [kind_title(kind)]
        updated = int(item.get("updated_at") or 0)
        if updated:
            parts.append(f"updated {age_text(max(0.0, time.time() - updated))}")
        return " · ".join(parts)

    # ------------------------------------------------------------------ edit
    def open_edit(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        item_id = self._typed_ref(ref)
        if str(self._item(session, item_id, protected=False).get("kind")) in MASTER_HIDDEN_FIELDS:
            lease = self._controller.guard.lease()
            self._auth.reauthenticate(t("typed.confirmEditNote"), lease, allow_hello=False)
            self._controller.require_lease(lease)
        item = self._item(session, item_id, protected=True)
        try:
            kind = str(item.get("kind"))
            payload = item.get("payload") or {}
            schema = _fields_for(kind)
            values = {f["name"]: payload.get(f["name"]) for f in schema
                      if not f["protected"] and payload.get(f["name"]) not in (None, "")}
            present = {f["name"]: bool(payload.get(f["name"])) for f in schema if f["protected"]}
            return {"kind": kind, "title": str(item.get("title") or ""), "tags": list(item.get("tags") or []),
                    "favorite": bool(item.get("favorite")), "collection_ids": list(item.get("collection_ids") or []),
                    "revision": item.get("revision"), "values": values, "protected_present": present}
        finally:
            (item.get("payload") or {}).clear()

    def save(self, ref: dict[str, Any] | None, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        if kind not in KIND_LABELS or kind == "document" and ref is None:
            raise ApiError("invalid", t("typed.err.chooseSupported"))
        title = str(data.get("title") or "").strip()
        if not title:
            raise ApiError("invalid", t("typed.err.titleEmpty"))
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        schema = {f["name"]: f for f in _fields_for(kind)}
        values = {k: v for k, v in dict(data.get("values") or {}).items() if k in schema and not schema[k]["protected"]}
        protected = {k: str(v) for k, v in dict(data.get("protected") or {}).items()
                     if k in schema and schema[k]["protected"] and v not in (None, "")}
        cleared = {k: "" for k in data.get("clear") or [] if k in schema and schema[k]["protected"]}
        payload = self._coerce(kind, {**values, **protected, **cleared}, creating=ref is None)
        metadata = {"favorite": bool(data.get("favorite")), "tags": [str(t) for t in data.get("tags") or []]}
        items = session.item_service
        try:
            if ref is None:
                item_id = self._create(items, kind, title, payload, metadata)
            else:
                item_id = self._typed_ref(ref)
                current = self._item(session, item_id, protected=False)
                expected = data.get("revision")
                if isinstance(expected, bool) or not isinstance(expected, int):
                    # An update without the revision the page edited would overwrite blindly.
                    raise ApiError("changed", t("typed.err.changed"))
                if str(current.get("kind")) != kind:
                    raise ApiError("invalid", t("typed.err.typeFixed"))
                if kind in PURCHASE_LIKE and "amount_minor" not in payload and current.get("payload", {}).get("currency"):
                    raise ApiError("invalid", t("typed.err.amountKept"))
                if kind == "note":
                    ok = items.update_item(item_id, title=title, body=payload.get("body"),
                                           expected_revision=expected, **metadata)
                elif kind == "bookmark":
                    ok = items.update_item(item_id, title=title, url=payload.get("url"), notes=payload.get("notes"),
                                           expected_revision=expected, **metadata)
                else:
                    if kind in SECRET_FORM_HIDDEN_FIELDS:
                        payload = {k: v for k, v in payload.items() if k not in SECRET_FORM_HIDDEN_FIELDS[kind]}
                    ok = items.update_typed_item(item_id, payload=payload, title=title,
                                                 expected_revision=expected, **metadata)
                if not ok and session.item_service.get_item(item_id) is None:
                    raise ApiError("not_found", t("typed.err.itemGone"))
                # ok False with the item still there: nothing changed, which is a successful save.
        except ItemLimitReached as exc:
            self._port.show_upgrade(limit=exc.limit, message=str(exc), on_enter=lambda: None)
            raise ApiError("item_limit", str(exc)) from None
        except (ItemSchemaError, ValueError) as exc:
            raise ApiError("invalid", str(exc)) from None
        except VaultError as exc:
            message = str(exc)
            code = "changed" if "revision" in message.lower() or "changed" in message.lower() else "vault_error"
            raise ApiError(code, message) from None
        finally:
            payload.clear()
            protected.clear()
        self._controller.touch()
        return {"ref": {"source": "typed", "id": item_id, "kind": kind}}

    @staticmethod
    def _coerce(kind: str, payload: dict[str, Any], *, creating: bool = True) -> dict[str, Any]:
        out = dict(payload)
        if kind in PURCHASE_LIKE:
            amount = str(out.pop("amount_minor", "") or "").strip()
            currency = str(out.get("currency", "") or "").strip()
            if amount or currency:
                try:
                    out["amount_minor"] = int(amount or "0")
                except ValueError:
                    raise ApiError("invalid", t("typed.err.amountWhole")) from None
                out["currency"] = currency or "XXX"
            else:
                out.pop("currency", None)
            if "active" in out:
                out["active"] = bool(out["active"])
        if kind == "wifi" and "hidden" in out:
            out["hidden"] = bool(out["hidden"])
        if kind == "identity" and creating:
            # Updates keep blanks: the payload is merged, so "" is how a field is cleared.
            out = {k: v for k, v in out.items() if str(v).strip()}
        return out

    @staticmethod
    def _create(items: Any, kind: str, title: str, payload: dict[str, Any], metadata: dict[str, Any]) -> str:
        if kind == "note":
            return items.create_note(title, payload.get("body", ""), **metadata)
        if kind == "bookmark":
            return items.create_bookmark(title, payload.get("url", ""), notes=payload.get("notes", ""), **metadata)
        if kind == "license":
            return items.create_license(title, **payload, **metadata)
        return items.create_typed(kind, title, payload, **metadata)

    # --------------------------------------------------------- reveal/copy
    def _release(self, ref: dict[str, Any], field: str, verb: str) -> str:
        session = self._session()
        item_id = self._typed_ref(ref)
        item = self._item(session, item_id, protected=False)
        kind = str(item.get("kind"))
        schema = {f["name"]: f for f in _fields_for(kind)}
        if field in MASTER_HIDDEN_FIELDS.get(kind, ()):
            lease = self._controller.guard.lease()
            self._auth.reauthenticate(t("typed.confirmRevealNote" if verb == "reveal" else "typed.confirmCopyNote"), lease, allow_hello=False)
            self._controller.require_lease(lease)
            plain = self._item(session, item_id, protected=True)
            try:
                return str((plain.get("payload") or {}).get(field) or "")
            finally:
                (plain.get("payload") or {}).clear()
        if field not in schema or not schema[field]["protected"]:
            raise ApiError("invalid", t("typed.err.unsupportedField"))
        lease = self._controller.guard.lease()
        self._auth.reauthenticate(t("typed.confirmRevealField" if verb == "reveal" else "typed.confirmCopyField", field=field), lease, allow_hello=True)
        self._controller.require_lease(lease)
        intent = f"user-selected protected field {verb}"
        try:
            if kind == "license":
                getter = session.item_service.reveal_license_value if verb == "reveal" else session.item_service.copy_license_value
                return getter(item_id, intent=f"user-selected license {verb}")
            getter = session.item_service.reveal_secret if verb == "reveal" else session.item_service.copy_secret
            return getter(item_id, field, intent=intent)
        except (VaultError, ItemSchemaError, ValueError) as exc:
            raise ApiError("vault_error", str(exc)) from None

    def reveal(self, ref: dict[str, Any], field: str) -> dict[str, Any]:
        value = self._release(ref, field, "reveal")
        self._controller.touch()
        return {"value": value, "mask_after": REVEAL_SECONDS}

    def copy(self, ref: dict[str, Any], field: str) -> dict[str, Any]:
        value = self._release(ref, field, "copy")
        self._controller.clipboard.copy(value)
        self._controller.touch()
        return clipboard_result(f"{field.replace('_', ' ').capitalize()} copied.", self._controller.clipboard)
