"""Credential Exchange Format (CXF v1.0) account export.

The exact inverse of :mod:`localvault.importers.cxf`: one CXF ``Account``
document whose ``items`` hold one item per record, so a file written here
imports back into the same records.

* login -> ``basic-auth`` (``scope.urls``, username, password), its 2FA setup
  as a ``totp`` credential and its notes as a ``note`` credential;
* note -> an item with a single ``note`` credential;
* passkey -> a ``passkey`` credential whose ``key`` is the base64url PKCS#8
  DER private key (the form the spec and the importer read).

Only the items the user selected are exported.  Passkey private keys are
never read from the vault here: the caller's ``release_private_keys``
callback releases them through the protected-field path after
re-authentication, and if it refuses (raises) nothing is written.  The
document is built fully in memory and written with :func:`atomic_write`
(temporary file, then rename), so a failed export leaves no file behind.
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from ..i18n import t
from ..importers import ImportedRecord, totp_uri_from_secret
from ..importers.cxf import PASSKEY_KEYS

_ALGORITHMS = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _new_id() -> str:
    return _b64u(os.urandom(16))


def _field(value: str, field_type: str = "string") -> dict[str, Any]:
    return {"id": _new_id(), "fieldType": field_type, "value": value}


def _totp_credential(uri: str) -> dict[str, Any] | None:
    """Split an ``otpauth://totp`` URI into a CXF ``totp`` credential."""
    parts = urlsplit(uri)
    if parts.scheme.casefold() != "otpauth" or parts.netloc.casefold() != "totp":
        return None
    query = {key.casefold(): values[0] for key, values in parse_qs(parts.query).items() if values}
    secret = query.get("secret", "").strip()
    if not secret:
        return None
    label = unquote(parts.path.lstrip("/"))
    issuer = query.get("issuer", "")
    prefix, colon, account = label.partition(":")
    if colon:
        issuer = issuer or prefix
    else:
        account = "" if label == "account" else label
    credential: dict[str, Any] = {"type": "totp", "secret": secret,
                                  "period": int(query["period"]) if query.get("period", "").isdigit() else 30,
                                  "digits": int(query["digits"]) if query.get("digits", "").isdigit() else 6,
                                  "algorithm": _ALGORITHMS.get(query.get("algorithm", "SHA1").upper(), "sha1")}
    if account:
        credential["username"] = account
    if issuer:
        credential["issuer"] = issuer
    return credential


def _date_stamp(text: str) -> int | None:
    try:
        day = _dt.date.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return int(_dt.datetime(day.year, day.month, day.day, tzinfo=_dt.timezone.utc).timestamp())


def _item(record: ImportedRecord, now: int) -> dict[str, Any]:
    item: dict[str, Any] = {"id": _new_id()}
    credentials: list[dict[str, Any]] = []
    created = record.created
    if record.kind == "login":
        # Always present, even when empty: without it the importer would read the item as a note (or drop it).
        credentials.append({"type": "basic-auth", "username": _field(record.username),
                            "password": _field(record.password, "concealed-string")})
        totp = _totp_credential(record.totp_uri) if record.totp_uri else None
        if totp is not None:
            credentials.append(totp)
        if record.notes:
            credentials.append({"type": "note", "content": _field(record.notes)})
    elif record.kind == "note":
        credentials.append({"type": "note", "content": _field(record.notes)})
    elif record.kind == "passkey":
        payload = {entry["name"]: entry["value"] for entry in record.custom_fields if entry["name"] in PASSKEY_KEYS}
        passkey = {"type": "passkey", "credentialId": payload.get("credential_id", ""),
                   "rpId": payload.get("relying_party_id", ""), "username": payload.get("user_name", ""),
                   "userDisplayName": payload.get("user_display_name", ""),
                   "userHandle": payload.get("user_handle", ""), "key": payload.get("private_key", "")}
        credentials.append(passkey)
        created = _date_stamp(payload.get("created", "")) or created
    else:
        raise ValueError(f"CXF export cannot hold a {record.kind!r} record")
    if created:
        item["creationAt"] = int(created)
    item["modifiedAt"] = int(record.modified or created or now)
    item["title"] = record.title
    item["scope"] = {"urls": list(record.urls), "androidApps": []}
    item["credentials"] = credentials
    return item


def build_cxf(records: Iterable[ImportedRecord], *, exporter_name: str = "LocalGateKeys",
              now: _dt.datetime) -> bytes:
    """One CXF ``Account`` document with an item per record (logins, notes and passkeys only).

    ``exporter_name`` names the exporting account; ``now`` dates items whose
    modification time is unknown.  Raises ``ValueError`` for other kinds.
    """
    stamp = int(now.timestamp())
    document = {"id": _new_id(), "username": exporter_name, "email": "", "collections": [],
                "items": [_item(record, stamp) for record in records], "extensions": []}
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------- vault -> records
def _entry_urls(entry: dict[str, Any]) -> list[str]:
    scope = entry.get("scope") if isinstance(entry.get("scope"), dict) else {}
    rows = scope.get("urls")
    urls = [str(row.get("url")) for row in rows if isinstance(row, dict) and row.get("url")] if isinstance(rows, list) else []
    if not urls and scope.get("origin"):
        urls = [str(scope["origin"])]
    return urls


def _login_record(entry: dict[str, Any], include_totp: bool) -> tuple[ImportedRecord, bool]:
    """The login as a record, and whether it held data CXF has no place for (custom fields, codes)."""
    from ..export import entry_to_record

    record = entry_to_record(entry)
    if record is None:
        raise ValueError("only web and desktop entries are logins")
    record.urls = _entry_urls(entry) if entry.get("kind") == "web" else []
    record.folder = ""
    record.totp_uri = ""
    totp = entry.get("totp")
    if include_totp and isinstance(totp, dict) and totp.get("secret"):
        issuer = str(totp.get("issuer") or "")
        username = record.username
        label = f"{issuer}:{username}" if issuer and username else (username or issuer)
        record.totp_uri = totp_uri_from_secret(str(totp["secret"]), label=label, issuer=issuer,
                                               digits=int(totp.get("digits", 6) or 6),
                                               period=int(totp.get("period", 30) or 30),
                                               algorithm=str(totp.get("algorithm") or "SHA1"))
    dropped = bool(record.custom_fields)
    record.custom_fields = []
    return record, dropped


def _passkey_record(item: dict[str, Any]) -> ImportedRecord:
    """The passkey without its private key (added after release)."""
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    values = {key: str(payload.get(key) or "") for key in PASSKEY_KEYS if key != "private_key"}
    if not values["created"] and item.get("created_at"):
        values["created"] = _dt.datetime.fromtimestamp(int(item["created_at"]), _dt.timezone.utc).date().isoformat()
    rp_id = values["relying_party_id"]
    return ImportedRecord(kind="passkey", title=str(item.get("title") or rp_id), username=values["user_name"],
                          urls=[f"https://{rp_id}"] if rp_id else [],
                          custom_fields=[{"name": key, "value": values[key], "hidden": False}
                                         for key in PASSKEY_KEYS if key != "private_key" and values[key]])


def _with_private_key(record: ImportedRecord, private_key: str) -> None:
    fields = {entry["name"]: entry for entry in record.custom_fields}
    fields["private_key"] = {"name": "private_key", "value": private_key, "hidden": True}
    record.custom_fields = [fields[key] for key in PASSKEY_KEYS if key in fields]


def export_cxf(session: Any, ids: list[str], path: Path | str, *,
               release_private_keys: Callable[[list[str]], dict[str, str]], include_totp: bool = True,
               overwrite: bool = False, restrict_permissions: bool = True,
               exporter_name: str = "LocalGateKeys"):
    """Write the selected items (``ids``) as a CXF file and return an ``ExportSummary``.

    ``release_private_keys`` receives the ids of the selected passkeys and
    returns ``{id: private key}``; it is called only when a passkey is
    selected, after every other record is collected and before anything is
    written.  Any exception it raises (``PermissionError`` when the user
    declines) propagates and no file is created.
    """
    from ..export import ExportError, _summary, atomic_write, item_to_record

    if hasattr(session, "is_unlocked") and not session.is_unlocked:
        raise ExportError("Vault is locked")
    wanted = list(dict.fromkeys(str(item_id) for item_id in ids or ()))
    if not wanted:
        raise ExportError(t("export.cxfChooseItems"))
    entries = {str(entry.get("id")): entry for entry in session.all_entries()}
    items = getattr(session, "items", None)
    records: list[ImportedRecord] = []
    passkeys: dict[str, ImportedRecord] = {}
    diagnostics: list[str] = []
    try:
        for item_id in wanted:
            entry = entries.get(item_id)
            if entry is not None and entry.get("kind") in {"web", "desktop"}:
                record, dropped = _login_record(entry, include_totp)
                records.append(record)
                if dropped:
                    diagnostics.append(t("export.cxfFieldsLeftOut", title=record.title))
                continue
            item = items.get_item(item_id) if items is not None else None
            kind = str(item.get("kind") or "") if item else ""
            if kind == "passkey":
                record = _passkey_record(item)
                payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
                if str(payload.get("notes") or "").strip():
                    diagnostics.append(t("export.cxfPasskeyNotesLeftOut", title=record.title))
                payload.clear()
                passkeys[item_id] = record
                records.append(record)
            elif kind == "note":
                full = items.get_item(item_id, include_protected=True) or {}
                try:
                    record = item_to_record(full)
                    if record is not None and record.custom_fields:
                        diagnostics.append(t("export.cxfFieldsLeftOut", title=record.title))
                        record.custom_fields = []
                    if record is not None:
                        records.append(record)
                finally:
                    payload = full.get("payload")
                    if isinstance(payload, dict):
                        payload.clear()
            else:
                title = str((item or entry or {}).get("title") or (entry or {}).get("label") or "")
                diagnostics.append(t("export.cxfKindSkipped", title=title or item_id))
        if passkeys:
            released = release_private_keys(list(passkeys))
            try:
                for item_id, record in passkeys.items():
                    key = released.get(item_id) if isinstance(released, dict) else None
                    if not isinstance(key, str) or not key:
                        raise ExportError(t("export.cxfPasskeyKeyMissing", title=record.title))
                    _with_private_key(record, key)
            finally:
                if isinstance(released, dict):
                    released.clear()
        if not records:
            raise ExportError(t("export.cxfNothingToExport"))
        data = build_cxf(records, exporter_name=exporter_name, now=_dt.datetime.now(_dt.timezone.utc))
        try:
            restricted = atomic_write(path, data, overwrite=overwrite, restrict=restrict_permissions)
        finally:
            data = b""
        return _summary(Path(path), "cxf", records, diagnostics, include_totp=include_totp, restricted=restricted,
                        restrict_requested=restrict_permissions, encrypted=False)
    finally:
        for record in records:
            record.wipe()
        for entry in entries.values():  # deep copies holding every login's secrets, selected or not
            entry.clear()


__all__ = ["build_cxf", "export_cxf"]
