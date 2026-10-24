"""Plaintext and encrypted exports of the vault.

Formats:

* :func:`export_csv` - Bitwarden CSV schema (``folder,favorite,type,name,
  notes,fields,reprompt,login_uri,login_username,login_password,login_totp``),
* :func:`export_json` - unencrypted Bitwarden JSON,
* :func:`export_keepass_xml` - KeePass 2 XML (importable by KeePass 2.x),
* :func:`export_kdbx` - encrypted KDBX 4 (AES-256, Argon2d, HMAC blocks,
  ChaCha20 protected stream) readable by KeePass 2.35+ and KeePassXC.

Writes are atomic (temporary file in the destination directory, then
``os.replace``) and the temporary file receives a restrictive ACL before it
becomes visible.  Every function returns an :class:`ExportSummary`; the UI
should show :class:`ExportWarning` texts before a plaintext export.
"""
from __future__ import annotations

import csv
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .importers import ImportedRecord
from .importers import kdbx as _kdbx
from .importers._source import iso_timestamp
from .importers.bitwarden import BITWARDEN_CSV_COLUMNS

EXPORT_FORMATS: dict[str, str] = {
    "csv": "Bitwarden-compatible CSV (plaintext)",
    "json": "Bitwarden JSON (plaintext)",
    "keepass-xml": "KeePass 2 XML (plaintext)",
    "kdbx": "KeePass KDBX 4 (encrypted)",
}
EXPORT_SUFFIXES = {"csv": ".csv", "json": ".json", "keepass-xml": ".xml", "kdbx": ".kdbx"}
# Same floor as the master password and .lgk backup passwords.
KDBX_MIN_PASSWORD = 12


class ExportWarning:
    """User-facing warning texts for the export UI."""

    PLAINTEXT = ("This export stores every password, note, custom field and one-time password secret as "
                 "plain text. Anyone who can read the file can read your passwords.")
    TOTP = ("Including one-time password secrets lets another password manager generate your codes, "
            "but it also removes the protection of your second factor if the file leaks.")
    SPREADSHEET = ("Do not open the CSV in a spreadsheet application; values beginning with =, +, - or @ "
                   "can be interpreted as formulas and the file may be cached in temporary locations.")
    DELETE_AFTER = ("Import the file into the destination application right away, then delete it and empty "
                    "the Recycle Bin. Cloud-synced folders and backups may keep copies.")
    KDBX = ("The .kdbx file is encrypted with the password you choose. Pick a long, unique password; "
            "there is no way to recover the contents without it.")
    PERMISSIONS = "The file's permissions could not be restricted to your Windows account."

    @classmethod
    def for_format(cls, export_format: str, *, include_totp: bool) -> tuple[str, ...]:
        if export_format == "kdbx":
            return (cls.KDBX,)
        warnings = [cls.PLAINTEXT]
        if include_totp:
            warnings.append(cls.TOTP)
        if export_format == "csv":
            warnings.append(cls.SPREADSHEET)
        warnings.append(cls.DELETE_AFTER)
        return tuple(warnings)


class ExportError(Exception):
    """The export could not be produced or written."""


@dataclass
class ExportSummary:
    path: Path
    format: str
    count: int
    skipped: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    include_totp: bool = False
    totp_count: int = 0
    warnings: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    permissions_restricted: bool = False
    encrypted: bool = False

    @property
    def label(self) -> str:
        return EXPORT_FORMATS.get(self.format, self.format)


# --------------------------------------------------------------------------- record collection
def _totp_uri(totp: Mapping[str, Any] | None, label: str) -> str:
    if not isinstance(totp, dict) or not totp.get("secret"):
        return ""
    name = quote(str(label or "account"), safe="@:")
    query = [f"secret={totp['secret']}"]
    issuer = str(totp.get("issuer") or "")
    if issuer:
        query.append(f"issuer={quote(issuer, safe='')}")
    digits = int(totp.get("digits", 6) or 6)
    period = int(totp.get("period", 30) or 30)
    algorithm = str(totp.get("algorithm") or "SHA1").upper()
    if digits != 6:
        query.append(f"digits={digits}")
    if period != 30:
        query.append(f"period={period}")
    if algorithm != "SHA1":
        query.append(f"algorithm={algorithm}")
    return f"otpauth://totp/{name}?" + "&".join(query)


def _custom_fields(values: Any) -> list[dict[str, Any]]:
    result = []
    for item in values or []:
        if isinstance(item, dict) and item.get("name"):
            result.append({"name": str(item["name"]), "value": str(item.get("value", "")), "hidden": bool(item.get("hidden", True))})
    return result


def entry_to_record(entry: Mapping[str, Any]) -> ImportedRecord | None:
    """Convert a vault credential (``web`` or ``desktop`` entry) into a record."""
    kind = entry.get("kind")
    scope = entry.get("scope") if isinstance(entry.get("scope"), dict) else {}
    label = str(entry.get("label") or "")
    if kind == "web":
        urls = [str(scope.get("origin"))] if scope.get("origin") else []
        folder = ""
    elif kind == "desktop":
        urls = []
        folder = "Desktop applications"
    else:
        return None
    record = ImportedRecord(
        kind="login", title=label or (urls[0] if urls else "Credential"), username=str(entry.get("username") or ""),
        password=str(entry.get("password") or ""), urls=urls, notes=str(entry.get("notes") or ""),
        totp_uri=_totp_uri(entry.get("totp"), label), folder=folder, favorite=bool(entry.get("favorite")),
        custom_fields=_custom_fields(entry.get("custom_fields")),
        created=int(entry["created_at"]) if entry.get("created_at") else None,
        modified=int(entry["updated_at"]) if entry.get("updated_at") else None,
        tags=[str(tag) for tag in entry.get("tags") or []],
    )
    if kind == "desktop":
        if scope.get("exe_path"):
            record.custom_fields.append({"name": "Application path", "value": str(scope["exe_path"]), "hidden": False})
        if scope.get("window_title"):
            record.custom_fields.append({"name": "Window title", "value": str(scope["window_title"]), "hidden": False})
    codes = [str(code) for code in entry.get("recovery_codes") or [] if code]
    if codes:
        record.custom_fields.append({"name": "Recovery codes", "value": "\n".join(codes), "hidden": True})
    return record


_HIDDEN_PAYLOAD_KEYS = {"license_value", "serial", "key", "password", "secret", "pin", "account_number"}


def item_to_record(item: Mapping[str, Any]) -> ImportedRecord | None:
    """Convert a typed catalog item (note, bookmark, identity, licence, ...) into a record."""
    kind = str(item.get("kind") or "")
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    base = {
        "title": str(item.get("title") or ""), "favorite": bool(item.get("favorite")),
        "tags": [str(tag) for tag in item.get("tags") or []],
        "created": int(item["created_at"]) if item.get("created_at") else None,
        "modified": int(item["updated_at"]) if item.get("updated_at") else None,
    }
    if kind == "note":
        return ImportedRecord(kind="note", notes=str(payload.get("body") or ""),
                              custom_fields=_custom_fields(payload.get("fields")), **base)
    if kind == "bookmark":
        url = str(payload.get("url") or "")
        return ImportedRecord(kind="login", urls=[url] if url else [], notes=str(payload.get("notes") or ""),
                              folder="Bookmarks", **base)
    if kind == "identity":
        values = {key: str(value) for key, value in payload.items() if key != "template_id" and isinstance(value, str) and value}
        return ImportedRecord(kind="identity", identity=values, **base)
    if kind in {"license", "purchase", "warranty", "subscription"}:
        record = ImportedRecord(kind="note", folder=kind.capitalize() + "s", **base)
        for key, value in payload.items():
            if key in {"template_id", "fields", "notes", "body"} or value in (None, "", [], {}):
                continue
            if isinstance(value, (str, int, float, bool)):
                record.custom_fields.append({"name": key.replace("_", " ").capitalize(), "value": str(value),
                                             "hidden": key in _HIDDEN_PAYLOAD_KEYS})
        record.notes = str(payload.get("notes") or payload.get("body") or "")
        record.custom_fields.extend(_custom_fields(payload.get("fields")))
        return record
    return None


def collect_export_records(session: Any) -> tuple[list[ImportedRecord], list[str]]:
    """Return every exportable record of an unlocked session plus skip diagnostics."""
    if hasattr(session, "is_unlocked") and not session.is_unlocked:
        raise ExportError("Vault is locked")
    records: list[ImportedRecord] = []
    diagnostics: list[str] = []
    for entry in session.all_entries():
        record = entry_to_record(entry)
        if record is None:
            diagnostics.append(f"Credential {entry.get('id', '?')} has an unsupported kind and was skipped.")
        else:
            records.append(record)
    items = getattr(session, "items", None)
    if items is not None:
        for summary in items.list_items():
            item = items.get_item(str(summary.get("id")), include_protected=True)
            if item is None:
                continue
            record = item_to_record(item)
            if record is None:
                diagnostics.append(f"{str(item.get('kind') or 'item').capitalize()} '{item.get('title', '')}' is not exportable and was skipped.")
            else:
                records.append(record)
    return records, diagnostics


def _records_from(source: Any) -> tuple[list[ImportedRecord], list[str]]:
    if hasattr(source, "all_entries"):
        return collect_export_records(source)
    records: list[ImportedRecord] = []
    diagnostics: list[str] = []
    for item in source:
        if isinstance(item, ImportedRecord):
            records.append(item)
        elif isinstance(item, Mapping):
            record = entry_to_record(item) if item.get("kind") in {"web", "desktop"} else item_to_record(item)
            if record is None:
                diagnostics.append("An entry with an unsupported kind was skipped.")
            else:
                records.append(record)
        else:
            raise ExportError("Export sources must be vault entries or ImportedRecord objects")
    return records, diagnostics


# --------------------------------------------------------------------------- writing
def _system32(executable: str) -> str:
    """Absolute path of a Windows tool so PATH entries cannot shadow it."""
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", executable)


def _current_user_sid() -> str | None:
    """Return the current Windows account SID (names can be ambiguous for icacls)."""
    try:
        import ctypes
        import ctypes.wintypes as wintypes

        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                                 ctypes.POINTER(wintypes.DWORD)]
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            return None
        try:
            size = wintypes.DWORD()
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                return None
            sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
            text = ctypes.c_wchar_p()
            if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid_pointer), ctypes.byref(text)):
                return None
            try:
                return text.value
            finally:
                kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            kernel32.CloseHandle(token)
    except (OSError, AttributeError, ValueError):
        pass
    try:
        output = subprocess.run([_system32("whoami.exe"), "/user", "/fo", "csv", "/nh"], check=True, capture_output=True,  # noqa: S603 - fixed System32 path, constant arguments
                                text=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        row = next(csv.reader(io.StringIO(output.strip())), None)
        if row and len(row) >= 2 and row[1].startswith("S-1-"):
            return row[1]
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return None


def _restrict_permissions(path: Path) -> bool:
    """Best effort: make ``path`` readable only by the current user."""
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
            return True
        sid = _current_user_sid()
        if not sid or not sid.startswith("S-1-"):
            # Never fall back to an account *name*: a bare user name can
            # resolve to the machine account and lock the owner out.
            return False
    except (OSError, ValueError):
        return False
    return _apply_windows_acl(path, sid)


def _icacls(path: Path, *arguments: str) -> None:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.run([_system32("icacls.exe"), str(path), *arguments], check=True, stdout=subprocess.DEVNULL,  # noqa: S603 - fixed System32 path, no shell
                   stderr=subprocess.DEVNULL, creationflags=flags, timeout=30)


def _owner_can_access(path: Path) -> bool:
    try:
        with open(path, "r+b"):
            return True
    except OSError:
        return False


def _apply_windows_acl(path: Path, sid: str) -> bool:
    """Grant only ``sid`` full control; on any failure restore inherited ACLs.

    The grant and the inheritance removal are issued in one icacls call so a
    failure cannot leave the file half-way between the two states, and the
    file is re-opened afterwards to prove the current user still has access.
    """
    try:
        _icacls(path, "/inheritance:r", "/grant:r", f"*{sid}:F")
        if _owner_can_access(path):
            return True
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    try:
        _icacls(path, "/reset")
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return False


def _restrict_directory(path: Path) -> bool:
    """Best effort: owner-only directory whose new children inherit the owner-only ACL."""
    try:
        if os.name != "nt":
            os.chmod(path, 0o700)
            return True
        sid = _current_user_sid()
        if not sid or not sid.startswith("S-1-"):
            return False
        _icacls(path, "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F")
        return True
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


_TEMP_PREFIX = ".lgk-export-"
# Leftovers younger than this may belong to an export still in progress.
STALE_TEMP_SECONDS = 60 * 60


def _plain_entry(path: Path) -> os.stat_result | None:
    """``lstat`` of ``path`` unless it is a symlink or junction (never followed)."""
    try:
        info = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0):
        return None
    return info


def sweep_stale_temporaries(directory: Path | str, *, max_age: float = STALE_TEMP_SECONDS) -> list[Path]:
    """Delete ``.lgk-export-*`` folders and ``.tmp`` files a crashed export left in ``directory``.

    Only entries older than ``max_age`` seconds are touched; a leftover
    folder is emptied of its own ``.lgk-export-*.tmp`` files only (anything
    else inside keeps it in place) and links or junctions are never followed.
    Returns the paths removed.
    """
    removed: list[Path] = []
    cutoff = time.time() - max_age
    try:
        candidates = [entry for entry in Path(directory).iterdir() if entry.name.startswith(_TEMP_PREFIX)]
    except OSError:
        return removed
    for entry in candidates:
        info = _plain_entry(entry)
        if info is None or info.st_mtime > cutoff:
            continue
        try:
            if stat.S_ISDIR(info.st_mode):
                for child in entry.iterdir():
                    child_info = _plain_entry(child)
                    if (child_info is not None and stat.S_ISREG(child_info.st_mode)
                            and child.name.startswith(_TEMP_PREFIX) and child.name.endswith(".tmp")):
                        child.unlink()
                entry.rmdir()
            elif stat.S_ISREG(info.st_mode) and entry.name.endswith(".tmp"):
                entry.unlink()
            else:
                continue
        except OSError:
            continue
        removed.append(entry)
    return removed


def atomic_write(path: Path | str, data: bytes, *, overwrite: bool = False, restrict: bool = True,
                 prepare: Callable[[Path], Any] | None = None) -> bool:
    """Write ``data`` to ``path`` via a same-volume temporary file and ``os.replace``.

    Returns whether restrictive permissions were applied.  With ``restrict``
    the owner-only ACL is in place before any byte is written: the temporary
    file is created inside a private directory that is restricted first (so
    the file is born with an inherited owner-only ACL and cannot be opened by
    another account in between), and the empty file itself is restricted
    before writing.  A handle opened earlier would otherwise keep its access.
    Nothing is left behind if any step fails, and an existing destination is
    never partially overwritten.  ``prepare`` runs on the finished temporary
    file before it is renamed into place (Save a copy uses it to add
    Mark-of-the-Web).  Temporaries a crash left in the destination folder are
    swept first.
    """
    destination = Path(path)
    if destination.exists() and not overwrite:
        raise ExportError("Export destination already exists")
    if destination.is_dir():
        raise ExportError("Export destination is a directory")
    private_dir: Path | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        sweep_stale_temporaries(destination.parent)
        directory = destination.parent
        if restrict:
            private_dir = Path(tempfile.mkdtemp(prefix=_TEMP_PREFIX, dir=destination.parent))
            _restrict_directory(private_dir)
            directory = private_dir
        fd, name = tempfile.mkstemp(prefix=_TEMP_PREFIX, suffix=".tmp", dir=directory)
    except OSError as exc:
        if private_dir is not None:
            shutil.rmtree(private_dir, ignore_errors=True)
        raise ExportError("Could not create the export file") from exc
    temporary = Path(name)
    restricted = False
    try:
        with os.fdopen(fd, "wb") as handle:
            if restrict:
                restricted = _restrict_permissions(temporary)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if prepare is not None:
            prepare(temporary)
        if destination.exists() and not overwrite:
            raise ExportError("Export destination already exists")
        os.replace(temporary, destination)
    except ExportError:
        temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ExportError("Could not write the export file") from exc
    finally:
        if private_dir is not None:
            shutil.rmtree(private_dir, ignore_errors=True)
    return restricted


def _summary(path: Path, export_format: str, records: list[ImportedRecord], diagnostics: list[str], *,
             include_totp: bool, restricted: bool, restrict_requested: bool, encrypted: bool) -> ExportSummary:
    by_kind: dict[str, int] = {}
    for record in records:
        by_kind[record.kind] = by_kind.get(record.kind, 0) + 1
    warnings = list(ExportWarning.for_format(export_format, include_totp=include_totp))
    if restrict_requested and not restricted:
        warnings.append(ExportWarning.PERMISSIONS)
    return ExportSummary(
        path=Path(path), format=export_format, count=len(records), skipped=len(diagnostics), by_kind=by_kind,
        include_totp=include_totp, totp_count=sum(1 for record in records if record.totp_uri),
        warnings=tuple(warnings), diagnostics=tuple(diagnostics), permissions_restricted=restricted, encrypted=encrypted,
    )


def _fields_column(record: ImportedRecord) -> str:
    lines = [f"{item['name']}: {item['value']}" for item in record.custom_fields]
    if record.kind == "identity":
        lines.extend(f"{key}: {value}" for key, value in record.identity.items())
    for extra in record.urls[1:] if record.kind != "login" else []:
        lines.append(f"url: {extra}")
    return "\n".join(lines)


def render_csv(records: Iterable[ImportedRecord], *, include_totp: bool) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(BITWARDEN_CSV_COLUMNS)
    for record in records:
        is_login = record.kind == "login"
        writer.writerow([
            record.folder, "1" if record.favorite else "", "login" if is_login else "note", record.title,
            record.notes, _fields_column(record), "0", ",".join(record.urls) if is_login else "",
            record.username if is_login else "", record.password if is_login else "",
            record.totp_uri if (is_login and include_totp) else "",
        ])
    return buffer.getvalue().encode("utf-8")


_IDENTITY_TO_BITWARDEN = {
    "given_name": "firstName", "middle_name": "middleName", "family_name": "lastName", "company": "company",
    "organization": "company", "email": "email", "phone": "phone", "address_line1": "address1",
    "address_line2": "address2", "address": "address1", "city": "city", "state": "state", "postal_code": "postalCode",
    "country": "country", "job_title": "title",
}


def _bitwarden_date(value: int | None) -> str:
    stamp = iso_timestamp(value) if value is not None else iso_timestamp(0)
    return stamp.replace("Z", ".000Z")


def render_json(records: Iterable[ImportedRecord], *, include_totp: bool) -> bytes:
    folders: dict[str, str] = {}
    items = []
    for record in records:
        folder_id = None
        if record.folder:
            folder_id = folders.setdefault(record.folder, str(uuid.uuid4()))
        fields = [{"name": item["name"], "value": item["value"], "type": 1 if item["hidden"] else 0, "linkedId": None}
                  for item in record.custom_fields]
        item: dict[str, Any] = {
            "passwordHistory": None, "revisionDate": _bitwarden_date(record.modified or record.created),
            "creationDate": _bitwarden_date(record.created), "deletedDate": None, "id": str(uuid.uuid4()),
            "organizationId": None, "folderId": folder_id, "type": 1, "reprompt": 0, "name": record.title,
            "notes": record.notes or None, "favorite": bool(record.favorite), "fields": fields, "collectionIds": None,
        }
        if record.kind == "login":
            item["type"] = 1
            item["login"] = {
                "fido2Credentials": [], "uris": [{"match": None, "uri": url} for url in record.urls],
                "username": record.username or None, "password": record.password or None,
                "totp": record.totp_uri if (include_totp and record.totp_uri) else None,
            }
        elif record.kind == "identity":
            item["type"] = 4
            identity = {key: None for key in ("title", "firstName", "middleName", "lastName", "address1", "address2", "address3",
                                              "city", "state", "postalCode", "country", "company", "email", "phone", "ssn",
                                              "username", "passportNumber", "licenseNumber")}
            for key, value in record.identity.items():
                target = _IDENTITY_TO_BITWARDEN.get(key)
                if target and value and not identity.get(target):
                    identity[target] = value
            item["identity"] = identity
        elif record.kind == "card":
            item["type"] = 3
            named = {entry["name"].casefold(): entry["value"] for entry in record.custom_fields}
            expiry = named.get("expiry", "")
            month, _, year = expiry.partition("/")
            item["card"] = {"cardholderName": named.get("cardholder name"), "brand": named.get("brand"),
                            "number": named.get("number"), "expMonth": month or None, "expYear": year or None,
                            "code": named.get("security code")}
            item["fields"] = [entry for entry in fields if entry["name"].casefold() not in
                              {"cardholder name", "brand", "number", "expiry", "security code"}]
        else:
            item["type"] = 2
            item["secureNote"] = {"type": 0}
        if record.tags:
            item["fields"].append({"name": "tags", "value": ", ".join(record.tags), "type": 0, "linkedId": None})
        items.append(item)
    document = {"encrypted": False, "folders": [{"id": fid, "name": name} for name, fid in folders.items()], "items": items}
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")


def render_keepass_xml(records: Iterable[ImportedRecord], *, include_totp: bool, database_name: str = "LocalGateKeys") -> bytes:
    body = _kdbx.build_keepass_xml(records, protect=False, version=3, database_name=database_name, include_totp=include_totp)
    return ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n' + body).encode("utf-8")


def _export(source: Any, path: Path | str, export_format: str, renderer, *, include_totp: bool, overwrite: bool,
            restrict: bool, encrypted: bool) -> ExportSummary:
    records, diagnostics = _records_from(source)
    data = renderer(records)
    try:
        restricted = atomic_write(path, data, overwrite=overwrite, restrict=restrict)
    finally:
        data = b""
    return _summary(Path(path), export_format, records, diagnostics, include_totp=include_totp, restricted=restricted,
                    restrict_requested=restrict, encrypted=encrypted)


def export_csv(session_or_entries: Any, path: Path | str, *, include_totp: bool = False, overwrite: bool = False,
               restrict_permissions: bool = True) -> ExportSummary:
    """Write a Bitwarden-compatible CSV (plaintext)."""
    return _export(session_or_entries, path, "csv", lambda records: render_csv(records, include_totp=include_totp),
                   include_totp=include_totp, overwrite=overwrite, restrict=restrict_permissions, encrypted=False)


def export_json(session_or_entries: Any, path: Path | str, *, include_totp: bool = False, overwrite: bool = False,
                restrict_permissions: bool = True) -> ExportSummary:
    """Write an unencrypted Bitwarden JSON export (plaintext)."""
    return _export(session_or_entries, path, "json", lambda records: render_json(records, include_totp=include_totp),
                   include_totp=include_totp, overwrite=overwrite, restrict=restrict_permissions, encrypted=False)


def export_keepass_xml(session_or_entries: Any, path: Path | str, *, include_totp: bool = False, overwrite: bool = False,
                       restrict_permissions: bool = True) -> ExportSummary:
    """Write a KeePass 2 XML export (plaintext)."""
    return _export(session_or_entries, path, "keepass-xml",
                   lambda records: render_keepass_xml(records, include_totp=include_totp),
                   include_totp=include_totp, overwrite=overwrite, restrict=restrict_permissions, encrypted=False)


def export_kdbx(session_or_entries: Any, path: Path | str, password: str, *, include_totp: bool = True,
                overwrite: bool = False, restrict_permissions: bool = True, kdf_params: Mapping[str, Any] | None = None,
                keyfile: bytes | Path | None = None, database_name: str = "LocalGateKeys") -> ExportSummary:
    """Write an encrypted KDBX 4 database (AES-256-CBC, Argon2d, HMAC-SHA256 blocks)."""
    if not password or len(password) < KDBX_MIN_PASSWORD:
        raise ExportError(f"Choose a password of at least {KDBX_MIN_PASSWORD} characters for the .kdbx export")
    try:
        return _export(
            session_or_entries, path, "kdbx",
            lambda records: _kdbx.write_kdbx(records, password, version=4, cipher="aes256", kdf="argon2d",
                                             kdf_params=kdf_params, keyfile=keyfile, database_name=database_name,
                                             include_totp=include_totp),
            include_totp=include_totp, overwrite=overwrite, restrict=restrict_permissions, encrypted=True)
    except _kdbx.KdbxError as exc:
        raise ExportError(str(exc)) from exc


def export_records(session_or_entries: Any, path: Path | str, export_format: str, *, include_totp: bool = False,
                   password: str | None = None, overwrite: bool = False, **kwargs: Any) -> ExportSummary:
    """Dispatch on ``export_format`` (one of :data:`EXPORT_FORMATS`)."""
    if export_format == "csv":
        return export_csv(session_or_entries, path, include_totp=include_totp, overwrite=overwrite, **kwargs)
    if export_format == "json":
        return export_json(session_or_entries, path, include_totp=include_totp, overwrite=overwrite, **kwargs)
    if export_format == "keepass-xml":
        return export_keepass_xml(session_or_entries, path, include_totp=include_totp, overwrite=overwrite, **kwargs)
    if export_format == "kdbx":
        return export_kdbx(session_or_entries, path, password or "", include_totp=include_totp, overwrite=overwrite, **kwargs)
    raise ExportError(f"Unknown export format {export_format!r}")


__all__ = [
    "EXPORT_FORMATS", "EXPORT_SUFFIXES", "KDBX_MIN_PASSWORD", "ExportError", "ExportSummary", "ExportWarning",
    "atomic_write", "sweep_stale_temporaries",
    "collect_export_records", "entry_to_record", "export_csv", "export_json", "export_kdbx", "export_keepass_xml",
    "export_records", "item_to_record", "render_csv", "render_json", "render_keepass_xml",
]
