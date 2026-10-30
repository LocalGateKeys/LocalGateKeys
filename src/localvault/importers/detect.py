"""Format detection (extension + content sniffing) and the loader dispatcher."""
from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import (
    ImporterError,
    ImportFormatError,
    ImportPasswordRequired,
    ImportResult,
    cap_diagnostics,
)
from ._source import decode_text, normalize_header, read_csv_table, read_source_bytes
from ..i18n import t

SUPPORTED_FORMATS: dict[str, str] = {
    "kdbx": "KeePass 2 database (.kdbx)",
    "keepass-xml": "KeePass 2 XML export",
    "keepass-csv": "KeePass / KeePassXC CSV",
    "1pux": "1Password export (.1pux)",
    "1password-csv": "1Password CSV",
    "protonpass-json": "Proton Pass export (.zip / JSON)",
    "protonpass-csv": "Proton Pass CSV",
    "bitwarden-json": "Bitwarden JSON",
    "bitwarden-encrypted-json": "Bitwarden password-protected JSON",
    "bitwarden-csv": "Bitwarden CSV",
    "lastpass-csv": "LastPass CSV",
    "dashlane-zip": "Dashlane export (.zip of CSV files)",
    "dashlane-csv": "Dashlane CSV",
    "chrome-csv": "Chrome / Edge / Brave passwords CSV",
    "firefox-csv": "Firefox logins CSV",
    "safari-csv": "Safari passwords CSV",
    "csv": "Generic CSV (choose columns)",
}
PASSWORD_FORMATS = frozenset({"kdbx", "bitwarden-encrypted-json"})
CSV_FORMATS = frozenset({"keepass-csv", "1password-csv", "bitwarden-csv", "lastpass-csv", "dashlane-csv",
                         "protonpass-csv", "chrome-csv", "firefox-csv", "safari-csv", "csv"})
FILE_DIALOG_PATTERNS = "*.kdbx *.1pux *.zip *.json *.csv *.xml"
DAMAGED_MESSAGE = ("detect.couldNotBeReadThe")
_PGP_ARMOR = b"-----BEGIN PGP MESSAGE-----"
_DASHLANE_ZIP_FILES = frozenset({"credentials.csv", "securenotes.csv", "payments.csv", "ids.csv", "personalinfo.csv"})
# Exceptions a parser bug could leak on hostile input; load_records converts
# them to ImportFormatError so the UI always gets one friendly error type.
_PARSER_LEAKS = (KeyError, IndexError, TypeError, AttributeError, ValueError, RecursionError, UnicodeError,
                 OverflowError, struct.error, zlib.error, EOFError, zipfile.BadZipFile, NotImplementedError)
_KDBX_MAGIC = b"\x03\xd9\xa2\x9a"


@dataclass(frozen=True)
class Detection:
    format: str
    needs_password: bool
    confidence: str
    reason: str
    fields: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return SUPPORTED_FORMATS.get(self.format, self.format)

    @property
    def is_csv(self) -> bool:
        return self.format in CSV_FORMATS


def _detect_csv(text: str) -> Detection:
    header, _rows = read_csv_table(text)
    keys = {normalize_header(cell) for cell in header}
    fields = tuple(header)

    def found(name: str, reason: str) -> Detection:
        return Detection(name, False, "high", reason, fields)

    if {"type", "name", "url", "username", "password", "note", "totp", "vault"} <= keys:
        return found("protonpass-csv", "Proton Pass CSV columns")
    if {"login uri", "login username", "login password"} <= keys:
        return found("bitwarden-csv", "Bitwarden login_* columns")
    if {"url", "username", "password", "extra", "grouping"} <= keys:
        return found("lastpass-csv", "LastPass extra/grouping columns")
    if {"title", "password"} <= keys and ({"username2", "otpsecret"} & keys or (keys >= {"title", "url", "username", "password", "note"} and "category" in keys)):
        return found("dashlane-csv", "Dashlane credential columns")
    if keys in ({"title", "note"}, {"title", "note", "category"}):
        return found("dashlane-csv", "Dashlane secure notes columns")
    from .dashlane import classify_header as dashlane_layout
    if dashlane_layout(header) in {"payments", "personal", "ids"}:
        return found("dashlane-csv", "Dashlane payments / IDs / personal info columns")
    if {"title", "url", "username", "password"} <= keys and ({"favorite", "archived", "tags"} & keys):
        return found("1password-csv", "1Password 8 CSV columns")
    if {"url", "username", "password", "httprealm", "formactionorigin"} <= keys:
        return found("firefox-csv", "Firefox logins columns")
    if {"title", "url", "username", "password", "otpauth"} <= keys:
        return found("safari-csv", "Safari passwords columns")
    if {"account", "login name", "password"} <= keys or {"group", "title", "username", "password", "url"} <= keys:
        return found("keepass-csv", "KeePass CSV columns")
    if {"name", "url", "username", "password"} <= keys:
        return found("chrome-csv", "Chrome/Edge passwords columns")
    if {"title", "url", "username", "password", "note"} <= keys:
        return found("dashlane-csv", "Legacy Dashlane columns")
    return Detection("csv", False, "low", "Unrecognised CSV header; column mapping required", fields)


def _detect_json(text: str, path: Path) -> Detection:
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ImportFormatError(t("detect.theFileLooksLikeJson")) from exc
    if not isinstance(document, dict):
        raise ImportFormatError(t("detect.unsupportedJsonDocument"))
    if isinstance(document.get("vaults"), dict):
        if document.get("encrypted") is True:
            from .protonpass import ENCRYPTED_MESSAGE
            raise ImportFormatError(t(ENCRYPTED_MESSAGE))
        return Detection("protonpass-json", False, "high", "Proton Pass vaults object")
    if document.get("encrypted") is True:
        if not document.get("passwordProtected"):
            from .bitwarden import ACCOUNT_RESTRICTED_MESSAGE
            raise ImportFormatError(t(ACCOUNT_RESTRICTED_MESSAGE))
        if "data" in document:
            return Detection("bitwarden-encrypted-json", True, "high", "Bitwarden encrypted envelope")
    if isinstance(document.get("items"), list):
        return Detection("bitwarden-json", False, "high", "Bitwarden items list")
    if isinstance(document.get("accounts"), list):
        return Detection("1pux", False, "high", "1Password export.data accounts list")
    raise ImportFormatError(t("detect.thisJsonFileIsNot"))


def detect_format(path: Path | str, data: bytes | None = None) -> Detection:
    """Detect the import format of ``path`` from its content (extension as a hint).

    Raises only :class:`ImporterError` subclasses, with a message that tells
    the user what to do next.
    """
    try:
        return _detect_format(Path(path), data)
    except ImporterError:
        raise
    except _PARSER_LEAKS as exc:
        raise ImportFormatError(t("detect.theFileCouldNotBe")) from exc


def _detect_format(path: Path, data: bytes | None) -> Detection:
    if data is None:
        data = read_source_bytes(path, limit=64 * 1024 * 1024)
    suffix = path.suffix.casefold()
    head = data[:16]
    if head[:4] == _KDBX_MAGIC:
        if head[4:8] == b"\x65\xfb\x4b\xb5":
            raise ImportFormatError(t("detect.keepass1XKdbDatabases"))
        return Detection("kdbx", True, "high", "KDBX signature")
    if suffix in {".kdbx", ".kdb"}:
        raise ImportFormatError(t("detect.theFileDoesNotHave"))
    if head[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
        except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, ValueError) as exc:
            raise ImportFormatError(t("detect.theArchiveIsCorrupted")) from exc
        if "export.data" in names:
            return Detection("1pux", False, "high", "Zip archive containing export.data")
        basenames = {name.rsplit("/", 1)[-1].casefold() for name in names}
        if "data.pgp" in basenames:
            from .protonpass import ENCRYPTED_MESSAGE
            raise ImportFormatError(t(ENCRYPTED_MESSAGE))
        if "data.json" in basenames:
            return Detection("protonpass-json", False, "high", "Zip archive containing Proton Pass data.json")
        if basenames & _DASHLANE_ZIP_FILES:
            return Detection("dashlane-zip", False, "high", "Zip archive containing Dashlane CSV files")
        raise ImportFormatError(t("detect.thisZipArchiveIsNot"))
    if suffix == ".1pux":
        raise ImportFormatError(t("detect.the1puxFileIsNot"))
    if suffix == ".1pif":
        raise ImportFormatError(t("detect.t1password71pifFilesAre"))
    if data.lstrip()[:len(_PGP_ARMOR)] == _PGP_ARMOR or suffix in {".pgp", ".gpg"}:
        raise ImportFormatError(t("detect.thisFileIsPgpEncrypted"))
    try:
        text = decode_text(data[:4 * 1024 * 1024] if len(data) > 4 * 1024 * 1024 else data)
    except ImportFormatError:
        raise ImportFormatError("Unsupported binary file") from None
    stripped = text.lstrip("﻿ \t\r\n")
    if stripped.startswith("{"):
        return _detect_json(decode_text(data), path)
    if stripped.startswith("<"):
        if "<KeePassFile" in stripped[:4096]:
            return Detection("keepass-xml", False, "high", "KeePassFile XML root")
        raise ImportFormatError(t("detect.unsupportedXmlDocumentExpectedA"))
    if "\x00" in stripped[:4096] or not stripped:
        raise ImportFormatError(t("detect.unsupportedOrEmptyFile"))
    if suffix in {".csv", ".txt", ".tsv", ""} or "," in stripped.splitlines()[0] or ";" in stripped.splitlines()[0] or "\t" in stripped.splitlines()[0]:
        return _detect_csv(decode_text(data))
    raise ImportFormatError(t("detect.unsupportedFileType"))


def load_records(path: Path | str, *, password: str | None = None, keyfile: bytes | Path | str | None = None,
                 source_format: str | None = None, column_mapping: Mapping[str, str] | None = None) -> ImportResult:
    """Detect (or honour ``source_format``) and load ``path`` into records.

    Raises :class:`ImportPasswordRequired` for encrypted sources without a
    password and :class:`ImportFormatError` for unknown formats.
    """
    path = Path(path)
    if source_format is None:
        source_format = detect_format(path).format
    if source_format not in SUPPORTED_FORMATS:
        raise ImportFormatError(f"Unsupported import format {source_format!r}")
    if source_format in PASSWORD_FORMATS and not password and not keyfile:
        raise ImportPasswordRequired(t("detect.requiresAPassword", v1=SUPPORTED_FORMATS[source_format]))
    try:
        result = _load(path, source_format, password=password, keyfile=keyfile, column_mapping=column_mapping)
        result.diagnostics = cap_diagnostics(result.diagnostics)
        return result
    except ImporterError:
        raise
    except _PARSER_LEAKS as exc:
        raise ImportFormatError(t(DAMAGED_MESSAGE, label=t(SUPPORTED_FORMATS[source_format]))) from exc


def _load(path: Path, source_format: str, *, password: str | None, keyfile: bytes | Path | str | None,
          column_mapping: Mapping[str, str] | None) -> ImportResult:
    if source_format == "kdbx":
        from .kdbx import load_kdbx
        return load_kdbx(path, password, keyfile=keyfile)
    if source_format == "keepass-xml":
        from .kdbx import load_keepass_xml
        return load_keepass_xml(path)
    if source_format == "keepass-csv":
        from .keepass_csv import load_keepass_csv
        return load_keepass_csv(path)
    if source_format == "1pux":
        from .onepassword import load_1pux
        return load_1pux(path)
    if source_format == "1password-csv":
        from .onepassword import load_1password_csv
        return load_1password_csv(path)
    if source_format == "protonpass-json":
        from .protonpass import load_protonpass_json
        return load_protonpass_json(path)
    if source_format == "protonpass-csv":
        from .protonpass import load_protonpass_csv
        return load_protonpass_csv(path)
    if source_format == "dashlane-zip":
        from .dashlane import load_dashlane_zip
        return load_dashlane_zip(path)
    if source_format in {"bitwarden-json", "bitwarden-encrypted-json"}:
        from .bitwarden import load_bitwarden_json
        return load_bitwarden_json(path, password=password)
    if source_format == "bitwarden-csv":
        from .bitwarden import load_bitwarden_csv
        return load_bitwarden_csv(path)
    if source_format == "lastpass-csv":
        from .lastpass import load_lastpass_csv
        return load_lastpass_csv(path)
    if source_format == "dashlane-csv":
        from .dashlane import load_dashlane_csv
        return load_dashlane_csv(path)
    if source_format in {"chrome-csv", "firefox-csv", "safari-csv"}:
        from .chrome import load_browser_csv
        return load_browser_csv(path)
    from .chrome import load_generic_csv
    return load_generic_csv(path, column_mapping=column_mapping)


def csv_header(path: Path | str) -> tuple[str, ...]:
    """Return the raw header row of a CSV source for column-mapping UIs."""
    header, _rows = read_csv_table(decode_text(read_source_bytes(path)))
    return tuple(header)


def describe(value: Any) -> str:
    return SUPPORTED_FORMATS.get(str(value), str(value))


__all__ = ["CSV_FORMATS", "DAMAGED_MESSAGE", "Detection", "FILE_DIALOG_PATTERNS", "PASSWORD_FORMATS", "SUPPORTED_FORMATS", "csv_header",
           "describe", "detect_format", "load_records"]
