"""Shared helpers for reading bounded import sources and CSV tables."""
from __future__ import annotations

import csv
import io
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import MAX_SOURCE_BYTES, ImporterError, ImportFormatError
from ..i18n import t

MAX_CSV_ROWS = 20_000


def read_bounded(handle: Any, limit: int, *, chunk_size: int = 1024 * 1024) -> bytes:
    """Up to ``limit + 1`` bytes from ``handle`` in chunks.

    ``handle.read(limit + 1)`` preallocates the whole limit (64 MiB for
    archives) even for a tiny file; reading in chunks keeps memory at the
    file's real size.
    """
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = handle.read(min(chunk_size, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def read_source_bytes(source: Path | str | bytes | bytearray | memoryview, *, limit: int = MAX_SOURCE_BYTES) -> bytes:
    """Return at most ``limit`` bytes from a path or in-memory buffer."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        if len(data) > limit:
            raise ImportFormatError(f"Import source exceeds {limit // (1024 * 1024)} MiB")
        return data
    path = Path(source)
    try:
        if path.stat().st_size > limit:
            raise ImportFormatError(f"Import source exceeds {limit // (1024 * 1024)} MiB")
        with path.open("rb") as handle:
            data = read_bounded(handle, limit)
    except ImporterError:
        raise
    except OSError as exc:
        raise ImportFormatError(t("importWorkflow.couldNotReadTheImport")) from exc
    if len(data) > limit:
        raise ImportFormatError(f"Import source exceeds {limit // (1024 * 1024)} MiB")
    return data


def decode_text(data: bytes) -> str:
    """Decode UTF-8 (with BOM) or UTF-16 text exports."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise ImportFormatError(t("Source.importSourceMustBeUtf2")) from exc
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp1252")
    except UnicodeDecodeError as exc:
        raise ImportFormatError(t("Source.importSourceMustBeUtf")) from exc


def normalize_header(name: Any) -> str:
    return " ".join(str(name).replace("﻿", "").strip().casefold().replace("_", " ").replace("-", " ").split())


def sniff_delimiter(text: str) -> str:
    lines = text[:4096].splitlines()
    head = lines[0] if lines else ""
    counts = {d: head.count(d) for d in (",", ";", "\t")}
    best = max(counts, key=counts.get)
    return best if counts[best] else ","


def read_csv_table(text: str, *, max_rows: int = MAX_CSV_ROWS) -> tuple[list[str], list[dict[str, str]]]:
    """Parse a CSV body into (raw header, rows keyed by normalised header).

    Row dicts are keyed by :func:`normalize_header`; the original header
    names are returned separately for column-mapping UIs.  ``__row__`` holds
    the 1-based line number of each row for diagnostics.
    """
    if "\x00" in text:
        raise ImportFormatError("CSV contains null characters")
    delimiter = sniff_delimiter(text)
    try:
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
        header = next(reader, None)
        if not header or not any(cell.strip() for cell in header):
            raise ImportFormatError("CSV has no header row")
        raw_header = [str(cell).replace("﻿", "").strip() for cell in header]
        keys = [normalize_header(cell) for cell in raw_header]
        rows: list[dict[str, str]] = []
        for number, values in enumerate(reader, 2):
            if not values or all(not str(cell).strip() for cell in values):
                continue
            row = {"__row__": str(number)}
            for key, value in zip(keys, values, strict=False):
                if key and key not in row:
                    row[key] = value
            if len(values) > len(keys):
                row["__extra__"] = "\n".join(values[len(keys):])
            rows.append(row)
            if len(rows) > max_rows:
                raise ImportFormatError(f"At most {max_rows:,} rows per CSV import")
    except csv.Error as exc:
        raise ImportFormatError("CSV is malformed") from exc
    return raw_header, rows


def pick(row: Mapping[str, str], *names: str) -> str:
    for name in names:
        value = row.get(normalize_header(name))
        if value is not None and str(value) != "":
            return str(value)
    return ""


def as_list(value: Any) -> list[Any]:
    """``value`` if it is a JSON array, else ``[]`` (hostile exports put scalars anywhere)."""
    return value if isinstance(value, list) else []


def truthy(value: Any) -> bool:
    return str(value).strip().casefold() in {"1", "true", "yes", "y", "on", "favorite"}


def parse_timestamp(value: Any) -> int | None:
    """Best-effort conversion of ISO-8601 / epoch values to Unix seconds."""
    if value in (None, "") or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:
            return None
        if number != number or number in (float("inf"), float("-inf")):
            return None
        if number > 10_000_000_000:
            number /= 1000.0
        return int(number) if number > 0 else None
    text = str(value).strip()
    if not text:
        return None
    digits = text.lstrip("-")
    if digits.isascii() and digits.isdecimal():
        return parse_timestamp(int(text)) if len(digits) <= 20 else None
    candidate = text.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.fromisoformat(candidate) if fmt is None else datetime.strptime(text, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return int(parsed.timestamp())
        except (ValueError, OverflowError, OSError):
            continue
    return None


def iso_timestamp(value: int | None) -> str:
    if value is None:
        return ""
    return datetime.fromtimestamp(int(value), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
