"""``lgk://<item id or title>/<field>`` references for the ``lgk`` command line tool.

Parsing is pure. Resolution works on :class:`RefItem` rows the CLI service builds under the vault lock: every
item takes part in matching, but only allowed ones (in ``developer_cli_items`` and not a strict login) carry a
reader, so a value is never read for an item the CLI may not have. Error messages name ids and titles only, never
a value.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import unquote

PREFIX = "lgk://"
MAX_REFERENCE = 2048


class RefError(Exception):
    """A reference that cannot be served; ``code`` is the stable error the CLI maps to an exit code."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


@dataclass(frozen=True)
class Ref:
    item: str
    field: str


@dataclass(frozen=True)
class RefItem:
    id: str
    title: str
    kind: str
    allowed: bool
    # field name -> value, or None when the item has no such field. Only allowed items get a real reader.
    read: Callable[[str], str | None] = lambda _field: None
    # In the CLI allow-list (an allow-listed strict login is listed but not allowed).
    listed: bool = False


def _decode(part: str) -> str:
    try:
        value = unquote(part, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RefError("bad_reference", "The reference is not valid percent-encoded UTF-8.") from exc
    if not value or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise RefError("bad_reference", "The reference has an empty part or a control character.")
    return value


def parse(ref: str) -> Ref:
    """``lgk://<item>/<field>``: exactly two non-empty path parts, each percent-decoded after splitting."""
    if not isinstance(ref, str) or len(ref) > MAX_REFERENCE or not ref.startswith(PREFIX):
        raise RefError("bad_reference", "A reference looks like lgk://<item id or title>/<field>.")
    parts = ref[len(PREFIX):].split("/")
    if len(parts) != 2:
        raise RefError("bad_reference", "A reference has exactly two parts: lgk://<item id or title>/<field>. "
                                        "Write a / inside a title as %2F.")
    return Ref(_decode(parts[0]), _decode(parts[1]))


def _describe(items: Iterable[RefItem]) -> str:
    return ", ".join(f"{item.id} ({item.title})" for item in items)


def find(ref: Ref, items: Iterable[RefItem]) -> RefItem:
    """The one item ``ref`` names: an exact id first, else a title (exact, then ignoring case).

    Titles only match among allowed items, so an ambiguity never lists an item the CLI may not use. A title that
    matches only items outside the allow-list is ``not_found``: any local process can run lgk.exe, and must not
    learn which titles the vault holds. Only an allow-listed strict login gives ``not_allowed`` by title.
    """
    rows = list(items)
    by_id = next((item for item in rows if item.id == ref.item), None)
    if by_id is not None:
        if not by_id.allowed:
            raise RefError("not_allowed", f"{by_id.id} is not allowed for command line access.")
        return by_id
    matches = [item for item in rows if item.title == ref.item]
    if not matches:
        needle = ref.item.casefold()
        matches = [item for item in rows if item.title.casefold() == needle]
    allowed = [item for item in matches if item.allowed]
    if len(allowed) == 1:
        return allowed[0]
    if len(allowed) > 1:
        raise RefError("ambiguous", "Several items have this title; use an id: " + _describe(allowed))
    if any(item.listed for item in matches):
        raise RefError("not_allowed", "That item is not allowed for command line access.")
    raise RefError("not_found", "No item has this id or title.")


def resolve(ref: Ref | str, items: Iterable[RefItem]) -> str:
    parsed = parse(ref) if isinstance(ref, str) else ref
    item = find(parsed, items)
    value = item.read(parsed.field)
    if value is None:
        raise RefError("no_field", f"{item.id} has no field named {parsed.field!r}.")
    return value
