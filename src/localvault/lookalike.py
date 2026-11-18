"""Lookalike-domain classifier for the phishing shield.

``match(origin, saved_origins)`` compares the origin a page runs on with
the origins saved in the vault and returns a :class:`Verdict`:

``exact``
    Same scheme, host and port as a saved origin (``same-origin``).
``related``
    Same host on another scheme or port (``same-host``), or the same
    registrable domain by the bundled Public Suffix List (``same-site``):
    ``accounts.example.com`` is related to ``example.com``, while
    ``other.github.io`` is not related to ``user.github.io``.
``lookalike``
    The registrable label imitates a saved one: the same letters after
    folding homoglyphs and diacritics (``homoglyph``), the same label on
    another public suffix (``other-suffix``), the saved domain placed in a
    subdomain (``embedded``), or a small Damerau-Levenshtein distance
    (``edit-distance``: 2 edits from 9 characters; for a saved label of 5-8
    characters 1 edit, where a substitution must swap look-alike characters).
    ``other-suffix`` and ``edit-distance`` need a saved label of at least 5
    characters.  A host label that mixes scripts beyond what UTS #39 "highly
    restrictive" allows (Latin with Cyrillic, say; Latin with Han and kana is
    fine) is a lookalike on its own (``mixed-script``, no match).
    Inputs should be canonical origins as browsers report them; ``127.1``
    is read as ``127.0.0.1`` and percent-escaped hosts are refused, the same
    in both runtimes.
``unknown``
    None of the above (``no-match``), or an origin that cannot be read
    (``invalid-origin``).

``classify`` (the phishing shield) narrows ``related`` to the same host, or the same host with or without
``www.``: another host on the same registrable domain gets ``unknown`` (reason ``same-site``, ``matched`` set),
since a domain can host other people's pages without being on the list.  ``match`` is the shared algorithm.

The strongest verdict wins: exact, then related, then lookalike; among
lookalikes homoglyph, other-suffix, embedded, then the smallest edit distance;
ties go to the earliest saved origin.  ``matched`` is that saved origin exactly
as the caller gave it.

Everything runs on the device: punycode labels are decoded with the standard
library ``punycode`` codec and registrable domains come from the bundled list
(``assets/public_suffix_list.dat``).  ``browser-extension/lookalike.js`` is
the same algorithm as ``match``; ``tests/vectors/lookalike/cases.json`` keeps them in step.
"""

from __future__ import annotations

import functools
import ipaddress
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from . import origin as _origin

__all__ = ["Verdict", "classify", "match", "clear_cache"]

MIN_EDIT_LABEL = 5
# Edit distance allowed for a saved registrable label of 5-8 characters, and
# for one of 9 or more (two edits in a short label make a different word:
# github/gitlab, apple/ample).
SHORT_EDIT_DISTANCE = 1
LONG_EDIT_LABEL = 9
LONG_EDIT_DISTANCE = 2
# In a 5-8 character label a single substitution only counts between these
# look-alike characters (paypa1, g0ogle), so apple/ample is not flagged; an
# added, dropped or swapped letter always counts.  Same text as lookalike.js.
_VISUAL_PAIRS_TABLE = "0o 1i 1l 2z 5s 8b 9g 9q gq il uv nm"
_VISUAL_PAIRS = frozenset(frozenset(pair) for pair in _VISUAL_PAIRS_TABLE.split())

# Homoglyphs folded onto the Latin letter they imitate: four hex digits of the
# code point followed by the letter.  Kept byte-identical with lookalike.js.
_CONFUSABLES_TABLE = (
    "0430a 0441c 0501d 0435e 04bbh 0456i 0458j 043ak 04cfl 043eo 0440p 051bq 0455s 0443y 0445x 051dw 04afy "
    "03b1a 03b5e 03b9i 03bak 03bdv 03bfo 03c1p 03c4t 03c5u 03c7x 03b3y "
    "0585o 057du 0581g 0570h 0578n 0566q "
    "0131i 0251a 0261g 0237j"
)
_CONFUSABLES = {chr(int(item[:4], 16)): item[4:] for item in _CONFUSABLES_TABLE.split()}

# Scripts told apart by the mixed-script check; anything else is "Other".
_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "HIRAGANA", "KATAKANA",
            "HANGUL", "BOPOMOFO", "THAI", "DEVANAGARI", "GEORGIAN", "CHEROKEE")
# Japanese marks whose Unicode Script is Common or Han but whose character
# name says otherwise: one fixed answer for both runtimes (h = Han, k = Katakana).
_SCRIPT_TABLE = "3005h 3006h 3007h 303bh 309bk 309ck 30a0k 30fbk 30fck"
_SCRIPT_FIXED = {chr(int(item[:4], 16)): {"h": "HAN", "k": "KATAKANA"}[item[4]] for item in _SCRIPT_TABLE.split()}
# UTS #39 "highly restrictive": one script, or Latin with one of these sets.
_ALLOWED_MIXES = (
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),
    frozenset({"LATIN", "HAN", "BOPOMOFO"}),
    frozenset({"LATIN", "HAN", "HANGUL"}),
)


@dataclass(frozen=True)
class Verdict:
    kind: str
    matched: str | None
    reason: str


@dataclass(frozen=True)
class _Site:
    scheme: str
    host: str  # A-label form
    port: int | None
    ip: bool
    registrable: str  # A-label form
    sub: str  # labels left of the registrable domain, A-label form
    label: str  # registrable label, Unicode
    suffix: str  # public suffix, A-label form
    labels: tuple[str, ...]  # every host label, Unicode


def _decode_label(label: str) -> str:
    """Unicode form of one A-label; ``ValueError`` when browsers would refuse it.

    The punycode must decode (stdlib codec), re-encode to the same text, give
    a non-ASCII NFC label and pass UTS-46 validation (what the WHATWG URL
    parser checks; emoji labels are valid there, unlike strict IDNA 2008).
    """
    if not label.startswith("xn--"):
        return label
    decoded = label[4:].encode("ascii").decode("punycode")
    if (decoded.isascii() or decoded.encode("punycode").decode("ascii") != label[4:]
            or unicodedata.normalize("NFC", decoded) != decoded):
        raise ValueError("non-canonical punycode")
    import idna

    if idna.uts46_remap(decoded, std3_rules=False, transitional=False) != decoded:
        raise ValueError("label is not in UTS-46 mapped form")
    if unicodedata.category(decoded[0]).startswith("M"):
        raise ValueError("label starts with a combining mark")  # UTS-46 validity criterion
    # UTS-46 CheckJoiners, as the URL parser runs it: ZWNJ/ZWJ need their context.
    for index, char in enumerate(decoded):
        if char in "‌‍" and not idna.valid_contextj(decoded, index):
            raise ValueError("joiner without a valid context")
    return decoded


def _check_bidi(labels: tuple[str, ...]) -> None:
    """RFC 5893 Bidi rule on each label that holds right-to-left characters,
    as the WHATWG URL parser (Node's and the browsers') applies it.  Labels
    without them pass even in a domain that has a right-to-left label."""
    import idna

    for label in labels:
        idna.check_bidi(label)  # IDNABidiError is a UnicodeError


def _number(part: str) -> int | None:
    """One WHATWG IPv4 number (decimal, 0x hex or 0 octal); ``None`` if invalid."""
    if part[:2].lower() == "0x":
        digits, base = part[2:], 16
    elif len(part) > 1 and part.startswith("0"):
        digits, base = part[1:], 8
    else:
        digits, base = part, 10
    if not digits:
        return 0 if base == 16 else None
    allowed = "0123456789abcdef"[:base]
    if any(char not in allowed for char in digits.lower()):
        return None
    return int(digits, base)


def _ends_in_number(host: str) -> bool:
    last = host.rsplit(".", 1)[-1]
    return last.isdigit() and last.isascii() or (last[:2].lower() == "0x" and _number(last) is not None)


def _whatwg_ipv4(host: str) -> str | None:
    """The WHATWG URL parser's IPv4 reading (``127.1`` is ``127.0.0.1``)."""
    parts = host.split(".")
    if len(parts) > 4 or any(not part for part in parts):
        return None
    numbers = [_number(part) for part in parts]
    if any(number is None for number in numbers):
        return None
    values = [number for number in numbers if number is not None]
    if any(value > 255 for value in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return None
    address = values[-1]
    for index, value in enumerate(values[:-1]):
        address += value * 256 ** (3 - index)
    return str(ipaddress.IPv4Address(address))


def _site(value: object, *, bare_host_ok: bool) -> _Site | None:
    if not isinstance(value, str) or not value:
        return None
    if bare_host_ok and "://" not in value:
        value = "https://" + value
    try:
        scheme, host, port, _path, _query = _origin._split_url(value)
    except _origin.OriginError:
        return None
    if ":" in host:  # IPv6, rendered the way the URL parser does
        host = ipaddress.IPv6Address(host).compressed
        return _Site(scheme, host, port, True, host, "", host, "", (host,))
    if _ends_in_number(host):
        ipv4 = _whatwg_ipv4(host)
        if ipv4 is None:
            return None
        return _Site(scheme, ipv4, port, True, ipv4, "", ipv4, "", (ipv4,))
    try:
        labels = tuple(_decode_label(label) for label in host.split("."))
        _check_bidi(labels)
    except (UnicodeError, ValueError):
        return None
    rules = _origin.suffix_rules()
    suffix = _origin.public_suffix(host, rules) if rules is not None and "." in host else ""
    if not suffix or suffix == host:
        return _Site(scheme, host, port, False, host, "", "", suffix, labels)
    head = host[: -len(suffix) - 1]
    sub, _dot, reg_label = head.rpartition(".")
    return _Site(scheme, host, port, False, f"{reg_label}.{suffix}", sub,
                 labels[len(sub.split(".")) if sub else 0], suffix, labels)


def _skeleton(label: str) -> str:
    folded = "".join(char for char in unicodedata.normalize("NFKD", label.lower())
                     if not unicodedata.category(char).startswith("M"))
    return "".join(_CONFUSABLES.get(char, char) for char in folded)


def _script(char: str) -> str | None:
    if char.isascii():
        return "LATIN" if char.isalpha() else None
    if char in _SCRIPT_FIXED:
        return _SCRIPT_FIXED[char]
    if not unicodedata.category(char).startswith(("L", "N")):
        return None  # marks, punctuation, symbols, emoji
    name = unicodedata.name(char, "")
    if name.startswith("CJK "):
        return "HAN"
    for script in _SCRIPTS:
        if name.startswith(script + " ") or name.startswith(script + "-"):
            return script
    return "OTHER"


def _mixed_script(label: str) -> bool:
    scripts = {script for script in map(_script, label) if script}
    return len(scripts) > 1 and not any(scripts <= allowed for allowed in _ALLOWED_MIXES)


def _short_edit_counts(a: str, b: str) -> bool:
    """For labels one edit apart: is that edit a lookalike edit (see _VISUAL_PAIRS)?"""
    if len(a) != len(b):
        return True
    diff = [index for index in range(len(a)) if a[index] != b[index]]
    if len(diff) == 1:
        return frozenset((a[diff[0]], b[diff[0]])) in _VISUAL_PAIRS
    return True  # an adjacent transposition


def _osa_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance, optimal string alignment variant."""
    rows = [list(range(len(b) + 1))]
    for i in range(1, len(a) + 1):
        row = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            row[j] = min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                row[j] = min(row[j], rows[i - 2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


# Rank of each match; lower is stronger.
_RANKS = {"same-origin": 0, "same-host": 1, "same-site": 2, "homoglyph": 3, "other-suffix": 4,
          "embedded": 5, "edit-distance": 6}
_KIND = {"same-origin": "exact", "same-host": "related", "same-site": "related"}


def _compare(site: _Site, saved: _Site) -> tuple[str, int] | None:
    if site.host == saved.host:
        if (site.scheme, site.port) == (saved.scheme, saved.port):
            return "same-origin", 0
        return "same-host", 0
    if site.ip or saved.ip:
        return None
    if site.registrable == saved.registrable:
        return "same-site", 0
    if not site.label or not saved.label:
        return None
    mine, theirs = _skeleton(site.label), _skeleton(saved.label)
    if mine == theirs and site.label != saved.label:
        return "homoglyph", 0
    long_enough = len(theirs) >= MIN_EDIT_LABEL
    if long_enough and site.label == saved.label:
        return "other-suffix", 0
    if site.sub and f".{saved.registrable}." in f".{site.sub}.":
        return "embedded", 0
    limit = LONG_EDIT_DISTANCE if len(theirs) >= LONG_EDIT_LABEL else SHORT_EDIT_DISTANCE
    if long_enough and abs(len(mine) - len(theirs)) <= limit:
        distance = _osa_distance(mine, theirs)
        if distance <= limit and (limit > SHORT_EDIT_DISTANCE or _short_edit_counts(mine, theirs)):
            return "edit-distance", distance
    return None


@functools.lru_cache(maxsize=4096)
def _saved_site(raw: str) -> _Site | None:
    """A saved origin, parsed once: the broker classifies against the same list on every page."""
    return _site(raw, bare_host_ok=True)


def clear_cache() -> None:
    """Forget every parsed saved origin (called when the vault locks)."""
    _saved_site.cache_clear()


def _best(site: _Site, saved_origins: Iterable[str], compare: Callable[[_Site, _Site], tuple[str, int] | None],
          ranks: dict[str, int]) -> tuple[str, str] | None:
    """(reason, saved origin as given) of the strongest match, or None."""
    best: tuple[int, int, int, str, str] | None = None
    for index, raw in enumerate(saved_origins or ()):
        saved = _saved_site(raw) if isinstance(raw, str) else None
        if saved is None:
            continue
        found = compare(site, saved)
        if found is None:
            continue
        reason, distance = found
        key = (ranks[reason], distance, index, reason, raw)
        if best is None or key[:3] < best[:3]:
            best = key
    return None if best is None else (best[3], best[4])


def match(origin: str, saved_origins: Iterable[str]) -> Verdict:
    """The shared algorithm (see module doc): the verdict every runtime gives for the vectors in
    ``tests/vectors/lookalike``.  The phishing shield uses ``classify``, which narrows "related"."""
    site = _site(origin, bare_host_ok=False)
    if site is None:
        return Verdict("unknown", None, "invalid-origin")
    best = _best(site, saved_origins, _compare, _RANKS)
    if best is not None:
        reason, matched = best
        return Verdict(_KIND.get(reason, "lookalike"), matched, reason)
    if not site.ip and any(_mixed_script(label) for label in site.labels):
        return Verdict("lookalike", None, "mixed-script")
    return Verdict("unknown", None, "no-match")


# The shield's ranks: "www-host" (``www.example.com`` and ``example.com``) counts as a same-host match.  A
# same-site match keeps its place above the lookalikes (a page on a domain the user saved a login for is not
# flagged for resembling another saved site), it only loses the "related" badge.
_SHIELD_RANKS = {**_RANKS, "www-host": _RANKS["same-host"]}
_SHIELD_KIND = {"same-origin": "exact", "same-host": "related", "www-host": "related", "same-site": "unknown"}


def _www_twin(first: str, second: str) -> bool:
    return first == "www." + second or second == "www." + first


def _shield_compare(site: _Site, saved: _Site) -> tuple[str, int] | None:
    found = _compare(site, saved)
    if found is not None and found[0] == "same-site" and _www_twin(site.host, saved.host):
        return "www-host", 0
    return found


def classify(origin: str, saved_origins: Iterable[str]) -> Verdict:
    """The phishing shield's verdict for ``origin`` against the vault's saved origins.

    ``match`` with one change (audit 2026-11-10): "related" (the reassuring "Related site" badge) only for the
    same host as a saved origin on another scheme or port, or the same host with or without a leading ``www.``.
    Another host on the same registrable domain is not vouched for: a domain can host other people's pages
    without being on the Public Suffix List (``sites.google.com`` next to a saved ``accounts.google.com``).
    That gives the neutral ``unknown`` with reason ``same-site`` and ``matched`` naming the saved origin, no badge
    and no guard; a host label that mixes scripts still makes it a lookalike.
    Filling is unchanged: it follows the saved URL rows' own matching rules, never this verdict.
    """
    site = _site(origin, bare_host_ok=False)
    if site is None:
        return Verdict("unknown", None, "invalid-origin")
    best = _best(site, saved_origins, _shield_compare, _SHIELD_RANKS)
    mixed = not site.ip and any(_mixed_script(label) for label in site.labels)
    if best is not None and not (best[0] == "same-site" and mixed):
        reason, matched = best
        return Verdict(_SHIELD_KIND.get(reason, "lookalike"), matched, reason)
    if mixed:
        return Verdict("lookalike", None, "mixed-script")
    # A same-site best match always returns above (it is only held back when mixed, which returns too).
    return Verdict("unknown", None, "no-match")
