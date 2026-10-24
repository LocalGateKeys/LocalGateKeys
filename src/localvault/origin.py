"""Origin canonicalization and multi-URL credential matching.

A website login historically held exactly one canonical origin.  Logins may
now also hold a list of ``{"url": ..., "match": ...}`` rows (see
``item_schema.validate_web_urls``).  This module compares such rows against a
candidate page URL using four closed match modes:

``exact_origin``
    canonical ``scheme://host[:port]`` equality (the legacy behaviour).
``host``
    the hostname and the port must be identical (a default port equals no
    port, whatever the scheme); scheme and path are ignored.
``base_domain``
    the registrable domain (``example.co.uk`` for ``login.example.co.uk``)
    must be identical.  The registrable domain comes from the bundled Mozilla
    Public Suffix List (``assets/public_suffix_list.dat``).
``starts_with``
    the normalized candidate URL must begin with the normalized stored URL at
    a path boundary (``/app`` matches ``/app/login`` but not ``/application``).
    This narrows *which login is offered*; it is not a security boundary,
    because every path of one origin shares that origin's script context.

Hosts and candidates
--------------------
Hosts are refused when they contain a code point the WHATWG URL standard
forbids in a domain (``\\ % ^ | < > [ ] # / ? @ :``, space, C0 controls, DEL)
or any whitespace: browsers never load such a host, and Python's ``urlsplit``
would file ``https://paypal.com\\.evil.com`` under ``evil.com``.  Bracketed
hosts must be plain IPv6 addresses: zone identifiers (``[::1%eth0]``),
IPv4-mapped addresses (``[::ffff:127.0.0.1]``) and IPvFuture literals are
refused.  One trailing dot is dropped (``example.com.`` is ``example.com``);
more than one is refused.  Every ``ValueError`` from ``urlsplit`` or
``ipaddress`` surfaces as :class:`OriginError`.  ``match_rank`` never matches
a plain-HTTP candidate on a non-loopback host, whatever the row's mode.

Public suffixes
---------------
The full Public Suffix List snapshot (ICANN and PRIVATE sections) is parsed
lazily once and applied with the standard algorithm: normal rules, ``*.``
wildcard rules, ``!`` exception rules and the default rule ``*``, all matched
on the IDNA A-label form.  :data:`_LOCAL_SUFFIX_RULES` adds a few rules that
only ever narrow a registrable domain.  The snapshot ages: a hosting platform
added upstream after it was taken still falls back to the default rule, which
may be *wider* than the real boundary, so the list must be refreshed with each
release.  If the asset is missing or unreadable, ``base_domain`` fails closed:
every host is its own base domain, so ``base_domain`` rows match the exact
host only.

Internationalized hosts
-----------------------
Non-ASCII hosts are encoded with UTS-46 non-transitional processing (the
``idna`` package), which is what browsers put in ``location.origin``:
``straße.de`` becomes ``xn--strae-oqa.de``.  Versions before 2026-10 used
Python's IDNA 2003 codec, which mapped the deviation characters (``ß``, ``ς``,
ZWJ, ZWNJ) to ``ss``/``σ``/nothing and stored e.g. ``https://strasse.de``.
Stored origins are already A-label ASCII, so the original spelling cannot be
recovered and no re-canonicalisation on load is attempted: such a login keeps
matching the ASCII host it literally records and never the IDN site, which
fails closed; the user re-saves it from the real site.
"""
from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit


class OriginError(ValueError):
    pass


MATCH_MODES: tuple[str, ...] = ("exact_origin", "host", "base_domain", "starts_with")
DEFAULT_MATCH_MODE = "exact_origin"
_MODE_RANK = {mode: index for index, mode in enumerate(MATCH_MODES)}

PUBLIC_SUFFIX_LIST_PATH = Path(__file__).resolve().parent / "assets" / "public_suffix_list.dat"

# Local additions to the bundled list.  Each one only ever makes a
# registrable domain *narrower* than the upstream list does, never wider.
# Upstream lists ``web.core.windows.net``, but Azure static websites are
# served as ``<account>.<zone>.web.core.windows.net`` (``z13``...), so without
# the wildcard every account in one zone would share a base domain.
_LOCAL_SUFFIX_RULES: tuple[str, ...] = ("*.web.core.windows.net",)


@dataclass(frozen=True)
class SuffixRules:
    """Public Suffix List rules in A-label form."""

    normal: frozenset[str]
    wildcard: frozenset[str]  # without the leading ``*.``
    exception: frozenset[str]  # without the leading ``!``


def _rule_to_ascii(rule: str) -> str:
    return ".".join(label.lower() if label.isascii() else _ascii_host(label)
                    for label in rule.split("."))


def parse_suffix_rules(lines: Iterable[str]) -> SuffixRules:
    """Parse Public Suffix List text; ICANN and PRIVATE sections alike.

    Rules are stored in their IDNA A-label form because hosts are compared
    after IDNA encoding.  Only the leading ``*.`` wildcard and ``!`` exception
    forms exist in the list; a rule with any other ``*`` or one that cannot
    be IDNA-encoded is ignored.
    """
    normal: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0]
        target = normal
        if rule.startswith("!"):
            target, rule = exception, rule[1:]
        elif rule.startswith("*."):
            target, rule = wildcard, rule[2:]
        if not rule or "*" in rule or "!" in rule:
            continue
        try:
            target.add(_rule_to_ascii(rule))
        except OriginError:
            continue
    return SuffixRules(frozenset(normal), frozenset(wildcard), frozenset(exception))


_SUFFIX_RULES_LOCK = threading.Lock()
_SUFFIX_RULES: SuffixRules | None = None
_SUFFIX_RULES_LOADED = False


def suffix_rules() -> SuffixRules | None:
    """The bundled list, parsed once.  ``None`` when missing or unreadable."""
    global _SUFFIX_RULES, _SUFFIX_RULES_LOADED
    if _SUFFIX_RULES_LOADED:
        return _SUFFIX_RULES
    with _SUFFIX_RULES_LOCK:
        if not _SUFFIX_RULES_LOADED:
            try:
                with open(PUBLIC_SUFFIX_LIST_PATH, encoding="utf-8") as handle:
                    rules = parse_suffix_rules(handle)
                local = parse_suffix_rules(_LOCAL_SUFFIX_RULES)
                rules = SuffixRules(rules.normal | local.normal, rules.wildcard | local.wildcard,
                                    rules.exception | local.exception)
                # An empty or truncated file is treated as missing.
                _SUFFIX_RULES = rules if len(rules.normal) > 1000 else None
            except (OSError, UnicodeError):
                _SUFFIX_RULES = None
            _SUFFIX_RULES_LOADED = True
    return _SUFFIX_RULES


def _reset_suffix_rules_cache() -> None:
    """Forget the parsed list (tests point PUBLIC_SUFFIX_LIST_PATH elsewhere)."""
    global _SUFFIX_RULES, _SUFFIX_RULES_LOADED
    with _SUFFIX_RULES_LOCK:
        _SUFFIX_RULES = None
        _SUFFIX_RULES_LOADED = False


def public_suffix(host: str, rules: SuffixRules) -> str:
    """Public suffix of an A-label ``host`` by the PSL algorithm.

    A matching exception rule prevails (its suffix drops the leftmost label);
    otherwise the matching rule with the most labels wins; with no match the
    default rule ``*`` makes the last label the suffix.
    """
    labels = host.split(".")
    count = len(labels)
    for index in range(count):
        if ".".join(labels[index:]) in rules.exception:
            return ".".join(labels[index + 1:])
    for index in range(count):  # lowest index = most labels
        if ".".join(labels[index:]) in rules.normal:
            return ".".join(labels[index:])
        if index + 1 < count and ".".join(labels[index + 1:]) in rules.wildcard:
            return ".".join(labels[index:])
    return labels[-1]


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# WHATWG URL "forbidden domain code points" (the forbidden host code points,
# C0 controls, "%" and DEL); whitespace and controls are checked separately.
_FORBIDDEN_HOST_CHARS = frozenset("#/:<>?@[\\]^|%\x7f")


def _check_host_chars(host: str) -> None:
    if any(ord(char) < 32 or char.isspace() or char in _FORBIDDEN_HOST_CHARS for char in host):
        raise OriginError("Host contains a character that browsers do not allow")


def _ascii_host(host: str) -> str:
    """Lower-case, IDNA-encode and strip one trailing dot from a hostname.

    ASCII hosts (what browsers send) keep the historical label-length checks.
    Non-ASCII hosts use UTS-46 non-transitional processing like browsers do,
    never Python's IDNA 2003 codec (``straße`` must not become ``strasse``).
    Hosts with a WHATWG forbidden domain code point or whitespace, and hosts
    ending in more than one dot, are refused.
    """
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise OriginError("Origin is missing a host")
    _check_host_chars(host)
    if host.endswith("."):
        raise OriginError("Invalid internationalized host name")
    try:
        if host.isascii():
            result = host.encode("idna").decode("ascii").lower()
        else:
            import idna

            result = idna.encode(host, uts46=True, transitional=False).decode("ascii").lower()
    except (UnicodeError, ValueError, ImportError) as exc:
        # idna.IDNAError is a UnicodeError; a missing package fails closed.
        raise OriginError("Invalid internationalized host name") from exc
    _check_host_chars(result)  # UTS-46 maps e.g. fullwidth forms onto ASCII
    return result


def _has_space_or_control(value: str) -> bool:
    return any(ord(char) < 32 or char.isspace() for char in value)


def _urlsplit(value: str) -> SplitResult:
    """``urlsplit`` with its ``ValueError`` (brackets, NFKC netloc) as :class:`OriginError`."""
    try:
        return urlsplit(value)
    except ValueError as exc:
        if "[" in value or "]" in value:
            raise OriginError("Invalid IPv6 URL") from exc
        raise OriginError("URL is malformed") from exc


def _url_host(parsed: SplitResult, missing: str) -> str:
    """The checked ASCII host of a split URL.

    A bracketed host must be a plain IPv6 address: no zone identifier, no
    IPv4-mapped address and no IPvFuture literal (browsers produce none of
    them).  Any other host goes through :func:`_ascii_host`.
    """
    host = parsed.hostname
    if not host:
        raise OriginError(missing)
    if "[" not in parsed.netloc.rpartition("@")[2]:
        return _ascii_host(host)
    if "%" in host:
        raise OriginError("IPv6 zone identifiers are not supported")
    try:
        ip = ipaddress.IPv6Address(host)
    except ValueError as exc:
        raise OriginError("Invalid IPv6 URL") from exc
    if ip.ipv4_mapped is not None:
        raise OriginError("IPv4-mapped IPv6 addresses are not supported")
    return host


def _port(parsed: SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError as exc:
        raise OriginError("Invalid port") from exc


def canonicalize_origin(value: str, *, allow_local_http: bool = True) -> str:
    """Return an exact scheme/host/port origin suitable for credential scoping.

    Production credentials are HTTPS-only. HTTP is accepted only for loopback
    hosts so the included local demo page can be tested safely.
    """

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise OriginError("Origin must be a non-empty string shorter than 2049 characters")
    if _has_space_or_control(value):
        raise OriginError("Origin contains whitespace or a control character")

    parsed = _urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise OriginError("Origins must not contain user information")
    if parsed.query or parsed.fragment:
        raise OriginError("Expected an origin, not a URL with a query or fragment")
    if parsed.path not in ("", "/"):
        raise OriginError("Expected an origin without a path")

    scheme = parsed.scheme.lower()
    if scheme not in {"https", "http"}:
        raise OriginError("Only HTTPS origins are allowed (HTTP is limited to localhost)")

    host = _url_host(parsed, "Origin is missing a host")

    if scheme == "http" and not (allow_local_http and _is_loopback(host)):
        raise OriginError("Plain HTTP is allowed only for loopback test origins")

    port = _port(parsed)

    default_port = 443 if scheme == "https" else 80
    port_suffix = "" if port in (None, default_port) else f":{port}"

    try:
        ip = ipaddress.ip_address(host)
        rendered_host = f"[{host}]" if ip.version == 6 else host
    except ValueError:
        rendered_host = host

    return f"{scheme}://{rendered_host}{port_suffix}"


def _split_url(value: Any) -> tuple[str, str, int | None, str, str]:
    """Return ``(scheme, ascii_host, port_or_None, path, query)`` for a URL."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise OriginError("URL must be a non-empty string shorter than 4097 characters")
    if _has_space_or_control(value):
        raise OriginError("URL contains whitespace or a control character")
    parsed = _urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"https", "http"}:
        raise OriginError("Only http(s) URLs can be matched")
    if parsed.username is not None or parsed.password is not None:
        raise OriginError("URLs must not contain user information")
    host = _url_host(parsed, "URL is missing a host")
    port = _port(parsed)
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        port = None
    return scheme, host, port, parsed.path or "/", parsed.query


def _render_host(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if ip.version == 6 else host


def normalize_url(value: Any) -> str:
    """Return a comparable URL: lower-case scheme/host, IDNA host, no default
    port, no trailing host dot, no fragment.  Path and query are preserved
    (the path is significant for ``starts_with``)."""
    scheme, host, port, path, query = _split_url(value)
    netloc = _render_host(host) + (f":{port}" if port is not None else "")
    return urlunsplit((scheme, netloc, path, query, ""))


def origin_of(value: Any) -> str:
    """Return the canonical ``scheme://host[:port]`` origin of any http(s) URL."""
    scheme, host, port, _path, _query = _split_url(value)
    return f"{scheme}://{_render_host(host)}" + (f":{port}" if port is not None else "")


def host_of(value: Any) -> str:
    """Return the normalized ASCII hostname of any http(s) URL."""
    return _split_url(value)[1]


def _host_and_port(value: Any) -> tuple[str, int | None]:
    """Host and non-default port (``None`` for the scheme's default)."""
    _scheme, host, port, _path, _query = _split_url(value)
    return host, port


def base_domain(host: str) -> str:
    """Return the registrable domain for ``host`` using the Public Suffix List.

    IP addresses and single-label hosts are returned unchanged.  When the host
    *is* a public suffix it is returned unchanged as well (there is no
    registrable domain above it).  Without a usable suffix list every host is
    its own base domain (fail closed: ``base_domain`` rows match the exact
    host only).
    """
    host = str(host)
    if ":" in host:  # an IPv6 literal (``host_of`` gives it without brackets)
        if "%" in host:
            raise OriginError("IPv6 zone identifiers are not supported")
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise OriginError("Invalid IPv6 URL") from exc
        return host.lower()
    host = _ascii_host(host)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    rules = suffix_rules()
    if rules is None or "." not in host:
        return host
    suffix = public_suffix(host, rules)
    if suffix == host:
        return host
    registrable = host[: -len(suffix) - 1].rsplit(".", 1)[-1]
    return f"{registrable}.{suffix}"


def base_domain_of(value: Any) -> str:
    return base_domain(host_of(value))


def _normalize_mode(mode: Any) -> str:
    if not isinstance(mode, str) or mode not in _MODE_RANK:
        raise OriginError("Unsupported URL match mode")
    return mode


def _coerce_rows(entry_urls: Iterable[Any], *, mode: str | None) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for row in entry_urls:
        if isinstance(row, Mapping):
            url = row.get("url")
            row_mode = row.get("match", DEFAULT_MATCH_MODE)
        else:
            url = row
            row_mode = DEFAULT_MATCH_MODE
        if not isinstance(url, str):
            raise OriginError("URL match row is malformed")
        rows.append((url, _normalize_mode(mode if mode is not None else row_mode)))
    return rows


def _starts_with(stored: str, candidate: str) -> bool:
    if candidate == stored:
        return True
    if not candidate.startswith(stored):
        return False
    if stored.endswith("/"):
        return True
    return candidate[len(stored)] in "/?"


def _row_matches(url: str, row_mode: str, candidate: str) -> bool:
    if row_mode == "exact_origin":
        return origin_of(url) == origin_of(candidate)
    if row_mode == "host":
        return _host_and_port(url) == _host_and_port(candidate)
    if row_mode == "base_domain":
        return base_domain_of(url) == base_domain_of(candidate)
    if row_mode == "starts_with":
        return _starts_with(normalize_url(url), normalize_url(candidate))
    raise OriginError("Unsupported URL match mode")  # pragma: no cover - guarded above


def match_rank(entry_urls: Iterable[Any], candidate: Any, *, mode: str | None = None) -> int | None:
    """Return the best (lowest) match-mode rank for ``candidate`` or ``None``.

    Stored rows that are malformed raise :class:`OriginError`; a malformed
    *candidate* simply yields ``None`` so callers fail closed for pages that
    cannot be scoped, and so does a plain-HTTP candidate on a non-loopback host
    (the rule of :func:`canonicalize_origin`; ``host`` and ``base_domain`` rows
    ignore the scheme).  ``mode`` overrides the per-row mode when given.
    """
    rows = _coerce_rows(entry_urls, mode=mode)
    try:
        scheme, host, _port_number, _path, _query = _split_url(candidate)
    except OriginError:
        return None
    if scheme == "http" and not _is_loopback(host):
        return None
    best: int | None = None
    for url, row_mode in rows:
        try:
            hit = _row_matches(url, row_mode, candidate)
        except OriginError:
            # A stored row that no longer parses must not match anything.
            continue
        if hit:
            rank = _MODE_RANK[row_mode]
            if best is None or rank < best:
                best = rank
    return best


def matches(entry_urls: Iterable[Any], candidate_origin_or_url: Any, *, mode: str | None = None) -> bool:
    """Return whether any stored URL row matches the candidate page URL/origin.

    ``entry_urls`` may contain ``{"url", "match"}`` mappings or plain URL
    strings (which default to ``exact_origin`` unless ``mode`` is given).
    """
    return match_rank(entry_urls, candidate_origin_or_url, mode=mode) is not None


def entry_urls(entry: Mapping[str, Any]) -> list[dict[str, str]]:
    """Return the URL rows of a web login, migrating the legacy single origin.

    A login without ``scope.urls`` yields ``[{"url": origin, "match":
    "exact_origin"}]`` so older vaults behave exactly as before.
    """
    scope = entry.get("scope") if isinstance(entry, Mapping) else None
    if not isinstance(scope, Mapping):
        return []
    rows = scope.get("urls")
    result: list[dict[str, str]] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, Mapping) and isinstance(row.get("url"), str):
                row_mode = row.get("match", DEFAULT_MATCH_MODE)
                result.append({"url": row["url"],
                               "match": row_mode if row_mode in _MODE_RANK else DEFAULT_MATCH_MODE})
    if not result:
        origin = scope.get("origin")
        if isinstance(origin, str) and origin:
            result.append({"url": origin, "match": DEFAULT_MATCH_MODE})
    return result


def candidates_for(entries: Iterable[Mapping[str, Any]], url: Any, *,
                   urls_of: Callable[[Mapping[str, Any]], Iterable[Any]] = entry_urls) -> list[dict[str, Any]]:
    """Return web logins matching ``url`` ranked exact-origin first.

    Ranking is by best match mode (``exact_origin`` < ``host`` <
    ``base_domain`` < ``starts_with``), then most recently updated, then id for
    determinism.  Non-web entries and malformed candidates yield nothing.
    """
    ranked: list[tuple[int, int, str, dict[str, Any]]] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or entry.get("kind") != "web":
            continue
        try:
            rank = match_rank(urls_of(entry), url)
        except OriginError:
            continue
        if rank is None:
            continue
        updated = entry.get("updated_at", 0)
        updated = updated if isinstance(updated, int) else 0
        ranked.append((rank, -updated, str(entry.get("id", "")), dict(entry)))
    ranked.sort(key=lambda row: row[:3])
    return [row[3] for row in ranked]


__all__ = [
    "DEFAULT_MATCH_MODE",
    "MATCH_MODES",
    "PUBLIC_SUFFIX_LIST_PATH",
    "OriginError",
    "base_domain",
    "base_domain_of",
    "candidates_for",
    "canonicalize_origin",
    "entry_urls",
    "host_of",
    "match_rank",
    "matches",
    "normalize_url",
    "origin_of",
    "public_suffix",
    "suffix_rules",
]
