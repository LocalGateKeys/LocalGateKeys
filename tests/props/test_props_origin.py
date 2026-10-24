"""Property tests for origin/URL canonicalisation and matching (src/localvault/origin.py)."""
from __future__ import annotations

import re

import idna
import pytest
from hypothesis import assume, example, given, note
from hypothesis import strategies as st

from localvault import origin as O
from localvault.origin import OriginError

RULES = O.suffix_rules()
assert RULES is not None, "bundled PSL must load"
NORMAL = sorted(RULES.normal)
WILDCARD = sorted(RULES.wildcard)
EXCEPTION = sorted(RULES.exception)

# ---------------------------------------------------------------- strategies
SPECIAL = list("./:@\\%[]?#-_~!$&'()*+,;=^|<>`{}\"") + ["。", "．", "｡", "‍", "‌", "ß",
                                                         "İ", "K", "：", "／", "․", "﹒",
                                                         " ", "\t", "\n", "\x00", "\x7f", "\u0000", " "]
ascii_label = st.from_regex(r"[a-z0-9](?:[a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True)
uni_label = st.text(alphabet=st.characters(codec="utf-8", categories=("Ll", "Lu", "Lo", "Nd", "Mn")), min_size=1,
                    max_size=8)
weird_label = st.text(alphabet=st.sampled_from(SPECIAL + list("abcxn-09")), min_size=1, max_size=8)
label = st.one_of(ascii_label, ascii_label, uni_label, weird_label)

suffix = st.one_of(st.sampled_from(NORMAL), st.sampled_from(WILDCARD).flatmap(lambda w: ascii_label.map(lambda a: f"{a}.{w}")),
                   st.sampled_from(EXCEPTION))

ipv4 = st.tuples(*[st.integers(0, 255)] * 4).map(lambda t: ".".join(map(str, t)))
ipv4_weird = st.sampled_from(["0x7f.1", "127.1", "0177.0.0.1", "2130706433", "1.2.3", "01.02.03.04", "256.1.1.1",
                              "1.2.3.4.", "1.2.3.4..", "0x7f000001"])
ipv6 = st.ip_addresses(v=6).map(lambda a: f"[{a}]")
ipv6_weird = st.sampled_from(["[::1%eth0]", "[fe80::1%25eth0]", "[::ffff:127.0.0.1]", "[v1.x]", "[::1", "::1]",
                              "[::1]x", "[[::1]]", "[::FFFF:7F00:1]", "[0:0:0:0:0:0:0:1]", "[::1]:", "[::]"])
host = st.one_of(
    st.lists(label, min_size=1, max_size=4).flatmap(lambda ls: suffix.map(lambda s: ".".join(ls + [s]))),
    st.lists(label, min_size=1, max_size=4).map(".".join),
    ipv4, ipv4_weird, ipv6, ipv6_weird, st.just("localhost"), ascii_label.map(lambda a: f"{a}.localhost"),
    st.text(min_size=0, max_size=20),
)
port = st.one_of(st.just(""), st.integers(0, 70000).map(lambda p: f":{p}"),
                 st.sampled_from([":", ":443", ":80", ":0443", ":+1", ": 1", ":-1", ":١٢", ":99999999999", ":0x1"]))
userinfo = st.one_of(st.just(""), st.just(""), st.sampled_from(["u@", "u:p@", "@", ":@", "victim.example@"]))
path = st.one_of(st.just(""), st.just("/"), st.lists(st.sampled_from(list("/abc%2F.?#&=\\") + ["%2e", "%00"]), max_size=15).map("".join).map(lambda t: "/" + t))
scheme = st.sampled_from(["https", "https", "HTTPS", "http", "HtTp", "ftp", "javascript", "file", "", "https:"])
url = st.builds(lambda s, u, h, p, pa: f"{s}://{u}{h}{p}{pa}", scheme, userinfo, host, port, path)
any_url = st.one_of(url, url, st.text(max_size=60), st.text(alphabet=st.sampled_from(SPECIAL + list("htps:/a.bcom")),
                                                             max_size=40))

FUNCS = (O.canonicalize_origin, O.normalize_url, O.origin_of, O.host_of, O.base_domain_of)


def _call(fn, value):
    try:
        return fn(value)
    except OriginError:
        return None


# ---------------------------------------------------------------- P1: only OriginError escapes
@given(any_url)
@example("https://a.com\\.evil.com")
@example("https://victim.com。")
@example("https://xn--.com")
@example("https://[::ffff:1.2.3.4]")
@example("https://a..com")
def test_only_origin_error(value):
    for fn in FUNCS:
        _call(fn, value)
    for mode in O.MATCH_MODES:
        O.match_rank([{"url": "https://example.com", "match": mode}], value)
        try:
            O.match_rank([{"url": value, "match": mode}], "https://example.com/")
        except OriginError:
            pass


# ---------------------------------------------------------------- P2: idempotence / consistency
# Finding O-1 (UTS-46 dot mapped after the one-trailing-dot strip) is fixed: strict.


def _host_has_trailing_dot(normalized: str) -> bool:
    netloc = normalized.split("/")[2]
    if netloc.startswith("["):
        return False
    return netloc.rsplit(":", 1)[0].endswith(".") if ":" in netloc else netloc.endswith(".")

@given(any_url)
@example("https://victim.com。/")
@example("https://victim.com．")
@example("https://EXAMPLE.com./a")
def test_idempotent(value):
    n = _call(O.normalize_url, value)
    if n is not None:
        assert not _host_has_trailing_dot(n), "finding O-1: a normalised host keeps a trailing dot"
        note(f"normalize -> {n!r}")
        assert O.normalize_url(n) == n, "normalize_url is not idempotent"
        assert O.origin_of(n) == O.origin_of(value)
        assert O.host_of(n) == O.host_of(value)
        assert O.base_domain_of(n) == O.base_domain_of(value)
    c = _call(O.canonicalize_origin, value)
    if c is not None:
        note(f"canonical -> {c!r}")
        assert O.canonicalize_origin(c) == c, "canonicalize_origin is not idempotent"
        assert O.origin_of(value) == c, "canonicalize_origin disagrees with origin_of"


# ---------------------------------------------------------------- P3: exact match vs independent host parse
_SPLIT = re.compile(r"[/?#\\]")


def _reference_host(value: str) -> str | None:
    """A WHATWG-flavoured host extraction (backslash is a path separator for special schemes)."""
    if "://" not in value:
        return None
    rest = value.split("://", 1)[1]
    authority = _SPLIT.split(rest, 1)[0]
    if "@" in authority:
        return None
    if authority.startswith("["):
        return authority[1:authority.index("]")].lower() if "]" in authority else None
    hostpart = authority.rsplit(":", 1)[0] if ":" in authority else authority
    hostpart = hostpart.rstrip(".") if hostpart.endswith(".") and not hostpart.endswith("..") else hostpart
    try:
        return idna.encode(hostpart, uts46=True, transitional=False).decode().lower()
    except Exception:  # noqa: BLE001
        return None


VICTIMS = ["https://victim.example", "https://login.victim.co.uk", "https://[2001:db8::1]", "https://xn--strae-oqa.de"]


@given(st.sampled_from(VICTIMS), any_url)
def test_exact_and_host_match_agrees_with_reference_host(stored, candidate):
    stored_host = O.host_of(stored)
    for mode in ("exact_origin", "host"):
        if O.match_rank([{"url": stored, "match": mode}], candidate) is not None:
            ref = _reference_host(candidate)
            note(f"mode={mode} candidate={candidate!r} ref={ref!r}")
            assert ref == stored_host, "matched a candidate whose reference host differs"


@given(st.sampled_from(VICTIMS), any_url)
def test_base_domain_match_stays_inside_registrable_domain(stored, candidate):
    if O.match_rank([{"url": stored, "match": "base_domain"}], candidate) is not None:
        cand = O.host_of(candidate)
        want = O.base_domain_of(stored)
        assert cand == want or cand.endswith("." + want)
        ref = _reference_host(candidate)
        assert ref is not None and (ref == want or ref.endswith("." + want))


# ---------------------------------------------------------------- P4: base_domain vs independent PSL implementation
try:
    from publicsuffixlist import PublicSuffixList

    with open(O.PUBLIC_SUFFIX_LIST_PATH, encoding="utf-8") as _h:
        _REF = PublicSuffixList(_h.read().splitlines() + list(O._LOCAL_SUFFIX_RULES))
except Exception:  # noqa: BLE001
    _REF = None

ascii_host = st.lists(ascii_label, min_size=1, max_size=4).flatmap(
    lambda ls: suffix.map(lambda s: ".".join(ls + [s]).lower()))


@pytest.mark.skipif(_REF is None, reason="publicsuffixlist not installed")
@given(ascii_host)
def test_base_domain_matches_reference_psl(h):
    try:
        mine = O.base_domain(h)
    except OriginError:
        return
    ref = _REF.privatesuffix(h) or h
    note(f"host={h} mine={mine} ref={ref}")
    assert mine == ref


@given(ascii_label, suffix, ascii_label, suffix, st.lists(ascii_label, max_size=2), st.lists(ascii_label, max_size=2))
def test_no_cross_registrable_base_domain_match(r1, s1, r2, s2, sub1, sub2):
    h1 = ".".join(sub1 + [r1, s1])
    h2 = ".".join(sub2 + [r2, s2])
    try:
        b1, b2 = O.base_domain(h1), O.base_domain(h2)
    except OriginError:
        return
    matched = O.matches([{"url": f"https://{h1}", "match": "base_domain"}], f"https://{h2}/")
    assert matched == (b1 == b2)
    if matched and _REF is not None:
        assert (_REF.privatesuffix(h1) or h1) == (_REF.privatesuffix(h2) or h2)


# ---------------------------------------------------------------- P5: scheme / port / starts_with confinement
@given(any_url, any_url)
def test_starts_with_never_crosses_origin(stored, candidate):
    try:
        hit = O.match_rank([{"url": stored, "match": "starts_with"}], candidate)
    except OriginError:
        return
    if hit is not None:
        assert O.origin_of(stored) == O.origin_of(candidate)


@given(any_url)
def test_http_candidate_on_public_host_never_matches(candidate):
    try:
        scheme, h, _p, _pa, _q = O._split_url(candidate)
    except OriginError:
        return
    if scheme == "http" and not O._is_loopback(h):
        for mode in O.MATCH_MODES:
            assert O.match_rank([{"url": "https://" + (f"[{h}]" if ":" in h else h), "match": mode}],
                                candidate) is None


@given(ascii_host, st.integers(1, 65535), st.integers(1, 65535))
def test_host_mode_port_must_be_equal(h, p1, p2):
    a, b = f"https://{h}:{p1}", f"https://{h}:{p2}/x"
    same = (p1 if p1 != 443 else None) == (p2 if p2 != 443 else None)
    assert O.matches([{"url": a, "match": "host"}], b) == same
    assert O.matches([{"url": a, "match": "exact_origin"}], b) == same


@given(st.lists(st.fixed_dictionaries({"url": any_url, "match": st.sampled_from(O.MATCH_MODES + ("bogus", 1))}),
                max_size=4), any_url)
def test_match_rank_is_min_over_rows(rows, candidate):
    try:
        best = O.match_rank(rows, candidate)
    except OriginError:
        assume(False)
        return
    per = []
    for row in rows:
        try:
            r = O.match_rank([row], candidate)
        except OriginError:
            r = None
        if r is not None:
            per.append(r)
    assert best == (min(per) if per else None)
