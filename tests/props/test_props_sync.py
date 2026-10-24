"""Property tests for sync: version vectors, merge convergence, sealed view files,
view signatures and the per-network pre-auth limit (sync/transport.py _source_prefix)."""
from __future__ import annotations

import ipaddress

from cryptography.hazmat.primitives.asymmetric import ed25519
from hypothesis import assume, given, note
from hypothesis import strategies as st

from localvault.sync import engine as E
from localvault.sync import group as G
from localvault.sync import transport as T
from localvault.updates import canonical_json

DEVICES = ["A", "B", "C", "dev-4"]
vv = st.dictionaries(st.sampled_from(DEVICES), st.integers(0, 4), max_size=4)
big_vv = st.dictionaries(st.from_regex(r"[A-Za-z0-9._:-]{1,8}", fullmatch=True), st.integers(0, 2**53 - 1), max_size=6)


# ------------------------------------------------------------- version vector laws
@given(big_vv, big_vv)
def test_compare_antisymmetric(a, b):
    flip = {"a": "b", "b": "a", "equal": "equal", "concurrent": "concurrent"}
    assert E.compare(a, b) == flip[E.compare(b, a)]


@given(big_vv)
def test_compare_reflexive(a):
    assert E.compare(a, a) == "equal"
    assert E.compare(a, {"zz-absent": 0, **a}) == "equal"  # an explicit zero equals a missing entry


@given(big_vv, big_vv, big_vv)
def test_max_vv_is_a_join(a, b, c):
    m = E._max_vv
    assert m(a, b) == m(b, a)
    assert m(m(a, b), c) == m(a, m(b, c))
    assert m(a, a) == {k: v for k, v in sorted(a.items()) if v}
    j = m(a, b)
    assert E.compare(j, a) in ("a", "equal") and E.compare(j, b) in ("a", "equal")


@given(big_vv, st.sampled_from(DEVICES))
def test_bump_dominates(a, dev):
    try:
        b = E.bump(a, dev)
    except E.EngineError:
        assert a.get(dev, 0) == 2**53 - 1
        return
    assert E.compare(b, a) == "a"


# ------------------------------------------------------------- merge convergence
item = st.fixed_dictionaries({"updated_at": st.integers(0, 3), "v": st.integers(0, 2)})


@st.composite
def state(draw, item_id="item-1"):
    deleted = draw(st.booleans())
    return E.ItemState(item_id, draw(vv), deleted, draw(st.one_of(st.none(), st.integers(0, 5))) if deleted else None,
                       None if deleted else draw(item))


def _apply(local: dict, outcome: E.MergeOutcome) -> dict:
    out = dict(local)
    for s in outcome.upserts + outcome.deletes + outcome.copies:
        out[s.item_id] = s
    return out


def _fingerprint(states: dict) -> dict:
    return {k: (tuple(sorted(s.vv.items())), s.deleted, None if s.item is None else canonical_json(s.item))
            for k, s in states.items()}


@given(state(), state())
def test_two_device_merge_converges(left, right):
    one = _apply({left.item_id: left}, E.merge({left.item_id: left}, [right]))
    two = _apply({right.item_id: right}, E.merge({right.item_id: right}, [left]))
    note(f"one={one}\ntwo={two}")
    # Both sides must hold the same winner for the original id.
    assert _fingerprint(one)["item-1"][:2] == _fingerprint(two)["item-1"][:2]
    assert _fingerprint(one)["item-1"][2] == _fingerprint(two)["item-1"][2]


@given(state(), state())
def test_merge_idempotent(left, right):
    first = _apply({left.item_id: left}, E.merge({left.item_id: left}, [right]))
    again = E.merge(first, [right])
    assert _fingerprint(_apply(first, again)) == _fingerprint(first)
    # Finding S-1 (fixed): equal vectors + different content must not re-report a conflict every round.
    assert not again.upserts and not again.deletes and not again.copies and not again.conflicts, again


@given(state(), state(), state())
def test_three_way_order_independence(a, b, c):
    def run(order):
        local = {order[0].item_id: order[0]}
        for remote in order[1:]:
            local = _apply(local, E.merge(local, [remote]))
            # exchange back the merged state so copies propagate too
        return local
    r1 = run([a, b, c])
    r2 = run([a, c, b])
    # The surviving state for the original id must be the same whatever the arrival order.
    f1, f2 = _fingerprint(r1)["item-1"], _fingerprint(r2)["item-1"]
    note(f"{r1}\n{r2}")
    assert f1[0] == f2[0]


# ------------------------------------------------------------- sealed views
GK = G.GroupKey("group-1", 1, bytes(range(32)))
GK_OTHER = G.GroupKey("group-1", 2, bytes(range(32)))


@st.composite
def states(draw):
    ids = draw(st.lists(st.from_regex(r"[a-z0-9-]{1,10}", fullmatch=True), unique=True, max_size=4))
    return [draw(state(item_id=i)) for i in ids]


@given(states(), st.data())
def test_view_rejects_any_mutation(sts, data):
    raw = G.encode_view(GK, "dev-1", 7, sts, 1000)
    view = G.decode_view(GK, raw, expected_device_id="dev-1")
    assert [s.item_id for s in view.states] == sorted(s.item_id for s in sts)
    kind = data.draw(st.sampled_from(["flip", "truncate", "extend", "insert"]))
    if kind == "flip":
        pos = data.draw(st.integers(0, len(raw) - 1))
        mutated = bytearray(raw)
        mutated[pos] ^= 1 << data.draw(st.integers(0, 7))
        mutated = bytes(mutated)
    elif kind == "truncate":
        mutated = raw[:data.draw(st.integers(0, len(raw) - 1))]
    elif kind == "extend":
        mutated = raw + data.draw(st.binary(min_size=1, max_size=16))
    else:
        pos = data.draw(st.integers(0, len(raw)))
        mutated = raw[:pos] + data.draw(st.binary(min_size=1, max_size=4)) + raw[pos:]
    try:
        G.decode_view(GK, mutated, expected_device_id="dev-1")
    except G.SyncFormatError:
        return
    raise AssertionError(f"mutated view accepted ({kind})")


@given(states())
def test_view_bound_to_epoch_and_device(sts):
    raw = G.encode_view(GK, "dev-1", 7, sts, 1000)
    for kwargs, gk in (({"expected_device_id": "dev-2"}, GK), ({}, GK_OTHER),
                       ({}, G.GroupKey("group-1", 1, bytes(32)))):
        try:
            G.decode_view(gk, raw, **kwargs)
        except G.SyncFormatError:
            continue
        raise AssertionError(kwargs)


SIGNER = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


@given(states(), st.data())
def test_view_signature_rejects_mutation(sts, data):
    raw = G.encode_view(GK, "dev-1", 7, sts, 1000)
    sig = G.sign_view(raw, SIGNER)
    header, _hb, _end = G._read_header(raw)
    assert G.verify_view_signature(sig, raw, header) == SIGNER.public_key().public_bytes_raw()
    pos = data.draw(st.integers(0, len(sig) - 1))
    mutated = bytearray(sig)
    mutated[pos] ^= 1 << data.draw(st.integers(0, 7))
    try:
        G.verify_view_signature(bytes(mutated), raw, header)
    except G.SyncFormatError:
        return
    raise AssertionError("mutated signature accepted")


# ------------------------------------------------------------- pre-auth per-network limit
v4 = st.ip_addresses(v=4)
v6 = st.ip_addresses(v=6)
scope = st.sampled_from(["", "%1", "%eth0", "%25", "%", "%%", "%é"])


@given(st.one_of(st.text(max_size=60), st.from_regex(r"[0-9a-fA-F:.%]{0,45}", fullmatch=True)))
def test_source_prefix_total(text):
    out = T._source_prefix(text)
    assert isinstance(out, str)


@given(v4, scope)
def test_mapped_and_scoped_share_the_ipv4_bucket(addr, sc):
    plain = T._source_prefix(str(addr))
    assert plain == str(ipaddress.ip_network(f"{addr}/24", strict=False))
    assert T._source_prefix(f"::ffff:{addr}") == plain
    assert T._source_prefix(f"::ffff:{addr}{sc}") == plain
    assert T._source_prefix(f"::FFFF:{addr}") == plain


@given(v6, scope)
def test_ipv6_scope_ignored(addr, sc):
    assume(addr.ipv4_mapped is None)
    assert T._source_prefix(f"{addr}{sc}") == T._source_prefix(str(addr))
    assert T._source_prefix(str(addr).upper()) == T._source_prefix(str(addr))


@given(v4, v4)
def test_ipv4_same_bucket_iff_same_24(a, b):
    same = int(a) >> 8 == int(b) >> 8
    assert (T._source_prefix(str(a)) == T._source_prefix(str(b))) == same


class _Sock:
    pass


@given(st.lists(st.tuples(st.sampled_from(["admit", "auth", "release"]),
                          st.one_of(v4.map(str), v4.map(lambda a: f"::ffff:{a}"),
                                    st.sampled_from(["10.0.0.1", "10.0.0.2", "10.0.0.3", "::ffff:10.0.0.4",
                                                     "fe80::1%3", "fe80::2%4", "fe80::1", "junk"])),
                          st.integers(0, 7)), max_size=40))
def test_reserve_inbound_invariants(ops):
    t = T.SyncTransport()
    socks = [_Sock() for _ in range(8)]
    for op, address, index in ops:
        sock = socks[index]
        if op == "admit" and sock not in t._inbound:
            t._reserve_inbound(sock, address)
        elif op == "auth":
            t._inbound_authenticated(sock)
        elif op == "release":
            t._release_inbound(sock)
        assert len(t._inbound) <= T.MAX_INBOUND_CONNECTIONS
        per_prefix: dict[str, int] = {}
        for prefix in t._pre_auth.values():
            per_prefix[prefix] = per_prefix.get(prefix, 0) + 1
        assert all(n <= T.MAX_PRE_AUTH_PER_PREFIX for n in per_prefix.values())
        per_addr: dict[str, int] = {}
        for a in t._inbound.values():
            per_addr[a] = per_addr.get(a, 0) + 1
        assert all(n <= T.MAX_INBOUND_PER_ADDRESS for n in per_addr.values())
        assert set(t._pre_auth) <= set(t._inbound)
