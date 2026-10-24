import hashlib
import itertools
import random
import uuid

import pytest

from localvault.sync.engine import (
    EngineError,
    ItemState,
    MergeOutcome,
    bump,
    compare,
    conflict_copy_id,
    merge,
)
from localvault.updates import canonical_json


def digest(item):
    body = {k: v for k, v in item.items() if k != "id"}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def live(item_id, vv, **item):
    return ItemState(item_id, dict(vv), False, None, item or {"title": "x"})


def dead(item_id, vv, at=100):
    return ItemState(item_id, dict(vv), True, at, None)


def test_compare_cases():
    assert compare({}, {}) == "equal"
    assert compare({"a": 1}, {"a": 1}) == "equal"
    assert compare({"a": 0}, {}) == "equal"
    assert compare({"a": 2}, {"a": 1}) == "a"
    assert compare({"a": 1, "b": 1}, {"a": 1}) == "a"
    assert compare({"a": 1}, {"a": 1, "b": 1}) == "b"
    assert compare({"a": 1}, {"b": 1}) == "concurrent"
    assert compare({"a": 2, "b": 1}, {"a": 1, "b": 2}) == "concurrent"


def test_compare_validation():
    for bad in ({"": 1}, {"a|b": 1}, {"a\x00": 1}, {"x" * 129: 1}, {"a": -1},
                {"a": True}, {"a": 1.0}, {1: 1}):
        with pytest.raises(EngineError):
            compare(bad, {})
    assert issubclass(EngineError, ValueError)


def test_itemstate_validation():
    with pytest.raises(EngineError):
        ItemState("", {}, False, None, {})
    with pytest.raises(EngineError):
        ItemState("a", {}, True, 1, {"t": 1})
    with pytest.raises(EngineError):
        ItemState("a", {}, False, None, None)


def test_remote_newer_wins():
    local = {"i": live("i", {"a": 1}, t="old")}
    out = merge(local, [live("i", {"a": 2}, t="new")])
    assert [s.item for s in out.upserts] == [{"t": "new"}]
    assert not out.deletes and not out.conflicts
    out = merge(local, [dead("i", {"a": 2})])
    assert [s.item_id for s in out.deletes] == ["i"] and not out.upserts
    out = merge({}, [live("n", {"a": 1})])
    assert [s.item_id for s in out.upserts] == ["n"]
    out = merge({}, [dead("n", {"a": 1})])
    assert [s.item_id for s in out.deletes] == ["n"]


def test_local_newer_kept():
    local = {"i": live("i", {"a": 2}, t="new")}
    assert merge(local, [live("i", {"a": 1}, t="old")]) == MergeOutcome((), (), ())


def test_concurrent_edit_reports_conflict():
    loc = live("i", {"a": 1}, t="A", updated_at=5)
    r = live("i", {"b": 1}, t="B", updated_at=9)
    out = merge({"i": loc}, [r])
    assert out.conflicts == ((loc, r),)
    assert [(u.item, u.vv) for u in out.upserts] == [(r.item, {"a": 1, "b": 1})]
    assert not out.deletes
    cid = conflict_copy_id("i", digest(loc.item))
    assert out.copies == (ItemState(cid, {"a": 1}, False, None, {**loc.item, "id": cid}),)


def test_local_winner_also_upserted_with_merged_vv():
    loc = live("i", {"a": 1}, t="A", updated_at=9)
    r = live("i", {"b": 1}, t="B", updated_at=5)
    out = merge({"i": loc}, [r])
    assert [(u.item, u.vv) for u in out.upserts] == [(loc.item, {"a": 1, "b": 1})]
    assert out.copies[0].vv == {"b": 1} and out.copies[0].item["t"] == "B"


def test_winner_tiebreak_and_nonint_updated_at():
    a = live("i", {"a": 1}, t="A", updated_at="9")  # non-int counts as 0
    b = live("i", {"b": 1}, t="B", updated_at=1)
    assert merge({"i": a}, [b]).upserts[0].item["t"] == "B"
    a = live("i", {"a": 1}, t="A", updated_at=3)
    b = live("i", {"b": 1}, t="B", updated_at=3)
    w1 = merge({"i": a}, [b]).upserts[0].item
    w2 = merge({"i": b}, [a]).upserts[0].item
    assert w1 == w2


def test_equal_vv_different_content_is_conflict():
    a = live("i", {"a": 1}, t="A")
    b = live("i", {"a": 1}, t="B")
    o1, o2 = merge({"i": a}, [b]), merge({"i": b}, [a])
    # The side whose local state wins upserts nothing (it would be a no-op with the same
    # vector); the other side takes the winner.  Both end with the same winner and copy.
    winners = [u.item for u in (*o1.upserts, *o2.upserts)]
    assert len(winners) == 1
    assert o1.copies == o2.copies and len(o1.copies) == 1
    after1 = {"i": o1.upserts[0] if o1.upserts else a, **{c.item_id: c for c in o1.copies}}
    after2 = {"i": o2.upserts[0] if o2.upserts else b, **{c.item_id: c for c in o2.copies}}
    assert after1 == after2


def test_edit_vs_delete_keeps_item():
    dd, lv = dead("i", {"a": 1}), live("i", {"b": 1}, t="B")
    for loc, r in ((dd, lv), (lv, dd)):
        out = merge({"i": loc}, [r])
        assert [(u.item, u.vv) for u in out.upserts] == [({"t": "B"}, {"a": 1, "b": 1})]
        assert not out.deletes and not out.copies and out.conflicts == ((loc, r),)


def test_concurrent_identical_merges_vectors():
    loc, r = live("i", {"a": 2}, t="S"), live("i", {"a": 1, "b": 3}, t="S")
    out = merge({"i": loc}, [r])
    assert out.upserts[0].vv == {"a": 2, "b": 3} and not out.conflicts
    loc, r = dead("i", {"a": 2}, at=5), dead("i", {"b": 1}, at=9)
    out = merge({"i": loc}, [r])
    assert out.deletes[0].vv == {"a": 2, "b": 1} and out.deletes[0].deleted_at == 9
    assert not out.conflicts
    # local already holds the merged tombstone: nothing to do
    assert merge({"i": out.deletes[0]}, [r]) == MergeOutcome((), (), ())


def test_idempotent_repeat():
    remote = [live("i", {"a": 2}, t="n"), dead("d", {"a": 1})]
    out = merge({}, remote)
    local = {s.item_id: s for s in out.upserts + out.deletes}
    assert merge(local, remote) == MergeOutcome((), (), ())
    # same edit via two routes in one call is a duplicate id
    with pytest.raises(EngineError):
        merge({}, [remote[0], remote[0]])


def test_merge_ignores_timestamps():
    a = dead("i", {"a": 1}, at=1)
    b = dead("i", {"a": 1}, at=10**12)
    # equal vectors: only the tombstone stamp converges (to the max), in both directions
    out = merge({"i": a}, [b])
    assert [d.deleted_at for d in out.deletes] == [10**12]
    assert merge({"i": b}, [a]) == MergeOutcome((), (), ())
    out = merge({"i": live("i", {"a": 1})}, [dead("i", {"a": 2}, at=1)])
    out2 = merge({"i": live("i", {"a": 1})}, [dead("i", {"a": 2}, at=10**12)])
    assert len(out.deletes) == len(out2.deletes) == 1


def test_conflict_copy_id_deterministic():
    u = str(uuid.uuid4())
    a = conflict_copy_id(u, "d1")
    assert a == conflict_copy_id(u, "d1")
    assert a != conflict_copy_id(u, "d2")
    assert a != conflict_copy_id(str(uuid.uuid4()), "d1")
    assert a == str(uuid.uuid5(uuid.UUID(u), "lgk-copy:d1"))
    ns = uuid.uuid5(uuid.NAMESPACE_URL, "lgk-item:not-a-uuid")
    assert conflict_copy_id("not-a-uuid", "d1") == str(uuid.uuid5(ns, "lgk-copy:d1"))


def test_copy_dropped_when_already_held():
    loc = live("i", {"a": 1}, t="A", updated_at=1)
    r = live("i", {"b": 1}, t="B", updated_at=9)
    cid = conflict_copy_id("i", digest(loc.item))
    held = live(cid, {"a": 1}, t="A", id=cid)
    assert merge({"i": loc, cid: held}, [r]).copies == ()
    assert merge({"i": loc}, [r, held]).copies == ()
    assert len(merge({"i": loc}, [r]).copies) == 1


def test_item_validation_and_bounds():
    for bad in ({1: "x"}, {"a": float("nan")}, {"a": float("inf")}, {"a": {1, 2}},
                {"a": "\ud800"}, {"a": [object()]}, {"a": {2: 1}}):
        with pytest.raises(EngineError):
            ItemState("i", {}, False, None, bad)
    for bad_id in ("x" * 129, "a\x00b", 5):
        with pytest.raises(EngineError):
            ItemState(bad_id, {}, False, None, {})
    with pytest.raises(EngineError):
        ItemState("i", {"a": 2**53}, False, None, {})
    ItemState("i", {"a": 2**53 - 1}, True, 2**53 - 1, None)
    for bad_at in (-1, 2**53, True, 1.5):
        with pytest.raises(EngineError):
            ItemState("i", {}, True, bad_at, None)


def test_updated_at_float_counts_as_zero():
    a = live("i", {"a": 1}, t="A", updated_at=99.5)
    b = live("i", {"b": 1}, t="B", updated_at=1)
    assert merge({"i": a}, [b]).upserts[0].item["t"] == "B"


def test_vv_keys_sorted():
    st = ItemState("i", {"z": 1, "a": 2, "m": 0}, False, None, {})
    assert list(st.vv) == ["a", "z"]
    out = merge({"i": live("i", {"z": 1})}, [live("i", {"b": 1, "a": 1}, t="y")])
    assert list(out.upserts[0].vv) == sorted(out.upserts[0].vv)


def _live_contents_unique(state):
    seen = [canonical_json({k: v for k, v in s.item.items() if k != "id"})
            for s in state.values() if not s.deleted]
    return len(seen) == len(set(seen))


def test_three_way_regression_all_gossip_orders():
    base = [
        {"x": live("x", {"a": 1}, pw="A", updated_at=3)},
        {"x": live("x", {"b": 1}, pw="B", updated_at=2)},
        {"x": live("x", {"c": 1}, pw="C", updated_at=1)},
    ]
    edges = [(i, j) for i in range(3) for j in range(3) if i != j]
    for order in itertools.permutations(edges):
        devs = [dict(x) for x in base]
        for _round in range(3):
            for dst, src in order:
                devs[dst] = _sync(devs[dst], devs[src])
        assert devs[0] == devs[1] == devs[2], order
        live_items = [s for s in devs[0].values() if not s.deleted]
        assert len(live_items) == 3, order
        assert sorted(s.item["pw"] for s in live_items) == ["A", "B", "C"]
        assert devs[0]["x"].item["pw"] == "A"
        assert _live_contents_unique(devs[0])


def test_merge_validates_inputs():
    with pytest.raises(EngineError):
        merge({"x": live("i", {})}, [])
    with pytest.raises(EngineError):
        merge({}, ["nope"])


def _apply(local, out):
    new = dict(local)
    for st in out.upserts + out.deletes:
        new[st.item_id] = st
    for st in out.copies:
        new[st.item_id] = st  # merge() already dropped copies that exist
    return new


def _sync(dst, src):
    """dst merges src's view; returns the new dst."""
    return _apply(dst, merge(dst, list(src.values())))


def _gen_state(rng, item_id, vv):
    """State is a pure function of (item_id, vv) so equal vectors imply equal states."""
    key = sorted((d, n) for d, n in vv.items() if n)
    h = sum(n * (ord(d) + 1) for d, n in key) + len(item_id)
    if h % 4 == 0:
        return dead(item_id, vv, at=h)
    return live(item_id, vv, t=f"{item_id}:{key}", updated_at=h % 3)


def _gen_side(rng, ids, devs):
    st = {}
    for i in ids:
        if rng.random() < 0.2:
            continue
        vv = {d: rng.randint(0, 2) for d in devs if rng.random() < 0.7}
        st[i] = _gen_state(rng, i, vv)
    return st


def test_property_two_way_convergence():
    rng = random.Random(1234)  # noqa: S311
    ids = ["i1", "i2", "i3"]
    for _ in range(400):
        A, B = _gen_side(rng, ids, "abc"), _gen_side(rng, ids, "abc")
        shuffled = list(B.values())
        rng.shuffle(shuffled)
        assert merge(A, shuffled) == merge(A, list(B.values()))
        fa = _sync(A, B)
        fb = _sync(B, fa)
        fa = _sync(fa, fb)
        assert fa == fb


def test_property_three_device_convergence():
    rng = random.Random(99)  # noqa: S311
    ids = ["i1", "i2", "i3"]
    for _ in range(300):
        base = [_gen_side(rng, ids, "abc") for _ in range(3)]
        orders = [[(0, 1), (1, 2), (2, 0)], [(1, 0), (2, 1), (0, 2)]]
        shuf = [(i, j) for i in range(3) for j in range(3) if i != j]
        rng.shuffle(shuf)
        orders.append(shuf)
        for order in orders:
            devs = [dict(x) for x in base]
            for _round in range(6):
                for dst, src in order:
                    devs[dst] = _sync(devs[dst], devs[src])
            assert devs[0] == devs[1] == devs[2], order


def test_bump_standard_increment():
    assert bump({}, "a") == {"a": 1}
    assert bump({"c": 1, "a": 4}, "a") == {"a": 5, "c": 1}
    assert bump({"z": 2, "a": 0}, "b") == {"b": 1, "z": 2}
    assert list(bump({"z": 1, "b": 1}, "m")) == ["b", "m", "z"]
    src = {"a": 1}
    bump(src, "a")
    assert src == {"a": 1}
    for bad_vv, dev in (({}, ""), ({}, "a|b"), ({"a": -1}, "a"), ({"a": 2**53 - 1}, "a")):
        with pytest.raises(EngineError):
            bump(bad_vv, dev)


class _Sim:
    """Devices with real user histories, tracking every authored content version.

    Oracle: after full gossip, each authored version (content minus "id", authoring
    vector) is live somewhere under any id, or causally covered: a user edit or
    delete at a vector dominating the authoring vector, either of a state holding
    exactly that content (the original or a conflict copy of it) or of the same id
    on a device that had seen the content.
    """

    def __init__(self, names):
        self.names = list(names)
        self.devs = {n: {} for n in self.names}
        self.seen = {n: set() for n in self.names}
        self.authored = []  # (item_id, digest, vv)
        self.covering = []  # (device, item_id, prior vv, prior digest) per edit/delete
        self.counter = itertools.count(1)

    def _observe(self, n):
        self.seen[n].update(digest(s.item) for s in self.devs[n].values() if not s.deleted)

    def lives(self, n):
        return sorted(i for i, st in self.devs[n].items() if not st.deleted)

    def create(self, n, updated_at=0, iid=None):
        iid = iid or f"n{next(self.counter)}"
        st = live(iid, bump({}, n), t=f"v{next(self.counter)}", updated_at=updated_at)
        self.devs[n][iid] = st
        self.authored.append((iid, digest(st.item), st.vv))
        self._observe(n)
        return iid

    def _supersede(self, n, iid):
        prior = self.devs[n][iid]
        assert not prior.deleted
        self.covering.append((n, iid, prior.vv, digest(prior.item)))
        return prior

    def edit(self, n, iid, updated_at=0):
        prior = self._supersede(n, iid)
        item = {**prior.item, "t": f"v{next(self.counter)}", "updated_at": updated_at}
        st = ItemState(iid, bump(prior.vv, n), False, None, item)
        self.devs[n][iid] = st
        self.authored.append((iid, digest(item), st.vv))
        self._observe(n)

    def delete(self, n, iid, at=0):
        prior = self._supersede(n, iid)
        self.devs[n][iid] = dead(iid, bump(prior.vv, n), at=at)

    def sync(self, dst, src):
        self.devs[dst] = _sync(self.devs[dst], self.devs[src])
        self._observe(dst)

    def gossip(self, order, max_rounds=8):
        """Repeat *order* until a round changes nothing; returns rounds used."""
        for rnd in range(1, max_rounds + 1):
            before = {n: dict(d) for n, d in self.devs.items()}
            for dst, src in order:
                self.sync(dst, src)
            if self.devs == before:
                return rnd
        raise AssertionError(f"gossip did not reach a fixed point in {max_rounds} rounds")

    def _covered(self, iid, dg, vv):
        for n, cid, prior_vv, prior_dg in self.covering:
            if compare(prior_vv, vv) not in ("a", "equal"):
                continue
            # the user replaced this very content (original or a conflict copy of
            # it), or a later version of the same id on a device that had seen it
            if prior_dg == dg or (cid == iid and dg in self.seen[n]):
                return True
        return False

    def check(self, order):
        self.gossip(order)
        first = self.devs[self.names[0]]
        for n in self.names[1:]:
            assert self.devs[n] == first, (n, order)
        # termination: one extra round of every pair changes nothing
        snapshot = {n: dict(d) for n, d in self.devs.items()}
        for dst in self.names:
            for src in self.names:
                if dst != src:
                    assert merge(self.devs[dst], list(self.devs[src].values())) == \
                        MergeOutcome((), (), ()), (dst, src)
        assert self.devs == snapshot
        present = {digest(s.item) for s in first.values() if not s.deleted}
        lost = [(iid, vv) for iid, dg, vv in self.authored
                if dg not in present and not self._covered(iid, dg, vv)]
        assert not lost, (lost, order)

    def clone(self):
        c = _Sim(self.names)
        c.devs = {n: dict(d) for n, d in self.devs.items()}
        c.seen = {n: set(s) for n, s in self.seen.items()}
        c.authored, c.covering = list(self.authored), list(self.covering)
        return c


def test_retirement_regression_edited_copy_survives_all_gossip_orders():
    """Reviewer's 3-device history that made copy retirement delete a user edit."""
    sim = _Sim("abc")
    sim.create("c", updated_at=0, iid="x")            # 1. c creates O
    sim.sync("a", "c")
    sim.sync("b", "c")
    sim.edit("b", "x", updated_at=9)                  # 2. b edits to Z
    sim.sync("c", "b")
    sim.edit("b", "x", updated_at=9)                  #    b edits to Z2 ...
    sim.delete("b", "x", at=50)                       #    ... then deletes it
    sim.edit("a", "x", updated_at=1)                  # 3. a edits to X concurrently
    x_item, x_vv = sim.devs["a"]["x"].item, sim.devs["a"]["x"].vv
    sim.sync("c", "a")                                # 4. Z wins on c, copy(X)
    cid = conflict_copy_id("x", digest(x_item))
    assert sim.devs["c"]["x"].item["t"] != x_item["t"] and cid in sim.devs["c"]
    sim.sync("a", "b")                                # 5. edit beats delete on a
    assert sim.devs["a"]["x"].item == x_item
    sim.sync("b", "c")                                # 6. b receives copy(X) live
    assert not sim.devs["b"][cid].deleted
    sim.edit("b", cid, updated_at=5)                  #    user on b edits the copy
    edited = sim.devs["b"][cid].item
    # X itself may give way to this edit: its vector dominates X's authoring vector
    assert compare(sim.devs["b"][cid].vv, x_vv) == "a"
    edges = [(i, j) for i in "abc" for j in "abc" if i != j]
    for order in itertools.permutations(edges):
        run = sim.clone()
        run.check(order)                              # 7./8. gossip in every order
        final = run.devs["a"]
        assert final[cid].item == edited, order
        assert not final["x"].deleted, order


@pytest.mark.parametrize(("sync_weight", "seed"), [(1, 7), (6, 8)])
def test_oracle_no_authored_content_disappears(sync_weight, seed):
    """Random 4-device histories: no user content is lost unless causally covered."""
    rng = random.Random(seed)  # noqa: S311
    names = "abcd"
    pairs = [(x, y) for x in names for y in names if x != y]
    for _ in range(300):
        sim = _Sim(names)
        for _step in range(rng.randint(5, 40)):
            n = rng.choice(names)
            op = rng.choice(["create"] + ["edit"] * 4 + ["delete"] * 2 + ["sync"] * sync_weight)
            lives = sim.lives(n)
            if op == "create" or (op in ("edit", "delete") and not lives):
                sim.create(n, updated_at=rng.randint(0, 3))
            elif op == "edit":
                sim.edit(n, rng.choice(lives), updated_at=rng.randint(0, 3))
            elif op == "delete":
                sim.delete(n, rng.choice(lives), at=rng.randint(0, 99))
            else:
                sim.sync(n, rng.choice([x for x in names if x != n]))
        order = list(pairs)
        rng.shuffle(order)
        sim.check(order)


def test_identifiers_are_ascii_restricted():
    import pytest

    from localvault.sync.engine import EngineError, is_valid_id

    good = ["a", "A.b_c:d-1", str(uuid.uuid4()), "x" * 128]
    bad = ["", "x" * 129, "a b", "a|b", "a/b", "café", "\ud800", "a\n", "a\x00", 5, None]
    for v in good:
        assert is_valid_id(v)
        ItemState(v, {v: 1}, True, None, None)
    for v in bad:
        assert not is_valid_id(v)
        with pytest.raises(EngineError):
            ItemState(v, {}, True, None, None)
        with pytest.raises(EngineError):
            compare({v: 1}, {})
        with pytest.raises(EngineError):
            bump({}, v)
    # conflict-copy ids stay inside the alphabet
    cid = conflict_copy_id("item-1", "ab" * 32)
    assert is_valid_id(cid)
    assert is_valid_id(conflict_copy_id(str(uuid.uuid4()), "ab" * 32))


def test_item_ints_bounded_to_int64():
    ok = {"n": 2**63 - 1, "m": -(2**63 - 1)}
    ItemState("x", {"A": 1}, False, None, ok)
    for bad in (2**63, -(2**63)):
        with pytest.raises(EngineError):
            ItemState("x", {"A": 1}, False, None, {"n": bad})


def test_copy_namespace_only_for_hyphenated_uuid():
    u = "0f8fad5b-d9cb-469f-a165-70867728950e"
    d = "a" * 64
    assert conflict_copy_id(u, d) == conflict_copy_id(u.upper(), d)
    plain = u.replace("-", "")
    assert conflict_copy_id(plain, d) == str(uuid.uuid5(uuid.uuid5(uuid.NAMESPACE_URL, "lgk-item:" + plain), "lgk-copy:" + d))
    urn = "urn:uuid:" + u
    assert conflict_copy_id(urn, d) == str(uuid.uuid5(uuid.uuid5(uuid.NAMESPACE_URL, "lgk-item:" + urn), "lgk-copy:" + d))
