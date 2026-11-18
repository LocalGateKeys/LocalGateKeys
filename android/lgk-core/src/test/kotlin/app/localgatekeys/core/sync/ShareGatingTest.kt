package app.localgatekeys.core.sync

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Share v2 (keyring format 3, `docs/superpowers/specs/2026-11-12-collections-crypto-gating.md`) against the desktop's
 * bytes in `tests/vectors/share/collections/gating.json` (scripts/make_share_gating_vectors.py): every keyring written
 * byte for byte from the recorded random draws, the content key each device opens, the view sealed with `C`, and the
 * negatives refused with the desktop's reason.
 */
class ShareGatingTest {
    private val doc: Map<String, JsonValue> = Vectors.json(Vectors.shareCollections("gating.json")).obj().fields
    private val yes: (String) -> Boolean = { true }
    private val gid = str(doc["group_id"])!!
    private val cid = str(doc["collection_id"])!!
    private val now = (doc["now"] as JsonValue.Int).v
    private val password = str(doc["password"])!!
    private val newPassword = str(doc["new_password"])!!
    private val pin = ShareKeyring.Pin.of(case("create")["keyring"]!!)

    private fun id(who: String): DeviceIdentity = SyncFixtures.identity(who)

    private fun case(name: String): Map<String, JsonValue> = obj(doc[name])

    private fun ring(name: String): JsonValue = case(name)["keyring"]!!

    private fun queue(c: Map<String, JsonValue>) = QueueRandom(arr(c["random_reads_hex"]).map { Vectors.hex(str(it)!!) })

    private fun canonical(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    private fun table(): KeyringRotate.KeyDerivation {
        val known = obj(doc["argon2"]).mapValues { Vectors.hex(str(it.value)!!) }
        return KeyringRotate.KeyDerivation { pw, salt -> known["$pw|${Base64Std.encode(salt)}"] ?: ByteArray(32) }
    }

    private fun pwKey(keyring: JsonValue): ByteArray {
        val salt = str(obj(obj(keyring)["kdf"])["salt"])!!
        return Vectors.hex(str(obj(doc["argon2"])["$password|$salt"])!!)
    }

    private fun gk1() = GroupKey(gid, 1, Vectors.hex(str(case("create")["group_key_hex"])!!))

    private fun reason(f: () -> Any?): String? = try {
        f()
        null
    } catch (e: KeyringException) {
        e.reason
    }

    private fun ids(v: JsonValue?): List<String> = arr(v).map { str(it)!! }

    @Test fun create_join_approve_join_and_remove_byte_for_byte() {
        val c = case("create")
        val random = queue(c)
        val spec = ShareKeyring.Spec(cid, str(doc["name"])!!, str(doc["shared_mode"])!!)
        val (created, gk) = ShareKeyring.create(password, id("A"), "Owner phone", spec, random, now, yes, table())
        assertTrue(random.isEmpty)
        assertContentEquals(canonical(ring("create")), canonical(created))
        assertContentEquals(Vectors.hex(str(c["group_key_hex"])!!), gk.key)
        assertEquals(2, ShareKeyring.shareVersion(created))
        assertContentEquals(Vectors.hex(str(c["content_key_hex"])!!), assertNotNull(ShareKeyring.openContentKey(created, id("A"))).key)

        val jb = case("join_b")
        val rb = queue(jb)
        val (joinedB, gkB) = ShareKeyring.join(created, pwKey(created), id("B"), "Bea", rb, FixedClock(now + 60))
        assertTrue(rb.isEmpty)
        assertContentEquals(canonical(ring("join_b")), canonical(joinedB))
        assertEquals(gk1(), gkB)

        val ab = case("approve_b")
        val ra = queue(ab)
        val approved = ShareKeyring.approve(joinedB, gk1(), id("A"), ids(ab["approve"]), ra)
        assertTrue(ra.isEmpty)
        assertContentEquals(canonical(ring("approve_b")), canonical(approved))
        // The same approval through the pending-only entry point.
        assertContentEquals(canonical(approved), canonical(ShareKeyring.approvePending(joinedB, gk1(), id("A"), ids(ab["approve"]), queue(ab))))

        val jc = case("join_c")
        val rc = queue(jc)
        val (joinedC, _) = ShareKeyring.join(approved, pwKey(approved), id("C"), "Cy", rc, FixedClock(now + 120))
        assertTrue(rc.isEmpty)
        assertContentEquals(canonical(ring("join_c")), canonical(joinedC))

        val r = case("remove_b")
        val rr = queue(r)
        val (rotated, gk2) = ShareKeyring.rotate(joinedC, gk1(), id("A"), newPassword, ids(r["remove"]), rr, yes, table())
        assertTrue(rr.isEmpty)
        assertContentEquals(canonical(ring("remove_b")), canonical(rotated))
        assertContentEquals(Vectors.hex(str(r["group_key_hex"])!!), gk2.key)
        assertContentEquals(Vectors.hex(str(r["content_key_hex"])!!), assertNotNull(ShareKeyring.openContentKey(rotated, id("A"))).key)
        // removeMember draws the same (the pending C goes with B).
        val removed = ShareKeyring.removeMember(joinedC, gk1(), id("A"), id("B").deviceId, newPassword, queue(r), yes, now, table())
        assertContentEquals(canonical(rotated), canonical(removed.keyring))
    }

    @Test fun upgrade_from_share_v1_with_the_same_password_byte_for_byte() {
        val u = case("upgrade")
        val stored = u["stored"]!!
        val storedGid = str(obj(stored)["group_id"])!!
        val storedKey = GroupKey(storedGid, 1, Vectors.hex(str(u["stored_group_key_hex"])!!))
        assertEquals(1, ShareKeyring.shareVersion(stored))
        val random = queue(u)
        val (upgraded, gk) = ShareKeyring.upgrade(stored, storedKey, id("A"), str(u["password"])!!, random, yes, table())
        assertTrue(random.isEmpty)
        assertContentEquals(canonical(u["keyring"]!!), canonical(upgraded))
        assertContentEquals(Vectors.hex(str(u["group_key_hex"])!!), gk.key)
        assertEquals(ids(u["approved"]).toSet(), ShareKeyring.approvedMembers(upgraded))
        assertEquals(gk, ShareKeyring.accept(upgraded, storedKey, id("C")))
        assertNull(ShareKeyring.openContentKey(upgraded, id("C")))
        assertEquals("already-v2", reason { ShareKeyring.upgrade(upgraded, gk, id("A"), password, queue(u), yes, table()) })
        assertEquals("not-owner", reason { ShareKeyring.upgrade(stored, storedKey, id("B"), password, queue(u), yes, table()) })
    }

    @Test fun each_device_opens_exactly_the_content_key_it_was_given() {
        for ((name, opens) in obj(doc["open"])) {
            val keyring = if (name == "upgrade") obj(doc["upgrade"])["keyring"]!! else ring(name)
            for ((who, hex) in obj(opens)) {
                val got = ShareKeyring.openContentKey(keyring, id(who))
                if (hex == JsonValue.Null) {
                    assertNull(got, "$name/$who")
                } else {
                    assertEquals(str(hex), Hex.lower(assertNotNull(got, "$name/$who").key), "$name/$who")
                }
            }
        }
        for (c in arr(doc["open_negative"]).map { obj(it) }) {
            assertEquals(str(c["reason"]), reason { ShareKeyring.openContentKey(c["keyring"]!!, id(str(c["device"])!!)) }, str(c["name"]))
        }
        assertEquals("not-share-v2", reason {
            ShareKeyring.openContentKey(obj(doc["upgrade"])["stored"]!!, id("A"))
        })
    }

    @Test fun the_view_opens_with_the_content_key_and_never_with_the_group_key() {
        val v = case("view")
        val raw = Base64Std.decodeStrict(str(v["view_b64"])!!)
        val ck = GroupKey(gid, 1, Vectors.hex(str(case("create")["content_key_hex"])!!))
        val a = id(str(v["device"])!!).deviceId
        val (_, states) = ViewFile.decode(raw, ck, a)
        val want = arr(v["states"]).map { obj(it) }
        assertEquals(want.map { str(it["id"]) }, states.map { it.itemId })
        for ((w, s) in want.zip(states)) {
            assertContentEquals(canonical(w["item"]!!), canonical(s.item!!))
            assertEquals(obj(w["vv"]).mapValues { (it.value as JsonValue.Int).v }, s.vv)
        }
        val wrong = try {
            ViewFile.decode(raw, gk1(), a)
            null
        } catch (e: SyncFormatException) {
            e.reason
        }
        assertEquals(str(v["group_key_reason"]), wrong)
        // Written the same from the recorded nonces.
        val again = ViewFile.encode(ck, a, 1, states, FixedClock(now), QueueRandom(arr(v["nonce_reads_hex"]).map { Vectors.hex(str(it)!!) }))
        assertContentEquals(raw, again)
    }

    @Test fun adopt_refuses_every_negative_with_the_desktops_reason() {
        for (c in arr(doc["negative"]).map { obj(it) }) {
            val trusted = GroupKey(gid, (c["trusted_epoch"] as JsonValue.Int).v, Vectors.hex(str(c["trusted_key_hex"])!!))
            val device = id(str(c["device"])!!)
            val candidate = c["candidate"]!!
            val got = reason { ShareKeyring.adopt(c["stored"]!!, candidate, trusted, device, pin) }
            assertEquals(str(c["reason"]), got, str(c["name"]))
        }
        // And the genuine steps are adopted.
        assertEquals(gk1(), ShareKeyring.adopt(ring("join_b"), ring("approve_b"), gk1(), id("B"), pin))
        assertEquals(gk1(), ShareKeyring.adopt(ring("approve_b"), ring("join_c"), gk1(), id("A"), pin))
        assertContentEquals(
            Vectors.hex(str(case("remove_b")["group_key_hex"])!!),
            ShareKeyring.adopt(ring("join_c"), ring("remove_b"), gk1(), id("A"), pin).key,
        )
    }

    @Test fun adopt_accepts_every_positive_case() {
        val cases = arr(doc["positive"]).map { obj(it) }
        assertTrue(cases.isNotEmpty())
        for (c in cases) {
            val trusted = GroupKey(gid, (c["trusted_epoch"] as JsonValue.Int).v, Vectors.hex(str(c["trusted_key_hex"])!!))
            val got = ShareKeyring.adopt(c["stored"]!!, c["candidate"]!!, trusted, id(str(c["device"])!!), pin)
            assertEquals((c["new_epoch"] as JsonValue.Int).v, got.epoch, str(c["name"]))
            assertContentEquals(Vectors.hex(str(c["new_key_hex"])!!), got.key, str(c["name"]))
        }
    }

    @Test fun owner_reconcile_reuses_its_stored_content_wraps() {
        // C joined from the folder's join_b while the owner approved B on its own copy: the merge keeps B's stored wrap.
        val approved = ring("approve_b")
        val (racedC, _) = ShareKeyring.join(ring("join_b"), pwKey(ring("join_b")), id("C"), "Cy", QueueRandom(emptyList()), FixedClock(now + 90))
        val merged = assertNotNull(ShareKeyring.reconcileOwner(approved, racedC, gk1(), id("A"), pin))
        assertEquals(obj(obj(approved)["content"]), obj(obj(merged)["content"]))
        ShareKeyring.checkSameEpochGrowth(approved, merged)
        assertNull(ShareKeyring.openContentKey(merged, id("C")))
    }
}
