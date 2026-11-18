package app.localgatekeys.core.keyring

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.password.StrengthEstimator
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The rotation writer against the desktop's bytes: `mac/keyring_write.json` and `keyring_epoch2.json`. */
class KeyringRotateTest {
    private val write: Map<String, JsonValue> = Vectors.json(Vectors.sync("mac/keyring_write.json")).obj().fields
    private val yes: (String) -> Boolean = { true }

    private fun identity(who: String): DeviceIdentity = SyncFixtures.identity(who)

    private fun queue(case: Map<String, JsonValue>) = QueueRandom(arr(case["random_reads_hex"]).map { Vectors.hex(str(it)!!) })

    /** The vector's Argon2id outputs by `password|salt`; an unknown pair gives a key that opens nothing. */
    private fun table(): KeyringRotate.KeyDerivation {
        val known = obj(write["argon2"]).mapValues { Vectors.hex(str(it.value)!!) }
        return KeyringRotate.KeyDerivation { pw, salt -> known["$pw|${Base64Std.encode(salt)}"] ?: ByteArray(32) }
    }

    private fun canonical(v: JsonValue) = CanonicalJson.encode(v, Dialect.UTF8)

    private fun reason(f: () -> Any?): String? = try {
        f()
        null
    } catch (e: KeyringException) {
        e.reason
    }

    private fun joined(): Pair<JsonValue, GroupKey> {
        val ring = obj(write["join"])["keyring"]!!
        val gk = GroupKey(str(write["group_id"])!!, 1, Vectors.hex(str(obj(write["create"])["group_key_hex"])!!))
        return ring to gk
    }

    @Test fun rotate_matches_the_desktop_writer_byte_for_byte() {
        val (ring, gk) = joined()
        val a = identity("A")
        for (name in listOf("remove_member", "change_password")) {
            val case = obj(write[name])
            val remove = arr(case["remove"]).map { str(it)!! }
            val random = queue(case)
            val (rotated, newKey) = Keyring.rotate(ring, gk, a, str(write["new_password"])!!, remove, random, yes, table())
            assertTrue(random.isEmpty, name)
            assertContentEquals(canonical(case["keyring"]!!), canonical(rotated), name)
            assertContentEquals(Vectors.hex(str(case["group_key_hex"])!!), newKey.key, name)
            assertEquals(2, newKey.epoch)
            assertEquals(newKey, Keyring.accept(rotated, gk, a), name)
        }
    }

    @Test fun rotate_reproduces_keyring_epoch2() {
        // make_sync_vectors.py: DetRand("keyring") drew 12 blocks for create + two joins, then A rotated without C.
        val rand = DetRand("keyring")
        repeat(12) { rand.bytes(1) }
        val exp = Vectors.json(Vectors.sync("expected.json")).obj().fields
        val pw2 = str(exp["password_epoch2"])!!
        val ring1 = Keyring.parse(Vectors.sync("keyring_epoch1.json").readBytes())
        val ring2 = Vectors.sync("keyring_epoch2.json").readBytes()
        val salt2 = Base64Std.decodeStrict(str(obj(obj(Keyring.parse(ring2))["kdf"])["salt"])!!)
        val pwKey2 = SyncFixtures.pwKey("2")
        val derive = KeyringRotate.KeyDerivation { pw, salt -> if (pw == pw2 && salt.contentEquals(salt2)) pwKey2 else ByteArray(32) }
        val (rotated, gk2) = Keyring.rotate(ring1, SyncFixtures.epochKey("1"), identity("A"), pw2, listOf(SyncFixtures.identity("C").deviceId), rand, yes, derive)
        assertContentEquals(ring2, canonical(rotated))
        assertContentEquals(SyncFixtures.epochKey("2").key, gk2.key)
        assertEquals(2, gk2.epoch)
    }

    @Test fun rotate_refusals() {
        val (ring, gk) = joined()
        val a = identity("A")
        val b = identity("B")
        val pw = str(write["new_password"])!!
        val old = str(write["password"])!!
        val d = table()
        fun r(identity: DeviceIdentity = a, password: String = pw, remove: List<String> = emptyList(), trusted: GroupKey = gk, strong: (String) -> Boolean = yes) =
            reason { Keyring.rotate(ring, trusted, identity, password, remove, DetRand("refuse"), strong, d) }
        assertEquals("weak-password", r(strong = { false }))
        assertEquals("cannot-remove-self", r(remove = listOf(a.deviceId)))
        assertEquals("not-member", r(remove = listOf("d4444444-0000-4000-8000-00000000000d")))
        assertEquals("password-reused", r(password = old))
        assertEquals("not-member", r(identity = identity("C")))
        assertEquals("group-mismatch", r(trusted = GroupKey("other-group", 1, gk.key)))
        // B can rotate too and keeps A.
        val (rotated, newKey) = Keyring.rotate(ring, gk, b, pw, emptyList(), DetRand("b"), yes, d)
        assertEquals(newKey, Keyring.accept(rotated, gk, a))
    }

    @Test fun stale_trust_after_adopting_a_newer_epoch() {
        val ring2 = Keyring.parse(Vectors.sync("keyring_epoch2.json").readBytes())
        val r = reason {
            Keyring.rotate(ring2, SyncFixtures.epochKey("1"), identity("A"), "a brand new sync phrase 77", emptyList(), DetRand("s"), yes) { _, _ -> ByteArray(32) }
        }
        assertEquals("stale-trust", r)
    }

    @Test fun sync_password_rule_is_the_desktop_one() {
        val doc = (Vectors.json(File(Vectors.root, "password_strength/vectors.json")) as JsonValue.Obj).fields
        val dict = (doc.getValue("dictionary") as JsonValue.Obj).fields
        val asset = File(Vectors.root.parentFile.parentFile, "src/localvault/assets/eff_large_wordlist.txt")
        val packaged = asset.readText(Charsets.UTF_8).lines().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && Regex("[a-z]{3,12}").matches(it) }.toSortedSet()
        val extra = (dict.getValue("extra_words") as JsonValue.Arr).items.map { (it as JsonValue.Str).v }
        val estimator = StrengthEstimator(packaged + extra, packaged.size)
        assertTrue(Keyring.isStrongSyncPassword("violet tram sundial 1987 pebble", estimator))
        assertFalse(Keyring.isStrongSyncPassword("short1!", estimator))
        assertFalse(Keyring.isStrongSyncPassword("password1234", estimator))
    }
}
