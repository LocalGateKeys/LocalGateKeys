package app.localgatekeys.core.keyring

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.DeviceIdentityException
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.FixedRandom
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Port of Swift `KeyringTests`. Argon2id runs at production cost only where the Swift tests run it;
 * the rest use the raw Argon2id outputs from expected.json through the key-taking overloads.
 */
class KeyringTest {
    private val A = MergeVectors.A
    private val B = MergeVectors.B
    private val C = MergeVectors.C

    // ---- helpers ----

    private fun read(name: String): ByteArray = Vectors.sync(name).readBytes()

    private fun expected(): Map<String, JsonValue> = Vectors.json(Vectors.sync("expected.json")).obj().fields

    private fun identity(who: String): DeviceIdentity {
        val ids = obj(Vectors.json(Vectors.sync("identities.json")).obj().fields["devices"])
        val p = obj(obj(ids[who])["private"])
        return DeviceIdentity(
            str(p["device_id"])!!,
            Base64Std.decodeStrict(str(p["signing_private"])!!),
            Base64Std.decodeStrict(str(p["exchange_private"])!!),
        )
    }

    private fun ring(name: String): JsonValue = Keyring.parse(read(name))

    private fun base(existing: Boolean): Map<String, JsonValue> =
        if (existing) obj(expected()["existing_group"]) else expected()

    private fun epochKey(e: String, existing: Boolean = false): GroupKey {
        val b = base(existing)
        return GroupKey(str(b["group_id"])!!, e.toLong(), Vectors.hex(str(obj(obj(b["epochs"])[e])["group_key_hex"])!!))
    }

    private fun pwKey(e: String, existing: Boolean = false): ByteArray =
        Vectors.hex(str(obj(obj(base(existing)["epochs"])[e])["password_wrap_key_hex"])!!)

    private fun names(e: String, existing: Boolean = false): Map<String, String?> {
        val out = LinkedHashMap<String, String?>()
        for ((k, v) in obj(obj(obj(base(existing)["epochs"])[e])["member_names"])) out[k] = str(v)
        return out
    }

    private fun reason(f: () -> Any?): String? = try {
        f()
        null
    } catch (e: KeyringException) {
        e.reason
    } catch (e: Exception) {
        "other: $e"
    }

    private fun GroupKey.withEpoch1() = GroupKey(groupId, 1, key)

    // ---- identities ----

    @Test
    fun identities_match_vectors() {
        val ids = obj(Vectors.json(Vectors.sync("identities.json")).obj().fields["devices"])
        for (who in listOf("A", "B", "C")) {
            val d = obj(ids[who])
            val id = identity(who)
            assertEquals(str(d["device_id"]), id.deviceId)
            assertEquals(str(d["signing_public_b64"]), Base64Std.encode(id.signingPublicKey))
            assertEquals(str(d["exchange_public_b64"]), Base64Std.encode(id.exchangePublicKey))
            assertEquals(str(d["fingerprint_sha256_of_signing_public"]), id.fingerprint)
        }
    }

    // ---- structure and MAC ----

    @Test
    fun every_keyring_file_verifies() {
        val cases = listOf(
            Triple("keyring_epoch1.json", "1", false), Triple("keyring_epoch2.json", "2", false),
            Triple("keyring_epoch1_ab.json", "1", false), Triple("keyring_existing_epoch1.json", "1", true),
            Triple("keyring_existing_epoch3.json", "3", true), Triple("keyring_attach.json", "1", true),
        )
        for ((file, e, existing) in cases) {
            val raw = read(file)
            val r = Keyring.parse(raw)
            assertContentEquals(raw, CanonicalJson.encode(r, Dialect.UTF8), file)
            assertTrue(Keyring.macOk(r, epochKey(e, existing)), file)
        }
        val x = expected()
        for (e in listOf("1", "2")) {
            val gk = epochKey(e)
            assertEquals(str(obj(obj(x["epochs"])[e])["keyring_mac_key_hex"]), Vectors.hexString(Keyring.macKey(gk)))
            assertEquals(str(obj(obj(x["epochs"])[e])["member_name_key_hex"]), Vectors.hexString(Keyring.nameKey(gk)))
        }
    }

    @Test
    fun parse_rejects_malformed() {
        val text = String(read("keyring_epoch1.json"), Charsets.UTF_8)
        fun parse(s: String) = Keyring.parse(s.toByteArray(Charsets.UTF_8))
        assertEquals("bad-json", reason { parse("{\"a\":1,\"a\":2}") })
        assertEquals("bad-keyring", reason { parse("[1]") })
        assertEquals("bad-json", reason { parse("{\"x\":NaN}") })
        assertEquals("too-large", reason { Keyring.parse(ByteArray(256 * 1024 + 1) { 0x20 }) })
        assertEquals("bad-format", reason { parse(text.replace("\"format\":1", "\"format\":1.0")) })
        assertEquals("bad-epoch", reason { parse(text.replace("\"epoch\":1", "\"epoch\":0")) })
        assertEquals("bad-kdf", reason { parse(text.replace("\"iterations\":4", "\"iterations\":3")) })
        assertEquals("bad-fields", reason { parse(text.replace("\"format\":1,", "\"format\":1,\"extra\":1,")) })
        val mac32 = Base64Std.encode(ByteArray(32) { 1 })
        assertEquals("bad-fields", reason { parse(text.replace("\"prev_mac\":null", "\"prev_mac\":\"$mac32\"")) })
        // Non-canonical base64 of the salt (strip padding).
        val salt = str(obj(obj(ring("keyring_epoch1.json"))["kdf"])["salt"])!!
        assertEquals("bad-base64", reason { parse(text.replace(salt, salt.dropLast(2))) })
    }

    // ---- password and device unwraps ----

    /** The two production-cost unwraps (one per password). */
    @Test
    fun password_unwrap_with_both_passwords() {
        val x = expected()
        assertEquals(epochKey("1"), Keyring.unwrapWithPassword(ring("keyring_epoch1.json"), str(x["password_epoch1"])!!))
        assertEquals(epochKey("2"), Keyring.unwrapWithPassword(ring("keyring_epoch2.json"), str(x["password_epoch2"])!!))
    }

    @Test
    fun password_unwrap_with_known_keys() {
        assertEquals(epochKey("1"), Keyring.unwrap(ring("keyring_epoch1.json"), pwKey("1")))
        assertEquals(epochKey("2"), Keyring.unwrap(ring("keyring_epoch2.json"), pwKey("2")))
        assertEquals(epochKey("1", true), Keyring.unwrap(ring("keyring_existing_epoch1.json"), pwKey("1", true)))
        assertEquals(epochKey("3", true), Keyring.unwrap(ring("keyring_existing_epoch3.json"), pwKey("3", true)))
        assertEquals("password", reason { Keyring.unwrap(ring("keyring_epoch1.json"), pwKey("2")) })
    }

    @Test
    fun device_wraps_for_all_devices() {
        val r1 = ring("keyring_epoch1.json")
        for (who in listOf("A", "B", "C")) assertEquals(epochKey("1"), Keyring.unwrapDevice(r1, identity(who)), who)
        val r2 = ring("keyring_epoch2.json")
        for (who in listOf("A", "B")) assertEquals(epochKey("2"), Keyring.unwrapDevice(r2, identity(who)), who)
        assertEquals("not-member", reason { Keyring.unwrapDevice(r2, identity("C")) })
        // Same device id, other exchange key.
        val c = identity("C")
        val fakeA = DeviceIdentity(A, c.signingPrivateKey, c.exchangePrivateKey)
        assertEquals("key-mismatch", reason { Keyring.unwrapDevice(r2, fakeA) })
    }

    // ---- accept ----

    @Test
    fun accept_rotation_and_rejections() {
        val r1 = ring("keyring_epoch1.json")
        val r2 = ring("keyring_epoch2.json")
        val g1 = epochKey("1")
        val g2 = epochKey("2")
        for (who in listOf("A", "B")) {
            assertEquals(g2, Keyring.accept(r2, g1, identity(who)), who)
            assertEquals(g1, Keyring.accept(r1, g1, identity(who)), who)
        }
        assertEquals("not-member", reason { Keyring.accept(r2, g1, identity("C")) })
        assertEquals("rollback", reason { Keyring.accept(r1, g2, identity("A")) })
        val other = GroupKey("other", 1, g1.key)
        assertEquals("group-mismatch", reason { Keyring.accept(r1, other, identity("A")) })
        val ex1 = epochKey("1", true)
        assertEquals("missed-rotation", reason { Keyring.accept(ring("keyring_existing_epoch3.json"), ex1, identity("A")) })
        val wrong = GroupKey(g1.groupId, 1, g2.key)
        assertEquals("tampered", reason { Keyring.accept(r1, wrong, identity("A")) })
        assertEquals("tampered", reason { Keyring.accept(r2, wrong, identity("A")) })
        // Body change after the MAC.
        val o = LinkedHashMap(obj(r1))
        o["members"] = JsonValue.Arr(arr(o["members"]).take(2))
        val w = LinkedHashMap(obj(o["device_wraps"]))
        w.remove(C)
        o["device_wraps"] = JsonValue.Obj(w)
        assertEquals("tampered", reason { Keyring.accept(JsonValue.Obj(o), g1, identity("A")) })

        // (a) Epoch 2 with B dropped but prev_mac kept: the chain verifies, the final MAC must not.
        val o2 = LinkedHashMap(obj(r2))
        o2["members"] = JsonValue.Arr(arr(o2["members"]).filter { str(obj(it)["device_id"]) != B })
        val w2 = LinkedHashMap(obj(o2["device_wraps"]))
        w2.remove(B)
        o2["device_wraps"] = JsonValue.Obj(w2)
        assertEquals("tampered", reason { Keyring.accept(JsonValue.Obj(o2), g1, identity("A")) })

        // (b) key-mismatch through accept.
        val c = identity("C")
        val fakeA = DeviceIdentity(A, c.signingPrivateKey, c.exchangePrivateKey)
        assertEquals("key-mismatch", reason { Keyring.accept(r2, g1, fakeA) })

        // (c) device-wrap through accept: zero (low-order) ephemeral key in A's wrap.
        val o3 = LinkedHashMap(obj(r2))
        val w3 = LinkedHashMap(obj(o3["device_wraps"]))
        val wa = LinkedHashMap(obj(w3[A]))
        wa["eph"] = JsonValue.Str(Base64Std.encode(ByteArray(32)))
        w3[A] = JsonValue.Obj(wa)
        o3["device_wraps"] = JsonValue.Obj(w3)
        assertEquals("device-wrap", reason { Keyring.accept(JsonValue.Obj(o3), g1, identity("A")) })
    }

    // ---- structure table ----

    private fun mutated(file: String, f: (LinkedHashMap<String, JsonValue>) -> Unit): ByteArray {
        val o = LinkedHashMap(obj(ring(file)))
        f(o)
        return CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8)
    }

    private fun editMember(o: LinkedHashMap<String, JsonValue>, i: Int, key: String, v: JsonValue) {
        val ms = arr(o["members"]).toMutableList()
        val m = LinkedHashMap(obj(ms[i]))
        m[key] = v
        ms[i] = JsonValue.Obj(m)
        o["members"] = JsonValue.Arr(ms)
    }

    @Test
    fun structure_rejections_table() {
        fun b64(n: Int) = JsonValue.Str(Base64Std.encode(ByteArray(n) { 7 }))
        val cases = listOf<Pair<String, (LinkedHashMap<String, JsonValue>) -> Unit>>(
            "bad-group-id" to { o -> o["group_id"] = JsonValue.Str("bad id") },
            "bad-members" to { o -> o["members"] = JsonValue.Arr(emptyList()) },
            "bad-members" to { o -> o["members"] = JsonValue.Str("x") },
            "too-many-members" to { o ->
                val m = arr(o["members"])
                o["members"] = JsonValue.Arr(List(17) { m[it % m.size] })
            },
            "bad-device-id" to { o -> editMember(o, 0, "device_id", JsonValue.Str("bad id")) },
            "duplicate-member" to { o -> editMember(o, 1, "device_id", obj(arr(o["members"])[0])["device_id"]!!) },
            "bad-name" to { o -> editMember(o, 0, "name_ct", b64(10)) },
            "bad-name" to { o -> editMember(o, 0, "name_ct", b64(93)) },
            "bad-fields" to { o -> editMember(o, 0, "added_at", JsonValue.Int(-1)) },
            "bad-fields" to { o -> editMember(o, 0, "added_at", JsonValue.Float(1.0)) },
            "bad-length" to { o -> editMember(o, 0, "exchange_public", b64(31)) },
            "bad-length" to { o ->
                val pw = LinkedHashMap(obj(o["password_wrap"]))
                pw["nonce"] = b64(11)
                o["password_wrap"] = JsonValue.Obj(pw)
            },
            "wrap-mismatch" to { o ->
                val w = LinkedHashMap(obj(o["device_wraps"]))
                w.remove(C)
                o["device_wraps"] = JsonValue.Obj(w)
            },
            "bad-fields" to { o -> o["prev_mac"] = b64(32) },
        )
        val failures = ArrayList<String>()
        for ((i, c) in cases.withIndex()) {
            val got = reason { Keyring.parse(mutated("keyring_epoch1.json", c.second)) }
            if (got != c.first) failures += "case $i: want ${c.first}, got $got"
        }
        assertTrue(failures.isEmpty(), failures.joinToString("; "))
        // prev_mac null is structurally allowed above epoch 1 (authentication catches it later).
        Keyring.parse(mutated("keyring_epoch1.json") { it["epoch"] = JsonValue.Int(2) })
    }

    // ---- password text ----

    @Test
    fun lone_surrogate_password_is_rejected_before_any_kdf() {
        val saved = app.localgatekeys.core.crypto.Argon2.default
        app.localgatekeys.core.crypto.Argon2.default = object : app.localgatekeys.core.crypto.Argon2id {
            override fun derive(password: ByteArray, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray =
                throw AssertionError("KDF must not run")
        }
        try {
            val bad = "ab\uD800c"
            assertEquals("password", reason { Keyring.unwrapWithPassword(ring("keyring_epoch1.json"), bad) })
            val me = DeviceIdentity.generate(random = DetRand("sur"))
            assertEquals("password", reason { Keyring.join(ring("keyring_epoch1_ab.json"), bad, me, "n", DetRand("s"), FixedClock(1)) })
            val ex = epochKey("1", true)
            assertEquals(
                "password",
                reason { Keyring.attach(ring("keyring_existing_epoch1.json"), bad, identity("B"), "n", ex, DetRand("s"), FixedClock(1)) },
            )
        } finally {
            app.localgatekeys.core.crypto.Argon2.default = saved
        }
    }

    @Test
    fun existing_and_attach_keyrings_accepted() {
        val ex1 = epochKey("1", true)
        val ex3 = epochKey("3", true)
        val a = identity("A")
        val b = identity("B")
        assertEquals(ex1, Keyring.accept(ring("keyring_existing_epoch1.json"), ex1, a))
        assertEquals(ex3, Keyring.accept(ring("keyring_existing_epoch3.json"), ex3, a))
        val att = ring("keyring_attach.json")
        assertEquals(ex1, Keyring.accept(att, ex1, a))
        assertEquals(ex1, Keyring.accept(att, ex1, b))
        assertEquals(ex1, Keyring.unwrapDevice(att, b))
        assertEquals(names("1", true) + (B to "Laptop (Windows)"), Keyring.memberNames(att, ex1))
    }

    // ---- names ----

    @Test
    fun member_names_every_epoch() {
        assertEquals(names("1"), Keyring.memberNames(ring("keyring_epoch1.json"), epochKey("1")))
        assertEquals(names("2"), Keyring.memberNames(ring("keyring_epoch2.json"), epochKey("2")))
        assertEquals(names("1", true), Keyring.memberNames(ring("keyring_existing_epoch1.json"), epochKey("1", true)))
        assertEquals(names("3", true), Keyring.memberNames(ring("keyring_existing_epoch3.json"), epochKey("3", true)))
        // Wrong key reads as null, never throws.
        val n = Keyring.memberNames(ring("keyring_epoch1.json"), epochKey("2").withEpoch1())
        assertEquals(3, n.size)
        assertTrue(n.values.all { it == null })
    }

    // ---- join and attach ----

    @Test
    fun join_output_verifies_on_desktop_rules() {
        val ab = ring("keyring_epoch1_ab.json")
        val g1 = epochKey("1")
        val me = DeviceIdentity.generate(random = DetRand("swift-join-id"))
        val (joined, gk) = Keyring.join(
            ab, str(expected()["password_epoch1"])!!, me, "iPhone", DetRand("swift-join"), FixedClock(1790000500),
        )
        assertEquals(g1, gk)
        // Re-parse the canonical bytes: structure + MAC as the desktop checks them.
        val back = Keyring.parse(CanonicalJson.encode(joined, Dialect.UTF8))
        assertTrue(Keyring.macOk(back, g1))
        assertEquals(g1, Keyring.accept(back, g1, me))
        assertEquals(g1, Keyring.accept(back, g1, identity("A")))
        assertEquals(g1, Keyring.unwrapDevice(back, me))
        val o = obj(back)
        val old = obj(ab)
        for (k in listOf("password_wrap", "kdf", "prev_mac", "group_id", "epoch", "format")) assertEquals(old[k], o[k], k)
        val members = arr(o["members"])
        assertEquals(3, members.size)
        assertEquals(arr(old["members"]), members.take(2))
        assertEquals(JsonValue.Int(1790000500), obj(members[2])["added_at"])
        assertEquals("iPhone", Keyring.memberNames(back, g1)[me.deviceId])
        // A second join of the same device is refused before any KDF work.
        assertEquals("already-member", reason { Keyring.join(back, "x", me, "iPhone", DetRand("j2"), FixedClock(0)) })
        assertEquals("bad-name", reason { Keyring.join(ab, "x", me, "", DetRand("j3"), FixedClock(0)) })
    }

    @Test
    fun device_name_with_lone_surrogate_is_bad_name() {
        val ab = ring("keyring_epoch1_ab.json")
        val me = DeviceIdentity.generate(random = DetRand("kt-surrogate-id"))
        // A lone high surrogate, a lone low surrogate and a reversed pair: none is UTF-8 encodable.
        for (name in listOf("Pixel\uD83D", "\uDE00Pixel", "a\uDE00\uD83Db")) {
            assertEquals("bad-name", reason { Keyring.join(ab, "x", me, name, DetRand("j4"), FixedClock(0)) }, name)
        }
        // A proper pair (an emoji) is fine and survives the round trip.
        val (back, gk) = Keyring.join(ab, pwKey("1"), me, "Pixel 😀", DetRand("j5"), FixedClock(1790000600))
        assertEquals("Pixel 😀", Keyring.memberNames(back, gk)[me.deviceId])
    }

    @Test
    fun join_with_known_key_draws_in_order_and_is_deterministic() {
        val ab = ring("keyring_epoch1_ab.json")
        val me = DeviceIdentity.generate(random = DetRand("kt-join-id"))
        val one = Keyring.join(ab, pwKey("1"), me, "Pixel", DetRand("kt"), FixedClock(1790000600))
        val two = Keyring.join(ab, pwKey("1"), me, "Pixel", DetRand("kt"), FixedClock(1790000600))
        assertContentEquals(CanonicalJson.encode(one.first, Dialect.UTF8), CanonicalJson.encode(two.first, Dialect.UTF8))
        // Same inputs give identical bytes; the draw order is asserted in join_draws_eph_nonce_name_nonce_in_order.
        val back = Keyring.parse(CanonicalJson.encode(one.first, Dialect.UTF8))
        assertEquals("Pixel", Keyring.memberNames(back, epochKey("1"))[me.deviceId])
        assertEquals("password", reason { Keyring.join(ab, pwKey("2"), me, "Pixel", DetRand("kt"), FixedClock(1)) })
        assertEquals("bad-fields", reason { Keyring.join(ab, pwKey("1"), me, "Pixel", DetRand("kt"), FixedClock(-1)) })
    }

    private class SeqRandom(private val data: ByteArray) : app.localgatekeys.core.primitives.RandomSource {
        private var pos = 0
        override fun bytes(count: Int): ByteArray = data.copyOfRange(pos, pos + count).also { pos += count }
    }

    @Test
    fun join_draws_eph_nonce_name_nonce_in_order() {
        val stream = ByteArray(56) { (it * 3 + 1).toByte() }
        val me = DeviceIdentity.generate(random = DetRand("order-id"))
        val (joined, _) = Keyring.join(ring("keyring_epoch1_ab.json"), pwKey("1"), me, "Pixel", SeqRandom(stream), FixedClock(5))
        val wrap = obj(obj(obj(joined)["device_wraps"])[me.deviceId])
        assertContentEquals(
            app.localgatekeys.core.primitives.X25519.publicKey(stream.copyOfRange(0, 32)),
            Base64Std.decodeStrict(str(wrap["eph"])!!),
        )
        assertContentEquals(stream.copyOfRange(32, 44), Base64Std.decodeStrict(str(wrap["nonce"])!!))
        val nameCt = Base64Std.decodeStrict(str(obj(arr(obj(joined)["members"]).last())["name_ct"])!!)
        assertContentEquals(stream.copyOfRange(44, 56), nameCt.copyOfRange(0, 12))
    }

    @Test
    fun attach_with_known_key() {
        val ex1 = epochKey("1", true)
        val pw = pwKey("1", true)
        val base = ring("keyring_existing_epoch1.json")
        val b = identity("B")
        val out = Keyring.attach(base, pw, b, "Laptop (Windows)", ex1, DetRand("swift-attach"), FixedClock(1790000060))
        val back = Keyring.parse(CanonicalJson.encode(out, Dialect.UTF8))
        assertEquals(ex1, Keyring.accept(back, ex1, b))
        assertEquals(obj(base)["password_wrap"], obj(back)["password_wrap"])
        assertEquals(obj(base)["kdf"], obj(back)["kdf"])
        assertEquals(
            arr(obj(base)["members"]).first { str(obj(it)["device_id"]) == A },
            arr(obj(back)["members"]).first { str(obj(it)["device_id"]) == A },
        )
        assertEquals(obj(obj(base)["device_wraps"])[A], obj(obj(back)["device_wraps"])[A])
        // Idempotent with the vector keyring that already lists B.
        val att = ring("keyring_attach.json")
        assertEquals(att, Keyring.attach(att, pw, b, "Laptop (Windows)", ex1, DetRand("x"), FixedClock(0)))
        // C is not listed in the vector: a C impostor under B's id is already-member.
        val c = identity("C")
        val fakeB = DeviceIdentity(B, c.signingPrivateKey, c.exchangePrivateKey)
        assertEquals("already-member", reason { Keyring.attach(att, pw, fakeB, "x", ex1, DetRand("x"), FixedClock(0)) })
        val ex3 = epochKey("3", true)
        assertEquals("epoch-mismatch", reason { Keyring.attach(base, pw, b, "x", ex3, DetRand("x"), FixedClock(0)) })
        val otherKey = GroupKey(ex1.groupId, 1, ex3.key)
        assertEquals("different-group-key", reason { Keyring.attach(base, pw, b, "x", otherKey, DetRand("x"), FixedClock(0)) })
    }

    // ---- extra rules the Kotlin port must keep ----

    @Test
    fun wrap_device_maps_bad_exchange_keys_to_bad_member_key() {
        val g1 = epochKey("1")
        assertEquals("bad-member-key", reason { Keyring.wrapDevice(g1, A, ByteArray(32), DetRand("w")) })
        val order8 = Vectors.hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
        assertEquals("bad-member-key", reason { Keyring.wrapDevice(g1, A, order8, DetRand("w")) })
        assertEquals("bad-member-key", reason { Keyring.wrapDevice(g1, A, ByteArray(31), DetRand("w")) })
        assertEquals("bad-random", reason { Keyring.wrapDevice(g1, A, identity("A").exchangePublicKey, FixedRandom(ByteArray(5))) })
    }

    @Test
    fun device_wrap_with_low_order_ephemeral_is_device_wrap() {
        val r1 = ring("keyring_epoch1.json")
        val o = LinkedHashMap(obj(r1))
        val wraps = LinkedHashMap(obj(o["device_wraps"]))
        val w = LinkedHashMap(obj(wraps[A]))
        w["eph"] = JsonValue.Str(Base64Std.encode(ByteArray(32)))
        wraps[A] = JsonValue.Obj(w)
        o["device_wraps"] = JsonValue.Obj(wraps)
        assertEquals("device-wrap", reason { Keyring.unwrapDevice(JsonValue.Obj(o), identity("A")) })
    }

    @Test
    fun device_identity_rules() {
        val a = identity("A")
        assertFailsWith<DeviceIdentityException> { DeviceIdentity("bad id", a.signingPrivateKey, a.exchangePrivateKey) }
        assertFailsWith<DeviceIdentityException> { DeviceIdentity(A, ByteArray(31), a.exchangePrivateKey) }
        assertFailsWith<DeviceIdentityException> { DeviceIdentity(A, a.signingPrivateKey, ByteArray(33)) }
        assertFailsWith<DeviceIdentityException> { a.exchange(ByteArray(32)) }
        assertFailsWith<DeviceIdentityException> { a.exchange(ByteArray(31)) }
        val sig = a.sign("hello".toByteArray())
        assertTrue(DeviceIdentity.verify(sig, "hello".toByteArray(), a.signingPublicKey))
        assertFalse(DeviceIdentity.verify(sig, "hellO".toByteArray(), a.signingPublicKey))
        assertFalse(DeviceIdentity.verify(sig, "hello".toByteArray(), ByteArray(31)))
        assertEquals(a, identity("A"))
        assertEquals(a.hashCode(), identity("A").hashCode())
        val text = a.toString()
        assertTrue(text.contains(a.deviceId) && text.contains(a.fingerprint))
        assertFalse(text.contains(Base64Std.encode(a.signingPrivateKey)) || text.contains(Vectors.hexString(a.signingPrivateKey)))
        val g = DeviceIdentity.generate(random = DetRand("uuid"))
        assertTrue(Regex("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}").matches(g.deviceId))
        assertEquals("fixed", DeviceIdentity.generate("fixed", DetRand("uuid")).deviceId)
        assertFailsWith<DeviceIdentityException> { DeviceIdentity.generate(random = FixedRandom(ByteArray(3))) }
    }
}
