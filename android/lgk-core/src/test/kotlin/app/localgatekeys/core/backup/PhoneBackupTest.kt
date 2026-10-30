package app.localgatekeys.core.backup

import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.crypto.Argon2id
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests for the `LGKMBAK1` phone backup (no Swift version; ported from tests/test_phone_backup.py and
 * tests/test_backup_vectors.py). Argon2id is memoised per (password, salt, costs) so each real derivation runs once.
 */
class PhoneBackupTest {
    private class CountingArgon2 : Argon2id {
        private val real = Argon2.default
        private val cache = HashMap<String, ByteArray>()
        var calls = 0

        override fun derive(password: ByteArray, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray {
            calls++
            val k = "${password.toList()}|${salt.toList()}|$memoryKiB|$iterations|$parallelism|$length"
            return cache.getOrPut(k) { real.derive(password, salt, memoryKiB, iterations, parallelism, length) }.copyOf()
        }
    }

    private class ThrowingArgon2 : Argon2id {
        override fun derive(password: ByteArray, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray =
            throw AssertionError("Argon2 must not run")
    }

    private companion object {
        // Shared across tests so the production-cost derivation of the vector runs once per JVM.
        val shared = CountingArgon2()
        val FAST: Map<String, Int> = mapOf("time_cost" to 1, "memory_cost_kib" to 8192, "parallelism" to 1)
        const val PW = "pw \u00fc"
    }

    private lateinit var saved: Argon2id

    @BeforeTest
    fun install() {
        saved = Argon2.default
        Argon2.default = shared
    }

    @AfterTest
    fun restore() {
        Argon2.default = saved
    }

    private fun <T> withoutArgon(block: () -> T): T {
        Argon2.default = ThrowingArgon2()
        try {
            return block()
        } finally {
            Argon2.default = shared
        }
    }

    // ---- helpers ----

    private fun str(s: String) = JsonValue.Str(s)

    private fun int(n: Long) = JsonValue.Int(n)

    private fun states(): List<ItemState> = listOf(
        ItemState(
            "a1", mapOf("phone" to 2L), false, null,
            JsonValue.Obj(
                mapOf(
                    "ns" to str("entry"), "schema" to int(1), "updated_at" to int(5),
                    "record" to JsonValue.Obj(mapOf("id" to str("a1"), "label" to str("x"))),
                ),
            ),
        ),
        ItemState("b2", mapOf("phone" to 1L), true, 7, null),
    )

    private val salt16 = ByteArray(16) { 's'.code.toByte() }
    private val nonce12 = ByteArray(12) { 'n'.code.toByte() }

    private fun blob(
        list: List<ItemState> = states(),
        password: String = PW,
        deviceId: String = "phone",
        platform: String = "android",
        appVersion: String = "1.0.0",
        createdAt: Long = 1790000000,
        proHint: Boolean = false,
        kdf: Map<String, Int>? = FAST,
    ): ByteArray = PhoneBackupFormat.write(
        list, password, deviceId, platform, appVersion, createdAt, proHint, QueueRandom(listOf(salt16, nonce12)), kdf,
    )

    private fun reason(password: String = PW, data: () -> ByteArray): String =
        assertFailsWith<PhoneBackupException> { PhoneBackupFormat.read(data(), password) }.reason

    private fun reasonOf(data: ByteArray, password: String = PW): String = reason(password) { data }

    private fun enc(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    private fun envelope(data: ByteArray = blob()): MutableMap<String, JsonValue> =
        CanonicalJson.parse(data).obj().fields.toMutableMap()

    private fun withHeader(edit: (MutableMap<String, JsonValue>) -> Unit): ByteArray {
        val env = envelope()
        val h = (env["header"] as JsonValue.Obj).fields.toMutableMap()
        edit(h)
        env["header"] = JsonValue.Obj(h)
        return enc(JsonValue.Obj(env))
    }

    private fun withKdf(edit: (MutableMap<String, JsonValue>) -> Unit): ByteArray = withHeader { h ->
        val k = (h["kdf"] as JsonValue.Obj).fields.toMutableMap()
        edit(k)
        h["kdf"] = JsonValue.Obj(k)
    }

    /** Encrypts hand-built plaintext bytes under the FAST key of a fresh blob's header. */
    private fun forge(plain: ByteArray, password: String = PW): ByteArray {
        val env = envelope()
        val header = env["header"] as JsonValue.Obj
        val salt = Base64Std.decodeStrict(header.fields["salt"]!!.str())
        val nonce = Base64Std.decodeStrict(header.fields["nonce"]!!.str())
        val key = shared.derive(password.toByteArray(Charsets.UTF_8), salt, 8192, 1, 1, 32)
        val ct = CryptoBox.sealGcm(key, nonce, plain, enc(header))
        env["ciphertext"] = str(Base64Std.encode(ct))
        return enc(JsonValue.Obj(env))
    }

    private fun forgePayload(payload: JsonValue) = forge(enc(payload))

    private fun goodPayload(list: List<JsonValue>, edit: (MutableMap<String, JsonValue>) -> Unit = {}): JsonValue {
        val m = mutableMapOf<String, JsonValue>(
            "app_version" to str("1.0.0"), "device_id" to str("phone"), "pro_hint" to JsonValue.Bool(false),
            "states" to JsonValue.Arr(list), "version" to int(1),
        )
        edit(m)
        return JsonValue.Obj(m)
    }

    private fun st(id: String, deleted: Boolean = false, edit: (MutableMap<String, JsonValue>) -> Unit = {}): JsonValue {
        val m = mutableMapOf<String, JsonValue>(
            "deleted" to JsonValue.Bool(deleted),
            "deleted_at" to if (deleted) int(1) else JsonValue.Null,
            "id" to str(id),
            "item" to if (deleted) JsonValue.Null else JsonValue.Obj(mapOf("a" to int(1))),
            "vv" to JsonValue.Obj(mapOf("phone" to int(1))),
        )
        edit(m)
        return JsonValue.Obj(m)
    }

    private fun expected(): Map<String, JsonValue> = Vectors.json(Vectors.backup("expected.json")).obj().fields

    private fun vectorBytes() = Vectors.backup("backup.lgkm").readBytes()

    private fun inputStates(): List<ItemState> = expectedStates()

    private fun expectedStates(): List<ItemState> = expected()["states"]!!.arr().map { s ->
        val f = s.obj().fields
        ItemState(
            f["id"]!!.str(),
            f["vv"]!!.obj().fields.mapValues { it.value.long() },
            (f["deleted"] as JsonValue.Bool).v,
            (f["deleted_at"] as? JsonValue.Int)?.v,
            f["item"]!!.takeIf { it != JsonValue.Null },
        )
    }

    // ---- round trip and writer ----

    @Test
    fun round_trip_keeps_states_header_and_hint() {
        val b = PhoneBackupFormat.read(blob(proHint = true), PW)
        assertEquals(states(), b.states)
        assertEquals("phone", b.deviceId)
        assertEquals("1.0.0", b.appVersion)
        assertTrue(b.proHint)
        assertEquals("android", b.header.platform)
        assertEquals(1790000000L, b.header.createdAt)
        assertEquals(PhoneBackupFormat.inspect(blob(proHint = true)), b.header)
    }

    @Test
    fun new_files_use_production_kdf_by_default() {
        var seen: List<Int>? = null
        Argon2.default = object : Argon2id {
            override fun derive(password: ByteArray, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray {
                seen = listOf(iterations, memoryKiB, parallelism, length)
                return ByteArray(32) { 'k'.code.toByte() }
            }
        }
        val data = blob(kdf = null)
        assertEquals(listOf(4, 131072, 4, 32), seen)
        val kdf = envelope(data)["header"]!!.obj().fields["kdf"]!!
        assertEquals(
            JsonValue.Obj(
                mapOf("name" to str("argon2id"), "time_cost" to int(4), "memory_cost_kib" to int(131072), "parallelism" to int(4)),
            ),
            kdf,
        )
    }

    @Test
    fun inspect_needs_no_password_and_no_argon() {
        val data = blob()
        withoutArgon {
            val h = PhoneBackupFormat.inspect(data)
            assertEquals("android", h.platform)
            assertEquals(1L, h.kdf["time_cost"])
            assertContentEquals(salt16, h.salt)
        }
        assertFailsWith<PhoneBackupException> { PhoneBackupFormat.inspect("{".toByteArray()) }
    }

    @Test
    fun output_is_canonical_and_deterministic_with_fixed_salt_and_nonce() {
        val a = blob()
        val b = blob()
        assertContentEquals(a, b)
        assertContentEquals(a, enc(CanonicalJson.parse(a)))
        assertTrue(a.last() != '\n'.code.toByte())
    }

    @Test
    fun salt_is_drawn_before_nonce() {
        val data = blob()
        val h = PhoneBackupFormat.inspect(data)
        assertContentEquals(salt16, h.salt)
        assertContentEquals(nonce12, h.nonce)
    }

    @Test
    fun writer_sorts_states_and_refuses_bad_input() {
        val reversed = PhoneBackupFormat.read(blob(list = states().reversed()), PW)
        assertEquals(listOf("a1", "b2"), reversed.states.map { it.itemId })
        fun failure(f: () -> Unit) = assertFailsWith<PhoneBackupException> { f() }.reason
        assertEquals("bad-payload", failure { blob(list = states() + states()) })
        assertEquals("bad-payload", failure { blob(deviceId = "bad id") })
        assertEquals("bad-payload", failure { blob(platform = "windows") })
        assertEquals("bad-payload", failure { blob(createdAt = -1) })
        assertEquals("bad-payload", failure { blob(createdAt = 1L shl 53) })
    }

    @Test
    fun writer_refuses_out_of_bounds_kdf() {
        fun failure(k: Map<String, Int>) = assertFailsWith<PhoneBackupException> { blob(kdf = k) }.reason
        assertEquals("bad-kdf", failure(FAST + ("time_cost" to 99)))
        assertEquals("bad-kdf", failure(FAST + ("time_cost" to 0)))
        assertEquals("bad-kdf", failure(FAST + ("memory_cost_kib" to 4096)))
        assertEquals("bad-kdf", failure(FAST + ("parallelism" to 17)))
        assertEquals("bad-kdf", failure(FAST + ("extra" to 1)))
        assertEquals("bad-kdf", failure(mapOf("time_cost" to 1)))
    }

    @Test
    fun app_version_must_be_printable_ascii_up_to_32() {
        for (bad in listOf("1.0\u00e9", "x".repeat(33), "", "a\tb")) {
            val plain = goodPayload(emptyList()) { it["app_version"] = str(bad) }
            assertEquals("bad-payload", reasonOf(forgePayload(plain)), bad)
            assertEquals("bad-payload", assertFailsWith<PhoneBackupException> { blob(appVersion = bad) }.reason, bad)
        }
        assertEquals("x".repeat(32), PhoneBackupFormat.read(blob(appVersion = "x".repeat(32)), PW).appVersion)
    }

    @Test
    fun zero_vv_counter_is_rejected_and_read_write_is_byte_identical() {
        val zero = st("a") { it["vv"] = JsonValue.Obj(mapOf("phone" to int(0))) }
        assertEquals("bad-payload", reasonOf(forgePayload(goodPayload(listOf(zero)))))
        val data = blob()
        val b = PhoneBackupFormat.read(data, PW)
        val kdf = b.header.kdf.filterKeys { it != "name" }.mapValues { (it.value as Long).toInt() }
        val again = PhoneBackupFormat.write(
            b.states, PW, b.deviceId, b.header.platform, b.appVersion, b.header.createdAt, b.proHint,
            QueueRandom(listOf(b.header.salt, b.header.nonce)), kdf,
        )
        assertContentEquals(data, again)
    }

    // ---- envelope and check order (no Argon2) ----

    @Test
    fun garbage_and_truncated_files_are_not_backups_without_argon() {
        val data = blob()
        val text = String(data, Charsets.UTF_8)
        val saltText = (envelope()["header"] as JsonValue.Obj).fields["salt"]!!.str()
        assertTrue(saltText.endsWith("=="))
        val alt = if (saltText[saltText.length - 3] != 'B') 'B' else 'C'
        val looseSalt = saltText.substring(0, saltText.length - 3) + alt + "=="
        val cases = listOf(
            "empty" to ByteArray(0),
            "brace" to "{".toByteArray(),
            "zip" to byteArrayOf(0x50, 0x4B, 3, 4),
            "truncated" to data.copyOf(40),
            "array" to "[]".toByteArray(),
            "invalid utf8" to byteArrayOf(0xFF.toByte(), '{'.code.toByte(), '}'.code.toByte()),
            "bom" to byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + data,
            "list platform" to withHeader { it["platform"] = JsonValue.Arr(listOf(int(1))) },
            "object platform" to withHeader { it["platform"] = JsonValue.Obj(mapOf("a" to int(1))) },
            "bad platform" to withHeader { it["platform"] = str("windows") },
            "loose salt" to withHeader { it["salt"] = str(looseSalt) },
            "short salt" to withHeader { it["salt"] = str(Base64Std.encode(ByteArray(15) { 'x'.code.toByte() })) },
            "short nonce" to withHeader { it["nonce"] = str(Base64Std.encode(ByteArray(11) { 'x'.code.toByte() })) },
            "extra header key" to withHeader { it["extra"] = int(1) },
            "missing header key" to withHeader { it.remove("nonce") },
            "wrong format" to withHeader { it["format"] = str("LGKMBAK2") },
            "float created_at" to withHeader { it["created_at"] = JsonValue.Float(1.5) },
            "negative created_at" to withHeader { it["created_at"] = int(-1) },
            "huge created_at" to withHeader { it["created_at"] = int(1L shl 53) },
            "bool created_at" to withHeader { it["created_at"] = JsonValue.Bool(true) },
            "duplicate key" to text.replaceFirst("\"version\":1", "\"version\":1,\"version\":1").toByteArray(),
            "NaN" to text.replace("\"created_at\":1790000000", "\"created_at\":NaN").toByteArray(),
            "version 0" to withHeader { it["version"] = int(0) },
            "version -1" to withHeader { it["version"] = int(-1) },
            "version str" to withHeader { it["version"] = str("2") },
            "version bool" to withHeader { it["version"] = JsonValue.Bool(true) },
            "version float" to withHeader { it["version"] = JsonValue.Float(1.0) },
        )
        withoutArgon {
            for ((name, bytes) in cases) assertEquals("not-a-backup", reasonOf(bytes), name)
        }
    }

    @Test
    fun envelope_with_extra_key_or_noncanonical_ciphertext_is_not_a_backup() {
        val env = envelope()
        val withExtra = enc(JsonValue.Obj(env + ("extra" to int(1))))
        // "Qh==" has a spare bit set: a second spelling of the byte 0x42, whose canonical text is "Qg=="
        assertEquals("Qg==", Base64Std.encode(byteArrayOf(0x42)))
        val loose = enc(JsonValue.Obj(env + ("ciphertext" to str("Qh=="))))
        withoutArgon {
            assertEquals("not-a-backup", reasonOf(withExtra))
            assertEquals("not-a-backup", reasonOf(loose))
        }
    }

    @Test
    fun version_and_kdf_rules_run_without_argon() {
        val edits: List<Pair<String, (MutableMap<String, JsonValue>) -> Unit>> = listOf(
            "time 11" to { it["time_cost"] = int(11) },
            "time 0" to { it["time_cost"] = int(0) },
            "mem low" to { it["memory_cost_kib"] = int(4096) },
            "mem high" to { it["memory_cost_kib"] = int(512 * 1024 + 1) },
            "par 17" to { it["parallelism"] = int(17) },
            "par 0" to { it["parallelism"] = int(0) },
            "scrypt" to { it["name"] = str("scrypt") },
            "float time" to { it["time_cost"] = JsonValue.Float(1.0) },
            "bool time" to { it["time_cost"] = JsonValue.Bool(true) },
            "extra key" to { it["extra"] = int(1) },
            "missing key" to { it.remove("parallelism") },
        )
        val forged = edits.map { (n, e) -> n to withKdf(e) }
        val notObject = withHeader { it["kdf"] = str("argon2id") }
        val v2 = withHeader { it["version"] = int(3) }
        val vBig = withHeader { it["version"] = int(1L shl 40) }
        withoutArgon {
            assertEquals("unsupported-version", reasonOf(v2))
            assertEquals("unsupported-version", reasonOf(vBig))
            assertEquals("bad-kdf", reasonOf(notObject))
            for ((n, d) in forged) assertEquals("bad-kdf", reasonOf(d), n)
        }
    }

    @Test
    fun too_large_is_rejected_before_parsing() {
        withoutArgon {
            assertEquals("too-large", reasonOf(ByteArray(PhoneBackupFormat.MAX_FILE_BYTES + 1) { 'x'.code.toByte() }))
        }
        assertEquals("not-a-backup", reasonOf(ByteArray(PhoneBackupFormat.MAX_FILE_BYTES) { 'x'.code.toByte() }))
    }

    @Test
    fun lone_surrogate_password_never_reaches_argon() {
        val data = blob()
        withoutArgon { assertEquals("wrong-password-or-damaged", reasonOf(data, "ab\uD800c")) }
    }

    // ---- decryption ----

    @Test
    fun wrong_password_and_tampering_give_the_same_reason_and_message() {
        val data = blob()
        val env = envelope(data)
        val ct = Base64Std.decodeStrict(env["ciphertext"]!!.str())
        ct[3] = (ct[3].toInt() xor 1).toByte()
        val flipped = enc(JsonValue.Obj(env + ("ciphertext" to str(Base64Std.encode(ct)))))
        val edited = withHeader { it["created_at"] = int(1790000001) }
        for ((bytes, pw) in listOf(data to "other", flipped to PW, edited to PW)) {
            val e = assertFailsWith<PhoneBackupException> { PhoneBackupFormat.read(bytes, pw) }
            assertEquals("wrong-password-or-damaged", e.reason)
            assertEquals("Wrong password, or the file is damaged.", e.message)
        }
        // shorter than a tag
        val tiny = enc(JsonValue.Obj(env + ("ciphertext" to str(Base64Std.encode(ByteArray(5))))))
        assertEquals("wrong-password-or-damaged", reasonOf(tiny))
    }

    // ---- payload ----

    @Test
    fun payload_rules() {
        fun a(vararg ids: String) = ids.map { st(it) }
        val bad = mapOf(
            "unsorted" to goodPayload(a("b", "a")),
            "duplicate" to goodPayload(a("a", "a")),
            "deleted with item" to goodPayload(listOf(st("a", true) { it["item"] = JsonValue.Obj(mapOf("a" to int(1))) })),
            "live without item" to goodPayload(listOf(st("a") { it["item"] = JsonValue.Null })),
            "deleted flag not bool" to goodPayload(listOf(st("a") { it["deleted"] = int(0) })),
            "item not object" to goodPayload(listOf(st("a") { it["item"] = JsonValue.Arr(emptyList()) })),
            "deleted_at float" to goodPayload(listOf(st("a", true) { it["deleted_at"] = JsonValue.Float(1.0) })),
            "deleted_at negative" to goodPayload(listOf(st("a", true) { it["deleted_at"] = int(-1) })),
            "deleted_at huge" to goodPayload(listOf(st("a", true) { it["deleted_at"] = int(1L shl 53) })),
            "bad id" to goodPayload(listOf(st("a b"))),
            "extra state key" to goodPayload(listOf(st("a") { it["extra"] = int(1) })),
            "missing state key" to goodPayload(listOf(st("a") { it.remove("vv") })),
            "vv not object" to goodPayload(listOf(st("a") { it["vv"] = JsonValue.Arr(emptyList()) })),
            "vv bad device" to goodPayload(listOf(st("a") { it["vv"] = JsonValue.Obj(mapOf("bad id" to int(1))) })),
            "vv float" to goodPayload(listOf(st("a") { it["vv"] = JsonValue.Obj(mapOf("p" to JsonValue.Float(1.0))) })),
            "vv bool" to goodPayload(listOf(st("a") { it["vv"] = JsonValue.Obj(mapOf("p" to JsonValue.Bool(true))) })),
            "vv huge" to goodPayload(listOf(st("a") { it["vv"] = JsonValue.Obj(mapOf("p" to int(1L shl 53))) })),
            "too many" to goodPayload((0..20000).map { st("i%05d".format(it)) }),
            "version 2" to goodPayload(emptyList()) { it["version"] = int(2) },
            "version float" to goodPayload(emptyList()) { it["version"] = JsonValue.Float(1.0) },
            "extra key" to goodPayload(emptyList()) { it["extra"] = int(1) },
            "empty app_version" to goodPayload(emptyList()) { it["app_version"] = str("") },
            "bad device" to goodPayload(emptyList()) { it["device_id"] = str("bad id") },
            "pro_hint not bool" to goodPayload(emptyList()) { it["pro_hint"] = int(0) },
            "states not list" to goodPayload(emptyList()) { it["states"] = JsonValue.Obj(emptyMap()) },
        )
        for ((name, payload) in bad) assertEquals("bad-payload", reasonOf(forgePayload(payload)), name)
        assertEquals("bad-payload", reasonOf(forge("[]".toByteArray())))
        val ok = PhoneBackupFormat.read(forgePayload(goodPayload(listOf(st("a"), st("b")))), PW)
        assertEquals("a", ok.states[0].itemId)
        val max = PhoneBackupFormat.read(forgePayload(goodPayload((0 until 20000).map { st("i%05d".format(it)) })), PW)
        assertEquals(20000, max.states.size)
    }

    @Test
    fun payload_plaintext_must_be_strict_json() {
        val good = enc(goodPayload(emptyList()))
        val text = String(good, Charsets.UTF_8)
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + good
        val cases = mapOf(
            "bom" to bom,
            "invalid utf8" to byteArrayOf(0xFF.toByte()) + good,
            "duplicate key" to text.replaceFirst("\"version\":1", "\"version\":1,\"version\":1").toByteArray(),
            "nan" to text.replace("\"pro_hint\":false", "\"pro_hint\":NaN").toByteArray(),
            "garbage" to "not json".toByteArray(),
            "trailing" to (text + "x").toByteArray(),
        )
        for ((name, bytes) in cases) assertEquals("bad-payload", reasonOf(forge(bytes)), name)
    }

    @Test
    fun item_depth_and_integer_limits() {
        fun nested(levels: Int, leaf: JsonValue): JsonValue {
            var v = leaf
            repeat(levels) { v = JsonValue.Obj(mapOf("k" to v)) }
            return v
        }

        fun payloadWith(item: JsonValue) = goodPayload(listOf(st("a") { it["item"] = item }))

        // the item itself is depth 0; a scalar at depth 64 is fine, at depth 65 it is rejected
        assertEquals(1, PhoneBackupFormat.read(forgePayload(payloadWith(nested(64, int(1)))), PW).states.size)
        assertEquals("bad-payload", reasonOf(forgePayload(payloadWith(nested(65, int(1))))))
        val maxInt = JsonValue.Obj(mapOf("n" to int(Long.MAX_VALUE), "m" to int(-Long.MAX_VALUE)))
        assertEquals(maxInt, PhoneBackupFormat.read(forgePayload(payloadWith(maxInt)), PW).states[0].item)
        val minText = String(enc(payloadWith(JsonValue.Obj(mapOf("n" to int(0))))), Charsets.UTF_8)
            .replace("\"n\":0", "\"n\":-9223372036854775808")
        assertEquals("bad-payload", reasonOf(forge(minText.toByteArray())))
        val big = String(enc(payloadWith(JsonValue.Obj(mapOf("n" to int(0))))), Charsets.UTF_8)
            .replace("\"n\":0", "\"n\":9223372036854775808")
        assertEquals("bad-payload", reasonOf(forge(big.toByteArray())))
        val lone = String(enc(payloadWith(JsonValue.Obj(mapOf("n" to str("x"))))), Charsets.UTF_8)
            .replace("\"n\":\"x\"", "\"n\":\"\\ud800\"")
        assertEquals("bad-payload", reasonOf(forge(lone.toByteArray())))
    }

    @Test
    fun supplementary_plane_text_round_trips() {
        val item = JsonValue.Obj(mapOf("\uD83D\uDE00" to str("\uD840\uDC00 \u00e9"), "z" to str("a")))
        val list = listOf(ItemState("emoji", mapOf("d" to 1L), false, null, item))
        val b = PhoneBackupFormat.read(blob(list = list), PW)
        assertEquals(list, b.states)
    }

    // ---- vectors ----

    @Test
    fun backup_vector_decodes_to_expected_states_and_key() {
        val raw = vectorBytes()
        val e = expected()
        val password = e["password"]!!.str()
        val backup = PhoneBackupFormat.read(raw, password)
        assertEquals(expectedStates(), backup.states)
        assertEquals(10, backup.states.size)
        assertTrue(backup.states.last().itemId.startsWith("lic:"))
        assertEquals(e["device_id"]!!.str(), backup.deviceId)
        assertEquals(e["app_version"]!!.str(), backup.appVersion)
        assertEquals((e["pro_hint"] as JsonValue.Bool).v, backup.proHint)
        assertEquals(e["created_at"]!!.long(), backup.header.createdAt)
        assertEquals(e["platform"]!!.str(), backup.header.platform)
        assertEquals(backup.header, PhoneBackupFormat.inspect(raw))
        val salt = Base64Std.decodeStrict(e["salt_b64"]!!.str())
        val nonce = Base64Std.decodeStrict(e["nonce_b64"]!!.str())
        assertContentEquals(salt, backup.header.salt)
        assertContentEquals(nonce, backup.header.nonce)
        val key = Argon2.default.derive(password.toByteArray(Charsets.UTF_8), salt, 131072, 4, 4, 32)
        assertEquals(e["key_hex"]!!.str(), Vectors.hexString(key))
        // header, AAD and plaintext
        val envelope = CanonicalJson.parse(raw).obj().fields
        assertEquals(e["header"], envelope["header"])
        val aad = enc(envelope["header"]!!)
        assertEquals(e["aad_hex"]!!.str(), Vectors.hexString(aad))
        val plain = CryptoBox.openGcm(key, nonce, Base64Std.decodeStrict(envelope["ciphertext"]!!.str()), aad)
        assertEquals(e["payload_canonical"]!!.str(), String(plain, Charsets.UTF_8))
    }

    @Test
    fun writing_again_with_the_fixed_inputs_gives_the_same_bytes() {
        val e = expected()
        val salt = Base64Std.decodeStrict(e["salt_b64"]!!.str())
        val nonce = Base64Std.decodeStrict(e["nonce_b64"]!!.str())
        val raw = vectorBytes()
        fun write(list: List<ItemState>) = PhoneBackupFormat.write(
            list, e["password"]!!.str(), e["device_id"]!!.str(), e["platform"]!!.str(), e["app_version"]!!.str(),
            e["created_at"]!!.long(), (e["pro_hint"] as JsonValue.Bool).v, QueueRandom(listOf(salt, nonce)),
        )
        val written = write(inputStates())
        assertContentEquals(raw, written)
        assertContentEquals(written, write(PhoneBackupFormat.read(written, e["password"]!!.str()).states))
        assertContentEquals(written, write(inputStates().reversed()))
    }

    @Test
    fun rejected_vectors_give_their_reason() {
        val e = expected()
        val rejected = e["rejected"]!!.obj().fields
        val dir = File(Vectors.backup("backup.lgkm").parentFile, "rejected")
        val onDisk = dir.listFiles { f -> f.name.endsWith(".lgkm") }!!.map { it.name }.sorted()
        assertEquals(rejected.keys.sorted(), onDisk)
        assertEquals(12, rejected.size)
        val password = e["password"]!!.str()
        for ((name, entry) in rejected) {
            val f = entry.obj().fields
            assertEquals(if (name == "wrong_password.lgkm") "wrong" else password, f["password"]!!.str(), name)
            val bytes = File(dir, name).readBytes()
            assertEquals(f["reason"]!!.str(), reasonOf(bytes, f["password"]!!.str()), name)
        }
        assertContentEquals(vectorBytes(), File(dir, "wrong_password.lgkm").readBytes())
        assertContentEquals(vectorBytes().copyOf(100), File(dir, "truncated.lgkm").readBytes())
    }

    @Test
    fun cheap_rejected_vectors_never_call_argon() {
        val dir = File(Vectors.backup("backup.lgkm").parentFile, "rejected")
        val expect = mapOf(
            "version_3.lgkm" to "unsupported-version",
            "kdf_time_11.lgkm" to "bad-kdf",
            "extra_header_key.lgkm" to "not-a-backup",
            "truncated.lgkm" to "not-a-backup",
            "noncanonical_salt.lgkm" to "not-a-backup",
            "noncanonical_ciphertext.lgkm" to "not-a-backup",
        )
        withoutArgon {
            for ((name, why) in expect) assertEquals(why, reasonOf(File(dir, name).readBytes()), name)
        }
    }

    @Test
    fun vector_files_are_byte_exact_and_have_no_trailing_newline() {
        val dir = File(Vectors.backup("backup.lgkm").parentFile, "rejected")
        val all = listOf(File(Vectors.backup("backup.lgkm").path)) + dir.listFiles { f -> f.name.endsWith(".lgkm") }!!
        for (f in all) {
            val b = f.readBytes()
            assertTrue(b.none { it == '\r'.code.toByte() } && b.last() != '\n'.code.toByte(), f.name)
        }
    }

    @Test
    fun integers_beyond_64_bits_are_refused() {
        val file = String(blob(), Charsets.UTF_8)
        val big = "1180591620717411303424"
        val cases = listOf(
            file.replace("\"version\":1", "\"version\":$big"),
            file.replace("\"time_cost\":1", "\"time_cost\":$big"),
            file.replace("\"created_at\":1790000000", "\"created_at\":-$big"),
            file.replace("\"version\":1", "\"version\":9223372036854775808"),
        )
        withoutArgon { for (c in cases) assertEquals("not-a-backup", reasonOf(c.toByteArray())) }
        val plain = String(enc(goodPayload(listOf(st("a") { it["item"] = JsonValue.Obj(mapOf("n" to int(0))) }))), Charsets.UTF_8)
        assertEquals("bad-payload", reasonOf(forge(plain.replace("\"n\":0", "\"n\":$big").toByteArray())))
    }

    @Test
    fun non_finite_floats_are_refused() {
        // 1e400 overflows to infinity: refused as not-a-backup in the envelope (before the version/kdf
        // checks, without Argon2) and as bad-payload inside the payload, like phone_backup.py.
        val file = String(blob(), Charsets.UTF_8)
        val envelopeCases = listOf(
            "time_cost" to file.replace("\"time_cost\":1", "\"time_cost\":1e400"),
            "version" to file.replace("\"version\":1", "\"version\":1e400"),
            "created_at" to file.replace("\"created_at\":1790000000", "\"created_at\":-1e400"),
        )
        for ((name, c) in envelopeCases) assertTrue(c != file, name)
        withoutArgon { for ((name, c) in envelopeCases) assertEquals("not-a-backup", reasonOf(c.toByteArray()), name) }
        val plain = String(enc(goodPayload(listOf(st("a") { it["item"] = JsonValue.Obj(mapOf("n" to int(0))) }))), Charsets.UTF_8)
        assertEquals("bad-payload", reasonOf(forge(plain.replace("\"n\":0", "\"n\":1e400").toByteArray())))
        assertEquals("bad-payload", reasonOf(forge(plain.replace("\"version\":1", "\"version\":-1e400").toByteArray())))
    }

    @Test
    fun write_refuses_a_lone_surrogate_password_without_argon() {
        withoutArgon { assertFailsWith<IllegalArgumentException> { blob(password = "ab\uD800c") } }
    }

    @Test
    fun version_3_wins_over_a_bad_kdf() {
        val data = withHeader { h ->
            h["version"] = int(3)
            h["kdf"] = str("junk")
        }
        withoutArgon { assertEquals("unsupported-version", reasonOf(data)) }
    }

    // ---- format 2 (document files) ----

    private fun f2Expected(): Map<String, JsonValue> = Vectors.json(Vectors.backup("format2/expected.json")).obj().fields

    private fun f2States(): List<ItemState> = f2Expected()["states"]!!.arr().map { s ->
        val f = s.obj().fields
        ItemState(
            f["id"]!!.str(),
            f["vv"]!!.obj().fields.mapValues { it.value.long() },
            (f["deleted"] as JsonValue.Bool).v,
            (f["deleted_at"] as? JsonValue.Int)?.v,
            f["item"]!!.takeIf { it != JsonValue.Null },
        )
    }

    @Test
    fun format2_vector_opens_with_its_file_and_writes_back_byte_for_byte() {
        val e = f2Expected()
        val raw = Vectors.backup("format2/backup.lgkm").readBytes()
        assertEquals(e["file_sha256"]!!.str(), Vectors.hexString(java.security.MessageDigest.getInstance("SHA-256").digest(raw)))
        val password = e["password"]!!.str()
        val backup = PhoneBackupFormat.read(raw, password)
        assertEquals(2, backup.header.version)
        assertEquals(backup.header, PhoneBackupFormat.inspect(raw))
        assertEquals(f2States(), backup.states)
        assertEquals(e["device_id"]!!.str(), backup.deviceId)
        val files = e["files"]!!.arr().map { it.obj().fields }
        assertEquals(files.map { it["blob"]!!.str() }, backup.files.keys.toList())
        for (f in files) {
            val data = backup.files.getValue(f["blob"]!!.str())
            assertEquals(f["blob_size"]!!.long(), data.size.toLong())
            assertEquals(f["blob_sha256"]!!.str(), AttachmentSyncBlobId(data))
        }
        val envelope = CanonicalJson.parse(raw).obj().fields
        assertEquals(e["header"], envelope["header"])
        assertEquals(e["aad_hex"]!!.str(), Vectors.hexString(enc(envelope["header"]!!)))
        val v1 = expected()
        val h = backup.header
        fun write(list: List<ItemState>, files: Map<String, ByteArray>) = PhoneBackupFormat.write(
            list, password, backup.deviceId, h.platform, backup.appVersion, h.createdAt, backup.proHint,
            QueueRandom(listOf(h.salt, h.nonce)), files = files,
        )
        assertEquals(v1["app_version"]!!.str(), backup.appVersion)
        assertContentEquals(raw, write(f2States(), backup.files))
        assertContentEquals(raw, write(f2States().reversed(), backup.files))
        // The same states without files are a version-1 file.
        val noFiles = write(f2States(), emptyMap())
        assertEquals(1, PhoneBackupFormat.inspect(noFiles).version)
    }

    private fun AttachmentSyncBlobId(b: ByteArray): String = app.localgatekeys.core.sync.AttachmentSync.blobId(b)

    @Test
    fun format2_rejected_vectors_give_their_reason() {
        val e = f2Expected()
        val rejected = e["rejected"]!!.obj().fields
        val dir = File(Vectors.backup("format2/backup.lgkm").parentFile, "rejected")
        val onDisk = dir.listFiles { f -> f.name.endsWith(".lgkm") }!!.map { it.name }.sorted()
        assertEquals(rejected.keys.sorted(), onDisk)
        assertEquals(6, rejected.size)
        for ((name, entry) in rejected) {
            val f = entry.obj().fields
            assertEquals(f["reason"]!!.str(), reasonOf(File(dir, name).readBytes(), f["password"]!!.str()), name)
        }
    }

    @Test
    fun writer_refuses_files_no_document_names_and_select_files_keeps_the_budget() {
        val backup = PhoneBackupFormat.read(Vectors.backup("format2/backup.lgkm").readBytes(), f2Expected()["password"]!!.str())
        val h = backup.header
        val withoutDoc = backup.states.filter { !app.localgatekeys.core.sync.Documents.isDocumentState(it) }
        val reason = assertFailsWith<PhoneBackupException> {
            PhoneBackupFormat.write(
                withoutDoc, "pw", backup.deviceId, h.platform, backup.appVersion, h.createdAt, false,
                QueueRandom(listOf(h.salt, h.nonce)), kdf = mapOf("time_cost" to 1, "memory_cost_kib" to 8192, "parallelism" to 1),
                files = backup.files,
            )
        }.reason
        assertEquals("bad-payload", reason)
        val blob = backup.files.values.single()
        val all = PhoneBackupFormat.selectFiles(backup.states, { blob })
        assertEquals(backup.files.keys, all.files.keys)
        assertTrue(all.leftOut.isEmpty())
        val tight = PhoneBackupFormat.selectFiles(backup.states, { blob }, budget = blob.size - 1L)
        assertTrue(tight.files.isEmpty())
        assertEquals(1, tight.leftOut.size)
        val missing = PhoneBackupFormat.selectFiles(backup.states, { null })
        assertEquals(1, missing.leftOut.size)
    }
}
