package app.localgatekeys.android.vault

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import java.io.File
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Ports of the AppKeychainVaultTests / VaultCounterStore behaviour that applies to Android (Keychain access
 * groups, migration and presence checks are iOS-only) plus the sealed-file rules of Ruling A.
 */
class SecretSlotsTest {
    @get:Rule val tmp = TemporaryFolder()

    private class FixedRandom(private val fill: Int = 0xAB) : RandomSource {
        var calls = 0
        override fun bytes(count: Int): ByteArray {
            calls++
            return ByteArray(count) { (fill + calls + it).toByte() }
        }
    }

    private val key = ByteArray(32) { (it + 1).toByte() }
    private fun file() = File(tmp.root, "secrets.bin")
    private fun slots(k: ByteArray = key, f: File = file(), r: RandomSource = FixedRandom()) = SecretSlots(f, k, r)
    private fun hooked(before: (File) -> Unit = {}, dirSync: (File) -> Unit = {}) =
        SecretSlots(file(), key, FixedRandom(), before, dirSync)

    private fun peer(endpoint: LanEndpoint? = LanEndpoint("192.168.1.20", 9000)) = PinnedPeer(
        deviceId = "dev-1", groupId = "grp-1",
        signingPublic = ByteArray(32) { 1 }, exchangePublic = ByteArray(32) { 2 }, endpoint = endpoint,
    )

    private fun expectCorrupt(block: () -> Unit) {
        try {
            block()
            fail("expected SecretSlotsException")
        } catch (e: SecretSlotsException) {
            assertEquals(SecretSlotsException.Kind.CORRUPT, e.kind)
        }
    }

    private fun expectMalformed(block: () -> Unit) {
        try {
            block()
            fail("expected SecretSlotsException")
        } catch (e: SecretSlotsException) {
            assertEquals(SecretSlotsException.Kind.MALFORMED, e.kind)
        }
    }

    // --- sealed file

    @Test fun missing_file_is_empty() {
        val s = slots()
        for (slot in Slot.entries) assertNull(s.read(slot))
        assertFalse(file().exists())
    }

    @Test fun slots_round_trip_across_instances() {
        val s = slots()
        s.write(Slot.FOLDER_URI, "content://tree/1".toByteArray())
        s.write(Slot.HELLO_COUNTER, byteArrayOf(1, 2, 3))
        val again = slots()
        assertArrayEquals("content://tree/1".toByteArray(), again.read(Slot.FOLDER_URI))
        assertArrayEquals(byteArrayOf(1, 2, 3), again.read(Slot.HELLO_COUNTER))
        assertNull(again.read(Slot.PAIRED_PEER))
    }

    @Test fun delete_removes_only_that_slot_and_missing_delete_is_fine() {
        val s = slots()
        s.write(Slot.FOLDER_URI, byteArrayOf(1))
        s.write(Slot.INSTALL_ID, byteArrayOf(2))
        s.delete(Slot.FOLDER_URI)
        s.delete(Slot.PEER_COUNTERS)
        val again = slots()
        assertNull(again.read(Slot.FOLDER_URI))
        assertArrayEquals(byteArrayOf(2), again.read(Slot.INSTALL_ID))
    }

    @Test fun file_is_sealed_with_the_expected_aad_and_hides_values() {
        val s = slots()
        s.write(Slot.FOLDER_URI, "very-secret-folder-uri".toByteArray())
        val raw = file().readBytes()
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("very-secret"))
        assertTrue(raw.size >= 28)
        val nonce = raw.copyOfRange(0, 12)
        val plain = CryptoBox.openGcm(key, nonce, raw.copyOfRange(12, raw.size), "localgatekeys|android-secrets|v1".toByteArray())
        val o = CanonicalJson.parse(plain).obj().fields
        assertEquals(
            "very-secret-folder-uri",
            String(Base64Std.decodeStrict(o.getValue("folder-uri").str())),
        )
    }

    @Test fun every_write_uses_a_fresh_nonce() {
        val s = slots()
        s.write(Slot.FOLDER_URI, byteArrayOf(1))
        val n1 = file().readBytes().copyOfRange(0, 12)
        s.write(Slot.FOLDER_URI, byteArrayOf(1))
        val n2 = file().readBytes().copyOfRange(0, 12)
        assertFalse(n1.contentEquals(n2))
    }

    @Test fun wrong_local_key_is_corrupt() {
        slots().write(Slot.FOLDER_URI, byteArrayOf(1))
        val other = ByteArray(32) { 9 }
        expectCorrupt { slots(other).read(Slot.FOLDER_URI) }
        expectCorrupt { slots(other).write(Slot.INSTALL_ID, byteArrayOf(1)) }
    }

    @Test fun tampered_file_is_corrupt_everywhere() {
        slots().write(Slot.FOLDER_URI, byteArrayOf(1, 2, 3))
        val raw = file().readBytes()
        for (i in listOf(0, 11, 12, raw.size / 2, raw.size - 1)) {
            val t = raw.copyOf()
            t[i] = (t[i].toInt() xor 1).toByte()
            file().writeBytes(t)
            expectCorrupt { slots().read(Slot.FOLDER_URI) }
        }
    }

    @Test fun truncated_or_empty_or_garbage_file_is_corrupt() {
        slots().write(Slot.FOLDER_URI, byteArrayOf(1))
        val raw = file().readBytes()
        file().writeBytes(raw.copyOf(20))
        expectCorrupt { slots().read(Slot.FOLDER_URI) }
        file().writeBytes(ByteArray(0))
        expectCorrupt { slots().read(Slot.FOLDER_URI) }
        file().writeBytes(ByteArray(100) { 7 })
        expectCorrupt { slots().read(Slot.FOLDER_URI) }
    }

    @Test fun authentic_file_with_wrong_plaintext_shape_is_corrupt() {
        val aad = "localgatekeys|android-secrets|v1".toByteArray()
        fun sealed(json: String): ByteArray {
            val nonce = ByteArray(12) { 5 }
            return nonce + CryptoBox.sealGcm(key, nonce, json.toByteArray(), aad)
        }
        for (bad in listOf("[]", "{\"folder-uri\":1}", "{\"folder-uri\":\"not base64!\"}", "nope")) {
            file().writeBytes(sealed(bad))
            expectCorrupt { slots().read(Slot.FOLDER_URI) }
        }
    }

    @Test fun key_must_be_32_bytes() {
        try {
            SecretSlots(file(), ByteArray(16), FixedRandom())
            fail()
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test fun close_zeroes_the_instances_key_copy_not_the_callers() {
        val k = key.copyOf()
        val s = SecretSlots(file(), k, FixedRandom())
        s.write(Slot.FOLDER_URI, byteArrayOf(1))
        s.close()
        assertArrayEquals(key, k)
        try {
            s.read(Slot.FOLDER_URI)
            fail("closed slots must refuse")
        } catch (e: IllegalStateException) {
            // expected
        }
    }

    @Test fun atomic_write_leaves_old_file_on_failure_and_no_temp() {
        val failing = hooked(before = { throw IOException("disk gone") })
        val good = slots()
        good.write(Slot.FOLDER_URI, byteArrayOf(1))
        val before = file().readBytes()
        try {
            failing.write(Slot.FOLDER_URI, byteArrayOf(2))
            fail()
        } catch (e: IOException) {
            // expected
        }
        assertArrayEquals(before, file().readBytes())
        assertArrayEquals(byteArrayOf(1), slots().read(Slot.FOLDER_URI))
        assertEquals(listOf("secrets.bin"), tmp.root.list()!!.toList())
    }

    @Test fun temp_file_follows_the_dot_final_name_tmp_pattern() {
        var seen: String? = null
        val s = hooked(before = { f -> seen = f.name })
        s.write(Slot.FOLDER_URI, byteArrayOf(1))
        val name = seen!!
        assertTrue(name, name.startsWith(".secrets.bin.") && name.endsWith(".tmp"))
    }

    // --- paired peer

    @Test fun paired_peer_round_trips_and_matches_the_ios_json() {
        val s = slots()
        assertNull(s.pairedPeer())
        s.setPairedPeer(peer())
        assertEquals(peer(), slots().pairedPeer())
        val json = CanonicalJson.parse(s.read(Slot.PAIRED_PEER)!!).obj().fields
        assertEquals(setOf("device_id", "group_id", "signing_public", "exchange_public", "endpoint"), json.keys)
        assertEquals(JsonValue.Str("dev-1"), json["device_id"])
        assertEquals(JsonValue.Str(Base64Std.encode(ByteArray(32) { 1 })), json["signing_public"])
        val ep = json.getValue("endpoint").obj().fields
        assertEquals(JsonValue.Str("192.168.1.20"), ep["host"])
        assertEquals(JsonValue.Int(9000), ep["port"])
        // Canonical bytes exactly (sorted keys, no spaces, UTF-8 dialect).
        val expected = CanonicalJson.encode(JsonValue.Obj(json), Dialect.UTF8)
        assertArrayEquals(expected, s.read(Slot.PAIRED_PEER))
    }

    @Test fun paired_peer_without_endpoint_stores_null() {
        val s = slots()
        s.setPairedPeer(peer(endpoint = null))
        assertEquals(JsonValue.Null, CanonicalJson.parse(s.read(Slot.PAIRED_PEER)!!).obj().fields["endpoint"])
        assertNull(s.pairedPeer()!!.endpoint)
    }

    @Test fun paired_peer_with_a_non_lan_endpoint_is_refused() {
        val s = slots()
        fun withEndpoint(host: String, port: JsonValue): ByteArray = CanonicalJson.encode(
            JsonValue.Obj(
                mapOf(
                    "device_id" to JsonValue.Str("d"), "group_id" to JsonValue.Str("g"),
                    "signing_public" to JsonValue.Str(Base64Std.encode(ByteArray(32))),
                    "exchange_public" to JsonValue.Str(Base64Std.encode(ByteArray(32))),
                    "endpoint" to JsonValue.Obj(mapOf("host" to JsonValue.Str(host), "port" to port)),
                ),
            ),
            Dialect.UTF8,
        )
        s.write(Slot.PAIRED_PEER, withEndpoint("8.8.8.8", JsonValue.Int(9000)))
        expectMalformed { s.pairedPeer() }
        s.write(Slot.PAIRED_PEER, withEndpoint("192.168.1.2", JsonValue.Int(99999)))
        expectMalformed { s.pairedPeer() }
        s.write(Slot.PAIRED_PEER, withEndpoint("192.168.1.2", JsonValue.Str("9000")))
        expectMalformed { s.pairedPeer() }
    }

    @Test fun paired_peer_malformed_json_or_fields_are_refused() {
        val s = slots()
        s.write(Slot.PAIRED_PEER, "not json".toByteArray())
        expectMalformed { s.pairedPeer() }
        s.write(Slot.PAIRED_PEER, "[]".toByteArray())
        expectMalformed { s.pairedPeer() }
        s.write(Slot.PAIRED_PEER, "{\"device_id\":\"d\"}".toByteArray())
        expectMalformed { s.pairedPeer() }
        s.write(
            Slot.PAIRED_PEER,
            "{\"device_id\":\"d\",\"group_id\":\"g\",\"signing_public\":\"!!\",\"exchange_public\":\"AAAA\",\"endpoint\":null}".toByteArray(),
        )
        expectMalformed { s.pairedPeer() }
    }

    // --- install id

    @Test fun install_id_is_32_lowercase_hex_created_once() {
        val r = FixedRandom()
        val s = slots(r = r)
        val id = s.installId()
        assertTrue(id, Regex("[0-9a-f]{32}").matches(id))
        assertEquals(id, s.installId())
        assertEquals(id, slots(r = FixedRandom(0x10)).installId())
        assertArrayEquals(id.toByteArray(), s.read(Slot.INSTALL_ID))
    }

    @Test fun empty_or_non_utf8_install_id_is_malformed() {
        val s = slots()
        s.write(Slot.INSTALL_ID, ByteArray(0))
        expectMalformed { s.installId() }
        s.write(Slot.INSTALL_ID, byteArrayOf(0xFF.toByte(), 0xFE.toByte()))
        expectMalformed { s.installId() }
    }

    // --- counters

    @Test fun counters_default_to_zero_and_hello_counter_is_8_bytes_big_endian() {
        val c = VaultCounterStore(slots())
        assertEquals(0L, c.persistedHelloCounter())
        assertEquals(0L, c.lastAcceptedCounter("peer"))
        c.persistHelloCounter(0x0102030405060708L)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), slots().read(Slot.HELLO_COUNTER))
        assertEquals(0x0102030405060708L, VaultCounterStore(slots()).persistedHelloCounter())
        c.persistHelloCounter(-2L)
        assertEquals(-2L, c.persistedHelloCounter())
    }

    @Test fun hello_counter_of_wrong_length_is_malformed() {
        val s = slots()
        s.write(Slot.HELLO_COUNTER, byteArrayOf(1, 2, 3))
        expectMalformed { VaultCounterStore(s).persistedHelloCounter() }
    }

    @Test fun peer_counters_are_a_json_object_per_peer() {
        val s = slots()
        val c = VaultCounterStore(s)
        c.setLastAcceptedCounter(5, "a")
        c.setLastAcceptedCounter(9, "b")
        c.setLastAcceptedCounter(7, "a")
        assertEquals(7L, c.lastAcceptedCounter("a"))
        assertEquals(9L, c.lastAcceptedCounter("b"))
        assertEquals(0L, c.lastAcceptedCounter("c"))
        val o = CanonicalJson.parse(s.read(Slot.PEER_COUNTERS)!!).obj().fields
        assertEquals(mapOf<String, JsonValue>("a" to JsonValue.Int(7), "b" to JsonValue.Int(9)), o)
        assertEquals(7L, VaultCounterStore(slots()).lastAcceptedCounter("a"))
    }

    @Test fun peer_counters_with_a_non_integer_value_are_malformed() {
        val s = slots()
        s.write(Slot.PEER_COUNTERS, "{\"a\":\"x\"}".toByteArray())
        expectMalformed { VaultCounterStore(s).lastAcceptedCounter("a") }
        s.write(Slot.PEER_COUNTERS, "[1]".toByteArray())
        expectMalformed { VaultCounterStore(s).lastAcceptedCounter("a") }
    }

    @Test fun hello_counter_source_reserves_blocks_through_the_store() {
        val store = VaultCounterStore(slots())
        val clock = object : UnixClock { override val now = 0L }
        val src = HelloCounterSource(store, clock)
        assertEquals(1L, src.nextCounter())
        assertEquals(64L, store.persistedHelloCounter())
        val next = HelloCounterSource(VaultCounterStore(slots()), clock)
        assertEquals(65L, next.nextCounter())
        src.acceptInbound(3, "p")
        assertEquals(3L, store.lastAcceptedCounter("p"))
    }

    @Test fun counter_write_failure_propagates_and_keeps_the_old_value() {
        val failing = hooked(before = { throw IOException("full") })
        val good = slots()
        VaultCounterStore(good).persistHelloCounter(10)
        try {
            VaultCounterStore(failing).persistHelloCounter(20)
            fail()
        } catch (e: IOException) {
            // expected
        }
        assertEquals(10L, VaultCounterStore(slots()).persistedHelloCounter())
    }

    // --- fake vault key (the JVM stand-in later tasks use)

    @Test fun fake_vault_key_wraps_and_unwraps_with_iv_prefix() {
        val v = FakeVaultKey()
        assertFalse(v.exists())
        v.create()
        assertTrue(v.exists())
        val wrapped = v.wrap(key, v.cipherForWrap())
        assertEquals(12 + 32 + 16, wrapped.size)
        assertArrayEquals(key, v.unwrap(wrapped, v.cipherForUnwrap(wrapped)))
        val w2 = v.wrap(key, v.cipherForWrap())
        assertNotEquals(wrapped.toList(), w2.toList())
        v.delete()
        assertFalse(v.exists())
        try {
            v.cipherForUnwrap(wrapped)
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.MISSING, e.kind)
        }
    }

    @Test fun fake_vault_key_tamper_and_invalidation() {
        val v = FakeVaultKey().also { it.create() }
        val wrapped = v.wrap(key, v.cipherForWrap())
        val t = wrapped.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
        try {
            v.unwrap(t, v.cipherForUnwrap(t))
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
        try {
            v.cipherForUnwrap(ByteArray(10))
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
        v.invalidate()
        try {
            v.cipherForWrap()
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.INVALIDATED, e.kind)
        }
        try {
            FakeVaultKey().also { it.create() }.create()
            fail()
        } catch (e: VaultKeyException) {
            assertNotNull(e)
        }
    }
}
