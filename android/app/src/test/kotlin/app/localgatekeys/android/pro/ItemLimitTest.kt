package app.localgatekeys.android.pro

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.StoreSnapshot
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Ports of the item-limit rules, SettingsTests/LicenseKeysTests (license_keys_match_desktop) and the ProFeatures
 * rule. The Swift ProAvailabilityTests are ProModel tests and land with the billing task.
 */
class ItemLimitTest {
    private val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))

    private fun vector(): Map<String, JsonValue> =
        CanonicalJson.parse(File(repo, "tests/vectors/sync/license_state.json").readBytes()).obj().fields

    private fun testKeys(): Map<String, ByteArray> {
        val o = vector()
        return mapOf(o.getValue("key_id").str() to Base64Std.decodeStrict(o.getValue("public_key_b64").str()))
    }

    private fun meta(deleted: Boolean = false) = SyncMeta(
        digest = if (deleted) null else "d", body = if (deleted) null else "b", updatedAt = 1,
        vv = emptyMap(), deleted = deleted, deletedAt = if (deleted) 2 else null,
    )

    private fun entry(ns: String, kind: String): JsonValue =
        JsonValue.Obj(mapOf("ns" to JsonValue.Str(ns), "record" to JsonValue.Obj(mapOf("kind" to JsonValue.Str(kind)))))

    private fun snapshot(vararg rows: Triple<String, JsonValue, Boolean>) = StoreSnapshot(
        records = rows.filter { !it.third }.associate { it.first to it.second },
        meta = rows.associate { it.first to meta(it.third) },
    )

    private fun login(id: String) = Triple(id, entry("entry", "login"), false)

    private fun licenseSnapshot(extra: List<Triple<String, JsonValue, Boolean>> = emptyList()): StoreSnapshot {
        val o = vector()
        val licenseRow = Triple(o.getValue("state_id").str(), o.getValue("wrapper"), false)
        return snapshot(*(extra + licenseRow).toTypedArray())
    }

    @Test fun free_items_is_four() = assertEquals(4, ItemLimit.FREE_ITEMS)

    @Test fun live_count_excludes_licence_document_and_deleted() {
        val s = snapshot(
            login("a"), login("b"),
            Triple("t", entry("item", "totp"), false),
            Triple("d", entry("item", "document"), false),
            Triple("lic:x", entry("license", "license"), false),
            Triple("gone", entry("entry", "login"), true),
        )
        assertEquals(3, ItemLimit.liveCount(s))
        assertEquals(0, ItemLimit.liveCount(StoreSnapshot()))
    }

    @Test fun live_count_ignores_a_record_marked_deleted_in_meta_even_if_still_present() {
        val s = StoreSnapshot(
            records = mapOf("a" to entry("entry", "login"), "b" to entry("entry", "login")),
            meta = mapOf("b" to meta(deleted = true)),
        )
        assertEquals(1, ItemLimit.liveCount(s))
    }

    @Test fun allows_matrix() {
        val full = snapshot(login("a"), login("b"), login("c"), login("d"))
        val three = snapshot(login("a"), login("b"), login("c"))
        for (a in listOf(ItemLimit.Action.CREATE, ItemLimit.Action.RESTORE)) {
            assertTrue(ItemLimit.allows(a, three, isPro = false))
            assertFalse(ItemLimit.allows(a, full, isPro = false))
            assertTrue(ItemLimit.allows(a, full, isPro = true))
        }
        for (a in listOf(ItemLimit.Action.EDIT, ItemLimit.Action.DELETE, ItemLimit.Action.AUTOFILL)) {
            assertTrue(ItemLimit.allows(a, full, isPro = false))
        }
    }

    @Test fun a_deleted_item_frees_its_slot() {
        val s = snapshot(login("a"), login("b"), login("c"), Triple("d", entry("entry", "login"), true))
        assertTrue(ItemLimit.allows(ItemLimit.Action.CREATE, s, isPro = false))
    }

    @Test fun restore_at_four_live_items_plus_a_tombstone_needs_pro() {
        val s = snapshot(
            login("a"), login("b"), login("c"), login("d"),
            Triple("gone", entry("entry", "login"), true),
        )
        assertEquals(4, ItemLimit.liveCount(s))
        assertFalse(ItemLimit.allows(ItemLimit.Action.RESTORE, s, isPro = false))
        assertTrue(ItemLimit.allows(ItemLimit.Action.RESTORE, s, isPro = true))
        assertFalse(ItemLimit.allows(ItemLimit.Action.CREATE, s, isPro = false))
    }

    /** A licence bundle signed by a throwaway Ed25519 key made in the test; returns the wrapper and the raw public key. */
    private fun signedWrapper(licenseId: String, kp: java.security.KeyPair): JsonValue {
        val raw = kp.public.encoded.takeLast(32).toByteArray()
        val keyId = java.security.MessageDigest.getInstance("SHA-256").digest(raw).take(8)
            .joinToString("") { "%02x".format(it) }
        val lic = JsonValue.Obj(
            mapOf(
                "format" to JsonValue.Int(1), "license_id" to JsonValue.Str(licenseId), "edition" to JsonValue.Str("pro"),
                "name" to JsonValue.Str("T"), "email" to JsonValue.Str("t@example.com"),
                "issued_at" to JsonValue.Str("2026-09-21"), "updates_until" to JsonValue.Str("2027-09-21"),
            ),
        )
        val sig = java.security.Signature.getInstance("Ed25519").run {
            initSign(kp.private)
            update(app.localgatekeys.core.json.CanonicalJson.encode(lic, app.localgatekeys.core.json.Dialect.UTF8))
            sign()
        }
        val bundle = JsonValue.Obj(
            mapOf(
                "license" to lic,
                "signature" to JsonValue.Obj(
                    mapOf(
                        "alg" to JsonValue.Str("Ed25519"), "key_id" to JsonValue.Str(keyId),
                        "signature" to JsonValue.Str(java.util.Base64.getEncoder().encodeToString(sig)),
                    ),
                ),
            ),
        )
        return JsonValue.Obj(
            mapOf("ns" to JsonValue.Str("license"), "schema" to JsonValue.Int(1), "updated_at" to JsonValue.Int(0), "record" to bundle),
        )
    }

    @Test fun with_two_valid_licences_the_first_in_scalar_order_wins() {
        val kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val raw = kp.public.encoded.takeLast(32).toByteArray()
        val keyId = java.security.MessageDigest.getInstance("SHA-256").digest(raw).take(8)
            .joinToString("") { "%02x".format(it) }
        val keys = mapOf(keyId to raw)
        val rows = listOf("lic-one", "lic-two").map { id ->
            Triple(app.localgatekeys.core.records.License.stateId(id), id, signedWrapper(id, kp))
        }.sortedBy { it.first }
        // Both verify alone.
        for (r in rows) assertEquals(r.second, ItemLimit.validLicense(snapshot(Triple(r.first, r.third, false)), keys)!!.licenseId)
        val both = rows.map { Triple(it.first, it.third, false) }
        assertEquals(rows[0].second, ItemLimit.validLicense(snapshot(*both.toTypedArray()), keys)!!.licenseId)
        assertEquals(rows[0].second, ItemLimit.validLicense(snapshot(*both.reversed().toTypedArray()), keys)!!.licenseId)
    }

    @Test fun valid_license_from_the_vector() {
        val info = ItemLimit.validLicense(licenseSnapshot(), testKeys())
        assertNotNull(info)
        assertEquals("lic-vector-0001", info!!.licenseId)
        assertEquals("Ada Lovelace", info.name)
    }

    @Test fun valid_license_needs_keys_and_the_right_key() {
        val s = licenseSnapshot()
        assertNull(ItemLimit.validLicense(s, emptyMap()))
        assertNull("production key does not verify the test licence", ItemLimit.validLicense(s, LicenseKeys.production))
        assertNull(ItemLimit.validLicense(StoreSnapshot(), testKeys()))
    }

    @Test fun valid_license_rejects_a_state_stored_under_the_wrong_id_or_namespace() {
        val o = vector()
        val wrapper = o.getValue("wrapper")
        val wrongId = snapshot(Triple("lic:00000000000000000000000000000000", wrapper, false))
        assertNull(ItemLimit.validLicense(wrongId, testKeys()))
        val w = wrapper.obj().fields
        val wrongNs = JsonValue.Obj(w + ("ns" to JsonValue.Str("entry")))
        assertNull(ItemLimit.validLicense(snapshot(Triple(o.getValue("state_id").str(), wrongNs, false)), testKeys()))
        val tampered = JsonValue.Obj(w + ("record" to JsonValue.Obj(w.getValue("record").obj().fields - "signature")))
        assertNull(ItemLimit.validLicense(snapshot(Triple(o.getValue("state_id").str(), tampered, false)), testKeys()))
    }

    @Test fun valid_license_skips_junk_and_finds_the_good_one() {
        val s = licenseSnapshot(listOf(Triple("lic:0000", JsonValue.Str("junk"), false), login("a")))
        assertNotNull(ItemLimit.validLicense(s, testKeys()))
    }

    @Test fun license_keys_match_desktop() {
        val source = File(repo, "src/localvault/licensing.py").readText()
        val line = source.lines().first { it.startsWith("LICENSE_KEYS: dict[str, str] = ") }
        val desktop = Regex("\"([0-9a-f]{16})\":\\s*\"([A-Za-z0-9+/=]+)\"").findAll(line)
            .associate { it.groupValues[1] to Base64Std.decodeStrict(it.groupValues[2]) }
        assertFalse(desktop.isEmpty())
        assertEquals(desktop.keys, LicenseKeys.production.keys)
        for ((id, bytes) in desktop) assertTrue(id, bytes.contentEquals(LicenseKeys.production.getValue(id)))
    }

    @Test fun production_key_is_the_current_one() {
        assertEquals(setOf("9f76e21ed03c0482"), LicenseKeys.production.keys)
        val raw = LicenseKeys.production.getValue("9f76e21ed03c0482")
        assertEquals(32, raw.size)
        assertEquals(
            "f87e9cea9c40fd00135d763544f184717f391e94575ca60bfd7af39306b63a06",
            raw.joinToString("") { "%02x".format(it) },
        )
        // The key id is the first 8 bytes of SHA-256 of the raw key (License.verify enforces it).
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(raw)
        assertEquals("9f76e21ed03c0482", digest.take(8).joinToString("") { "%02x".format(it) })
    }

    @Test fun totp_message_and_change_rule() {
        assertEquals(
            "Adding or changing two-factor codes needs LocalGateKeys Pro. Codes you already saved keep working.",
            ProFeatures.totpMessage(EnglishTxt()),
        )
        val a = JsonValue.Str("a")
        val b = JsonValue.Str("b")
        assertFalse(ProFeatures.totpChangeNeedsPro(null, null))
        assertFalse(ProFeatures.totpChangeNeedsPro(JsonValue.Null, a))
        assertFalse(ProFeatures.totpChangeNeedsPro(null, a))
        assertFalse(ProFeatures.totpChangeNeedsPro(a, a))
        assertTrue(ProFeatures.totpChangeNeedsPro(a, null))
        assertTrue(ProFeatures.totpChangeNeedsPro(a, JsonValue.Null))
        assertTrue(ProFeatures.totpChangeNeedsPro(b, a))
    }
}
