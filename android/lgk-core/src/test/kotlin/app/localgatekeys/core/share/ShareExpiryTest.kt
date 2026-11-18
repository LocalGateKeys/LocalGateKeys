package app.localgatekeys.core.share

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.support.FixedRandom
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** `.lgkshare` v1.1 (sub-plan 12): an earlier embedded expiry wins, a later one is capped, `one_use` is accepted. */
class ShareExpiryTest {
    private val opens = Vectors.json(File(Vectors.root, "share/v1_1.json")).obj().fields.getValue("opens").arr().map { it.obj().fields }

    @Test fun v1_1_vectors_open_until_their_expiry() {
        assertEquals(2, opens.size)
        for (case in opens) {
            val data = case.getValue("package").str().toByteArray(Charsets.UTF_8)
            val code = case.getValue("code").str()
            val now = case.getValue("now").long()
            val opened = Share.open(data, code, now)
            assertEquals(case.getValue("expires_at").long(), opened.expiresAt, case.getValue("name").str())
            assertEquals(case.getValue("item"), opened.item)
            val e = assertFailsWith<ShareException> { Share.open(data, code, opened.expiresAt) }
            assertEquals("expired", e.reason)
        }
    }

    @Test fun opened_once_per_device_even_with_one_use() {
        val case = opens.first { it.getValue("one_use") == JsonValue.Bool(true) }
        val data = case.getValue("package").str().toByteArray(Charsets.UTF_8)
        val e = assertFailsWith<ShareException> {
            Share.open(data, case.getValue("code").str(), case.getValue("now").long(), opened = setOf(case.getValue("id").str()))
        }
        assertEquals("already-opened", e.reason)
    }

    private fun seal(case: Map<String, JsonValue>, expires: Long?, oneUse: Boolean): ByteArray =
        Share.seal(
            case.getValue("item"), case.getValue("code").str(), "Vector PC", case.getValue("now").long(), FixedRandom(ByteArray(32)),
            packageId = case.getValue("id").str(), salt = ByteArray(16) { it.toByte() }, nonce = ByteArray(12) { it.toByte() },
            expires = expires, oneUse = oneUse,
        )

    @Test fun seal_reproduces_the_v1_1_vectors() {
        for (case in opens) {
            val now = case.getValue("now").long()
            val expiresAt = case.getValue("expires_at").long()
            // the capped case was sealed with a later expiry; any expiry past 24 h gives the same bytes
            val expires = if (expiresAt == now + Share.LIFETIME) now + 7 * Share.LIFETIME else expiresAt
            val bytes = seal(case, expires, case.getValue("one_use") == JsonValue.Bool(true))
            assertEquals(case.getValue("package").str(), bytes.toString(Charsets.UTF_8), case.getValue("name").str())
        }
    }

    @Test fun seal_refuses_an_expiry_not_in_the_future() {
        val case = opens.first()
        val now = case.getValue("now").long()
        assertEquals("malformed", assertFailsWith<ShareException> { seal(case, now, false) }.reason)
        assertEquals("malformed", assertFailsWith<ShareException> { seal(case, now - 1, false) }.reason)
    }

    @Test fun revoked_package_is_refused_after_the_other_checks() {
        val case = opens.first()
        val data = case.getValue("package").str().toByteArray(Charsets.UTF_8)
        val code = case.getValue("code").str()
        val now = case.getValue("now").long()
        val id = case.getValue("id").str()
        assertEquals("revoked", assertFailsWith<ShareException> { Share.open(data, code, now, revoked = setOf(id)) }.reason)
        // expiry is checked first, like Python
        assertEquals("expired", assertFailsWith<ShareException> { Share.open(data, code, now + Share.LIFETIME, revoked = setOf(id)) }.reason)
        Share.open(data, code, now, revoked = setOf("00000000-0000-4000-8000-0000000000ff"))
    }
}
