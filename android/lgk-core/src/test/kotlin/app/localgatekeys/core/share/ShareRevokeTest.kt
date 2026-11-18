package app.localgatekeys.core.share

import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** LGKSHARE v1.1 revoke notices (desktop `share_revoke`); vector `tests/vectors/share/revoke_v1.json`. */
class ShareRevokeTest {
    private val v = Vectors.json(File(Vectors.root, "share/revoke_v1.json")).obj().fields
    private val seed = Base64Std.decodeStrict(v.getValue("seed").str())
    private val pub = Base64Std.decodeStrict(v.getValue("public_key").str())
    private val notice = v.getValue("notice").str().toByteArray(Charsets.UTF_8)
    private val pid = v.getValue("package_id").str()
    private val signer = v.getValue("signer").str()

    @Test fun python_notice_verifies_and_make_reproduces_it() {
        assertEquals(pid, ShareRevoke.verify(notice, pub, pid))
        assertTrue(Ed25519.publicKey(seed).contentEquals(pub))
        assertEquals(notice.toString(Charsets.UTF_8), ShareRevoke.make(seed, pid, signer, 1800000000).toString(Charsets.UTF_8))
    }

    @Test fun verify_refusals() {
        assertEquals("other-package", assertFailsWith<RevokeException> { ShareRevoke.verify(notice, pub, "00000000-0000-4000-8000-000000000002") }.reason)
        val other = Ed25519.publicKey(ByteArray(32) { 9 })
        assertEquals("bad-signature", assertFailsWith<RevokeException> { ShareRevoke.verify(notice, other, pid) }.reason)
        val tampered = notice.toString(Charsets.UTF_8).replace("1800000000", "1800000001").toByteArray()
        assertEquals("bad-signature", assertFailsWith<RevokeException> { ShareRevoke.verify(tampered, pub, pid) }.reason)
        assertEquals("bad-revoke", assertFailsWith<RevokeException> { ShareRevoke.verify(ByteArray(1025) { 32 }, pub, pid) }.reason)
        assertEquals("bad-revoke", assertFailsWith<RevokeException> { ShareRevoke.verify("{}".toByteArray(), pub, pid) }.reason)
        val hex = "0000000a-0000-4000-8000-00000000000b"
        val upper = ShareRevoke.make(seed, hex, signer, 1).toString(Charsets.UTF_8).replace(hex, hex.uppercase()).toByteArray()
        assertEquals("bad-revoke", assertFailsWith<RevokeException> { ShareRevoke.verify(upper, pub, hex.uppercase()) }.reason)
        assertFailsWith<RevokeException> { ShareRevoke.make(seed, "not-a-uuid", signer, 1) }
    }

    @Test fun collect_keeps_only_trusted_signers_and_notice_files() {
        val trusted = mapOf(signer to Base64Std.encode(pub))
        val stranger = ShareRevoke.make(ByteArray(32) { 7 }, "00000000-0000-4000-8000-000000000003", "someone", 1)
        val forged = ShareRevoke.make(ByteArray(32) { 7 }, "00000000-0000-4000-8000-000000000004", signer, 1)
        val files = listOf(
            "$pid.lgkrevoke" to notice,
            "a.lgkrevoke" to stranger,
            "b.lgkrevoke" to forged,
            "c.txt" to ShareRevoke.make(seed, "00000000-0000-4000-8000-000000000005", signer, 1),
            "d.lgkrevoke" to "garbage".toByteArray(),
        )
        assertEquals(setOf(pid), ShareRevoke.collect(files, trusted))
        assertEquals(emptySet(), ShareRevoke.collect(files, emptyMap()))
    }

    @Test fun collect_reads_at_most_512_files() {
        val trusted = mapOf(signer to Base64Std.encode(pub))
        val filler = (0 until 512).map { "%04d.lgkrevoke".format(it) to "x".toByteArray() }
        assertEquals(emptySet(), ShareRevoke.collect(filler + ("zzzz.lgkrevoke" to notice), trusted))
    }
}
