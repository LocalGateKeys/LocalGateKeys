package app.localgatekeys.android.unlock

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.primitives.Hex
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.application.BadResponseException
import com.yubico.yubikit.core.application.TimeoutException
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.YubiOtpSession
import java.io.File
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The bytes YubiKit puts on the wire (docs/formats/COMPOSITE_KEY_V1.md §1.2): through the real `YubiOtpSession` over a
 * fake NFC smart-card connection, the HMAC command carries exactly the vector's `padded_challenge_hex` (YubiKit pads
 * nothing), and a key in variable-input mode answers with the vector's response.
 */
class YubiKeyReaderTest {
    private val yubikey = CanonicalJson.parse(
        File(File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set")), "tests/vectors/composite_key/cases.json").readBytes(),
    ).obj().fields.getValue("yubikey").obj().fields
    private val padded = Hex.decode(yubikey.getValue("padded_challenge_hex").str())

    /** A YubiKey 5.4.3 over NFC: no management applet answer, the OTP applet, and one HMAC-SHA1 slot. */
    private class FakeCard(private val slotSecret: ByteArray?, private val dropAtHmac: Boolean = false) : SmartCardConnection {
        val apdus = mutableListOf<ByteArray>()
        override fun sendAndReceive(apdu: ByteArray): ByteArray {
            apdus += apdu
            val ins = apdu[1].toInt() and 0xff
            return when {
                // The OTP applet (YubiKit selects a0000005272001 with its 01 suffix).
                ins == 0xA4 && Hex.lower(apdu.copyOfRange(5, apdu.size)).startsWith("a0000005272001") ->
                    byteArrayOf(5, 4, 3, 1, 3, 0) + OK // version, sequence, touch level: both slots set
                ins == 0xA4 -> byteArrayOf(0x6A, 0x82.toByte()) // the management applet: not found
                ins == 0x01 -> {
                    if (dropAtHmac) throw IOException("Tag was lost.")
                    val secret = slotSecret ?: return OK // an unprogrammed slot answers nothing
                    FactorUnlockModelTest.FakeFactorSource.variableModeHmac(secret, apdu.copyOfRange(5, 5 + 64)) + OK
                }
                else -> byteArrayOf(0x6D, 0x00)
            }
        }
        override fun getTransport() = Transport.NFC
        override fun isExtendedLengthApduSupported() = false
        override fun getAtr(): ByteArray = ByteArray(0)
        override fun close() {}

        companion object {
            val OK = byteArrayOf(0x90.toByte(), 0x00)
        }
    }

    @Test fun theWireCarriesTheFullPaddedChallenge() {
        val card = FakeCard(yubikey.getValue("hmac_secret").str().toByteArray())
        val response = YubiOtpSession(card).use { YubiKeyReader.respondWith(it, 2, padded) }
        assertEquals(yubikey.getValue("response_hex").str(), Hex.lower(response))
        val hmac = card.apdus.last()
        // 00 01 38 00 40 || the 64 bytes, nothing else: slot 2, no padding of YubiKit's own.
        assertEquals("0001380040" + yubikey.getValue("padded_challenge_hex").str(), Hex.lower(hmac))
        // Slot 1 is P1 0x30.
        val one = FakeCard(ByteArray(20))
        YubiOtpSession(one).use { YubiKeyReader.respondWith(it, 1, padded) }
        assertEquals("0001300040", Hex.lower(one.apdus.last().copyOf(5)))
        // Why: handed the bare 32 bytes, YubiKit pads with its own byte (0x00), not KeePassXC's 0x20.
        val bare = FakeCard(ByteArray(20))
        YubiOtpSession(bare).use { it.calculateHmacSha1(Slot.TWO, padded.copyOf(32), null) }
        assertEquals(Hex.lower(padded.copyOf(32)) + "00".repeat(32), Hex.lower(bare.apdus.last().copyOfRange(5, 69)))
        // The bare 32 bytes are never handed over.
        assertTrue(runCatching { YubiOtpSession(FakeCard(ByteArray(20))).use { YubiKeyReader.respondWith(it, 2, padded.copyOf(32)) } }.exceptionOrNull() is IllegalArgumentException)
    }

    @Test fun failuresMapToMessagesNotCrashes() {
        // The tag leaves mid-answer: "Touch your YubiKey again".
        val lost = runCatching { YubiOtpSession(FakeCard(ByteArray(20), dropAtHmac = true)).use { YubiKeyReader.respondWith(it, 2, padded) } }.exceptionOrNull()!!
        assertEquals(YubiKeyException.Code.REMOVED, YubiKeyReader.failure(lost, 2).code)
        // An unprogrammed slot answers with no data.
        val empty = runCatching { YubiOtpSession(FakeCard(null)).use { YubiKeyReader.respondWith(it, 2, padded) } }.exceptionOrNull()!!
        assertEquals(YubiKeyException.Code.SLOT_NOT_CONFIGURED, YubiKeyReader.failure(empty, 2).code)
        assertEquals(YubiKeyException.Code.TIMEOUT, YubiKeyReader.failure(TimeoutException("touch"), 1).code)
        assertEquals(YubiKeyException.Code.SLOT_NOT_CONFIGURED, YubiKeyReader.failure(BadResponseException("length"), 1).code)
        assertEquals(YubiKeyException.Code.BAD_ANSWER, YubiKeyReader.failure(IllegalStateException(), 1).code)
        assertEquals(1, YubiKeyReader.failure(IOException(), 1).slot)
    }

    @Test fun keyFilesAreReadWithABound() {
        val big = ByteArray(200_000) { it.toByte() }
        assertArrayEquals(big, AndroidFactorSource.readBounded(big.inputStream(), 300_000))
        assertEquals(100_001, AndroidFactorSource.readBounded(big.inputStream(), 100_000).size)
        assertEquals(0, AndroidFactorSource.readBounded(ByteArray(0).inputStream(), 10).size)
    }
}
