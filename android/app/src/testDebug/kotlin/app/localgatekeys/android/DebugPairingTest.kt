package app.localgatekeys.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Ruling D: the debug pairing extra carries the QR text as scanned (trimmed); nothing when absent or blank. */
class DebugPairingTest {
    @Test fun the_extra_is_the_scanned_text() {
        assertEquals("lgk-pair:abc", DebugPairing.text("  lgk-pair:abc\n"))
        assertNull(DebugPairing.text(null))
        assertNull(DebugPairing.text("   "))
        assertEquals("lgk.debug.pairing", DebugPairing.EXTRA)
    }
}
