package app.localgatekeys.android.autofill

import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.core.records.UrlMatchMode
import app.localgatekeys.core.records.UrlRow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

/** The sealed fill index on a real Keystore: round trip, no plaintext on disk, erase removes it. */
class FillIndexStoreDeviceTest {
    @Test fun round_trip_sealed_and_erased() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val file = File(ctx.cacheDir, "fill-index-test.bin")
        val store = FillIndexStore(file)
        val index = FillIndex(
            listOf(IndexEntry("w1", "Example", "sample.user@example.com", listOf(UrlRow("https://example.com", UrlMatchMode.BASE_DOMAIN)), 7)),
            mapOf("com.example" to listOf("w1")),
        )
        store.write(index)
        assertEquals(index, store.read())
        assertFalse(String(file.readBytes(), Charsets.ISO_8859_1).contains("sample.user"))
        store.erase()
        assertFalse(file.exists())
        assertNull(store.read())
    }
}
