package app.localgatekeys.android

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.SharedPrefsStore
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** The SharedPreferences adapter on a real device: types, wrong-type reads, remove and durable writes. */
class SharedPrefsStoreTest {
    private val ctx: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val name = "settings-test"

    @Before fun clean() = wipe()
    @After fun after() = wipe()

    private fun wipe() {
        ctx.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit()
        ctx.deleteSharedPreferences(name)
    }

    private fun prefsFile() = File(ctx.dataDir, "shared_prefs/$name.xml")

    @Test fun round_trips_each_type_and_remove() {
        val s = SharedPrefsStore(ctx, name)
        assertNull(s.getLong("l")); assertNull(s.getBoolean("b")); assertNull(s.getString("s"))
        s.putLong("l", 1L shl 40); s.putBoolean("b", true); s.putString("s", "x")
        assertEquals(1L shl 40, s.getLong("l")); assertEquals(true, s.getBoolean("b")); assertEquals("x", s.getString("s"))
        s.putBoolean("b", false)
        assertEquals(false, s.getBoolean("b"))
        s.remove("l"); s.remove("b"); s.remove("s")
        assertNull(s.getLong("l")); assertNull(s.getBoolean("b")); assertNull(s.getString("s"))
    }

    @Test fun wrong_typed_reads_are_null() {
        val s = SharedPrefsStore(ctx, name)
        s.putString("k", "text")
        assertNull(s.getLong("k")); assertNull(s.getBoolean("k"))
        s.putLong("n", 5)
        assertNull(s.getString("n")); assertNull(s.getBoolean("n"))
        s.putBoolean("f", true)
        assertNull(s.getLong("f")); assertNull(s.getString("f"))
        assertEquals("text", s.getString("k"))
    }

    @Test fun settings_over_the_adapter_use_defaults_and_wrong_types() {
        val s = SharedPrefsStore(ctx, name)
        s.putString(AppSettings.Key.AUTO_LOCK_DELAY, "oops")
        val a = AppSettings(s)
        assertEquals(app.localgatekeys.android.settings.AutoLockDelay.IMMEDIATELY, a.autoLockDelay)
        a.initials = "ada lovelace"
        assertEquals("AL", AppSettings(SharedPrefsStore(ctx, name)).initials)
    }

    @Test fun durable_writes_are_on_disk_immediately() {
        val s = SharedPrefsStore(ctx, name)
        val a = AppSettings(s)
        a.erasePending = true
        a.planFullRevision = 42
        // The file holds both before the call returns: read the XML itself and through a new instance.
        val xml = prefsFile().readText()
        assertTrue(xml, xml.contains("settings.erasePending") && xml.contains("value=\"true\""))
        assertTrue(xml, xml.contains("settings.planFullRevision") && xml.contains("42"))
        val fresh = AppSettings(SharedPrefsStore(ctx, name))
        assertTrue(fresh.erasePending); assertEquals(42L, fresh.planFullRevision)
        a.erasePending = false
        a.planFullRevision = null
        val after = prefsFile().readText()
        assertTrue(after, after.contains("settings.erasePending") && after.contains("value=\"false\""))
        assertFalse(after, after.contains("settings.planFullRevision"))
    }
}
