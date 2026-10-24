package app.localgatekeys.android.settings

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** A durable write that SharedPreferences.commit() did not save is surfaced, never ignored. */
class SharedPrefsDurableWriteTest {
    /** SharedPreferences whose commit() reports failure (disk full, I/O error). */
    private class RefusingPrefs : SharedPreferences {
        var commits = 0
        var applies = 0
        private val editor = object : SharedPreferences.Editor {
            override fun putString(key: String?, value: String?) = this
            override fun putStringSet(key: String?, values: MutableSet<String>?) = this
            override fun putInt(key: String?, value: Int) = this
            override fun putLong(key: String?, value: Long) = this
            override fun putFloat(key: String?, value: Float) = this
            override fun putBoolean(key: String?, value: Boolean) = this
            override fun remove(key: String?) = this
            override fun clear() = this
            override fun commit(): Boolean { commits++; return false }
            override fun apply() { applies++ }
        }
        override fun getAll(): MutableMap<String, *> = mutableMapOf<String, Any>()
        override fun getString(key: String?, defValue: String?) = defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?) = defValues
        override fun getInt(key: String?, defValue: Int) = defValue
        override fun getLong(key: String?, defValue: Long) = defValue
        override fun getFloat(key: String?, defValue: Float) = defValue
        override fun getBoolean(key: String?, defValue: Boolean) = defValue
        override fun contains(key: String?) = false
        override fun edit(): SharedPreferences.Editor = editor
        override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    @Test fun failed_durable_write_throws() {
        val prefs = RefusingPrefs()
        val settings = AppSettings(SharedPrefsStore(prefs))
        try {
            settings.erasePending = true
            fail("the erase flag must be known to be on disk")
        } catch (e: SettingsWriteException) {
            assertEquals(1, prefs.commits)
        }
        try {
            settings.eraseAllExceptPending()
            fail()
        } catch (e: SettingsWriteException) {
            // expected
        }
    }

    /** commit() updates memory before the disk write fails: the store rolls memory back, so reads match the disk. */
    @Test fun failed_durable_write_is_rolled_back_in_memory() {
        val prefs = FlakyPrefs()
        val settings = AppSettings(SharedPrefsStore(prefs))
        settings.planFullRevision = 4
        prefs.failCommit = { true }
        try { settings.erasePending = true; fail() } catch (e: SettingsWriteException) { /* expected */ }
        assertEquals(false, settings.erasePending)
        assertTrue(!prefs.memory.containsKey(AppSettings.Key.ERASE_PENDING))
        try { settings.planFullRevision = 9; fail() } catch (e: SettingsWriteException) { /* expected */ }
        assertEquals("previous value restored", 4L, settings.planFullRevision)
        try { settings.planFullRevision = null; fail() } catch (e: SettingsWriteException) { /* expected */ }
        assertEquals("a failed removal is undone too", 4L, settings.planFullRevision)
        prefs.failCommit = { false }
        settings.erasePending = true
        assertEquals(true, prefs.disk[AppSettings.Key.ERASE_PENDING])
    }

    @Test fun ordinary_writes_stay_asynchronous() {
        val prefs = RefusingPrefs()
        AppSettings(SharedPrefsStore(prefs)).initials = "AB"
        assertEquals(0, prefs.commits)
        assertTrue(prefs.applies == 1)
    }
}
