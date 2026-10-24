package app.localgatekeys.android.detail

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Build
import androidx.compose.material3.Text
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.LockScheduler
import app.localgatekeys.android.unlock.LockTimer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The real clipboard behind the secret clipboard (the ownership rules themselves are JVM-tested in
 * SystemClipboardSinkRulesTest). A Compose test activity holds focus, because Android 10 and later let only the focused
 * app look at the clipboard.
 *
 * The emulator mirrors its clipboard with the host and writes our text back as its own untagged clip at unpredictable
 * moments. That echo is rightly "not ours", so a check that needs our clip in place is skipped (assumption) when the echo
 * has already replaced it, instead of failing at random.
 */
class SystemClipboardSinkTest {
    @get:Rule val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager = context.getSystemService(ClipboardManager::class.java)
    private lateinit var sink: SystemClipboardSink
    private val racyEmulator = Build.VERSION.SDK_INT < 30 && Build.HARDWARE == "ranchu"

    private class HandScheduler : LockScheduler {
        val actions = mutableListOf<Pair<Long, () -> Unit>>()
        override fun schedule(afterSeconds: Long, action: () -> Unit): LockTimer {
            actions.add(afterSeconds to action)
            return object : LockTimer { override fun cancel() {} }
        }
    }

    @Before fun setUp() {
        // The Android 10 emulator's system server crashes ("beginBroadcast() called while already in a broadcast" in
        // ClipboardService.HostClipboardMonitor) when its host-clipboard echo races app writes, which kills the whole
        // run. That monitor exists only in emulator images, so these writes are skipped there; API 30+ runs them.
        assumeFalse("API 29 emulator clipboard race (HostClipboardMonitor)", racyEmulator)
        rule.setContent { Text("focus") }
        rule.waitForIdle()
        rule.runOnUiThread { sink = SystemClipboardSink(context) }
    }

    @After fun tearDown() {
        if (!racyEmulator) rule.runOnUiThread { manager.clearPrimaryClip() }
    }

    private fun clipText(): String? = manager.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()

    /** The clipboard is empty, or holds only the host's untagged echo of what was there (never our tagged clip). */
    private fun clipTextOrEcho(): Boolean =
        clipText().isNullOrEmpty() || manager.primaryClipDescription?.let { AndroidClipboardPort.tagOf(it) } == null

    /**
     * Our tagged clip is on the clipboard (not yet replaced by the emulator's host echo). Read on the UI thread, judged
     * outside it: an assumption thrown inside runOnUiThread surfaces as a failure, not a skip.
     */
    private fun ourClip(): Boolean = manager.primaryClipDescription?.let { AndroidClipboardPort.tagOf(it) } != null

    private fun assumeOurClip(ours: Boolean) = assumeTrue("the emulator's host clipboard echo replaced our clip", ours)

    @Test fun the_clip_is_marked_sensitive_and_tagged() {
        val marked = AndroidClipboardPort.clip("s3cret-Maple", sensitive = true, tag = "t1")
        assertTrue(marked.description.extras!!.getBoolean(AndroidClipboardPort.EXTRA_IS_SENSITIVE))
        assertEquals("t1", AndroidClipboardPort.tagOf(marked.description))
        assertEquals("s3cret-Maple", marked.getItemAt(0).text.toString())
        val plain = AndroidClipboardPort.clip("plain", sensitive = false, tag = "t2")
        assertFalse(plain.description.extras!!.getBoolean(AndroidClipboardPort.EXTRA_IS_SENSITIVE))
        if (Build.VERSION.SDK_INT >= 33) assertEquals(ClipDescription.EXTRA_IS_SENSITIVE, AndroidClipboardPort.EXTRA_IS_SENSITIVE)
    }

    @Test fun the_system_keeps_the_flag_and_tag_and_the_sink_sees_its_copy() {
        // Read on the UI thread (one description read: the echo may land at any moment), judge outside it.
        val (tagged, sensitive, current) = rule.runOnUiThread {
            sink.set("s3cret-Maple", sensitive = true)
            val d = manager.primaryClipDescription
            val tagged = d != null && AndroidClipboardPort.tagOf(d) != null
            val sensitive = d?.extras?.getBoolean(AndroidClipboardPort.EXTRA_IS_SENSITIVE) == true
            val current = sink.current()
            // Still ours after reading it: an echo landing in between would make current() null for a good reason.
            Triple(tagged && ourClip(), sensitive, current)
        }
        assumeOurClip(tagged)
        assertTrue(sensitive)
        assertEquals("s3cret-Maple", current)
    }

    @Test fun a_copy_made_elsewhere_is_not_ours() {
        rule.runOnUiThread {
            sink.set("s3cret", sensitive = true)
            manager.setPrimaryClip(ClipData.newPlainText("", "user text"))
            assertNull(sink.current())
        }
    }

    @Test fun clear_and_the_expiry_empty_the_clipboard() {
        val scheduler = HandScheduler()
        val ours = rule.runOnUiThread {
            sink.set("s3cret", sensitive = true)
            sink.clear()
            assertTrue(clipTextOrEcho())

            val clip = SecretClipboard(sink, AppSettings(MemoryStore()), scheduler, ElapsedClock()).also { it.focusChanged(true) }
            clip.copy("s3cret-2")
            assertEquals(60L, scheduler.actions.single().first)
            ourClip()
        }
        assumeOurClip(ours)
        rule.runOnUiThread {
            scheduler.actions.single().second() // the expiry fires
            assertTrue("expired copy is gone", clipTextOrEcho())
        }
    }

    @Test fun the_expiry_leaves_a_later_foreign_copy_alone() {
        val scheduler = HandScheduler()
        rule.runOnUiThread {
            val clip = SecretClipboard(sink, AppSettings(MemoryStore()), scheduler, ElapsedClock()).also { it.focusChanged(true) }
            clip.copy("s3cret")
            manager.setPrimaryClip(ClipData.newPlainText("", "user text"))
            scheduler.actions.single().second()
            // Not cleared. ("user text" itself, unless the host's echo of "s3cret" landed after it: also not ours.)
            assertFalse(clipText().isNullOrEmpty())
        }
    }
}
