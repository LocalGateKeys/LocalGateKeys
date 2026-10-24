package app.localgatekeys.android.detail

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.TestClock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The phone clipboard's ownership rules over a fake system clipboard: tags, focus, the change listener. */
class SystemClipboardSinkRulesTest {
    private class FakePort : ClipboardPort {
        data class Clip(val text: String, val sensitive: Boolean, val tag: String?)

        var clip: Clip? = null
        /** False: the app has no window focus and may not look. */
        var focused = true
        var clears = 0
        private val listeners = mutableListOf<() -> Unit>()

        override fun put(text: String, sensitive: Boolean, tag: String) { clip = Clip(text, sensitive, tag); changed() }
        override fun visibleTag(): String? = if (!focused) null else clip?.let { it.tag ?: "" }
        override fun clear() { clip = null; clears++; changed() }
        override fun onChange(listener: () -> Unit) { listeners.add(listener) }

        /** Someone else copied (another app, or the host's clipboard echo on an emulator). */
        fun foreign(text: String) { clip = Clip(text, false, null); changed() }

        private fun changed() { if (focused) listeners.forEach { it() } }
    }

    private val port = FakePort()
    private val sink = SystemClipboardSink(port)
    private val clock = TestClock(1_000)
    private val scheduler = ManualScheduler(clock)
    private val clip = SecretClipboard(sink, AppSettings(MemoryStore()), scheduler, clock).also { it.focusChanged(true) }

    private fun focus(has: Boolean) {
        port.focused = has
        clip.focusChanged(has)
    }

    @Test fun a_copy_is_sensitive_tagged_and_ours() {
        sink.set("s3cret", sensitive = true)
        assertTrue(port.clip!!.sensitive)
        assertFalse(port.clip!!.tag.isNullOrEmpty())
        assertEquals("s3cret", sink.current())
    }

    @Test fun every_copy_gets_a_fresh_tag() {
        sink.set("a", true); val first = port.clip!!.tag
        sink.set("a", true)
        assertFalse(first == port.clip!!.tag)
    }

    @Test fun a_foreign_copy_seen_while_focused_is_not_ours() {
        sink.set("s3cret", true)
        port.foreign("user text")
        assertNull(sink.current())
    }

    @Test fun a_foreign_copy_seen_by_the_listener_stays_not_ours_after_focus_comes_back() {
        sink.set("s3cret", true)
        port.foreign("user text")
        port.focused = false
        port.focused = true
        assertNull(sink.current())
    }

    @Test fun without_focus_the_sink_never_claims_the_clipboard() {
        sink.set("s3cret", true)
        port.focused = false
        assertNull("cannot look: not verifiably ours", sink.current())
        port.focused = true
        assertEquals("ownership was not forgotten while it could not look", "s3cret", sink.current())
    }

    @Test fun background_expiry_defers_until_focus() {
        clip.copy("s3cret")
        focus(false)
        scheduler.advance(60)
        assertEquals("never a blind clear", "s3cret", port.clip?.text); assertEquals(0, port.clears)
        focus(true)
        assertNull(port.clip); assertEquals(1, port.clears)
    }

    @Test fun deferred_expiry_spares_a_foreign_copy() {
        clip.copy("s3cret")
        focus(false)
        scheduler.advance(60)
        port.foreign("copied in the browser") // unseen: no focus, no listener
        focus(true)
        assertEquals("copied in the browser", port.clip?.text); assertEquals(0, port.clears)
        assertFalse(clip.isDue)
    }

    @Test fun a_deadline_passed_in_deep_sleep_clears_our_copy_on_focus() {
        clip.copy("s3cret")
        focus(false)
        clock.now += 3_600 // elapsed time ran in deep sleep; the uptime timer never fired
        focus(true)
        assertNull(port.clip)
    }

    @Test fun clear_forgets_our_copy() {
        sink.set("s3cret", true)
        sink.clear()
        assertNull(port.clip); assertNull(sink.current())
    }

    @Test fun with_focus_the_expiry_clears_ours_and_spares_a_foreign_copy() {
        clip.copy("s3cret")
        scheduler.advance(60)
        assertNull(port.clip)
        clip.copy("s3cret-2")
        port.foreign("user text")
        scheduler.advance(60)
        assertEquals("user text", port.clip?.text)
    }

    @Test fun to_string_never_shows_the_copy() {
        sink.set("s3cret-Maple", true)
        assertFalse(sink.toString().contains("s3cret"))
    }
}
