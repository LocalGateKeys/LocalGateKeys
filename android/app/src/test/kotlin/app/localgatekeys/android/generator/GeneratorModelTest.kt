package app.localgatekeys.android.generator

import app.localgatekeys.android.detail.FakeClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.editor
import app.localgatekeys.android.generator.GeneratorOptions.Mode
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.ClipboardExpiry
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.primitives.RandomSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Port of `ios/LocalGateKeysTests/GeneratorModelTests.swift`. */
class GeneratorModelTest {
    init { TestWordlist.install() }

    private val clock = TestClock(1_800_000_000)
    private val settings = AppSettings(MemoryStore())
    private val sink = FakeClipboardSink()
    private val scheduler = ManualScheduler(clock)
    private val clipboard = SecretClipboard(sink, settings, scheduler, clock).also { it.focusChanged(true) }

    /** The main thread's queue: what the model posts runs only when the test drains it ("a later main-actor turn"). */
    private val mainQueue = ArrayDeque<() -> Unit>()
    private fun drain() { while (mainQueue.isNotEmpty()) mainQueue.removeFirst()() }

    private var wordlist = PassphraseWordlist.packaged

    private fun model(random: RandomSource = StepRandom()) =
        GeneratorModel(GeneratorDefaults(settings), random, clipboard, wordlist, post = { mainQueue.addLast(it) })

    @Test fun start_generates_from_saved_options() {
        val saved = GeneratorOptions(length = 31, symbols = false)
        GeneratorDefaults(settings).save(saved)
        val m = model()
        assertEquals(saved, m.options)
        assertEquals("nothing is generated before the sheet appears", "", m.value)
        m.start()
        assertEquals(31, m.value.length)
        val first = m.value
        m.start()
        assertEquals("appearing again keeps the value", first, m.value)
    }

    @Test fun regenerate_changes_the_value() {
        val m = model(); m.start()
        val first = m.value
        m.regenerate()
        assertNotEquals(first, m.value)
        assertEquals(20, m.value.length)
    }

    @Test fun options_persist_and_regenerate() {
        val m = model(); m.start()
        val first = m.value
        m.update { it.copy(mode = Mode.PASSPHRASE) }
        assertNotEquals(first, m.value)
        assertEquals(6, m.value.split("-").size)
        m.update { it.copy(words = 4) }
        assertEquals(Mode.PASSPHRASE, GeneratorDefaults(settings).load().mode)
        assertEquals(4, GeneratorDefaults(settings).load().words)
        assertEquals("a new sheet starts from them", m.options, model().options)
    }

    @Test fun bad_options_show_the_error_and_disable_use() {
        val m = model(); m.start()
        assertTrue(m.canUse)
        m.update { it.copy(lowercase = false, uppercase = false, digits = false, symbols = false) }
        assertEquals("", m.value)
        assertEquals(GeneratorError.NoGroups.message, m.error)
        assertFalse(m.canUse)
        var dismissed = 0
        val delivered = mutableListOf<String>()
        m.use(dismiss = { dismissed++ }, deliver = { delivered.add(it) })
        drain()
        assertEquals(0, dismissed); assertEquals(emptyList<String>(), delivered)
        m.update { it.copy(digits = true) }
        assertNull(m.error); assertTrue(m.canUse)
    }

    @Test fun strength_follows_the_options() {
        val m = model()
        assertEquals(GeneratorStrength.Level.VERY_STRONG, m.strength)
        m.update { it.copy(mode = Mode.PASSPHRASE, words = 3) }
        assertEquals(GeneratorStrength.level(m.options), m.strength)
        assertEquals(GeneratorStrength.Level.WEAK, m.strength)
    }

    /** iPhone: local-only with the settings expiry. Android: a sensitive clip that the secret clipboard clears then. */
    @Test fun copy_is_sensitive_with_the_settings_expiry() {
        settings.clipboardExpiry = ClipboardExpiry.TWO_MINUTES
        val m = model(); m.start()
        m.copy()
        assertEquals(listOf(FakeClipboardSink.Write(m.value, sensitive = true)), sink.history)
        assertEquals(clock.now + ClipboardExpiry.TWO_MINUTES.seconds, scheduler.timers.single { !it.cancelled }.due)
        assertTrue(m.copied)
        m.regenerate()
        assertFalse("a new value has not been copied", m.copied)
        scheduler.advance(120)
        assertNull("the copy expires", sink.text)
    }

    @Test fun use_dismisses_first_then_delivers_to_the_editor_exactly_once() {
        val editor = editor(CountingStore(), kind = EditorKind.WEB)
        val m = model(); m.start()
        val value = m.value
        val events = mutableListOf<String>()
        var delivered = 0
        val deliver: (String) -> Unit = { v ->
            events.add("deliver"); delivered++
            editor.set("password", v)
        }
        m.use(dismiss = { events.add("dismiss") }, deliver = deliver)
        assertEquals("the value is delivered on a later main-thread turn, after dismiss", listOf("dismiss"), events)
        assertEquals("", editor.value("password"))
        // A second tap while the sheet closes delivers nothing more.
        m.use(dismiss = { events.add("dismiss") }, deliver = deliver)
        assertFalse(m.canUse)
        drain()
        assertEquals(listOf("dismiss", "deliver"), events)
        assertEquals(1, delivered)
        assertEquals(value, editor.value("password"))
        assertTrue("never through the clipboard", sink.history.isEmpty())
    }

    @Test fun length_slider_covers_8_to_64_and_keeps_a_longer_stepper_length() {
        var length = 100
        val range = GeneratorSlider.LENGTH_RANGE
        assertEquals(8..64, range)
        assertEquals("thumb at the end", 64f, GeneratorSlider.position(length, range))
        GeneratorSlider.moved(64f, length, range)?.let { length = it }
        assertEquals("the slider reporting its end position does not cut the length", 100, length)
        GeneratorSlider.moved(31.6f, length, range)?.let { length = it }
        assertEquals(32, length)
        GeneratorSlider.moved(8f, length, range)?.let { length = it }
        assertEquals(8, length)
    }

    // ---- Android additions ----

    @Test fun to_string_never_shows_the_generated_value() {
        val m = model(); m.start()
        val value = m.value
        assertFalse(m.toString().contains(value))
        assertFalse(m.state.value.toString().contains(value))
        assertTrue(m.state.value.toString().contains("<20 chars>"))
    }

    @Test fun the_stepper_stays_within_8_to_256() {
        val m = model()
        m.update { it.copy(length = 256) }
        m.stepLength(+1)
        assertEquals(256, m.options.length)
        m.update { it.copy(length = 8) }
        m.stepLength(-1)
        assertEquals(8, m.options.length)
        m.stepLength(+1)
        assertEquals(9, m.options.length)
    }

    /** The model works from the list it was given (read off the main thread): strength and passphrases both use it. */
    @Test fun the_model_uses_the_list_it_was_given() {
        wordlist = PassphraseWordlist.FALLBACK
        val m = model()
        m.update { it.copy(mode = Mode.PASSPHRASE, words = 6) }
        assertEquals(GeneratorStrength.level(m.options, PassphraseWordlist.FALLBACK.size), m.strength)
        assertEquals(GeneratorStrength.Level.FAIR, m.strength) // 6 * log2(340) = 50.5 bits; the packaged list is strong
        assertTrue(m.value.split("-").all { it in PassphraseWordlist.FALLBACK })
    }
}
