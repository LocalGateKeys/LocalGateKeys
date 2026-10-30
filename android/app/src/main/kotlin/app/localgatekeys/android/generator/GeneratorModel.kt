package app.localgatekeys.android.generator

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.SystemRandomSource
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlin.math.roundToInt

/**
 * The generator sheet's state: options (saved as the new defaults on every change), the current value, and the hand-off
 * of that value to whoever opened the sheet. Port of `ios/App/Generator/GeneratorModel.swift`. Main thread only.
 *
 * [post] runs a block on a later main-thread turn (a Handler post on the phone), so the value reaches the editor after
 * the sheet has closed. The value only ever leaves through [use] (into the editor) or [copy] (the secret clipboard).
 */
class GeneratorModel(
    private val defaults: GeneratorDefaults,
    random: RandomSource = SystemRandomSource(),
    private val clipboard: SecretClipboard,
    /**
     * The passphrase list, already read: [PassphraseWordlist.packaged] fetched off the main thread by whoever opens
     * the sheet, so neither the sheet nor [strength] ever parses the asset on the main thread.
     */
    private val wordlist: List<String>,
    private val post: (() -> Unit) -> Unit,
    private val t: Txt,
) {
    data class State(
        val options: GeneratorOptions,
        val value: String = "",
        val error: String? = null,
        /** The current value is on the clipboard (cleared when a new value is generated). */
        val copied: Boolean = false,
        /** Use was tapped: the sheet is closing and the value has been handed over (or is about to be). */
        val used: Boolean = false,
    ) {
        /** Never shows the value. */
        override fun toString(): String =
            "State(options=$options, value=<${value.length} chars>, error=$error, copied=$copied, used=$used)"
    }

    private val generator = PasswordGenerator(random) { wordlist }
    private val _state = MutableStateFlow(State(defaults.load()))
    val state: StateFlow<State> = _state.asStateFlow()

    /** Setting different options saves them and generates a new value. */
    var options: GeneratorOptions
        get() = _state.value.options
        set(new) {
            if (new == _state.value.options) return
            _state.update { it.copy(options = new) }
            defaults.save(new)
            regenerate()
        }

    fun update(change: (GeneratorOptions) -> GeneratorOptions) { options = change(options) }

    val value: String get() = _state.value.value
    val error: String? get() = _state.value.error
    val copied: Boolean get() = _state.value.copied
    val used: Boolean get() = _state.value.used

    val strength: GeneratorStrength.Level get() = GeneratorStrength.level(options, wordlist.size)
    val canUse: Boolean get() = value.isNotEmpty() && !used

    /** The first value, when the sheet appears (not in the constructor: the sheet may build the model more than once). */
    fun start() { if (value.isEmpty() && error == null) regenerate() }

    fun regenerate() {
        val next = try {
            generator.generate(options) to null
        } catch (e: GeneratorError) {
            "" to e.text(t)
        } catch (e: Exception) {
            "" to t.s(R.string.generator_failed)
        }
        _state.update { it.copy(value = next.first, error = next.second, copied = false) }
    }

    /** The stepper: one character more or fewer, within 8 to 256. */
    fun stepLength(by: Int) = update { it.copy(length = (it.length + by).coerceIn(PasswordGenerator.LENGTH_RANGE)) }

    /** Onto the secret clipboard (sensitive, cleared after the expiry chosen in Settings). */
    fun copy() {
        val v = value
        if (v.isEmpty()) return
        clipboard.copy(v)
        _state.update { it.copy(copied = true) }
    }

    /**
     * Closes the sheet first, then hands the value over on a later main-thread turn, so the editor is not changed while
     * the sheet is being dismissed. Delivers at most once.
     */
    fun use(dismiss: () -> Unit, deliver: (String) -> Unit) {
        if (!canUse) return
        val v = value
        _state.update { it.copy(used = true) }
        dismiss()
        post { deliver(v) }
    }

    override fun toString(): String = "GeneratorModel(state=${_state.value})"
}

/** An Int option on a slider whose range may be narrower than the option's (the length slider is 8-64, the stepper 256). */
object GeneratorSlider {
    val LENGTH_RANGE = 8..64

    /** The thumb: the value, held at the slider's end when it lies outside. */
    fun position(value: Int, range: IntRange): Float = value.coerceIn(range).toFloat()

    /**
     * The new value for a slider report, or null to keep [current]: a report of the thumb's own (clamped) position, as
     * when a stepper length over 64 shows the thumb at the end, does not cut the length.
     */
    fun moved(to: Float, current: Int, range: IntRange): Int? {
        val n = to.roundToInt()
        return if (n != current.coerceIn(range)) n else null
    }
}
