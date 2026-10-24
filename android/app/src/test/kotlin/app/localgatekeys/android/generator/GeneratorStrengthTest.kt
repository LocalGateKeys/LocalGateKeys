package app.localgatekeys.android.generator

import app.localgatekeys.android.generator.GeneratorOptions.Mode
import app.localgatekeys.android.generator.GeneratorStrength.Level
import org.junit.Assert.assertEquals
import org.junit.Test
import kotlin.math.log2

/** Port of `ios/LocalGateKeysTests/GeneratorStrengthTests.swift`, plus the saved-password estimate. */
class GeneratorStrengthTest {
    private val eps = 1e-9

    @Test fun level_thresholds() {
        assertEquals(Level.WEAK, GeneratorStrength.level(bits = 0.0))
        assertEquals(Level.WEAK, GeneratorStrength.level(bits = 49.99))
        assertEquals(Level.FAIR, GeneratorStrength.level(bits = 50.0))
        assertEquals(Level.FAIR, GeneratorStrength.level(bits = 69.99))
        assertEquals(Level.STRONG, GeneratorStrength.level(bits = 70.0))
        assertEquals(Level.STRONG, GeneratorStrength.level(bits = 99.99))
        assertEquals(Level.VERY_STRONG, GeneratorStrength.level(bits = 100.0))
        assertEquals(listOf("Weak", "Fair", "Strong", "Very strong"), Level.entries.map { it.label })
        assertEquals(listOf(1, 2, 3, 4), Level.entries.map { it.segments })
    }

    @Test fun default_password_is_very_strong() {
        // Look-alikes removed: 24 lowercase (no l, o), 24 uppercase (no I, O), 8 digits (no 0, 1), 22 symbols.
        assertEquals(78, GeneratorStrength.charsetSize(GeneratorOptions()))
        val bits = GeneratorStrength.entropyBits(GeneratorOptions(), wordlistCount = 7776)
        assertEquals(20 * log2(78.0), bits, eps)
        assertEquals(Level.VERY_STRONG, GeneratorStrength.level(bits = bits))
    }

    @Test fun known_password_cases() {
        var o = GeneratorOptions(lowercase = false, uppercase = false, symbols = false, length = 8)
        // PIN without look-alikes: 8 digits, 8 long = 24 bits.
        assertEquals(24.0, GeneratorStrength.entropyBits(o, wordlistCount = 7776), eps)
        assertEquals(Level.WEAK, GeneratorStrength.level(o, wordlistCount = 7776))

        o = GeneratorOptions(symbols = false, avoidAmbiguous = false, length = 12)
        // 62 alphanumerics, 12 long: 71.45 bits.
        assertEquals(12 * log2(62.0), GeneratorStrength.entropyBits(o, wordlistCount = 0), eps)
        assertEquals(Level.STRONG, GeneratorStrength.level(o, wordlistCount = 0))

        o = o.copy(length = 10) // 59.5 bits
        assertEquals(Level.FAIR, GeneratorStrength.level(o, wordlistCount = 0))

        o = GeneratorOptions(length = 3) // clamps to 8 like the generator
        assertEquals(8 * log2(78.0), GeneratorStrength.entropyBits(o, wordlistCount = 0), eps)
        o = o.copy(length = 999) // clamps to 256
        assertEquals(256 * log2(78.0), GeneratorStrength.entropyBits(o, wordlistCount = 0), eps)
    }

    @Test fun symbols_shared_with_other_groups_count_once_and_exclusions_apply() {
        var o = GeneratorOptions(lowercase = false, uppercase = false, digits = false, symbolSet = "!!--", avoidAmbiguous = false, length = 8)
        assertEquals(2, GeneratorStrength.charsetSize(o))
        o = GeneratorOptions(avoidAmbiguous = false, exclude = "abc")
        assertEquals(26 + 26 + 10 + 22 - 3, GeneratorStrength.charsetSize(o))
    }

    @Test fun no_groups_is_zero_bits() {
        val o = GeneratorOptions(lowercase = false, uppercase = false, digits = false, symbols = false)
        assertEquals(0.0, GeneratorStrength.entropyBits(o, wordlistCount = 7776), 0.0)
        assertEquals(Level.WEAK, GeneratorStrength.level(o, wordlistCount = 7776))
    }

    @Test fun known_passphrase_cases() {
        var o = GeneratorOptions(mode = Mode.PASSPHRASE)
        // Desktop default: 6 words of the EFF list (7776) = 77.5 bits.
        assertEquals(6 * log2(7776.0), GeneratorStrength.entropyBits(o, wordlistCount = 7776), eps)
        assertEquals(Level.STRONG, GeneratorStrength.level(o, wordlistCount = 7776))
        o = o.copy(words = 3) // 38.8 bits
        assertEquals(Level.WEAK, GeneratorStrength.level(o, wordlistCount = 7776))
        o = o.copy(words = 4) // 51.7 bits
        assertEquals(Level.FAIR, GeneratorStrength.level(o, wordlistCount = 7776))
        o = o.copy(words = 8) // 103.4 bits
        assertEquals(Level.VERY_STRONG, GeneratorStrength.level(o, wordlistCount = 7776))
        o = o.copy(words = 40) // clamps to 16
        assertEquals(16 * log2(7776.0), GeneratorStrength.entropyBits(o, wordlistCount = 7776), eps)
    }

    @Test fun passphrase_number_adds_its_bits_and_capitalising_adds_none() {
        var o = GeneratorOptions(mode = Mode.PASSPHRASE, words = 4)
        val base = GeneratorStrength.entropyBits(o, wordlistCount = 7776)
        o = o.copy(appendNumber = true) // 10...99: 90 choices
        assertEquals(base + log2(90.0), GeneratorStrength.entropyBits(o, wordlistCount = 7776), eps)
        o = o.copy(appendNumber = false, capitalize = true) // every word capitalised: nothing random added
        assertEquals(base, GeneratorStrength.entropyBits(o, wordlistCount = 7776), eps)
    }

    @Test fun passphrase_with_an_empty_list_uses_the_fallback_size() {
        val o = GeneratorOptions(mode = Mode.PASSPHRASE, words = 6)
        assertEquals(
            6 * log2(PassphraseWordlist.FALLBACK.size.toDouble()),
            GeneratorStrength.entropyBits(o, wordlistCount = 0), eps,
        )
    }

    @Test fun settings_summary_names_the_strength() {
        assertEquals("Password, 20 characters", GeneratorOptions().summary)
        assertEquals("Passphrase, 6 words", GeneratorOptions(mode = Mode.PASSPHRASE).summary)
        assertEquals(
            "the default list size is used when none is given",
            Level.VERY_STRONG, GeneratorStrength.level(GeneratorOptions()),
        )
    }

    // ---- the saved-password estimate (iOS SiteIconTests "password strength estimate", used on the detail screen) ----

    /** iOS SiteIconTests.test_password_strength_estimate, case for case. */
    @Test fun password_strength_estimate() {
        assertEquals(Level.WEAK, GeneratorStrength.estimate("abc123"))
        assertEquals(Level.WEAK, GeneratorStrength.estimate("aaaaaaaaaaaaaaaaaaaa"))
        assertEquals(Level.WEAK, GeneratorStrength.estimate("password"))
        assertEquals(Level.STRONG, GeneratorStrength.estimate("Tr0ub4dor&3xQ!"))
        assertEquals(Level.VERY_STRONG, GeneratorStrength.estimate("k#9Vq!2mZ@x7Lp\$4Rt8&wN"))
    }

    @Test fun estimate_of_a_saved_password() {
        assertEquals("under 8 is weak", Level.WEAK, GeneratorStrength.estimate("Ab1!xyz"))
        assertEquals(Level.WEAK, GeneratorStrength.estimate(""))
        // 8 lowercase, all different: 8 * log2(26) = 37.6 bits.
        assertEquals(Level.WEAK, GeneratorStrength.estimate("abcdefgh"))
        // 12 mixed, all different: 12 * log2(95) = 78.8 bits.
        assertEquals(Level.STRONG, GeneratorStrength.estimate("aB3!cD4@eF5#"))
        // Repeats count once more at most: "aaaaaaaaaaaaaaaaaaaa" is 2 * log2(26).
        assertEquals(Level.WEAK, GeneratorStrength.estimate("a".repeat(20)))
        // 20 characters from the default generator: very strong.
        assertEquals(Level.VERY_STRONG, GeneratorStrength.estimate("Tq7#mZ9!pW4%kR2&vX8*"))
        // Non-ASCII widens the pool by 100 (12 distinct scalars: 12 * log2(136) = 85.1).
        assertEquals(Level.STRONG, GeneratorStrength.estimate("abéèêë12cdef"))
        // Counted in code points: an emoji is one, not two.
        assertEquals(Level.WEAK, GeneratorStrength.estimate("😀".repeat(4) + "abc"))
    }
}
