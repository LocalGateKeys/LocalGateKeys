package app.localgatekeys.android.generator

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.core.primitives.SystemRandomSource
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Port of `ios/LocalGateKeysTests/PasswordGeneratorTests.swift` (PasswordGeneratorTests and PasswordGeneratorG2Tests). */
class PasswordGeneratorTest {
    init { TestWordlist.install() }

    private val symbols = "!@#$%^&*()-_=+[]{}:,.?"

    @Test fun defaults_match_the_desktop() {
        val o = GeneratorOptions()
        assertEquals(GeneratorOptions.Mode.PASSWORD, o.mode)
        assertEquals(20, o.length)
        assertTrue(o.lowercase && o.uppercase && o.digits && o.symbols && o.avoidAmbiguous)
        assertEquals(symbols, o.symbolSet)
        assertEquals("", o.exclude)
        assertEquals(1, o.minDigits); assertEquals(1, o.minSymbols)
        assertEquals(6, o.words); assertEquals("-", o.separator)
        assertFalse(o.capitalize); assertFalse(o.appendNumber)
        assertEquals("Il1O0o|`'\"".codePoints().toArray().toSet(), PasswordGenerator.AMBIGUOUS)
    }

    @Test fun password_uses_every_group_and_skips_ambiguous() {
        for (seed in 0 until 40) {
            val pw = PasswordGenerator(StepRandom(seed)).generate(GeneratorOptions())
            assertEquals(20, pw.length)
            assertTrue(pw.any { it.isLowerCase() }); assertTrue(pw.any { it.isUpperCase() })
            assertTrue(pw.any { it.isDigit() })
            assertTrue(pw.any { it in symbols })
            assertFalse(pw.any { it.code in PasswordGenerator.AMBIGUOUS })
        }
    }

    @Test fun fixed_random_is_deterministic_and_lengths_clamp() {
        val a = PasswordGenerator(StepRandom(7)).generate(GeneratorOptions())
        val b = PasswordGenerator(StepRandom(7)).generate(GeneratorOptions())
        assertEquals(a, b)
        val system = PasswordGenerator(SystemRandomSource())
        assertEquals(8, system.generate(GeneratorOptions(length = 3)).length)
        assertEquals(256, system.generate(GeneratorOptions(length = 999)).length)
        assertThrows(GeneratorError::class.java) {
            system.generate(GeneratorOptions(lowercase = false, uppercase = false, digits = false, symbols = false))
        }
        val pin = system.generate(GeneratorOptions(lowercase = false, uppercase = false, symbols = false, length = 8))
        assertTrue("PIN", pin.all { it in '0'..'9' })
    }

    @Test fun passphrase_uses_the_desktop_word_list() {
        val words = PassphraseWordlist.packaged
        assertTrue(words.size >= 1000)
        assertTrue(words.all { it.length in 3..12 && it.all { c -> c in 'a'..'z' } })
        var o = GeneratorOptions(mode = GeneratorOptions.Mode.PASSPHRASE)
        val phrase = PasswordGenerator(StepRandom()).generate(o)
        val parts = phrase.split("-")
        assertEquals(6, parts.size)
        assertTrue(parts.all { it in words })
        o = o.copy(capitalize = true, appendNumber = true, separator = ".", words = 3)
        val p2 = PasswordGenerator(StepRandom()).generate(o)
        assertEquals(3, p2.split(".").size)
        assertTrue(p2.first().isUpperCase())
        assertTrue(p2.takeLast(2).toIntOrNull()?.let { it in 10..99 } ?: false)
    }

    // ---- PasswordGeneratorG2Tests ----

    @Test fun missing_or_short_wordlist_falls_back_to_the_desktop_list() {
        assertEquals(PassphraseWordlist.FALLBACK, PassphraseWordlist.parse(null))
        assertEquals(PassphraseWordlist.FALLBACK, PassphraseWordlist.parse(""))
        assertEquals(PassphraseWordlist.FALLBACK, PassphraseWordlist.parse("apple\nbanana\n"))
        assertEquals(340, PassphraseWordlist.FALLBACK.size)
        assertEquals("acorn", PassphraseWordlist.FALLBACK.first())
        assertEquals("zone", PassphraseWordlist.FALLBACK.last())
        val p = PasswordGenerator(SystemRandomSource())
            .passphrase(words = 4, separator = "-", capitalize = false, appendNumber = false, wordlist = emptyList())
        assertEquals(4, p.split("-").size)
        assertTrue(p.split("-").all { it in PassphraseWordlist.FALLBACK })
    }

    @Test fun length_cap_matches_desktop() {
        assertEquals(8..256, PasswordGenerator.LENGTH_RANGE)
        assertEquals(3..16, PasswordGenerator.WORDS_RANGE)
    }

    @Test fun generator_options_persist_and_reset_to_desktop_defaults() {
        val kv = MemoryStore()
        val settings = AppSettings(kv)
        val store = GeneratorDefaults(settings)
        assertEquals("nothing saved: desktop defaults", GeneratorOptions(), store.load())
        val o = GeneratorOptions(mode = GeneratorOptions.Mode.PASSPHRASE, length = 32, symbols = false, words = 9, separator = "_")
        store.save(o)
        assertEquals(o, GeneratorDefaults(AppSettings(kv)).load())
        store.reset()
        assertEquals(GeneratorOptions(), store.load())
        assertNull(settings.generatorOptions)
    }

    @Test fun corrupt_saved_options_fall_back_to_defaults() {
        val settings = AppSettings(MemoryStore())
        settings.generatorOptions = "{nope"
        assertEquals(GeneratorOptions(), GeneratorDefaults(settings).load())
    }

    // ---- Android additions ----

    /** The same JSON keys and values as the iPhone's JSONEncoder output, so the setting reads the same everywhere. */
    @Test fun options_are_saved_as_json_with_the_iphone_keys() {
        val json = GeneratorOptions(mode = GeneratorOptions.Mode.PASSPHRASE, words = 9).toJson()
        assertEquals(
            "{\"appendNumber\":false,\"avoidAmbiguous\":true,\"capitalize\":false,\"digits\":true,\"exclude\":\"\"," +
                "\"length\":20,\"lowercase\":true,\"minDigits\":1,\"minSymbols\":1,\"mode\":\"passphrase\"," +
                "\"separator\":\"-\",\"symbolSet\":\"!@#\$%^&*()-_=+[]{}:,.?\",\"symbols\":true,\"uppercase\":true,\"words\":9}",
            json,
        )
        assertEquals(GeneratorOptions(mode = GeneratorOptions.Mode.PASSPHRASE, words = 9), GeneratorOptions.fromJson(json))
    }

    /** Swift's synthesised Decodable needs every key with its type: anything else gives the defaults. */
    @Test fun options_json_missing_a_key_or_with_a_wrong_type_or_mode_gives_null() {
        val good = GeneratorOptions().toJson()
        assertEquals(GeneratorOptions(), GeneratorOptions.fromJson(good))
        assertNull(GeneratorOptions.fromJson(good.replace("\"words\":6,", "").replace(",\"words\":6", "")))
        assertNull(GeneratorOptions.fromJson(good.replace("\"length\":20", "\"length\":\"20\"")))
        assertNull(GeneratorOptions.fromJson(good.replace("\"mode\":\"password\"", "\"mode\":\"pin\"")))
        assertNull(GeneratorOptions.fromJson("[]"))
        val settings = AppSettings(MemoryStore())
        settings.generatorOptions = good.replace("\"mode\":\"password\"", "\"mode\":\"pin\"")
        assertEquals(GeneratorOptions(), GeneratorDefaults(settings).load())
    }

    @Test fun generator_errors_use_the_desktop_wording() {
        val g = PasswordGenerator(SystemRandomSource())
        val none = assertThrows(GeneratorError::class.java) {
            g.generate(GeneratorOptions(lowercase = false, uppercase = false, digits = false, symbols = false))
        }
        assertEquals("Select at least one character group", none.message)
        val empty = assertThrows(GeneratorError::class.java) {
            g.generate(GeneratorOptions(lowercase = false, uppercase = false, symbols = false, exclude = "23456789"))
        }
        assertEquals("No usable digits remain after exclusions", empty.message)
        val sep = assertThrows(GeneratorError::class.java) {
            g.generate(GeneratorOptions(mode = GeneratorOptions.Mode.PASSPHRASE, separator = "+"))
        }
        assertEquals("Separator must be one of: dash, space, dot, underscore or none", sep.message)
    }

    /** The option minimums raise a too-short length, as on the desktop. */
    @Test fun minimums_raise_the_length() {
        val pw = PasswordGenerator(StepRandom(3)).generate(
            GeneratorOptions(length = 8, lowercase = false, uppercase = false, minDigits = 6, minSymbols = 5),
        )
        assertEquals(11, pw.length)
        assertTrue(pw.count { it.isDigit() } >= 6)
        assertTrue(pw.count { it in symbols } >= 5)
    }

    /** Rejection sampling: a 32-bit draw at or above the largest multiple of n is drawn again, so no value is favoured. */
    @Test fun below_rejects_the_biased_tail() {
        val draws = ArrayDeque(listOf(byteArrayOf(-1, -1, -1, -1), byteArrayOf(0, 0, 0, 7)))
        val g = PasswordGenerator(object : app.localgatekeys.core.primitives.RandomSource {
            override fun bytes(count: Int): ByteArray { assertEquals(4, count); return draws.removeFirst() }
        })
        // 2^32 / 3 * 3 = 4294967295: 0xFFFFFFFF is the rejected tail.
        assertEquals(7 % 3, g.below(3))
        assertTrue(draws.isEmpty())
    }

    @Test fun the_packaged_asset_is_the_desktop_list_byte_for_byte() {
        val desktop = File(TestWordlist.repoRoot, "src/localvault/assets/eff_large_wordlist.txt")
        assertArrayEquals(desktop.readBytes(), TestWordlist.asset.readBytes())
        assertEquals(5017, PassphraseWordlist.parse(TestWordlist.asset.readText()).size)
    }

    @Test fun the_fallback_list_is_the_iphone_list_verbatim() {
        val swift = File(TestWordlist.repoRoot, "ios/App/Generator/FallbackWordlist.swift").readText()
        val words = Regex("\"([a-z]+)\"").findAll(swift).map { it.groupValues[1] }.toList()
        assertEquals(words, PassphraseWordlist.FALLBACK)
    }
}
