package app.localgatekeys.core.primitives

import kotlin.test.Test
import kotlin.test.assertEquals

/** Golden values from Python `str.casefold()`, shared with the Swift CasefoldTests. */
class CasefoldTest {
    private fun cps(s: String): List<Int> = Casefold.fold(s).codePoints().toArray().toList()

    @Test fun golden_cases() {
        val cases: List<Pair<String, List<Int>>> = listOf(
            "ﬁ" to listOf(0x66, 0x69),
            "Ⱟ" to listOf(0x2C5F),
            "Ꟁ" to listOf(0xA7C1),
            "ŉ" to listOf(0x2BC, 0x6E),
            "ǰ" to listOf(0x6A, 0x30C),
            "ΐ" to listOf(0x3B9, 0x308, 0x301),
            "ẛ" to listOf(0x1E61),
            "ͅ" to listOf(0x3B9),
            "ᾳ" to listOf(0x3B1, 0x3B9),
            "ꭰ" to listOf(0x13A0),
            "Ꭰ" to listOf(0x13A0),
            "ᏸ" to listOf(0x13F0),
            "İ" to listOf(0x69, 0x307),
            "ß" to listOf(0x73, 0x73),
            "ẞ" to listOf(0x73, 0x73),
            "Σ" to listOf(0x3C3), "σ" to listOf(0x3C3), "ς" to listOf(0x3C3),
            "AbC-z9" to listOf(0x61, 0x62, 0x63, 0x2D, 0x7A, 0x39),
            "é" to listOf(0xE9),
            "é" to listOf(0x65, 0x301),
            "É" to listOf(0xE9),
            "K" to listOf(0x6B),
            "ϐ" to listOf(0x3B2),
            "ẞx" to listOf(0x73, 0x73, 0x78),
            "𐐀" to listOf(0x10428),
            "" to emptyList(),
        )
        for ((input, want) in cases) {
            assertEquals(want, cps(input), "input ${input.codePoints().toArray().joinToString { Integer.toHexString(it) }}")
        }
    }

    @Test fun version_and_supplementary_plane() {
        assertEquals("15.0.0", Casefold.unicodeVersion)
        // Adlam capital (U+1E900) folds to U+1E922; a pair of them keeps both code points intact.
        assertEquals(listOf(0x1E922, 0x1E922), cps("𞤀𞤀"))
        // Unmapped supplementary characters pass through.
        assertEquals(listOf(0x1F600, 0x61), cps("😀A"))
    }
}
