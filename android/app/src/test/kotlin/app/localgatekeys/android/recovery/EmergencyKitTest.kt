package app.localgatekeys.android.recovery

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.core.crypto.Bip39
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The emergency kit model: what the printed page says, with or without the recovery phrase. */
class EmergencyKitTest {
    private val facts = EmergencyKit.Facts(date = "3 November 2026", appVersion = "1.0.0", device = "Pixel 9")
    private val txt = EnglishTxt()

    private fun boxes(blocks: List<EmergencyKit.Block>) = blocks.filterIsInstance<EmergencyKit.Block.PhraseBoxes>().single().boxes

    @Test fun withoutPhraseHasBlankBoxes() {
        val boxes = boxes(EmergencyKit.build(txt, facts, null))
        // The app-password phrase is Bip39.WORD_COUNT words (AppPasswordLock / AppPasswordRecord.Created.phrase).
        assertEquals(Bip39.WORD_COUNT, boxes.size)
        assertEquals((1..Bip39.WORD_COUNT).toList(), boxes.map { it.number })
        assertTrue(boxes.all { it.word.isEmpty() })
    }

    @Test fun withPhraseHas24Words() {
        val words = List(Bip39.WORD_COUNT) { "secretword$it" }
        val blocks = EmergencyKit.build(txt, facts, words)
        assertEquals(24, Bip39.WORD_COUNT)
        assertEquals(words, boxes(blocks).map { it.word })
        // The words appear only in the boxes, never in the facts or the text.
        val rest = blocks.filter { it !is EmergencyKit.Block.PhraseBoxes }.joinToString(" ") { it.toString() }
        assertFalse(rest.contains("secretword"))
    }

    @Test fun aShortOrOverlongListStillMakesAFullSetOfBoxes() {
        assertEquals(Bip39.WORD_COUNT, boxes(EmergencyKit.build(txt, facts, listOf("one", "two"))).size)
        assertEquals(Bip39.WORD_COUNT, boxes(EmergencyKit.build(txt, facts, List(30) { "w$it" })).size)
    }

    @Test fun factsHaveNoVaultSecretsAndAppPasswordLineIsBlank() {
        val blocks = EmergencyKit.build(txt, facts, null)
        val fs = blocks.filterIsInstance<EmergencyKit.Block.Fact>().map { it.value }
        assertEquals(listOf("Pixel 9", "3 November 2026", "1.0.0"), fs)
        assertEquals(1, blocks.filterIsInstance<EmergencyKit.Block.BlankLine>().size)
        assertTrue(blocks.first() is EmergencyKit.Block.Title)
        assertTrue(blocks.last() is EmergencyKit.Block.Warning)
        assertTrue(blocks.filterIsInstance<EmergencyKit.Block.Steps>().single().items.isNotEmpty())
    }
}
