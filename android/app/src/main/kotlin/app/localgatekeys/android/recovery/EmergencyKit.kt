package app.localgatekeys.android.recovery

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.crypto.Bip39

/**
 * The printable emergency kit as a list of blocks (the Windows kit's content, adapted to the phone). The print layer
 * draws them; this has no Android classes so the content can be tested on the JVM.
 *
 * The kit belongs to the optional app password: the recovery phrase is the one the setup screen just showed. [build]
 * only copies the [words] it is given into the boxes; nothing here stores or logs them. The app password line is
 * always blank.
 */
object EmergencyKit {
    /** What the kit says about this phone and install. [date] is already formatted for the person's language. */
    class Facts(val date: String, val appVersion: String, val device: String)

    class Box(val number: Int, val word: String) {
        override fun toString(): String = "Box(number=$number)" // never the word, even in a log line
    }

    sealed interface Block {
        class Title(val text: String) : Block
        class Paragraph(val text: String) : Block
        class Fact(val label: String, val value: String) : Block
        /** A label with a line to write on. */
        class BlankLine(val label: String) : Block
        class Heading(val text: String) : Block
        class PhraseBoxes(val boxes: List<Box>) : Block
        class Steps(val items: List<String>) : Block
        class Warning(val text: String) : Block
    }

    /** [words]: the recovery phrase to print, or null for blank boxes. The boxes always number [Bip39.WORD_COUNT]. */
    fun build(t: Txt, facts: Facts, words: List<String>?): List<Block> {
        val count = Bip39.WORD_COUNT
        val boxes = List(count) { Box(it + 1, words?.getOrNull(it).orEmpty()) }
        return listOf(
            Block.Title(t.s(R.string.kit_title)),
            Block.Paragraph(t.s(R.string.kit_intro)),
            Block.Fact(t.s(R.string.kit_device), facts.device),
            Block.Fact(t.s(R.string.kit_date), facts.date),
            Block.Fact(t.s(R.string.kit_version), facts.appVersion),
            Block.BlankLine(t.s(R.string.kit_app_password)),
            Block.Heading(t.s(R.string.kit_phrase_heading, count)),
            Block.PhraseBoxes(boxes),
            Block.Heading(t.s(R.string.kit_steps_heading)),
            Block.Steps(
                listOf(
                    t.s(R.string.kit_step1, t.s(R.string.app_password_forgot)),
                    t.s(R.string.kit_step2, count),
                    t.s(R.string.kit_step3),
                    t.s(R.string.kit_step4),
                ),
            ),
            Block.Warning(t.s(R.string.kit_warning)),
        )
    }
}
