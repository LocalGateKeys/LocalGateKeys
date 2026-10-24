package app.localgatekeys.android.settings

import java.text.BreakIterator

/**
 * Up to two upper-cased letters for the avatar: first letters of the first two words, or the first two of one word.
 * Like Swift, a "letter" is a whole character (grapheme cluster, so a letter keeps its combining marks and a
 * supplementary-plane letter is one) and words split on Unicode White_Space only (not U+001C..U+001F).
 */
object AvatarInitials {
    private fun isSpace(cp: Int): Boolean = cp in 0x09..0x0D || cp == 0x85 || Character.isSpaceChar(cp)

    private fun words(text: String): List<List<String>> {
        val out = ArrayList<List<String>>()
        var cur = ArrayList<String>()
        fun flush() { if (cur.isNotEmpty()) out.add(cur); cur = ArrayList() }
        val it = BreakIterator.getCharacterInstance()
        it.setText(text)
        var start = it.first()
        var end = it.next()
        while (end != BreakIterator.DONE) {
            val cluster = text.substring(start, end)
            val cp = cluster.codePointAt(0)
            if (isSpace(cp)) flush() else if (Character.isLetter(cp)) cur.add(cluster)
            start = end
            end = it.next()
        }
        flush()
        return out
    }

    fun from(text: String): String? {
        val words = words(text)
        val first = words.firstOrNull() ?: return null
        val letters = if (words.size >= 2) words[0][0] + words[1][0] else first.take(2).joinToString("")
        return letters.uppercase()
    }
}
