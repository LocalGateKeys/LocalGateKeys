package app.localgatekeys.core.primitives

/**
 * Python `str.casefold()`, applied per code point with no normalisation (Python never composes or
 * decomposes when folding). Use it wherever the desktop compares casefolded text.
 */
object Casefold {
    const val unicodeVersion = CasefoldTable.UNICODE_VERSION

    private val table: HashMap<Int, IntArray> by lazy {
        val flat = CasefoldTable.flat
        val t = HashMap<Int, IntArray>(flat.size / 3 * 2)
        var i = 0
        while (i < flat.size) {
            val n = flat[i + 1]
            t[flat[i]] = flat.copyOfRange(i + 2, i + 2 + n)
            i += 2 + n
        }
        t
    }

    fun fold(s: String): String {
        val out = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            val seq = table[cp]
            if (seq != null) for (v in seq) out.appendCodePoint(v) else out.appendCodePoint(cp)
        }
        return out.toString()
    }
}
