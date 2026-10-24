package app.localgatekeys.core.records

/**
 * Python `str.isspace` / `str.strip()` / `str.split()` (no separator), by code point. Kotlin's `trim()` and
 * `Char.isWhitespace` use a different set (they miss U+0085 and U+00A0, for one), so they are never used where
 * the desktop strips. Port of Swift `Origin.isPySpace`, `Normalise.pyStrip` and `Normalise.pySplit`.
 */
object PyStrip {
    /** Python `str.isspace` for one code point: Unicode White_Space plus U+001C..U+001F. */
    fun isSpace(c: Int): Boolean = when (c) {
        in 0x09..0x0D, 0x20, 0x85, 0xA0, 0x1680, in 0x2000..0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000 -> true
        in 0x1C..0x1F -> true
        else -> false
    }

    /** Python `str.strip()`. */
    fun strip(s: String): String {
        var start = 0
        var end = s.length
        while (start < end) {
            val c = s.codePointAt(start)
            if (!isSpace(c)) break
            start += Character.charCount(c)
        }
        while (end > start) {
            val c = s.codePointBefore(end)
            if (!isSpace(c)) break
            end -= Character.charCount(c)
        }
        return s.substring(start, end)
    }

    /** Python `str.split()` with no separator: runs of whitespace, no empty parts. */
    fun split(s: String): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s.codePointAt(i)
            if (isSpace(c)) {
                if (cur.isNotEmpty()) {
                    out.add(cur.toString())
                    cur.setLength(0)
                }
            } else {
                cur.appendCodePoint(c)
            }
            i += Character.charCount(c)
        }
        if (cur.isNotEmpty()) out.add(cur.toString())
        return out
    }
}
