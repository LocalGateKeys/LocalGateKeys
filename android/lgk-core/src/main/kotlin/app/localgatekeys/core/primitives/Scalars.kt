package app.localgatekeys.core.primitives

/** Code-point (Unicode scalar) helpers: lengths and ordering follow Python `str`, not UTF-16 units. */
object Scalars {
    fun count(s: String): Int = s.codePointCount(0, s.length)

    /** Orders by code point, like Python `str` comparison (not `String.compareTo`). */
    fun compare(a: String, b: String): Int {
        var i = 0
        var j = 0
        while (i < a.length && j < b.length) {
            val x = a.codePointAt(i)
            val y = b.codePointAt(j)
            if (x != y) return if (x < y) -1 else 1
            i += Character.charCount(x)
            j += Character.charCount(y)
        }
        val aDone = i >= a.length
        val bDone = j >= b.length
        return if (aDone && bDone) 0 else if (aDone) -1 else 1
    }

    /** First `max` code points of [s]. */
    fun truncate(s: String, max: Int): String {
        if (max <= 0) return ""
        if (count(s) <= max) return s
        return s.substring(0, s.offsetByCodePoints(0, max))
    }

    /** Prefix test by code points, so a split surrogate pair never matches. */
    fun hasPrefix(s: String, p: String): Boolean {
        if (!s.startsWith(p)) return false
        // A prefix ending in a lone high surrogate would cut a pair in [s].
        return !(p.isNotEmpty() && Character.isHighSurrogate(p.last()) && p.length < s.length &&
            Character.isLowSurrogate(s[p.length]))
    }
}
