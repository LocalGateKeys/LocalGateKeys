package app.localgatekeys.core.records

import app.localgatekeys.core.primitives.Scalars

/** Conflict-copy label/title suffix (vectors README "Suffix and truncation"). Lengths are code points. */
object ConflictSuffix {
    const val SUFFIX = " (sync conflict)"

    /** Entry `label` and typed-item `title` limit. */
    const val LIMIT = 512

    fun apply(text: String, limit: Int = LIMIT): String {
        // The suffix is ASCII, so a UTF-16 suffix test equals the code point test.
        if (text.endsWith(SUFFIX)) return text
        val keep = maxOf(0, limit - Scalars.count(SUFFIX))
        return Scalars.truncate(text, keep) + SUFFIX
    }
}
