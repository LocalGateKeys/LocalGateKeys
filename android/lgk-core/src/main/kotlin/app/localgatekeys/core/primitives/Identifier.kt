package app.localgatekeys.core.primitives

object Identifier {
    private val reserved: Set<String> =
        setOf("CON", "PRN", "AUX", "NUL") + (0..9).map { "COM$it" } + (0..9).map { "LPT$it" }

    /** Format-1 identifier: ASCII `[A-Za-z0-9._:-]`, 1..128 characters. */
    fun isValid(s: String): Boolean {
        if (s.isEmpty() || s.length > 128) return false
        return s.all { c ->
            c in '0'..'9' || c in 'A'..'Z' || c in 'a'..'z' || c == '.' || c == '_' || c == ':' || c == '-'
        }
    }

    /** A valid id that is also a safe Windows/macOS file name stem. */
    fun isSafeDeviceFile(s: String): Boolean {
        if (!isValid(s)) return false
        if (s.contains(':') || s.startsWith('.') || s.endsWith('.') || s.endsWith(' ')) return false
        val stem = s.substringBefore('.')
        return stem.uppercase() !in reserved
    }
}
