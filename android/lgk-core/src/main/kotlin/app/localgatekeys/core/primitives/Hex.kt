package app.localgatekeys.core.primitives

/** Lowercase hex, the one hex codec of the core. */
object Hex {
    private const val DIGITS = "0123456789abcdef"

    fun lower(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xFF
            sb.append(DIGITS[v shr 4]).append(DIGITS[v and 15])
        }
        return sb.toString()
    }

    /** Accepts upper or lower case; throws [IllegalArgumentException] on odd length or a non-hex character. */
    fun decode(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) {
            val hi = Character.digit(s[it * 2], 16)
            val lo = Character.digit(s[it * 2 + 1], 16)
            require(hi >= 0 && lo >= 0 && s[it * 2].code < 128 && s[it * 2 + 1].code < 128) { "bad hex" }
            ((hi shl 4) or lo).toByte()
        }
    }
}
