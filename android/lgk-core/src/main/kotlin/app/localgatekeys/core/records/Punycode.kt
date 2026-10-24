package app.localgatekeys.core.records

/**
 * RFC 3492 Punycode for PSL rules. PSL rules are already lower-case NFC, the form UTS-46 mapping leaves unchanged,
 * so `xn--` + Punycode equals the desktop's `idna.encode(..., uts46=True)` for them (checked against the desktop's
 * parsed rule set in `UrlMatchTest`). Port of Swift `Punycode`.
 */
internal object Punycode {
    private const val BASE = 36L
    private const val T_MIN = 1L
    private const val T_MAX = 26L
    private const val SKEW = 38L
    private const val DAMP = 700L
    private const val U32_MAX = 0xFFFF_FFFFL

    /** One IDNA label (code points) to its `xn--` A-label; null when it cannot be encoded or is 64+ long. */
    fun idnaLabel(label: IntArray): String? {
        val lowered = ArrayList<Int>()
        for (cp in label) {
            String(Character.toChars(cp)).lowercase().codePoints().forEach { lowered.add(it) }
        }
        val enc = encode(lowered.toIntArray()) ?: return null
        val out = "xn--$enc"
        return if (out.length < 64) out else null
    }

    private fun digit(d: Long): Char = (if (d < 26) d + 97 else d + 22).toInt().toChar()

    private fun adapt(d: Long, numPoints: Long, first: Boolean): Long {
        var delta = if (first) d / DAMP else d / 2
        delta += delta / numPoints
        var k = 0L
        while (delta > ((BASE - T_MIN) * T_MAX) / 2) {
            delta /= BASE - T_MIN
            k += BASE
        }
        return k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
    }

    fun encode(input: IntArray): String? {
        var n = 128L
        var delta = 0L
        var bias = 72L
        val out = StringBuilder()
        for (c in input) if (c < 128) out.append(c.toChar())
        val b = out.length.toLong()
        var h = b
        if (b > 0) out.append('-')
        while (h < input.size) {
            val m = input.filter { it >= n }.minOrNull()?.toLong() ?: return null
            val mul = (m - n) * (h + 1)
            if (mul > U32_MAX) return null
            val d2 = delta + mul
            if (d2 > U32_MAX) return null
            delta = d2
            n = m
            for (cp in input) {
                val c = cp.toLong()
                if (c < n) delta += 1
                if (c == n) {
                    var q = delta
                    var k = BASE
                    while (true) {
                        val t = if (k <= bias) T_MIN else if (k >= bias + T_MAX) T_MAX else k - bias
                        if (q < t) break
                        out.append(digit(t + (q - t) % (BASE - t)))
                        q = (q - t) / (BASE - t)
                        k += BASE
                    }
                    out.append(digit(q))
                    bias = adapt(delta, h + 1, h == b)
                    delta = 0
                    h += 1
                }
            }
            delta += 1
            n += 1
        }
        return out.toString()
    }
}
