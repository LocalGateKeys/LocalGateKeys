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

    /**
     * Python's `punycode` codec decode of the text after `xn--` (strict): the basic part is everything before the last
     * `-`; digits are case-insensitive. Throws [IllegalArgumentException] on malformed input or a code point past
     * U+10FFFF. The result can hold surrogates, which the caller's checks then refuse.
     */
    fun decode(text: String): IntArray {
        val dash = text.lastIndexOf('-')
        val output = ArrayList<Int>()
        if (dash > 0) {
            for (j in 0 until dash) {
                val c = text[j].code
                require(c < 0x80) { "punycode: not basic" }
                output.add(c)
            }
        }
        var n = 128L
        var bias = 72L
        var i = 0L
        var index = if (dash >= 0) dash + 1 else 0
        while (index < text.length) {
            val oldi = i
            var w = 1L
            var k = BASE
            while (true) {
                require(index < text.length) { "punycode: truncated" }
                val c = text[index++]
                val d = when (c) {
                    in 'a'..'z' -> (c - 'a').toLong()
                    in 'A'..'Z' -> (c - 'A').toLong()
                    in '0'..'9' -> (c - '0').toLong() + 26
                    else -> throw IllegalArgumentException("punycode: bad digit")
                }
                i += d * w
                require(i <= 0x7FFF_FFFFL) { "punycode: overflow" }
                val t = if (k <= bias) T_MIN else if (k >= bias + T_MAX) T_MAX else k - bias
                if (d < t) break
                w *= BASE - t
                require(w <= 0x7FFF_FFFFL) { "punycode: overflow" }
                k += BASE
            }
            val points = output.size + 1L
            bias = adapt(i - oldi, points, oldi == 0L)
            n += i / points
            i %= points
            require(n <= 0x10FFFF) { "punycode: out of range" }
            output.add(i.toInt(), n.toInt())
            i++
        }
        return output.toIntArray()
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
                        out.append(digit(t + ((q - t) % (BASE - t))))
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
