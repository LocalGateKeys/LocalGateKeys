package app.localgatekeys.core.primitives

/**
 * Strict base64 matching the desktop's `b64decode(validate=True)` plus the canonical re-encode check.
 * `java.util.Base64` is deliberately not used: it accepts non-zero spare bits and some unpadded input.
 */
class Base64Exception : Exception("malformed")

private const val STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
private const val URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

private fun encode(bytes: ByteArray, alphabet: String, pad: Boolean): String {
    val out = StringBuilder((bytes.size + 2) / 3 * 4)
    var i = 0
    while (i < bytes.size) {
        val b0 = bytes[i].toInt() and 0xFF
        val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
        val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
        val n = (b0 shl 16) or (b1 shl 8) or b2
        out.append(alphabet[(n shr 18) and 63])
        out.append(alphabet[(n shr 12) and 63])
        if (i + 1 < bytes.size) out.append(alphabet[(n shr 6) and 63]) else if (pad) out.append('=')
        if (i + 2 < bytes.size) out.append(alphabet[n and 63]) else if (pad) out.append('=')
        i += 3
    }
    return out.toString()
}

private fun table(alphabet: String): IntArray {
    val t = IntArray(256) { -1 }
    for ((i, c) in alphabet.withIndex()) t[c.code] = i
    return t
}

private val stdTable = table(STD_ALPHABET)
private val urlTable = table(URL_ALPHABET)

/** `chars` is unpadded text; decodes and rejects non-zero spare bits. */
private fun decodeCore(chars: String, table: IntArray): ByteArray {
    if (chars.length % 4 == 1) throw Base64Exception()
    val out = java.io.ByteArrayOutputStream(chars.length / 4 * 3 + 3)
    var acc = 0
    var bits = 0
    for (c in chars) {
        val v = if (c.code < 256) table[c.code] else -1
        if (v < 0) throw Base64Exception()
        acc = ((acc shl 6) or v) and 0xFFFFFF
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.write((acc shr bits) and 0xFF)
        }
    }
    if (bits > 0 && (acc and ((1 shl bits) - 1)) != 0) throw Base64Exception()
    return out.toByteArray()
}

object Base64Std {
    fun encode(b: ByteArray): String = encode(b, STD_ALPHABET, true)

    /** Standard alphabet, mandatory padding, no whitespace, zero spare bits. */
    fun decodeStrict(s: String): ByteArray {
        if (s.length % 4 != 0) throw Base64Exception()
        var end = s.length
        var pad = 0
        while (pad < 2 && end > 0 && s[end - 1] == '=') {
            end--
            pad++
        }
        val body = s.substring(0, end)
        if (body.contains('=')) throw Base64Exception()
        val out = decodeCore(body, stdTable)
        if (encode(out) != s) throw Base64Exception()
        return out
    }
}

object Base64Url {
    fun encodeNoPad(b: ByteArray): String = encode(b, URL_ALPHABET, false)

    /** URL-safe alphabet, no padding allowed, zero spare bits. */
    fun decodeNoPadStrict(s: String): ByteArray {
        val out = decodeCore(s, urlTable)
        if (encodeNoPad(out) != s) throw Base64Exception()
        return out
    }

    /**
     * Desktop `passkeys.b64u_decode`: URL-safe alphabet only, no padding, at most `maxBytes` decoded bytes.
     * Lenient about spare bits like Python's `urlsafe_b64decode`. Returns null where the desktop raises.
     */
    fun decodeLenient(s: String, maxBytes: Int): ByteArray? {
        val utf8Len = s.toByteArray(Charsets.UTF_8).size
        if (utf8Len > (maxBytes * 4 + 2) / 3 || utf8Len % 4 == 1) return null
        val out = java.io.ByteArrayOutputStream(s.length * 3 / 4)
        var acc = 0
        var bits = 0
        for (c in s) {
            val v = if (c.code < 256) urlTable[c.code] else -1
            if (v < 0) return null
            acc = ((acc shl 6) or v) and 0xFFFFFF
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((acc shr bits) and 0xFF)
            }
        }
        return if (out.size() > maxBytes) null else out.toByteArray()
    }
}
