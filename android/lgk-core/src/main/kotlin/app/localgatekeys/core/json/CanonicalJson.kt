package app.localgatekeys.core.json

import java.io.ByteArrayOutputStream

/**
 * Canonical JSON as produced by Python's `json.dumps(sort_keys=True, separators=(",", ":"))`,
 * plus a strict byte-level parser. Port of the Swift `CanonicalJSON`.
 */
object CanonicalJson {
    private const val MAX_DEPTH = 512
    private val HEX = "0123456789abcdef".toByteArray(Charsets.US_ASCII)

    fun encode(v: JsonValue, dialect: Dialect): ByteArray {
        val out = ByteArrayOutputStream()
        write(v, dialect, out)
        return out.toByteArray()
    }

    fun parse(data: ByteArray): JsonValue {
        val p = Parser(data)
        p.skipWs()
        val v = p.value(0)
        p.skipWs()
        if (p.i != data.size) throw JsonException(JsonException.Kind.SYNTAX)
        return v
    }

    // ---- encoding -------------------------------------------------------------------------

    private fun ascii(s: String, out: ByteArrayOutputStream) = out.write(s.toByteArray(Charsets.US_ASCII))

    private fun write(v: JsonValue, d: Dialect, out: ByteArrayOutputStream) {
        when (v) {
            JsonValue.Null -> ascii("null", out)
            is JsonValue.Bool -> ascii(if (v.v) "true" else "false", out)
            is JsonValue.Int -> ascii(v.v.toString(), out)
            is JsonValue.Float -> {
                if (!v.v.isFinite()) throw JsonException(JsonException.Kind.NON_FINITE)
                ascii(PythonFloat.repr(v.v), out)
            }
            is JsonValue.Str -> writeString(v.v, d, out)
            is JsonValue.Arr -> {
                out.write('['.code)
                v.items.forEachIndexed { i, e ->
                    if (i > 0) out.write(','.code)
                    write(e, d, out)
                }
                out.write(']'.code)
            }
            is JsonValue.Obj -> {
                // Sort by Unicode code point (Python str order), not UTF-16 units.
                val sorted = v.fields.entries.sortedWith { a, b -> compareCodePoints(a.key, b.key) }
                out.write('{'.code)
                sorted.forEachIndexed { i, e ->
                    if (i > 0) out.write(','.code)
                    writeString(e.key, d, out)
                    out.write(':'.code)
                    write(e.value, d, out)
                }
                out.write('}'.code)
            }
        }
    }

    private fun compareCodePoints(a: String, b: String): Int {
        var i = 0
        var j = 0
        while (i < a.length && j < b.length) {
            val ca = a.codePointAt(i)
            val cb = b.codePointAt(j)
            if (ca != cb) return ca.compareTo(cb)
            i += Character.charCount(ca)
            j += Character.charCount(cb)
        }
        return (a.length - i).compareTo(b.length - j)
    }

    private fun u4(x: Int, out: ByteArrayOutputStream) {
        out.write('\\'.code)
        out.write('u'.code)
        for (shift in intArrayOf(12, 8, 4, 0)) out.write(HEX[(x shr shift) and 0xF].toInt())
    }

    private fun esc(ch: Char, out: ByteArrayOutputStream) {
        out.write('\\'.code)
        out.write(ch.code)
    }

    private fun writeString(s: String, d: Dialect, out: ByteArrayOutputStream) {
        out.write('"'.code)
        var i = 0
        while (i < s.length) {
            val c = s.codePointAt(i)
            i += Character.charCount(c)
            if (c in 0xD800..0xDFFF) throw JsonException(JsonException.Kind.LONE_SURROGATE)
            when {
                c == 0x22 -> esc('"', out)
                c == 0x5C -> esc('\\', out)
                c == 0x08 -> esc('b', out)
                c == 0x0C -> esc('f', out)
                c == 0x0A -> esc('n', out)
                c == 0x0D -> esc('r', out)
                c == 0x09 -> esc('t', out)
                c < 0x20 -> u4(c, out)
                c in 0x20..0x7E -> out.write(c)
                d == Dialect.UTF8 -> out.write(String(Character.toChars(c)).toByteArray(Charsets.UTF_8))
                c >= 0x10000 -> {
                    val x = c - 0x10000
                    u4(0xD800 + (x shr 10), out)
                    u4(0xDC00 + (x and 0x3FF), out)
                }
                else -> u4(c, out)
            }
        }
        out.write('"'.code)
    }

    // ---- parsing --------------------------------------------------------------------------

    private class Parser(val b: ByteArray) {
        var i = 0

        private fun err(kind: JsonException.Kind = JsonException.Kind.SYNTAX): Nothing = throw JsonException(kind)

        private fun at(k: Int): Int = b[k].toInt() and 0xFF

        fun skipWs() {
            while (i < b.size) {
                val c = at(i)
                if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D) i++ else break
            }
        }

        private fun peek(): Int = if (i < b.size) at(i) else -1

        private fun literal(s: String): Boolean {
            val u = s.toByteArray(Charsets.US_ASCII)
            if (i + u.size > b.size) return false
            for (k in u.indices) if (b[i + k] != u[k]) return false
            i += u.size
            return true
        }

        fun value(depth: Int): JsonValue {
            if (depth >= MAX_DEPTH) err()
            val c = peek()
            if (c < 0) err()
            return when (c) {
                0x7B -> obj(depth)
                0x5B -> arr(depth)
                0x22 -> JsonValue.Str(string())
                0x74 -> if (literal("true")) JsonValue.Bool(true) else err()
                0x66 -> if (literal("false")) JsonValue.Bool(false) else err()
                0x6E -> if (literal("null")) JsonValue.Null else err()
                0x4E -> if (literal("NaN")) err(JsonException.Kind.NON_FINITE) else err()
                0x49 -> if (literal("Infinity")) err(JsonException.Kind.NON_FINITE) else err()
                in 0x30..0x39, 0x2D -> {
                    if (c == 0x2D && i + 1 < b.size && at(i + 1) == 0x49) {
                        i += 1
                        if (literal("Infinity")) err(JsonException.Kind.NON_FINITE)
                        err()
                    }
                    number()
                }
                else -> err()
            }
        }

        private fun isDigit(c: Int) = c in 0x30..0x39

        private fun number(): JsonValue {
            val start = i
            var isFloat = false
            if (peek() == 0x2D) i++
            val f = peek()
            if (f < 0) err()
            if (f == 0x30) {
                i++
            } else if (f in 0x31..0x39) {
                while (isDigit(peek())) i++
            } else {
                err()
            }
            if (peek() == 0x2E) {
                isFloat = true
                i++
                if (!isDigit(peek())) err()
                while (isDigit(peek())) i++
            }
            val e = peek()
            if (e == 0x65 || e == 0x45) {
                isFloat = true
                i++
                val s = peek()
                if (s == 0x2B || s == 0x2D) i++
                if (!isDigit(peek())) err()
                while (isDigit(peek())) i++
            }
            val text = String(b, start, i - start, Charsets.US_ASCII)
            if (isFloat) {
                val d = text.toDoubleOrNull() ?: err()
                if (!d.isFinite()) err(JsonException.Kind.NON_FINITE)
                return JsonValue.Float(d)
            }
            val n = text.toLongOrNull() ?: err(JsonException.Kind.INT_OUT_OF_RANGE)
            if (n == Long.MIN_VALUE) err(JsonException.Kind.INT_OUT_OF_RANGE)
            return JsonValue.Int(n)
        }

        private fun hex4(): Int {
            if (i + 4 > b.size) err()
            var v = 0
            for (k in 0 until 4) {
                val c = at(i + k)
                val d = when (c) {
                    in 0x30..0x39 -> c - 0x30
                    in 0x61..0x66 -> c - 0x61 + 10
                    in 0x41..0x46 -> c - 0x41 + 10
                    else -> err()
                }
                v = (v shl 4) or d
            }
            i += 4
            return v
        }

        fun string(): String {
            i++ // opening quote
            val sb = StringBuilder()
            while (true) {
                val c = peek()
                if (c < 0) err()
                if (c == 0x22) {
                    i++
                    return sb.toString()
                }
                if (c < 0x20) err()
                if (c == 0x5C) {
                    i++
                    val e = peek()
                    if (e < 0) err()
                    i++
                    when (e) {
                        0x22 -> sb.append('"')
                        0x5C -> sb.append('\\')
                        0x2F -> sb.append('/')
                        0x62 -> sb.append('\b')
                        0x66 -> sb.append('\u000C')
                        0x6E -> sb.append('\n')
                        0x72 -> sb.append('\r')
                        0x74 -> sb.append('\t')
                        0x75 -> {
                            val u = hex4()
                            if (u in 0xD800..0xDBFF) {
                                if (!(i + 1 < b.size && at(i) == 0x5C && at(i + 1) == 0x75)) err(JsonException.Kind.LONE_SURROGATE)
                                i += 2
                                val lo = hex4()
                                if (lo !in 0xDC00..0xDFFF) err(JsonException.Kind.LONE_SURROGATE)
                                sb.appendCodePoint(0x10000 + ((u - 0xD800) shl 10) + (lo - 0xDC00))
                            } else if (u in 0xDC00..0xDFFF) {
                                err(JsonException.Kind.LONE_SURROGATE)
                            } else {
                                sb.append(u.toChar())
                            }
                        }
                        else -> err()
                    }
                } else if (c < 0x80) {
                    sb.append(c.toChar())
                    i++
                } else {
                    sb.appendCodePoint(utf8Scalar())
                }
            }
        }

        private fun utf8Scalar(): Int {
            val c = at(i)
            val n: Int
            val minV: Int
            var v: Int
            when (c) {
                in 0xC2..0xDF -> { n = 1; v = c and 0x1F; minV = 0x80 }
                in 0xE0..0xEF -> { n = 2; v = c and 0x0F; minV = 0x800 }
                in 0xF0..0xF4 -> { n = 3; v = c and 0x07; minV = 0x10000 }
                else -> err()
            }
            for (k in 1..n) {
                if (!(i + k < b.size && (at(i + k) and 0xC0) == 0x80)) err()
                v = (v shl 6) or (at(i + k) and 0x3F)
            }
            if (v < minV || v > 0x10FFFF || v in 0xD800..0xDFFF) err()
            i += n + 1
            return v
        }

        private fun arr(depth: Int): JsonValue {
            i++
            val out = ArrayList<JsonValue>()
            skipWs()
            if (peek() == 0x5D) {
                i++
                return JsonValue.Arr(out)
            }
            while (true) {
                skipWs()
                out.add(value(depth + 1))
                skipWs()
                val c = peek()
                if (c < 0) err()
                i++
                if (c == 0x2C) continue
                if (c == 0x5D) return JsonValue.Arr(out)
                err()
            }
        }

        private fun obj(depth: Int): JsonValue {
            i++
            val out = HashMap<String, JsonValue>()
            skipWs()
            if (peek() == 0x7D) {
                i++
                return JsonValue.Obj(out)
            }
            while (true) {
                skipWs()
                if (peek() != 0x22) err()
                val k = string()
                skipWs()
                if (peek() != 0x3A) err()
                i++
                skipWs()
                val v = value(depth + 1)
                if (out.containsKey(k)) err(JsonException.Kind.DUPLICATE_KEY)
                out[k] = v
                skipWs()
                val c = peek()
                if (c < 0) err()
                i++
                if (c == 0x2C) continue
                if (c == 0x7D) return JsonValue.Obj(out)
                err()
            }
        }
    }
}
