package app.localgatekeys.core.importing

import app.localgatekeys.core.json.PythonFloat
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.records.PyStrip

/** Python string semantics the Windows importers rely on, by code point (port of Swift `Py` in `ImportSource.swift`). */
internal object Py {
    fun strip(s: String): String = PyStrip.strip(s)
    fun casefold(s: String): String = Casefold.fold(s)
    fun split(s: String): List<String> = PyStrip.split(s)
    fun len(s: String): Int = s.codePointCount(0, s.length)
    fun cps(s: String): IntArray = s.codePoints().toArray()
    fun str(cps: IntArray, from: Int = 0, to: Int = cps.size): String = String(cps, from, to - from)

    /** The first [n] code points. */
    fun prefix(s: String, n: Int): String {
        if (n <= 0) return ""
        val c = cps(s)
        return if (c.size <= n) s else str(c, 0, n)
    }

    /** The last [n] code points. */
    fun suffix(s: String, n: Int): String {
        val c = cps(s)
        return if (c.size <= n) s else str(c, c.size - n, c.size)
    }

    fun lstrip(s: String, chars: Set<Int>): String {
        val c = cps(s)
        var i = 0
        while (i < c.size && c[i] in chars) i++
        return str(c, i)
    }

    fun rstrip(s: String, chars: Set<Int>): String {
        val c = cps(s)
        var e = c.size
        while (e > 0 && c[e - 1] in chars) e--
        return str(c, 0, e)
    }

    /** Python `str.strip(chars)`. */
    fun stripChars(s: String, chars: String): String {
        val set = cps(chars).toSet()
        return rstrip(lstrip(s, set), set)
    }

    /** `str.splitlines()`. */
    fun splitlines(s: String): List<String> {
        val out = ArrayList<String>()
        val u = cps(s)
        val cur = StringBuilder()
        var i = 0
        var pending = false
        while (i < u.size) {
            when (val c = u[i]) {
                0x0A, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029 -> { out.add(cur.toString()); cur.setLength(0); pending = false }
                0x0D -> {
                    out.add(cur.toString()); cur.setLength(0); pending = false
                    if (i + 1 < u.size && u[i + 1] == 0x0A) i++
                }
                else -> { cur.appendCodePoint(c); pending = true }
            }
            i++
        }
        if (pending) out.add(cur.toString())
        return out
    }

    /** `str.partition(sep)` on the first occurrence; null when absent. */
    fun partition(s: String, sep: Char): Pair<String, String>? {
        val i = s.indexOf(sep)
        if (i < 0) return null
        return s.substring(0, i) to s.substring(i + 1)
    }

    fun isAsciiDigits(s: String): Boolean = s.isNotEmpty() && s.all { it in '0'..'9' }

    /** `f"{n:,}"`. */
    fun thousands(n: Int): String {
        val digits = kotlin.math.abs(n.toLong()).toString()
        val out = StringBuilder()
        for ((i, c) in digits.withIndex()) {
            if (i > 0 && (digits.length - i) % 3 == 0) out.append(',')
            out.append(c)
        }
        return if (n < 0) "-$out" else out.toString()
    }

    /** `urllib.parse.quote(s, safe=safe)`. */
    fun quote(s: String, safe: String): String {
        val keep = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~" + safe).toByteArray(Charsets.UTF_8).toSet()
        val out = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            if (b in keep) out.append(b.toInt().toChar()) else out.append("%%%02X".format(b.toInt() and 0xFF))
        }
        return out.toString()
    }

    /** Python `int(text)` for plain decimal text (whitespace, a sign and `_` separators allowed). */
    fun int(text: String): Long? {
        var t = strip(text)
        var negative = false
        if (t.startsWith("+") || t.startsWith("-")) { negative = t.startsWith("-"); t = t.substring(1) }
        if (t.isEmpty() || t.startsWith("_") || t.endsWith("_") || t.contains("__")) return null
        t = t.replace("_", "")
        if (!isAsciiDigits(t)) return null
        val v = t.toLongOrNull() ?: return null
        return if (negative) -v else v
    }

    /** `str.capitalize()`. */
    fun capitalize(s: String): String {
        if (s.isEmpty()) return s
        val c = cps(s)
        return str(c, 0, 1).uppercase() + str(c, 1).lowercase()
    }
}

/** Loosely typed JSON keeping key order and repeats (Python `json.loads`, including NaN and Infinity). */
internal sealed class PyJson {
    object Null : PyJson()
    data class Bool(val v: Boolean) : PyJson()
    data class Int(val v: Long) : PyJson()
    data class Float(val v: Double) : PyJson()
    data class Str(val v: String) : PyJson()
    data class Arr(val items: List<PyJson>) : PyJson()
    data class Obj(val pairs: List<Pair<String, PyJson>>) : PyJson()

    /** The last value for [key] (Python dicts keep the last repeat). */
    operator fun get(key: String): PyJson? = (this as? Obj)?.pairs?.lastOrNull { it.first == key }?.second

    fun has(key: String): Boolean = get(key) != null
    val firstKey: String? get() = (this as? Obj)?.pairs?.firstOrNull()?.first
    val isObject: Boolean get() = this is Obj
    val isList: Boolean get() = this is Arr
    val list: List<PyJson> get() = (this as? Arr)?.items ?: emptyList()
    val isTrue: Boolean get() = this == Bool(true)

    val truthy: Boolean
        get() = when (this) {
            Null -> false
            is Bool -> v
            is Int -> v != 0L
            is Float -> v != 0.0
            is Str -> v.isNotEmpty()
            is Arr -> items.isNotEmpty()
            is Obj -> pairs.isNotEmpty()
        }

    /** `value == n` in Python (`True == 1`, `1.0 == 1`). */
    fun equalsNumber(n: Long): Boolean = when (this) {
        is Bool -> (if (v) 1L else 0L) == n
        is Int -> v == n
        is Float -> v == n.toDouble()
        else -> false
    }

    /** `str(value)`. */
    val str: String get() = if (this is Str) v else repr

    val repr: String
        get() = when (this) {
            Null -> "None"
            is Bool -> if (v) "True" else "False"
            is Int -> v.toString()
            is Float -> PythonFloat.repr(v)
            is Str -> {
                val quote = if (v.contains('\'') && !v.contains('"')) "\"" else "'"
                val out = StringBuilder(quote)
                v.codePoints().forEach { c ->
                    when {
                        c == '\\'.code -> out.append("\\\\")
                        c == '\n'.code -> out.append("\\n")
                        c == '\r'.code -> out.append("\\r")
                        c == '\t'.code -> out.append("\\t")
                        String(Character.toChars(c)) == quote -> out.append("\\").append(quote)
                        c < 0x20 || c == 0x7F -> out.append("\\x%02x".format(c))
                        else -> out.appendCodePoint(c)
                    }
                }
                out.append(quote).toString()
            }
            is Arr -> items.joinToString(", ", "[", "]") { it.repr }
            is Obj -> pairs.joinToString(", ", "{", "}") { Str(it.first).repr + ": " + it.second.repr }
        }

    /** Never prints values: imported documents hold secrets. */
    override fun toString(): String = "PyJson(${this::class.simpleName})"

    companion object {
        /** `str(x or "")`. */
        fun text(v: PyJson?): String = if (v != null && v.truthy) v.str else ""

        /** `_text`: "" for None, dicts and lists, else `str`. */
        fun scalarText(v: PyJson?): String = when (v) {
            null, Null, is Arr, is Obj -> ""
            else -> v.str
        }

        class Failure : Exception("invalid JSON")

        fun parse(text: String): PyJson {
            val p = Parser(Py.cps(text))
            p.ws()
            val v = p.value(0)
            p.ws()
            if (p.i != p.u.size) throw Failure()
            return v
        }
    }

    private class Parser(val u: IntArray) {
        var i = 0
        fun ws() { while (i < u.size && (u[i] == 0x20 || u[i] == 0x09 || u[i] == 0x0A || u[i] == 0x0D)) i++ }
        fun peek(): kotlin.Int = if (i < u.size) u[i] else -1
        fun lit(s: String): Boolean {
            if (i + s.length > u.size) return false
            for (k in s.indices) if (u[i + k] != s[k].code) return false
            i += s.length
            return true
        }

        fun value(depth: kotlin.Int): PyJson {
            if (depth >= 900) throw Failure()
            when (peek()) {
                -1 -> throw Failure()
                '{'.code -> {
                    i++; ws()
                    val pairs = ArrayList<Pair<String, PyJson>>()
                    if (peek() == '}'.code) { i++; return Obj(pairs) }
                    while (true) {
                        ws()
                        if (peek() != '"'.code) throw Failure()
                        val k = string()
                        ws()
                        if (peek() != ':'.code) throw Failure()
                        i++; ws()
                        pairs.add(k to value(depth + 1))
                        ws()
                        val d = peek()
                        if (d == -1) throw Failure()
                        i++
                        if (d == ','.code) continue
                        if (d == '}'.code) return Obj(pairs)
                        throw Failure()
                    }
                }
                '['.code -> {
                    i++; ws()
                    val items = ArrayList<PyJson>()
                    if (peek() == ']'.code) { i++; return Arr(items) }
                    while (true) {
                        ws()
                        items.add(value(depth + 1))
                        ws()
                        val d = peek()
                        if (d == -1) throw Failure()
                        i++
                        if (d == ','.code) continue
                        if (d == ']'.code) return Arr(items)
                        throw Failure()
                    }
                }
                '"'.code -> return Str(string())
                't'.code -> if (lit("true")) return Bool(true) else throw Failure()
                'f'.code -> if (lit("false")) return Bool(false) else throw Failure()
                'n'.code -> if (lit("null")) return Null else throw Failure()
                'N'.code -> if (lit("NaN")) return Float(Double.NaN) else throw Failure()
                'I'.code -> if (lit("Infinity")) return Float(Double.POSITIVE_INFINITY) else throw Failure()
                else -> {
                    if (peek() == '-'.code && lit("-Infinity")) return Float(Double.NEGATIVE_INFINITY)
                    return number()
                }
            }
        }

        private fun digit(c: kotlin.Int) = c in '0'.code..'9'.code

        fun number(): PyJson {
            val start = i
            var isFloat = false
            if (peek() == '-'.code) i++
            if (peek() == '0'.code) i++ else if (digit(peek())) { while (digit(peek())) i++ } else throw Failure()
            if (peek() == '.'.code && i + 1 < u.size && digit(u[i + 1])) { isFloat = true; i++; while (digit(peek())) i++ }
            if (peek() == 'e'.code || peek() == 'E'.code) {
                var j = i + 1
                if (j < u.size && (u[j] == '+'.code || u[j] == '-'.code)) j++
                if (j < u.size && digit(u[j])) { isFloat = true; i = j; while (digit(peek())) i++ }
            }
            val text = String(u, start, i - start)
            if (!isFloat) text.toLongOrNull()?.let { return Int(it) }
            return Float(text.toDoubleOrNull() ?: throw Failure())
        }

        fun hex4(): kotlin.Int {
            if (i + 4 > u.size) throw Failure()
            val v = String(u, i, 4).toIntOrNull(16) ?: throw Failure()
            i += 4
            return v
        }

        fun string(): String {
            i++
            val out = StringBuilder()
            while (true) {
                val c = peek()
                if (c == -1) throw Failure()
                i++
                if (c == '"'.code) return out.toString()
                if (c < 0x20) throw Failure()
                if (c != '\\'.code) { out.appendCodePoint(c); continue }
                val e = peek()
                if (e == -1) throw Failure()
                i++
                when (e) {
                    '"'.code -> out.append('"')
                    '\\'.code -> out.append('\\')
                    '/'.code -> out.append('/')
                    'b'.code -> out.append('\b')
                    'f'.code -> out.append('\u000C')
                    'n'.code -> out.append('\n')
                    'r'.code -> out.append('\r')
                    't'.code -> out.append('\t')
                    'u'.code -> {
                        var v = hex4()
                        if (v in 0xD800..0xDBFF && peek() == '\\'.code && i + 1 < u.size && u[i + 1] == 'u'.code) {
                            val save = i
                            i += 2
                            val lo = hex4()
                            if (lo in 0xDC00..0xDFFF) v = 0x10000 + ((v - 0xD800) shl 10) + (lo - 0xDC00) else i = save
                        }
                        // A lone surrogate cannot be held in a well-formed string: U+FFFD, as on the Mac.
                        if (v in 0xD800..0xDFFF) out.append('�') else out.appendCodePoint(v)
                    }
                    else -> throw Failure()
                }
            }
        }
    }
}

/** Bounded text sources (Windows `decode_text`). */
internal object ImportText {
    fun bounded(data: ByteArray, limit: Int = ImportSource.MAX_SOURCE_BYTES): ByteArray {
        if (data.size > limit) {
            if (limit == ImportSource.MAX_SOURCE_BYTES) throw ImportException(ImportException.Kind.TOO_LARGE)
            throw ImportException.malformed("Import source exceeds ${limit / (1024 * 1024)} MiB")
        }
        return data
    }

    /** UTF-16 with a BOM, UTF-8 (BOM stripped), else Windows-1252. */
    fun decode(b: ByteArray): String {
        if (b.size >= 2 && ((b[0] == 0xFF.toByte() && b[1] == 0xFE.toByte()) || (b[0] == 0xFE.toByte() && b[1] == 0xFF.toByte()))) {
            val little = b[0] == 0xFF.toByte()
            if ((b.size - 2) % 2 != 0) throw ImportException.malformed("Import source must be UTF-8 or UTF-16 text")
            val decoder = (if (little) Charsets.UTF_16LE else Charsets.UTF_16BE).newDecoder()
            return try {
                decoder.decode(java.nio.ByteBuffer.wrap(b, 2, b.size - 2)).toString()
            } catch (e: java.nio.charset.CharacterCodingException) {
                throw ImportException.malformed("Import source must be UTF-8 or UTF-16 text")
            }
        }
        val start = if (b.size >= 3 && b[0] == 0xEF.toByte() && b[1] == 0xBB.toByte() && b[2] == 0xBF.toByte()) 3 else 0
        try {
            return Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b, start, b.size - start)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
        }
        val out = StringBuilder(b.size - start)
        for (k in start until b.size) {
            val v = b[k].toInt() and 0xFF
            if (v == 0x81 || v == 0x8D || v == 0x8F || v == 0x90 || v == 0x9D) {
                throw ImportException.malformed("Import source must be UTF-8 text")
            }
            out.appendCodePoint(if (v in 0x80..0x9F) CP1252_HIGH[v - 0x80] else v)
        }
        return out.toString()
    }

    private val CP1252_HIGH = intArrayOf(
        0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F,
        0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178,
    )

    fun text(data: ByteArray): String = decode(bounded(data))
}

/** Windows `parse_timestamp`: Unix seconds, or null. */
internal object ImportTime {
    fun parse(v: PyJson?): Long? = when (v) {
        null, PyJson.Null, is PyJson.Bool -> null
        is PyJson.Int -> number(v.v.toDouble())
        is PyJson.Float -> number(v.v)
        else -> parse(v.str)
    }

    fun number(value: Double): Long? {
        if (!value.isFinite()) return null
        var n = value
        if (n > 10_000_000_000.0) n /= 1000
        if (!(n > 0 && n < 9.2e18)) return null
        return n.toLong()
    }

    fun parse(value: String): Long? {
        val text = Py.strip(value)
        if (text.isEmpty()) return null
        val digits = Py.lstrip(text, setOf('-'.code))
        if (Py.isAsciiDigits(digits)) {
            if (Py.len(digits) > 20) return null
            if (Py.len(text) - Py.len(digits) > 1) return null
            return number(text.toDoubleOrNull() ?: return null)
        }
        return isoformat(text.replace("Z", "+00:00")) ?: strptime(text)
    }

    fun epoch(y: Int, m: Int, d: Int, hh: Int, mm: Int, ss: Int): Long? {
        if (y !in 1..9999 || m !in 1..12 || hh !in 0..23 || mm !in 0..59 || ss !in 0..59) return null
        val leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        val dim = intArrayOf(31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[m - 1]
        if (d !in 1..dim) return null
        return java.time.LocalDate.of(y, m, d).toEpochDay() * 86400 + hh * 3600 + mm * 60 + ss
    }

    private fun ints(u: IntArray, from: Int, to: Int): Int? {
        val s = String(u, from, to - from)
        return if (Py.isAsciiDigits(s)) s.toInt() else null
    }

    private fun isDigit(c: Int) = c in '0'.code..'9'.code

    /** `datetime.fromisoformat` (Python 3.12) for the shapes exports use, then `int(dt.timestamp())`. */
    fun isoformat(text: String): Long? {
        val u = Py.cps(text)
        var y: Int
        var m: Int
        var d: Int
        var i: Int
        if (u.size >= 10 && u[4] == '-'.code && u[7] == '-'.code && ints(u, 0, 4) != null && ints(u, 5, 7) != null && ints(u, 8, 10) != null) {
            y = ints(u, 0, 4)!!; m = ints(u, 5, 7)!!; d = ints(u, 8, 10)!!; i = 10
        } else if (u.size >= 8 && ints(u, 0, 4) != null && ints(u, 4, 6) != null && ints(u, 6, 8) != null) {
            y = ints(u, 0, 4)!!; m = ints(u, 4, 6)!!; d = ints(u, 6, 8)!!; i = 8
            if (u.size > 8 && isDigit(u[8])) return null
        } else {
            return null
        }
        var hh = 0
        var mm = 0
        var ss = 0
        var frac = 0.0
        var offset = 0
        if (i < u.size) {
            i += 1
            if (i + 2 > u.size) return null
            hh = ints(u, i, i + 2) ?: return null
            i += 2
            val extended = i < u.size && u[i] == ':'.code
            fun two(): Int? {
                if (extended) { if (i >= u.size || u[i] != ':'.code) return null; i += 1 }
                if (i + 2 > u.size) return null
                val v = ints(u, i, i + 2) ?: return null
                i += 2
                return v
            }
            if (i < u.size && (extended || isDigit(u[i]))) {
                mm = two() ?: return null
                if (i < u.size && (if (extended) u[i] == ':'.code else isDigit(u[i]))) {
                    ss = two() ?: return null
                    if (i < u.size && (u[i] == '.'.code || u[i] == ','.code)) {
                        i += 1
                        val start = i
                        while (i < u.size && isDigit(u[i])) i++
                        if (i <= start) return null
                        frac = ("0." + String(u, start, i - start)).toDoubleOrNull() ?: 0.0
                    }
                }
            }
            if (i < u.size) {
                if (u[i] != '+'.code && u[i] != '-'.code) return null
                val sign = if (u[i] == '-'.code) -1 else 1
                i += 1
                if (i + 2 > u.size) return null
                val oh = ints(u, i, i + 2) ?: return null
                i += 2
                var om = 0
                var os = 0
                if (i < u.size) {
                    if (u[i] == ':'.code) i++
                    if (i + 2 > u.size) return null
                    om = ints(u, i, i + 2) ?: return null
                    i += 2
                    if (i < u.size) {
                        if (u[i] == ':'.code) i++
                        if (i + 2 > u.size) return null
                        os = ints(u, i, i + 2) ?: return null
                        i += 2
                        if (i < u.size && u[i] == '.'.code) { i++; while (i < u.size && isDigit(u[i])) i++ }
                    }
                }
                if (i != u.size || oh >= 24 || om >= 60 || os >= 60) return null
                offset = sign * (oh * 3600 + om * 60 + os)
            }
        }
        val base = epoch(y, m, d, hh, mm, ss) ?: return null
        val t = (base - offset).toDouble() + frac
        return t.toLong()
    }

    /** `strptime` with `%Y-%m-%dT%H:%M:%S`, `%Y-%m-%d %H:%M:%S` or `%Y-%m-%d` (unpadded numbers allowed). */
    fun strptime(text: String): Long? {
        fun nums(s: String, sep: Char, count: Int, maxLens: IntArray): IntArray? {
            val parts = s.split(sep)
            if (parts.size != count) return null
            val out = IntArray(count)
            for (k in 0 until count) {
                val p = parts[k]
                if (p.length !in 1..maxLens[k] || !Py.isAsciiDigits(p)) return null
                out[k] = p.toInt()
            }
            return out
        }
        for (sep in charArrayOf('T', ' ')) {
            val at = text.indexOf(sep)
            if (at >= 0) {
                val dd = nums(text.substring(0, at), '-', 3, intArrayOf(4, 2, 2))
                val tt = nums(text.substring(at + 1), ':', 3, intArrayOf(2, 2, 2))
                if (dd != null && tt != null) return epoch(dd[0], dd[1], dd[2], tt[0], tt[1], tt[2])
            }
        }
        val dd = nums(text, '-', 3, intArrayOf(4, 2, 2)) ?: return null
        return epoch(dd[0], dd[1], dd[2], 0, 0, 0)
    }
}
