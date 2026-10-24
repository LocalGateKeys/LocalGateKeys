package app.localgatekeys.core.password

import java.math.BigInteger
import java.util.Locale

/** One piece of the cheapest guess sequence (desktop `PatternMatch`); [i] and [j] are code point offsets, inclusive. */
data class PatternMatch(val pattern: String, val i: Int, val j: Int, val token: String, val guesses: Double, val detail: String = "") {
    /** The token can be a piece of a password: never printed. */
    override fun toString(): String = "PatternMatch($pattern, $i..$j, guesses=$guesses)"
}

/** The desktop's estimate (`StrengthEstimate` without the display and feedback fields, which the phones do not show). */
data class StrengthEstimate(val score: Int, val guesses: Double, val guessesLog10: Double, val matches: List<PatternMatch>) {
    override fun toString(): String = "StrengthEstimate(score=$score, guessesLog10=$guessesLog10)"
}

/**
 * A port of the desktop's zxcvbn-style `password_tools.estimate_strength` (dictionary with l33t, reversal and
 * capitals; sequences; repeats; keyboard walks; dates; brute force; the minimum-guesses sequence and the 0..4 score).
 * Pinned by tests/vectors/password_strength/vectors.json, which the desktop generates.
 *
 * Python strings are code point sequences: every offset, length and slice here works on code points, and the
 * character tests follow Python's `str.isalpha/islower/isupper/isdigit` and `str.lower`.
 *
 * [words] is the desktop's `_word_set()` (the packaged passphrase list plus the built-in fallback list) and
 * [wordRank] `len(load_wordlist())`, the guess rank of any word in it.
 */
class StrengthEstimator(private val words: Set<String>, private val wordRank: Int) {
    fun estimate(password: String): StrengthEstimate = estimate(cps(password), 0)

    private fun estimate(password: IntArray, depth: Int): StrengthEstimate {
        val analyzed = if (password.size > MAX_ANALYZED) password.copyOf(MAX_ANALYZED) else password
        val overflow = password.size - analyzed.size
        val matches = ArrayList<PatternMatch>()
        if (analyzed.isNotEmpty()) {
            matches += dictionaryMatches(analyzed)
            matches += sequenceMatches(analyzed)
            matches += repeatMatches(analyzed, depth)
            matches += spatialMatches(analyzed)
            matches += dateMatches(analyzed)
        }
        val (g, sequence) = mostGuessableSequence(analyzed, matches)
        var guesses = g
        if (overflow > 0) guesses *= Math.pow(BRUTEFORCE_CARDINALITY.toDouble(), overflow.toDouble())
        guesses = maxOf(1.0, guesses)
        return StrengthEstimate(score(guesses), guesses, Math.log10(guesses), sequence)
    }

    // MARK: dictionary

    private fun dictionaryRank(candidate: String): Pair<Int, String>? {
        CommonPasswords.rank[candidate]?.let { return it to "common" }
        if (candidate in words) return wordRank to "word"
        return null
    }

    private fun dictionaryMatches(password: IntArray): List<PatternMatch> {
        val matches = ArrayList<PatternMatch>()
        val n = password.size
        for (i in 0 until n) {
            for (j in i + 2 until n) {
                val tokenCps = password.copyOfRange(i, j + 1)
                val token = str(tokenCps)
                val lower = pyLower(token)
                val reversed = str(cps(lower).reversedArray())
                val candidates = ArrayList<Triple<String, Int, Boolean>>()
                candidates += Triple(lower, 0, false)
                candidates += Triple(reversed, 0, true)
                for ((v, subs) in l33tVariants(lower)) candidates += Triple(v, subs, false)
                for ((v, subs) in l33tVariants(reversed)) candidates += Triple(v, subs, true)
                var best: PatternMatch? = null
                for ((candidate, substitutions, rev) in candidates) {
                    val (rank, source) = dictionaryRank(candidate) ?: continue
                    var guesses = rank.toDouble() * uppercaseVariations(tokenCps)
                    var detail = source
                    if (substitutions > 0) {
                        guesses *= maxOf(2.0, Math.pow(2.0, substitutions.toDouble()))
                        detail += "+l33t"
                    }
                    if (rev) {
                        guesses *= 2
                        detail += "+reversed"
                    }
                    if (best == null || guesses < best.guesses) best = PatternMatch("dictionary", i, j, token, guesses, detail)
                }
                if (best != null) matches += best
            }
        }
        return matches
    }

    // MARK: sequences

    private fun sequenceMatches(password: IntArray): List<PatternMatch> {
        val matches = ArrayList<PatternMatch>()
        val n = password.size
        var i = 0
        while (i < n - 2) {
            var j = i + 1
            val delta = password[j] - password[i]
            if (Math.abs(delta) != 1 || charClass(password[i]) == OTHER || charClass(password[i]) != charClass(password[j])) {
                i += 1
                continue
            }
            while (j + 1 < n && password[j + 1] - password[j] == delta && charClass(password[j + 1]) == charClass(password[i])) j += 1
            if (j - i + 1 >= 3) {
                val tokenCps = password.copyOfRange(i, j + 1)
                val first = tokenCps[0]
                val base = when {
                    first in "aAzZ019".codePoints().toArray() -> 4
                    isDigit(first) -> 10
                    else -> 26
                }
                val guesses = (base * tokenCps.size).toDouble() * (if (delta < 0) 2 else 1)
                matches += PatternMatch("sequence", i, j, str(tokenCps), guesses, if (delta < 0) "descending" else "ascending")
                i = j
            }
            i += 1
        }
        return matches
    }

    // MARK: repeats (desktop regexes `(.+?)\1+` and `(.+)\1+`, done by hand on code points; `.` is anything but "\n")

    private class Repeat(val start: Int, val end: Int, val baseLength: Int)

    /** Repeats of [base] code points from [from]: how many full copies follow the first one. */
    private fun copies(p: IntArray, start: Int, base: Int): Int {
        var count = 0
        var at = start + base
        while (at + base <= p.size && regionEquals(p, start, at, base)) {
            count += 1
            at += base
        }
        return count
    }

    private fun regionEquals(p: IntArray, a: Int, b: Int, len: Int): Boolean {
        for (k in 0 until len) if (p[a + k] != p[b + k]) return false
        return true
    }

    /** The longest run of non-newline code points from [start]. */
    private fun dotRun(p: IntArray, start: Int): Int {
        var k = start
        while (k < p.size && p[k] != '\n'.code) k += 1
        return k - start
    }

    private fun lazySearch(p: IntArray, position: Int): Repeat? {
        for (s in position until p.size) {
            val run = dotRun(p, s)
            for (len in 1..run) {
                if (s + 2 * len > p.size) break
                val c = copies(p, s, len)
                if (c >= 1) return Repeat(s, s + len * (c + 1), len)
            }
        }
        return null
    }

    private fun greedyAt(p: IntArray, s: Int): Repeat? {
        val run = dotRun(p, s)
        for (len in run downTo 1) {
            if (s + 2 * len > p.size) continue
            val c = copies(p, s, len)
            if (c >= 1) return Repeat(s, s + len * (c + 1), len)
        }
        return null
    }

    private fun repeatMatches(password: IntArray, depth: Int): List<PatternMatch> {
        val matches = ArrayList<PatternMatch>()
        if (depth > 2) return matches
        var position = 0
        while (position < password.size) {
            val lazy = lazySearch(password, position) ?: break
            val greedy = greedyAt(password, lazy.start)
            val candidates = ArrayList<Repeat>()
            candidates += lazy
            if (greedy != null && greedy.end > lazy.end) candidates += greedy
            var chosen: Repeat? = null
            var chosenGuesses = Double.POSITIVE_INFINITY
            for (c in candidates) {
                val repeatCount = (c.end - c.start) / c.baseLength
                if (repeatCount < 2) continue
                val baseGuesses = estimate(password.copyOfRange(c.start, c.start + c.baseLength), depth + 1).guesses
                val guesses = baseGuesses * repeatCount
                if (guesses < chosenGuesses) {
                    chosen = c
                    chosenGuesses = guesses
                }
            }
            if (chosen == null) {
                position = lazy.start + 1
                continue
            }
            matches += PatternMatch("repeat", chosen.start, chosen.end - 1, str(password.copyOfRange(chosen.start, chosen.end)), chosenGuesses, "repeat")
            position = chosen.end
        }
        return matches
    }

    // MARK: keyboard walks

    private fun adjacent(ar: Int, ac: Int, br: Int, bc: Int): Pair<Int, Int>? {
        val dr = br - ar
        val dc = bc - ac
        return when {
            dr == 0 && Math.abs(dc) == 1 -> 0 to dc
            dr == 1 && (dc == 0 || dc == -1) -> 1 to dc
            dr == -1 && (dc == 0 || dc == 1) -> -1 to dc
            else -> null
        }
    }

    private fun spatialGuesses(length: Int, turns: Int, shifted: Int): Double {
        var guesses = 0.0
        for (i in 2..length) {
            for (j in 1..minOf(turns, i - 1)) {
                guesses += comb(i - 1, j - 1) * KEYBOARD_STARTS * Math.pow(KEYBOARD_AVERAGE_DEGREE, j.toDouble())
            }
        }
        if (shifted > 0) {
            val unshifted = length - shifted
            if (unshifted == 0) {
                guesses *= 2
            } else {
                var sum = 0.0
                for (k in 1..minOf(shifted, unshifted)) sum += comb(length, k)
                guesses *= sum
            }
        }
        return maxOf(guesses, 1.0)
    }

    private fun spatialMatches(password: IntArray): List<PatternMatch> {
        val matches = ArrayList<PatternMatch>()
        val n = password.size
        var i = 0
        while (i < n - 2) {
            val start = KEY_POSITIONS[password[i]]
            if (start == null) {
                i += 1
                continue
            }
            var j = i
            var turns = 0
            var last: Pair<Int, Int>? = null
            var shifted = if (start.shifted) 1 else 0
            var pr = start.row
            var pc = start.col
            while (j + 1 < n) {
                val next = KEY_POSITIONS[password[j + 1]] ?: break
                val direction = adjacent(pr, pc, next.row, next.col) ?: break
                if (direction != last) {
                    turns += 1
                    last = direction
                }
                if (next.shifted) shifted += 1
                pr = next.row
                pc = next.col
                j += 1
            }
            if (j - i + 1 >= 3) {
                val token = password.copyOfRange(i, j + 1)
                matches += PatternMatch("spatial", i, j, str(token), spatialGuesses(token.size, turns, shifted), "turns=$turns")
                i = j
            }
            i += 1
        }
        return matches
    }

    // MARK: dates

    private fun validDate(day0: Int, month0: Int, year0: Long): Triple<Int, Int, Long>? {
        var day = day0
        var month = month0
        if (month in 1..12 && day in 1..31) {
            // as given
        } else if (day in 1..12 && month in 1..31) {
            val t = day; day = month; month = t
        } else {
            return null
        }
        var year = year0
        if (year < 100) year += if (year > 30) 1900 else 2000
        if (year !in 1900..2050) return null
        return Triple(day, month, year)
    }

    private fun dateCandidates(token: IntArray): List<Triple<Int, Int, Long>> {
        val out = ArrayList<Triple<Int, Int, Long>>()
        if (token.size == 4 && token.all { isDigit(it) }) {
            val year = number(token)
            if (year in 1900..2050) out += Triple(1, 1, year)
        }
        for ((a, b) in DATE_SPLITS[token.size] ?: emptyList()) {
            val parts = listOf(token.copyOfRange(0, a), token.copyOfRange(a, b), token.copyOfRange(b, token.size))
            if (!parts.all { p -> p.isNotEmpty() && p.all { isDigit(it) } }) continue
            val p0 = number(parts[0])
            val p1 = number(parts[1])
            val p2 = number(parts[2])
            for ((day, month, year) in listOf(Triple(p1, p2, p0), Triple(p0, p1, p2))) {
                validDate(day.toIntClamped(), month.toIntClamped(), year)?.let { out += it }
            }
        }
        return out
    }

    private fun dateGuesses(year: Long, separated: Boolean): Double {
        val g = (maxOf(Math.abs(year - REFERENCE_YEAR), MIN_YEAR_SPACE.toLong()) * 365).toDouble()
        return if (separated) g * 4 else g
    }

    /** Python `\d` in a str pattern: any Unicode decimal digit. */
    private fun isDecimal(cp: Int): Boolean = Character.getType(cp) == Character.DECIMAL_DIGIT_NUMBER.toInt()

    /** Python `\s` in a str pattern (`str.isspace`). */
    private fun isSpace(cp: Int): Boolean = Character.isWhitespace(cp) || Character.isSpaceChar(cp) || cp == 0x85

    private fun decimalRun(p: IntArray, from: Int): Int {
        var k = from
        while (k < p.size && isDecimal(p[k])) k += 1
        return k - from
    }

    /** The separated-date regex matched at [s] (greedy groups, backtracking): end offset and groups 1, 3, 4; or null. */
    private fun separatedDateAt(p: IntArray, s: Int): Pair<Int, Triple<IntArray, IntArray, IntArray>>? {
        for (l1 in minOf(decimalRun(p, s), 4) downTo 1) {
            val sepAt = s + l1
            if (sepAt >= p.size) continue
            val sep = p[sepAt]
            if (!(isSpace(sep) || sep in DATE_SEPARATORS)) continue
            for (l3 in minOf(decimalRun(p, sepAt + 1), 2) downTo 1) {
                val sep2 = sepAt + 1 + l3
                if (sep2 >= p.size || p[sep2] != sep) continue
                val l4 = minOf(decimalRun(p, sep2 + 1), 4)
                if (l4 < 1) continue
                val groups = Triple(p.copyOfRange(s, sepAt), p.copyOfRange(sepAt + 1, sep2), p.copyOfRange(sep2 + 1, sep2 + 1 + l4))
                return (sep2 + 1 + l4) to groups
            }
        }
        return null
    }

    /**
     * The desktop's two date regexes, by hand on code points with Python's semantics (Android's regex engine has no
     * UNICODE_CHARACTER_CLASS): `\d{4,8}` (leftmost, greedy, non-overlapping), then the separated form
     * `(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})` (non-overlapping).
     */
    private fun dateMatches(password: IntArray): List<PatternMatch> {
        val matches = ArrayList<PatternMatch>()
        var at = 0
        while (at < password.size) {
            val run = decimalRun(password, at)
            if (run < 4) {
                at += maxOf(run, 1)
                continue
            }
            val startCp = at
            val token = password.copyOfRange(at, at + minOf(run, 8))
            at += token.size
            for (length in token.size downTo 4) {
                for (offset in 0..token.size - length) {
                    val sub = token.copyOfRange(offset, offset + length)
                    val candidates = dateCandidates(sub)
                    if (candidates.isEmpty()) continue
                    val year = candidates.minByOrNull { Math.abs(it.third - REFERENCE_YEAR) }!!.third
                    val i = startCp + offset
                    matches += PatternMatch("date", i, i + length - 1, str(sub), dateGuesses(year, false), year.toString())
                }
            }
        }
        var s = 0
        while (s < password.size) {
            val found = separatedDateAt(password, s)
            if (found == null) {
                s += 1
                continue
            }
            val (end, groups) = found
            val p0 = number(groups.first)
            val p1 = number(groups.second)
            val p2 = number(groups.third)
            for ((day, month, year) in listOf(Triple(p1, p2, p0), Triple(p0, p1, p2), Triple(p1, p0, p2))) {
                val resolved = validDate(day.toIntClamped(), month.toIntClamped(), year) ?: continue
                val token = str(password.copyOfRange(s, end))
                matches += PatternMatch("date", s, end - 1, token, dateGuesses(resolved.third, true), resolved.third.toString())
                break
            }
            s = end
        }
        return matches
    }

    // MARK: the cheapest sequence

    private fun bruteforce(password: IntArray, i: Int, j: Int): PatternMatch {
        val len = j - i + 1
        val guesses = Math.pow(BRUTEFORCE_CARDINALITY.toDouble(), len.toDouble())
        val minimum = if (len == 1) MIN_SUBMATCH_SINGLE else MIN_SUBMATCH_MULTI
        return PatternMatch("bruteforce", i, j, str(password.copyOfRange(i, j + 1)), maxOf(guesses, minimum.toDouble()))
    }

    private fun mostGuessableSequence(password: IntArray, matches: List<PatternMatch>): Pair<Double, List<PatternMatch>> {
        val n = password.size
        if (n == 0) return 1.0 to emptyList()
        val whole = str(password)
        val byEnd = Array(n) { ArrayList<PatternMatch>() }
        for (m in matches) byEnd[m.j].add(m)
        val optimalM = Array(n) { LinkedHashMap<Int, PatternMatch>() }
        val optimalPi = Array(n) { LinkedHashMap<Int, Double>() }
        val optimalG = Array(n) { LinkedHashMap<Int, Double>() }

        fun floored(m: PatternMatch): Double {
            if (m.token == whole) return m.guesses
            val minimum = if (m.token.codePointCount(0, m.token.length) == 1) MIN_SUBMATCH_SINGLE else MIN_SUBMATCH_MULTI
            return maxOf(m.guesses, minimum.toDouble())
        }

        fun update(m: PatternMatch, length: Int) {
            val k = m.j
            var pi = floored(m)
            if (length > 1) pi *= optimalPi[m.i - 1].getValue(length - 1)
            var g = factorial(length) * pi
            if (length > 1) g += Math.pow(MIN_GUESSES_BEFORE_GROWING_SEQUENCE.toDouble(), (length - 1).toDouble())
            for ((competingLength, competingG) in optimalG[k]) {
                if (competingLength > length) continue
                if (competingG <= g) return
            }
            optimalG[k][length] = g
            optimalM[k][length] = m
            optimalPi[k][length] = pi
        }

        for (k in 0 until n) {
            for (m in byEnd[k]) {
                if (m.i > 0) {
                    for (length in optimalM[m.i - 1].keys.toList()) update(m, length + 1)
                } else {
                    update(m, 1)
                }
            }
            update(bruteforce(password, 0, k), 1)
            for (i in 1..k) {
                val chunk = bruteforce(password, i, k)
                for ((length, last) in optimalM[i - 1].entries.toList()) {
                    if (last.pattern == "bruteforce") continue
                    update(chunk, length + 1)
                }
            }
        }
        var bestLength = -1
        var bestG = 0.0
        for ((length, g) in optimalG[n - 1]) if (bestLength < 0 || g < bestG) { bestLength = length; bestG = g }
        val sequence = ArrayList<PatternMatch>()
        var k = n - 1
        var length = bestLength
        while (k >= 0 && length > 0) {
            val m = optimalM[k].getValue(length)
            sequence.add(m)
            k = m.i - 1
            length -= 1
        }
        sequence.reverse()
        return bestG to sequence
    }

    companion object {
        /** Desktop `STRENGTH_LABELS`, by score. */
        val LABELS = listOf("Very weak", "Weak", "Fair", "Strong", "Very strong")

        private const val MIN_GUESSES_BEFORE_GROWING_SEQUENCE = 10_000
        private const val MIN_SUBMATCH_SINGLE = 10
        private const val MIN_SUBMATCH_MULTI = 50
        private const val BRUTEFORCE_CARDINALITY = 10
        private const val REFERENCE_YEAR = 2026L
        private const val MIN_YEAR_SPACE = 20
        const val MAX_ANALYZED = 100
        private const val KEYBOARD_STARTS = 47
        private const val KEYBOARD_AVERAGE_DEGREE = 4.6
        private const val OTHER = 3

        fun score(guesses: Double): Int = when {
            guesses < 1e3 + 5 -> 0
            guesses < 1e6 + 5 -> 1
            guesses < 1e8 + 5 -> 2
            guesses < 1e10 + 5 -> 3
            else -> 4
        }

        private val L33T_TABLE = linkedMapOf(
            'a' to "4@", 'b' to "8", 'c' to "({[<", 'e' to "3", 'g' to "69", 'i' to "1!|", 'l' to "1|7", 'o' to "0",
            's' to "$5", 't' to "+7", 'x' to "%", 'z' to "2",
        )
        private val L33T_REVERSE: Map<Int, List<Int>> = LinkedHashMap<Int, MutableList<Int>>().also { m ->
            for ((letter, subs) in L33T_TABLE) for (sub in subs) m.getOrPut(sub.code) { ArrayList() }.add(letter.code)
        }

        private class Key(val row: Int, val col: Int, val shifted: Boolean)

        private val KEY_POSITIONS: Map<Int, Key> = HashMap<Int, Key>().also { m ->
            val rows = listOf("`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./")
            val shifted = listOf("~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?")
            for (r in rows.indices) {
                rows[r].forEachIndexed { c, ch -> m[ch.code] = Key(r, c, false) }
                shifted[r].forEachIndexed { c, ch -> m[ch.code] = Key(r, c, true) }
            }
        }

        private val DATE_SPLITS: Map<Int, List<Pair<Int, Int>>> = mapOf(
            4 to listOf(1 to 2, 2 to 3),
            5 to listOf(1 to 3, 2 to 3),
            6 to listOf(1 to 2, 2 to 4, 4 to 5),
            7 to listOf(1 to 3, 2 to 3, 4 to 5, 4 to 6),
            8 to listOf(2 to 4, 4 to 6),
        )

        /** The separated-date separators besides whitespace (desktop `[\s/\\_.-]`): / \ _ . - */
        private val DATE_SEPARATORS = setOf(0x2F, 0x5C, 0x5F, 0x2E, 0x2D)

        fun cps(s: String): IntArray = s.codePoints().toArray()

        fun str(c: IntArray): String = String(c, 0, c.size)

        /** Python `str.lower()` (full Unicode lower-casing, locale independent). */
        fun pyLower(s: String): String = s.lowercase(Locale.ROOT)

        /**
         * Python `str.isdigit()` for one character: a decimal digit, or another digit character (superscripts, circled).
         *
         * Known gap: some Other_Number characters with a digit value, such as ㊀ (U+3280) and ㆒ (U+3192), count as digits
         * here (Android and the JDK give them a numeric value 0..9) but not on the desktop (their Unicode Numeric_Type is
         * Numeric, not Digit). The only effect is that such runs can form an extra sequence match: an extra match can
         * only lower the cheapest guess count, so the phone is only ever stricter than the desktop there.
         */
        fun isDigit(cp: Int): Boolean {
            val t = Character.getType(cp)
            if (t == Character.DECIMAL_DIGIT_NUMBER.toInt()) return true
            if (t != Character.OTHER_NUMBER.toInt()) return false
            val v = Character.getNumericValue(cp)
            return v in 0..9
        }

        private fun isLower(cp: Int) = Character.isLowerCase(cp)
        private fun isUpper(cp: Int) = Character.isUpperCase(cp)
        private fun isAlpha(cp: Int) = Character.isLetter(cp)

        private fun charClass(cp: Int): Int = when {
            isLower(cp) -> 0
            isUpper(cp) -> 1
            isDigit(cp) -> 2
            else -> OTHER
        }

        /** Python `int()` of a run of Unicode decimal digits (a huge value saturates; dates never use it). */
        private fun number(d: IntArray): Long {
            var v = 0L
            for (cp in d) {
                val digit = Character.digit(cp, 10).let { if (it < 0) Character.getNumericValue(cp) else it }
                v = if (v > Long.MAX_VALUE / 20) v else v * 10 + digit
            }
            return v
        }

        private fun Long.toIntClamped(): Int = if (this > Int.MAX_VALUE) Int.MAX_VALUE else this.toInt()

        private fun comb(n: Int, k: Int): Double = binomial(n, k).toDouble()

        private fun binomial(n: Int, k: Int): BigInteger {
            if (k < 0 || k > n) return BigInteger.ZERO
            var r = BigInteger.ONE
            for (x in 0 until k) r = r.multiply(BigInteger.valueOf((n - x).toLong())).divide(BigInteger.valueOf((x + 1).toLong()))
            return r
        }

        /** `math.factorial(n)` converted to a float the way Python multiplies an int by a float (correctly rounded). */
        private fun factorial(n: Int): Double {
            var r = BigInteger.ONE
            for (x in 2..n) r = r.multiply(BigInteger.valueOf(x.toLong()))
            return r.toDouble()
        }

        private fun uppercaseVariations(token: IntArray): Double {
            val letters = token.filter { isAlpha(it) }
            if (letters.isEmpty() || letters.all { isLower(it) }) return 1.0
            if ((isUpper(token[0]) && letters.drop(1).all { isLower(it) }) ||
                (isUpper(token[token.size - 1]) && letters.dropLast(1).all { isLower(it) }) || letters.all { isUpper(it) }
            ) {
                return 2.0
            }
            val upper = letters.count { isUpper(it) }
            val lower = letters.size - upper
            var sum = BigInteger.ZERO
            for (k in 1..minOf(upper, lower)) sum = sum.add(binomial(upper + lower, k))
            return maxOf(2.0, sum.toDouble())
        }

        /** (candidate, substitution count) pairs with l33t characters restored (desktop `_l33t_variants`, limit 32). */
        private fun l33tVariants(lowerToken: String, limit: Int = 32): List<Pair<String, Int>> {
            val chars = cps(lowerToken)
            if (chars.none { it in L33T_REVERSE }) return emptyList()
            var variants: List<Pair<StringBuilder, Int>> = listOf(StringBuilder() to 0)
            for (ch in chars) {
                val options = L33T_REVERSE[ch]
                variants = if (options != null) {
                    val next = ArrayList<Pair<StringBuilder, Int>>()
                    for ((prefix, count) in variants) for (letter in options) next += StringBuilder(prefix).appendCodePoint(letter) to count + 1
                    next.take(limit)
                } else {
                    variants.map { (prefix, count) -> prefix.appendCodePoint(ch) to count }
                }
            }
            return variants.map { it.first.toString() to it.second }.filter { it.first != lowerToken }
        }
    }
}
