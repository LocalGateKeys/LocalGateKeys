package app.localgatekeys.android.generator

import kotlin.math.log2

/**
 * How strong the generator's options make a value, from the entropy of how it is drawn (not from the value itself):
 * `length × log2(charset)` for a password, `words × log2(wordlist)` (+ log2(90) for the number) for a passphrase.
 * Capitalising every word is not random, so it adds nothing. Port of `ios/App/Generator/GeneratorStrength.swift`.
 */
object GeneratorStrength {
    enum class Level(val label: String) {
        WEAK("Weak"), FAIR("Fair"), STRONG("Strong"), VERY_STRONG("Very strong");

        /** Filled segments of the 4-segment bar. */
        val segments: Int get() = ordinal + 1
    }

    /** < 50 bits weak, < 70 fair, < 100 strong, else very strong. */
    fun level(bits: Double): Level = when {
        bits < 50 -> Level.WEAK
        bits < 70 -> Level.FAIR
        bits < 100 -> Level.STRONG
        else -> Level.VERY_STRONG
    }

    /**
     * A rough strength for a saved password, from the value itself: `length × log2(character pool)`, where repeated
     * characters count once more at most and anything under 8 characters (Unicode scalars) is weak. It cannot see
     * dictionary words or reuse, so it errs only towards "stronger than it is" for clever-looking phrases.
     */
    fun estimate(password: String): Level {
        val scalars = password.codePoints().toArray()
        if (scalars.size < 8) return Level.WEAK
        var pool = 0
        if (scalars.any { it in 'a'.code..'z'.code }) pool += 26
        if (scalars.any { it in 'A'.code..'Z'.code }) pool += 26
        if (scalars.any { it in '0'.code..'9'.code }) pool += 10
        if (scalars.any { it < 0x80 && !Character.isAlphabetic(it) && it !in '0'.code..'9'.code }) pool += 33
        if (scalars.any { it >= 0x80 }) pool += 100
        val effectiveLength = minOf(scalars.size, scalars.toSet().size * 2)
        return level(effectiveLength * log2(maxOf(pool, 2).toDouble()))
    }

    /** The default count reads (and on first use parses) the packaged list: off the main thread, or pass the count. */
    fun level(options: GeneratorOptions, wordlistCount: Int = PassphraseWordlist.packaged.size): Level =
        level(entropyBits(options, wordlistCount))

    fun entropyBits(options: GeneratorOptions, wordlistCount: Int): Double = when (options.mode) {
        GeneratorOptions.Mode.PASSWORD -> {
            val charset = charsetSize(options)
            if (charset <= 0) 0.0 else options.length.coerceIn(PasswordGenerator.LENGTH_RANGE) * log2(charset.toDouble())
        }
        GeneratorOptions.Mode.PASSPHRASE -> {
            // The generator falls back to the built-in list when it is given an empty one.
            val size = if (wordlistCount > 0) wordlistCount else PassphraseWordlist.FALLBACK.size
            options.words.coerceIn(PasswordGenerator.WORDS_RANGE) * log2(size.toDouble()) +
                (if (options.appendNumber) log2(90.0) else 0.0)
        }
    }

    /** Distinct characters the password draws from: the chosen groups minus look-alikes and exclusions. */
    fun charsetSize(o: GeneratorOptions): Int {
        val excluded = o.exclude.codePoints().toArray().toMutableSet()
        if (o.avoidAmbiguous) excluded.addAll(PasswordGenerator.AMBIGUOUS)
        val pool = HashSet<Int>()
        if (o.lowercase) PasswordGenerator.LOWERCASE.codePoints().forEach { pool.add(it) }
        if (o.uppercase) PasswordGenerator.UPPERCASE.codePoints().forEach { pool.add(it) }
        if (o.digits) PasswordGenerator.DIGITS.codePoints().forEach { pool.add(it) }
        if (o.symbols) o.symbolSet.codePoints().forEach { pool.add(it) }
        return (pool - excluded).size
    }
}
