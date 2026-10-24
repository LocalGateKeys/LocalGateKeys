package app.localgatekeys.android.generator

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.RandomSource

/**
 * Desktop `password_tools.GeneratorOptions`: same defaults and character sets (port of `ios/App/Generator`). Options
 * only, never a generated value, so the default toString is safe.
 */
data class GeneratorOptions(
    val mode: Mode = Mode.PASSWORD,
    val length: Int = 20,
    val lowercase: Boolean = true,
    val uppercase: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    val avoidAmbiguous: Boolean = true,
    val symbolSet: String = PasswordGenerator.DEFAULT_SYMBOLS,
    val exclude: String = "",
    val minDigits: Int = 1,
    val minSymbols: Int = 1,
    val words: Int = 6,
    val separator: String = "-",
    val capitalize: Boolean = false,
    val appendNumber: Boolean = false,
) {
    enum class Mode(val raw: String) { PASSWORD("password"), PASSPHRASE("passphrase") }

    /** The Settings row ("New passwords"): `SettingsView.summary`. */
    val summary: String
        get() = if (mode == Mode.PASSWORD) "Password, $length characters" else "Passphrase, $words words"

    /** The iPhone's JSONEncoder keys and values (sorted keys, no spaces). */
    fun toJson(): String {
        val f = linkedMapOf<String, JsonValue>(
            "mode" to JsonValue.Str(mode.raw), "length" to JsonValue.Int(length.toLong()),
            "lowercase" to JsonValue.Bool(lowercase), "uppercase" to JsonValue.Bool(uppercase),
            "digits" to JsonValue.Bool(digits), "symbols" to JsonValue.Bool(symbols),
            "avoidAmbiguous" to JsonValue.Bool(avoidAmbiguous), "symbolSet" to JsonValue.Str(symbolSet),
            "exclude" to JsonValue.Str(exclude), "minDigits" to JsonValue.Int(minDigits.toLong()),
            "minSymbols" to JsonValue.Int(minSymbols.toLong()), "words" to JsonValue.Int(words.toLong()),
            "separator" to JsonValue.Str(separator), "capitalize" to JsonValue.Bool(capitalize),
            "appendNumber" to JsonValue.Bool(appendNumber),
        )
        return CanonicalJson.encode(JsonValue.Obj(f), Dialect.UTF8).toString(Charsets.UTF_8)
    }

    companion object {
        /**
         * Options from [toJson] output; null when the text is not JSON, a key is missing, a value has the wrong type or
         * the mode is unknown (Swift's synthesised Decodable fails the same way). Unknown extra keys are ignored.
         */
        fun fromJson(text: String): GeneratorOptions? = try {
            val f = CanonicalJson.parse(text.toByteArray(Charsets.UTF_8)).obj().fields
            fun str(k: String) = f.getValue(k).str()
            fun int(k: String) = Math.toIntExact(f.getValue(k).long())
            fun bool(k: String) = (f.getValue(k) as JsonValue.Bool).v
            GeneratorOptions(
                mode = Mode.entries.first { it.raw == str("mode") }, length = int("length"),
                lowercase = bool("lowercase"), uppercase = bool("uppercase"), digits = bool("digits"),
                symbols = bool("symbols"), avoidAmbiguous = bool("avoidAmbiguous"), symbolSet = str("symbolSet"),
                exclude = str("exclude"), minDigits = int("minDigits"), minSymbols = int("minSymbols"),
                words = int("words"), separator = str("separator"), capitalize = bool("capitalize"),
                appendNumber = bool("appendNumber"),
            )
        } catch (e: Exception) {
            null
        }
    }
}

/**
 * The generator's last-used options, kept in [AppSettings.generatorOptions] so new passwords start from them. Options
 * only: a generated value is never saved. Missing or unreadable data gives the desktop defaults.
 */
class GeneratorDefaults(private val settings: AppSettings) {
    fun load(): GeneratorOptions = settings.generatorOptions?.let { GeneratorOptions.fromJson(it) } ?: GeneratorOptions()

    fun save(options: GeneratorOptions) { settings.generatorOptions = options.toJson() }

    fun reset() { settings.generatorOptions = null }
}

/** Desktop wording. */
sealed class GeneratorError(override val message: String) : Exception(message) {
    data object NoGroups : GeneratorError("Select at least one character group")
    class EmptyGroup(val name: String) : GeneratorError("No usable $name remain after exclusions")
    data object BadSeparator : GeneratorError("Separator must be one of: dash, space, dot, underscore or none")
}

/**
 * The packaged passphrase list (`assets/eff_large_wordlist.txt`, a byte-for-byte copy of the desktop's
 * `src/localvault/assets/eff_large_wordlist.txt`). LgkApp installs the asset reader at start; it is read and parsed once,
 * on first use. Not installed, unreadable or too short: the desktop's built-in list ([FALLBACK]).
 */
object PassphraseWordlist {
    const val ASSET = "eff_large_wordlist.txt"
    val FALLBACK: List<String> = FALLBACK_WORDLIST

    @Volatile private var source: () -> String? = { null }
    @Volatile private var cached: List<String>? = null

    /** Where the packaged text comes from (null or a throw: missing). Clears what was read before. */
    fun install(source: () -> String?) {
        this.source = source
        cached = null
    }

    val packaged: List<String>
        get() = cached ?: parse(try { source() } catch (e: Exception) { null }).also { cached = it }

    /**
     * Desktop `load_wordlist`: sorted, unique, `[a-z]{3,12}` words only, blank and `#` comment lines skipped. Null or
     * fewer than 1000 usable words gives [FALLBACK], as on the desktop.
     */
    fun parse(text: String?): List<String> {
        if (text == null) return FALLBACK
        val words = text.split(NEWLINES).mapNotNullTo(HashSet()) { line ->
            val w = line.trim { it == ' ' || it == '\t' || Character.getType(it) == Character.SPACE_SEPARATOR.toInt() }
            when {
                w.isEmpty() || w.startsWith("#") -> null
                w.length in 3..12 && w.all { it in 'a'..'z' } -> w
                else -> null
            }
        }
        return if (words.size >= 1000) words.sorted() else FALLBACK
    }

    private val NEWLINES = Regex("\r\n|[\n\r\u000B\u000C\u0085  ]")
}

/**
 * Port of desktop `generate_password` / `generate_passphrase` (via `ios/App/Generator/PasswordGenerator.swift`). All
 * randomness comes from [random] through [below] (unbiased rejection sampling), so a fixed source repeats exactly.
 */
class PasswordGenerator(
    private val random: RandomSource,
    private val wordlist: () -> List<String> = { PassphraseWordlist.packaged },
) {
    fun generate(o: GeneratorOptions): String =
        if (o.mode == GeneratorOptions.Mode.PASSPHRASE) {
            passphrase(o.words, o.separator, o.capitalize, o.appendNumber)
        } else {
            password(o)
        }

    fun password(o: GeneratorOptions): String {
        var length = o.length.coerceIn(LENGTH_RANGE)
        val excluded = o.exclude.codePoints().toArray().toMutableSet()
        if (o.avoidAmbiguous) excluded.addAll(AMBIGUOUS)
        val requested = buildList {
            if (o.lowercase) add(Triple("lowercase letters", LOWERCASE, 1))
            if (o.uppercase) add(Triple("uppercase letters", UPPERCASE, 1))
            if (o.digits) add(Triple("digits", DIGITS, maxOf(1, o.minDigits)))
            if (o.symbols) add(Triple("symbols", o.symbolSet, maxOf(1, o.minSymbols)))
        }
        if (requested.isEmpty()) throw GeneratorError.NoGroups
        val groups = requested.map { (name, alphabet, minimum) ->
            val seen = HashSet<Int>()
            val usable = alphabet.codePoints().toArray().filter { it !in excluded && seen.add(it) }
            if (usable.isEmpty()) throw GeneratorError.EmptyGroup(name)
            usable to minimum
        }
        length = maxOf(length, groups.sumOf { it.second })
        val selected = ArrayList<Int>(length)
        for ((alphabet, minimum) in groups) repeat(minimum) { selected.add(choice(alphabet)) }
        val pool = groups.flatMap { it.first }
        while (selected.size < length) selected.add(choice(pool))
        // random.shuffle: Fisher-Yates from the end.
        for (i in selected.size - 1 downTo 1) {
            val j = below(i + 1)
            val t = selected[i]; selected[i] = selected[j]; selected[j] = t
        }
        return buildString { selected.forEach { appendCodePoint(it) } }
    }

    fun passphrase(
        words: Int,
        separator: String,
        capitalize: Boolean,
        appendNumber: Boolean,
        wordlist: List<String>? = null,
    ): String {
        if (separator !in SEPARATORS) throw GeneratorError.BadSeparator
        val count = words.coerceIn(WORDS_RANGE)
        // Desktop `wordlist or load_wordlist()`; an empty list never reaches `choice`.
        val given = wordlist ?: this.wordlist()
        val list = given.ifEmpty { PassphraseWordlist.FALLBACK }
        var chosen = List(count) { choice(list) }
        if (capitalize) chosen = chosen.map { it.take(1).uppercase() + it.drop(1) }
        var phrase = chosen.joinToString(separator)
        if (appendNumber) phrase += (below(90) + 10).toString()
        return phrase
    }

    /** `secrets.randbelow(n)`: 4 random bytes big-endian, drawn again while at or above the largest multiple of n. */
    fun below(n: Int): Int {
        require(n > 0)
        val bound = n.toLong()
        val limit = (1L shl 32) / bound * bound
        while (true) {
            val b = random.bytes(4)
            val v = (b[0].toLong() and 0xff shl 24) or (b[1].toLong() and 0xff shl 16) or
                (b[2].toLong() and 0xff shl 8) or (b[3].toLong() and 0xff)
            if (v < limit) return (v % bound).toInt()
        }
    }

    private fun <T> choice(a: List<T>): T = a[below(a.size)]

    override fun toString(): String = "PasswordGenerator"

    companion object {
        const val DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?"
        /** Look-alike characters, as code points. */
        val AMBIGUOUS: Set<Int> = "Il1O0o|`'\"".codePoints().toArray().toSet()
        val SEPARATORS = listOf("-", " ", ".", "_", "")
        const val LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
        const val UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        const val DIGITS = "0123456789"
        /** Desktop `_bounded_int(..., 8, 256)` and `max(3, min(words, 16))`. */
        val LENGTH_RANGE = 8..256
        val WORDS_RANGE = 3..16
    }
}
