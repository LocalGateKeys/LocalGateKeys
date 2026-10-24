package app.localgatekeys.android.editor

import java.math.BigDecimal
import java.text.DecimalFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/**
 * Amounts: the record keeps whole minor units (cents) plus a currency code, as the desktop does; screens show the major
 * unit (12.99). Port of `Amount` in `ios/App/Editor/EditorModel.swift`: display for the detail screen, parsing
 * ([minorUnits]) and the local currency for the editor.
 */
object Amount {
    /** The person's currency code (three letters), or "" when the locale has none. */
    fun localCurrency(locale: Locale = Locale.getDefault()): String {
        val code = try {
            Currency.getInstance(locale)?.currencyCode ?: ""
        } catch (_: IllegalArgumentException) {
            ""
        }
        return if (code.length == 3) code else ""
    }

    /** Swift `.whitespaces`: tab and every space separator (Zs). */
    internal fun isSpace(c: Char): Boolean = c == '\t' || Character.getType(c) == Character.SPACE_SEPARATOR.toInt()

    /**
     * What was typed ("12.99", "12,99", "-3", ".5") in minor units of [currency]; empty is 0. Throws [AmountException]
     * with the editor's wording for anything else.
     */
    fun minorUnits(text: String, currency: String): Long {
        var t = text.trim { isSpace(it) }.replace(" ", "")
        if (t.isEmpty()) return 0
        t = t.replace(",", ".")
        val negative = t.startsWith("-")
        val body = if (negative) t.substring(1) else t
        val parts = body.split(".")
        if (parts.size > 2 || !parts.all { p -> p.all { it in '0'..'9' } } || parts.joinToString("").isEmpty()) {
            throw AmountException("Enter the amount as a number, for example 12.99.")
        }
        val digits = fractionDigits(currency)
        val fraction = if (parts.size == 2) parts[1] else ""
        if (fraction.length > digits) {
            throw AmountException(if (digits == 0) "This currency has no decimals." else "Use at most $digits decimals.")
        }
        val whole = parts[0].ifEmpty { "0" }
        val combined = whole + fraction.padEnd(digits, '0')
        val n = if (combined.length <= 17) combined.toLongOrNull() else null
        if (n == null || n > 1_000_000_000_000_000L) throw AmountException("This amount is too large.")
        return if (negative) -n else n
    }

    private fun knownCurrency(code: String): Currency? {
        if (code.length != 3 || code == "XXX") return null
        return try {
            Currency.getInstance(code).takeIf { it.defaultFractionDigits >= 0 }
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** Minor-unit digits for a currency (2 for EUR, 0 for JPY); 2 for the desktop's "no currency" XXX and unknown codes. */
    fun fractionDigits(code: String): Int = knownCurrency(code)?.defaultFractionDigits ?: 2

    /** 129999 CHF -> "1299.99"; 1500 EUR -> "15.00". */
    fun text(minor: Long, currency: String): String {
        val digits = fractionDigits(currency)
        val sign = if (minor < 0) "-" else ""
        val s = minor.toULong().let { if (minor < 0) (0uL - it) else it }.toString()
        if (digits == 0) return sign + s
        val padded = "0".repeat(maxOf(0, digits + 1 - s.length)) + s
        return sign + padded.dropLast(digits) + "." + padded.takeLast(digits)
    }

    /** "CHF 1,299.99" in the person's locale; no symbol for XXX; a well-formed code the platform does not know shows itself. */
    fun display(minor: Long, currency: String, locale: Locale = Locale.getDefault()): String {
        val digits = fractionDigits(currency)
        val f = NumberFormat.getCurrencyInstance(locale)
        val known = knownCurrency(currency)
        val unknownCode = known == null && currency.length == 3 && currency != "XXX" && currency.all { it in 'A'..'Z' }
        if (known != null) {
            f.currency = known
        } else if (f is DecimalFormat) {
            f.decimalFormatSymbols = f.decimalFormatSymbols.apply { currencySymbol = if (unknownCode) MARK else "" }
        }
        f.minimumFractionDigits = digits
        f.maximumFractionDigits = digits
        var s = f.format(BigDecimal.valueOf(minor, digits))
        if (unknownCode) s = placeCode(s, currency)
        return s.trim { it.isWhitespace() || it == ' ' || it == ' ' }
    }

    private const val MARK = ""

    /** Puts [code] where the locale puts the symbol, with a no-break space between it and the number (ICU's spacing). */
    private fun placeCode(formatted: String, code: String): String {
        val at = formatted.indexOf(MARK)
        if (at < 0) return formatted
        val before = formatted.getOrNull(at - 1)
        val after = formatted.getOrNull(at + MARK.length)
        val lead = if (before != null && before.isDigit()) " " else ""
        val trail = if (after != null && after.isDigit()) " " else ""
        return formatted.substring(0, at) + lead + code + trail + formatted.substring(at + MARK.length)
    }
}

/** An amount the editor cannot store; [message] is shown under the field. */
class AmountException(message: String) : Exception(message)
