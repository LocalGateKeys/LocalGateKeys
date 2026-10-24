package app.localgatekeys.core.json

import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode

/**
 * Formats a finite Double exactly like Python 3's `repr(float)`.
 *
 * Correctness relies on `BigDecimal.toDouble()` rounding correctly (true on JDK 17+; older JDKs could be off by one ulp).
 */
object PythonFloat {
    fun repr(value: Double): String {
        require(value.isFinite()) { "non-finite" }
        val negative = value < 0.0 || (value == 0.0 && 1.0 / value < 0.0)
        if (value == 0.0) return if (negative) "-0.0" else "0.0"

        // Shortest digit string that round-trips (JDK 17's Double.toString is not always shortest).
        val mag = Math.abs(value)
        val exact = BigDecimal(mag)
        var digits = "0"
        var pointPos = 1 // decimal point position relative to `digits`
        for (p in 1..17) {
            // The nearest p-digit decimal may miss the rounding interval while its neighbour hits it
            // (Python's repr picks any shortest string that round-trips, closest first).
            val near = exact.round(MathContext(p, RoundingMode.HALF_EVEN))
            val other = exact.round(
                MathContext(p, if (near < exact) RoundingMode.CEILING else RoundingMode.FLOOR),
            )
            val r = when {
                near.toDouble() == mag -> near
                other.toDouble() == mag -> other
                else -> null
            }
            if (r != null) {
                val unscaled = r.unscaledValue().toString()
                digits = unscaled
                pointPos = unscaled.length - r.scale()
                break
            }
        }
        digits = digits.trimEnd('0').ifEmpty { "0" }

        val sciExp = pointPos - 1
        val sb = StringBuilder()
        if (negative) sb.append('-')
        if (sciExp < -4 || sciExp >= 16) {
            sb.append(digits[0])
            if (digits.length > 1) sb.append('.').append(digits, 1, digits.length)
            sb.append('e').append(if (sciExp < 0) '-' else '+')
            val e = Math.abs(sciExp).toString()
            if (e.length < 2) sb.append('0')
            sb.append(e)
        } else if (pointPos <= 0) {
            sb.append("0.").append("0".repeat(-pointPos)).append(digits)
        } else if (pointPos >= digits.length) {
            sb.append(digits).append("0".repeat(pointPos - digits.length)).append(".0")
        } else {
            sb.append(digits, 0, pointPos).append('.').append(digits, pointPos, digits.length)
        }
        return sb.toString()
    }
}
