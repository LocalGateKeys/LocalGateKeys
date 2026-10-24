package app.localgatekeys.android.vault

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.totp.Totp

/** The current two-factor code of an item and how long it lasts. */
data class TotpState(val code: String, val period: Int, val secondsRemaining: Int) {
    val fractionRemaining: Double get() = secondsRemaining.toDouble() / period

    /** Never shows the code. */
    override fun toString(): String = "TotpState(period=$period, secondsRemaining=$secondsRemaining)"

    companion object {
        /**
         * From `record.totp` {secret, algorithm (SHA1), digits (6), period (30)} at [now] (Unix seconds); null when the
         * item has none or the secret or settings do not give a code.
         */
        fun of(item: VaultItem, now: Long): TotpState? {
            val t = item.record["totp"].objectOrNull() ?: return null
            val secret = t["secret"].stringOrNull() ?: return null
            val algorithm = t["algorithm"].stringOrNull() ?: "SHA1"
            val digits = (t["digits"] as? JsonValue.Int)?.v ?: 6L
            val period = (t["period"] as? JsonValue.Int)?.v ?: 30L
            if (digits !in 1..64 || period !in 1..86_400) return null
            return try {
                val code = Totp.code(secret, algorithm, digits.toInt(), period.toInt(), now)
                TotpState(code, period.toInt(), (period - now % period).toInt())
            } catch (_: Exception) {
                null
            }
        }
    }
}
