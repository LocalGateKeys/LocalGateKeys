package app.localgatekeys.android.editor

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.totp.TotpException

/** The 2FA secret field's messages, by the core's stable error kind (the core's own English is for logs and tests). */
object TotpText {
    fun message(e: TotpException, t: Txt): String = t.s(
        when (e.kind) {
            TotpException.Kind.EMPTY_SECRET -> R.string.totp_empty_secret
            TotpException.Kind.INVALID_BASE32, TotpException.Kind.INVALID_SECRET_LENGTH -> R.string.totp_invalid_base32
            TotpException.Kind.SECRET_TOO_SHORT -> R.string.totp_secret_too_short
            TotpException.Kind.SECRET_TOO_LONG -> R.string.totp_secret_too_long
            TotpException.Kind.UNSUPPORTED_DIGITS -> R.string.totp_unsupported_digits
            TotpException.Kind.UNSUPPORTED_PERIOD -> R.string.totp_unsupported_period
            TotpException.Kind.UNSUPPORTED_ALGORITHM -> R.string.totp_unsupported_algorithm
            TotpException.Kind.NOT_OTPAUTH_URI -> R.string.totp_not_otpauth
            TotpException.Kind.DUPLICATE_PARAMETER, TotpException.Kind.INVALID_PARAMETER -> R.string.totp_invalid_parameter
            TotpException.Kind.LABEL_TOO_LONG -> R.string.totp_label_too_long
            TotpException.Kind.INVALID_TIMESTAMP -> R.string.totp_invalid_secret
        },
    )
}
