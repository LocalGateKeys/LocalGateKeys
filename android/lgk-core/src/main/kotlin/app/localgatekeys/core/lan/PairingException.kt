package app.localgatekeys.core.lan

/**
 * A refused or malformed pairing step (Swift `PairingError`, desktop `sync.pairing.PairingError` family).
 *
 * [detail] is the Swift associated value: the message for [Kind.MALFORMED] and [Kind.AUTHENTICATION],
 * the refusal reason (one of `Enrollment.REFUSAL_REASONS`) for [Kind.REFUSED], empty for [Kind.EXPIRED].
 */
class PairingException(val kind: Kind, val detail: String = "") : Exception("${kind.name.lowercase()}: $detail") {
    enum class Kind { MALFORMED, EXPIRED, AUTHENTICATION, REFUSED }
}
