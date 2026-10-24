package app.localgatekeys.core.keyring

/** A keyring error; [reason] is the desktop `KeyringError.reason` string, tests assert it verbatim. */
class KeyringException(val reason: String, val detail: String = "") :
    Exception(if (detail.isEmpty()) reason else "$reason: $detail")
