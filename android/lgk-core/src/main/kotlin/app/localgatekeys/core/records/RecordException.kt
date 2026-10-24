package app.localgatekeys.core.records

/**
 * A record-level sync failure. [reason]: `update-needed`, `bad-remote` (both name [itemId]) or
 * `vault-changed`; a null reason means a malformed call (programming error, never a peer's fault).
 */
class RecordException(val reason: String?, val itemId: String?, val detail: String) :
    Exception("${reason ?: "error"}: ${itemId ?: "-"}: $detail")
