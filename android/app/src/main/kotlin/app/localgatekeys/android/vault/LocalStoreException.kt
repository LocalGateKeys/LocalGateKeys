package app.localgatekeys.android.vault

/**
 * A [LocalStore] failure. [detail] is a short, fixed description (a file name, a step, revisions); it never
 * holds item text, key material or file contents.
 *
 * - [NO_LOCAL_KEY]: the app has not been set up on this device (raised by the unlock layer, which owns the key).
 * - [BAD_LOCAL_KEY]: the key is not 32 bytes (or the store was closed).
 * - [VAULT_WITHOUT_KEY]: store files are present but the local key is not (raised by the unlock layer).
 * - [STALE]: a commit was based on an older revision.
 * - [CORRUPT]: damage or tampering; never silently rolled back.
 * - [IO]: the disk refused or a file is missing.
 */
class LocalStoreException(val kind: Kind, val detail: String = "") :
    Exception(if (detail.isEmpty()) kind.name else "${kind.name}: $detail") {
    enum class Kind { NO_LOCAL_KEY, BAD_LOCAL_KEY, VAULT_WITHOUT_KEY, STALE, CORRUPT, IO }
}
