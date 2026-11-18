package app.localgatekeys.android.settings

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.StringRes
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.vault.VaultSort
import app.localgatekeys.android.vault.VaultSortOption

/** How long the app may stay in the background before it locks. */
enum class AutoLockDelay(val seconds: Long, @StringRes private val labelRes: Int) {
    IMMEDIATELY(0, R.string.autolock_immediately),
    ONE_MINUTE(60, R.string.autolock_one_minute),
    FIVE_MINUTES(300, R.string.autolock_five_minutes),
    FIFTEEN_MINUTES(900, R.string.autolock_fifteen_minutes),
    ONE_HOUR(3600, R.string.autolock_one_hour),
    ;

    fun label(t: Txt): String = t.s(labelRes)

    companion object {
        fun of(seconds: Long?): AutoLockDelay? = entries.firstOrNull { it.seconds == seconds }
    }
}

/** How long the unlocked app may go without a touch before it locks. Stored as 0 for Never. */
enum class IdleLock(val seconds: Long, @StringRes private val labelRes: Int) {
    ONE_MINUTE(60, R.string.idle_one_minute),
    FIVE_MINUTES(300, R.string.idle_five_minutes),
    FIFTEEN_MINUTES(900, R.string.idle_fifteen_minutes),
    THIRTY_MINUTES(1800, R.string.idle_thirty_minutes),
    NEVER(0, R.string.settings_never),
    ;

    fun label(t: Txt): String = t.s(labelRes)

    /** Seconds before locking, or null for Never. */
    val limit: Long? get() = if (this == NEVER) null else seconds

    companion object {
        fun of(seconds: Long?): IdleLock? = entries.firstOrNull { it.seconds == seconds }
    }
}

/** When a copied secret leaves the clipboard. There is no "never": copies always expire. */
enum class ClipboardExpiry(val seconds: Long, @StringRes private val labelRes: Int) {
    THIRTY_SECONDS(30, R.string.clipboard_thirty_seconds),
    SIXTY_SECONDS(60, R.string.clipboard_sixty_seconds),
    TWO_MINUTES(120, R.string.clipboard_two_minutes),
    FIVE_MINUTES(300, R.string.clipboard_five_minutes),
    ;

    fun label(t: Txt): String = t.s(labelRes)

    companion object {
        fun of(seconds: Long?): ClipboardExpiry? = entries.firstOrNull { it.seconds == seconds }
    }
}

enum class Appearance(val raw: String, @StringRes private val labelRes: Int) {
    SYSTEM("system", R.string.settings_appearance_system),
    LIGHT("light", R.string.settings_appearance_light),
    DARK("dark", R.string.settings_appearance_dark),
    ;

    fun label(t: Txt): String = t.s(labelRes)

    companion object {
        fun of(raw: String?): Appearance? = entries.firstOrNull { it.raw == raw }
    }
}

/**
 * Plain key/value storage; a read returns null when the key is absent or holds another type.
 * A write with [durable] true is on disk when the call returns (SharedPreferences.commit), for flags that
 * guard a destructive retry, and throws [SettingsWriteException] when it is not; other writes may reach disk later.
 */
interface KeyValueStore {
    fun getLong(key: String): Long?
    fun getBoolean(key: String): Boolean?
    fun getString(key: String): String?
    fun putLong(key: String, value: Long, durable: Boolean = false)
    fun putBoolean(key: String, value: Boolean, durable: Boolean = false)
    fun putString(key: String, value: String, durable: Boolean = false)
    fun remove(key: String, durable: Boolean = false)
}

/** A durable preference write did not reach the disk. */
class SettingsWriteException : RuntimeException("a setting could not be saved")

class MemoryStore : KeyValueStore {
    private val values = java.util.concurrent.ConcurrentHashMap<String, Any>()
    override fun getLong(key: String): Long? = values[key] as? Long
    override fun getBoolean(key: String): Boolean? = values[key] as? Boolean
    override fun getString(key: String): String? = values[key] as? String
    override fun putLong(key: String, value: Long, durable: Boolean) { values[key] = value }
    override fun putBoolean(key: String, value: Boolean, durable: Boolean) { values[key] = value }
    override fun putString(key: String, value: String, durable: Boolean) { values[key] = value }
    override fun remove(key: String, durable: Boolean) { values.remove(key) }
}

/** [KeyValueStore] over private SharedPreferences. A value of the wrong type reads as absent. */
class SharedPrefsStore(private val prefs: SharedPreferences) : KeyValueStore {
    constructor(context: Context, name: String = "settings") :
        this(context.getSharedPreferences(name, Context.MODE_PRIVATE))

    private inline fun <T> read(block: () -> T): T? = try { block() } catch (e: ClassCastException) { null }

    private fun write(key: String, durable: Boolean, edit: SharedPreferences.Editor.() -> Unit) {
        // commit() updates the in-memory map before it writes the file, so a failed durable write is rolled back
        // in memory too: a flag that is not on disk must not read as set.
        val previous = if (durable) prefs.all[key] else null
        val hadKey = durable && prefs.contains(key)
        val e = prefs.edit()
        e.edit()
        if (!durable) {
            e.apply()
            return
        }
        // A durable write guards a destructive step (erasePending before an erase): a failure must be known.
        if (!e.commit()) {
            val undo = prefs.edit()
            when {
                !hadKey -> undo.remove(key)
                previous is Long -> undo.putLong(key, previous)
                previous is Boolean -> undo.putBoolean(key, previous)
                previous is String -> undo.putString(key, previous)
                previous is Int -> undo.putInt(key, previous)
                previous is Float -> undo.putFloat(key, previous)
                else -> undo.remove(key)
            }
            undo.apply()
            throw SettingsWriteException()
        }
    }

    override fun getLong(key: String): Long? = if (prefs.contains(key)) read { prefs.getLong(key, 0L) } else null
    override fun getBoolean(key: String): Boolean? = if (prefs.contains(key)) read { prefs.getBoolean(key, false) } else null
    override fun getString(key: String): String? = if (prefs.contains(key)) read { prefs.getString(key, null) } else null
    override fun putLong(key: String, value: Long, durable: Boolean) = write(key, durable) { putLong(key, value) }
    override fun putBoolean(key: String, value: Boolean, durable: Boolean) = write(key, durable) { putBoolean(key, value) }
    override fun putString(key: String, value: String, durable: Boolean) = write(key, durable) { putString(key, value) }
    override fun remove(key: String, durable: Boolean) = write(key, durable) { remove(key) }
}

/**
 * Every user preference. Nothing secret is ever stored here: only choices, flags and the generator options.
 * Each read goes to the store. The iPhone-only keys (QuickType, AutoFill identities, website icons) are omitted.
 */
class AppSettings(private val store: KeyValueStore) {
    object Key {
        const val AUTO_LOCK_DELAY = "autoLockDelaySeconds"
        const val IDLE_LOCK = "settings.idleLockSeconds"
        const val CLIPBOARD_EXPIRY = "settings.clipboardExpirySeconds"
        const val CONCEAL_SECRETS_IN_DETAIL = "settings.concealFieldsInDetail"
        const val SHOW_CODES_ROW = "settings.showCodesRow"
        const val PINNED_CODE_IDS = "settings.pinnedCodeIds"
        const val COPY_CODE_ON_FILL = "settings.copyCodeOnFill"
        const val APPEARANCE = "settings.appearance"
        const val GENERATOR_OPTIONS = "settings.generatorOptions"
        const val ERASE_PENDING = "settings.erasePending"
        const val INITIALS = "settings.initials"
        const val PLAN_FULL_REVISION = "settings.planFullRevision"
        const val VAULT_SORT = "settings.listSort"
        const val FAVORITES_FIRST = "settings.listFavoritesFirst"
        const val IMPORT_CARD_DISMISSED = "settings.importCardDismissed"
        const val APP_PASSWORD_FAILURES = "settings.unlockFailures"
        const val HEIR_FOLDERS = "settings.heirFolders"
        const val APP_PASSWORD_LAST_FAILURE = "settings.unlockFailureAt"
        const val APP_PASSWORD_LAST_FAILURE_ELAPSED = "settings.unlockFailureUptime"
        const val APP_PASSWORD_LAST_FAILURE_BOOT = "settings.unlockFailureBoot"
        const val SETUP_DONE = "settings.setupDone"
        const val SETUP_SEEN = "settings.setupSeen"
        const val SETUP_CARD_HIDDEN = "settings.setupCardHidden"
        const val AUTOFILL_SUGGESTIONS = "settings.autofillSuggestions"
        const val PASSKEY_PROVIDER = "settings.passkeyProvider"
        const val ERASE_ON_SYNC_REMOVAL = "settings.eraseOnSyncRemoval"
        const val AUTO_SYNC = "settings.autoSync"
        const val DEVICE_ERASED_NOTICE = "settings.deviceErasedNotice"
        const val NOTES_SHOW_FORMATTING = "settings.notesShowFormatting"
        const val UNLOCK_KEY_FILE_URI = "settings.unlockKeyFileUri"
        const val UNLOCK_KEY_FILE_NAME = "settings.unlockKeyFileName"
        const val FACTORS_ALWAYS_ASK = "settings.factorsAlwaysAsk"
        const val VAULT_COLLECTION = "settings.listCollection"
        const val WIFI_HOST_ON = "settings.wifiHostOn"
        const val WIFI_HOST_PORT = "settings.wifiHostPort"
        const val AUTOFILL_INLINE = "settings.autofillInline"
        const val AUTOFILL_BANNER_DISMISSED = "settings.autofillBannerDismissed"
        val all = listOf(
            AUTO_LOCK_DELAY, IDLE_LOCK, CLIPBOARD_EXPIRY, CONCEAL_SECRETS_IN_DETAIL, SHOW_CODES_ROW, PINNED_CODE_IDS, COPY_CODE_ON_FILL,
            APPEARANCE, GENERATOR_OPTIONS, ERASE_PENDING, INITIALS, PLAN_FULL_REVISION, VAULT_SORT, FAVORITES_FIRST,
            IMPORT_CARD_DISMISSED, APP_PASSWORD_FAILURES, APP_PASSWORD_LAST_FAILURE,
            APP_PASSWORD_LAST_FAILURE_ELAPSED, APP_PASSWORD_LAST_FAILURE_BOOT, SETUP_DONE, SETUP_SEEN, SETUP_CARD_HIDDEN,
            AUTOFILL_SUGGESTIONS, PASSKEY_PROVIDER, ERASE_ON_SYNC_REMOVAL, DEVICE_ERASED_NOTICE,
            NOTES_SHOW_FORMATTING, UNLOCK_KEY_FILE_URI, UNLOCK_KEY_FILE_NAME, FACTORS_ALWAYS_ASK, VAULT_COLLECTION,
            WIFI_HOST_ON, WIFI_HOST_PORT, AUTOFILL_INLINE, AUTOFILL_BANNER_DISMISSED,
        )

        /** Kept by [eraseAllExceptPending]: the erase flag and the one-time notice that an erase on removal happened. */
        val keptByErase = setOf(ERASE_PENDING, DEVICE_ERASED_NOTICE)
    }

    var autoLockDelay: AutoLockDelay
        get() = AutoLockDelay.of(store.getLong(Key.AUTO_LOCK_DELAY)) ?: AutoLockDelay.IMMEDIATELY
        set(v) = store.putLong(Key.AUTO_LOCK_DELAY, v.seconds)

    var idleLock: IdleLock
        get() = IdleLock.of(store.getLong(Key.IDLE_LOCK)) ?: IdleLock.FIVE_MINUTES
        set(v) = store.putLong(Key.IDLE_LOCK, v.seconds)

    var clipboardExpiry: ClipboardExpiry
        get() = ClipboardExpiry.of(store.getLong(Key.CLIPBOARD_EXPIRY)) ?: ClipboardExpiry.SIXTY_SECONDS
        set(v) = store.putLong(Key.CLIPBOARD_EXPIRY, v.seconds)

    /** Item detail shows protected fields masked until the eye is tapped. */
    var concealSecretsInDetail: Boolean
        get() = store.getBoolean(Key.CONCEAL_SECRETS_IN_DETAIL) ?: true
        set(v) = store.putBoolean(Key.CONCEAL_SECRETS_IN_DETAIL, v)

    /** Onboarding steps finished on this phone (their raw names, comma separated); never synced. */
    var setupDone: Set<String>
        get() = store.getString(Key.SETUP_DONE)?.split(',')?.filter { it.isNotEmpty() }?.toSet() ?: emptySet()
        set(v) = store.putString(Key.SETUP_DONE, v.sorted().joinToString(","))

    /** The onboarding pages were shown (finished or skipped) on this phone. */
    var setupSeen: Boolean
        get() = store.getBoolean(Key.SETUP_SEEN) ?: false
        set(v) = store.putBoolean(Key.SETUP_SEEN, v)

    /** Notes show Markdown formatting (the desktop's `notes_show_formatting`); this phone only. */
    var notesShowFormatting: Boolean
        get() = store.getBoolean(Key.NOTES_SHOW_FORMATTING) ?: true
        set(v) = store.putBoolean(Key.NOTES_SHOW_FORMATTING, v)

    /** Hide on the vault's "Finish setting up" card. */
    var setupCardHidden: Boolean
        get() = store.getBoolean(Key.SETUP_CARD_HIDDEN) ?: false
        set(v) = store.putBoolean(Key.SETUP_CARD_HIDDEN, v)

    /** "Not now" on the empty vault's "Import your passwords" card (this phone only). */
    var importCardDismissed: Boolean
        get() = store.getBoolean(Key.IMPORT_CARD_DISMISSED) ?: false
        set(v) = store.putBoolean(Key.IMPORT_CARD_DISMISSED, v)

    /** The Vault tab's pinned Codes row. */
    var showCodesRow: Boolean
        get() = store.getBoolean(Key.SHOW_CODES_ROW) ?: true
        set(v) = store.putBoolean(Key.SHOW_CODES_ROW, v)

    /**
     * The item ids pinned for the home-screen codes widget, in pin order (ids only, never a secret or a title; the
     * codes are read from the open vault). This phone only. See `codes.PinnedCodes` for the rules.
     */
    var pinnedCodeIds: List<String>
        get() = store.getString(Key.PINNED_CODE_IDS)?.split(',')?.filter { it.isNotEmpty() } ?: emptyList()
        set(v) = if (v.isEmpty()) store.remove(Key.PINNED_CODE_IDS) else store.putString(Key.PINNED_CODE_IDS, v.joinToString(","))

    /** Filling a login also copies its two-factor code. */
    var copyCodeOnFill: Boolean
        get() = store.getBoolean(Key.COPY_CODE_ON_FILL) ?: true
        set(v) = store.putBoolean(Key.COPY_CODE_ON_FILL, v)

    /** Part C: "Show logins in suggestions": off, autofill offers only "Unlock LocalGateKeys" (no titles or usernames). */
    var autofillSuggestions: Boolean
        get() = store.getBoolean(Key.AUTOFILL_SUGGESTIONS) ?: true
        set(v) = store.putBoolean(Key.AUTOFILL_SUGGESTIONS, v)

    /**
     * Review 2026-11-15 UX 2: "Show in keyboard": on Android 11+ the matching logins also show as chips in the keyboard's
     * suggestion strip (when the keyboard asks for them). On by default; off, only the dropdown under the field shows.
     */
    var autofillInline: Boolean
        get() = store.getBoolean(Key.AUTOFILL_INLINE) ?: true
        set(v) = store.putBoolean(Key.AUTOFILL_INLINE, v)

    /** "Not now" on the Vault list's "Turn on autofill" banner (this phone only). */
    var autofillBannerDismissed: Boolean
        get() = store.getBoolean(Key.AUTOFILL_BANNER_DISMISSED) ?: false
        set(v) = store.putBoolean(Key.AUTOFILL_BANNER_DISMISSED, v)

    /** Part C: "Offer LocalGateKeys for passkeys" (the desktop's `passkeys_enabled`). */
    var passkeyProvider: Boolean
        get() = store.getBoolean(Key.PASSKEY_PROVIDER) ?: true
        set(v) = store.putBoolean(Key.PASSKEY_PROVIDER, v)

    var appearance: Appearance
        get() = Appearance.of(store.getString(Key.APPEARANCE)) ?: Appearance.SYSTEM
        set(v) = store.putString(Key.APPEARANCE, v.raw)

    /** The generator's last-used options (JSON; never a generated value). Null: desktop defaults. */
    var generatorOptions: String?
        get() = store.getString(Key.GENERATOR_OPTIONS)
        set(v) { if (v == null) store.remove(Key.GENERATOR_OPTIONS) else store.putString(Key.GENERATOR_OPTIONS, v) }

    /**
     * "Erase this device if it is removed from sync" (desktop `erase_on_sync_removal`), default on: a signed removal
     * notice from another member erases this phone's vault. Off: the Sync screen says the phone was removed, nothing
     * is erased.
     */
    var eraseOnSyncRemoval: Boolean
        get() = store.getBoolean(Key.ERASE_ON_SYNC_REMOVAL) ?: true
        set(v) = store.putBoolean(Key.ERASE_ON_SYNC_REMOVAL, v, durable = true)

    /**
     * "Sync automatically", default on: sync at unlock, on coming back to the app and after an edit. Off: only
     * "Sync now" and pull-to-refresh sync.
     */
    var autoSync: Boolean
        get() = store.getBoolean(Key.AUTO_SYNC) ?: true
        set(v) = store.putBoolean(Key.AUTO_SYNC, v)

    /** Set before an erase on removal, shown once after it ("A vault was erased from this phone") until dismissed. */
    var deviceErasedNotice: Boolean
        get() = store.getBoolean(Key.DEVICE_ERASED_NOTICE) ?: false
        set(v) = store.putBoolean(Key.DEVICE_ERASED_NOTICE, v, durable = true)

    /** Set before an erase starts and cleared only when it succeeds; while set the app retries the erase before unlocking. */
    var erasePending: Boolean
        get() = store.getBoolean(Key.ERASE_PENDING) ?: false
        set(v) = store.putBoolean(Key.ERASE_PENDING, v, durable = true)

    /** The store revision at which the free plan was full with no valid synced licence (written on commit), or null. */
    var planFullRevision: Long?
        get() = store.getLong(Key.PLAN_FULL_REVISION)
        set(v) {
            if (v == null) store.remove(Key.PLAN_FULL_REVISION, durable = true)
            else store.putLong(Key.PLAN_FULL_REVISION, v, durable = true)
        }

    /** The vault list's sort (this phone only, never synced). Default: newest modified first. */
    var vaultSort: VaultSort
        get() = VaultSort(
            VaultSortOption.of(store.getString(Key.VAULT_SORT)) ?: VaultSortOption.MODIFIED_DESC,
            store.getBoolean(Key.FAVORITES_FIRST) ?: false,
        )
        set(v) {
            store.putString(Key.VAULT_SORT, v.option.raw)
            store.putBoolean(Key.FAVORITES_FIRST, v.favoritesFirst)
        }

    /** The Vault list's Collections filter (a collection id; null: All items). This phone only, never synced. */
    var vaultCollection: String?
        get() = store.getString(Key.VAULT_COLLECTION)
        set(v) = if (v == null) store.remove(Key.VAULT_COLLECTION) else store.putString(Key.VAULT_COLLECTION, v)

    /** The avatar letters (Settings, Appearance), at most two; empty shows the person glyph. */
    var initials: String
        get() = store.getString(Key.INITIALS) ?: ""
        set(v) = store.putString(Key.INITIALS, AvatarInitials.from(v) ?: "")

    /**
     * The emergency access folders' tree URIs (sub-plan 08): their persisted permissions are kept when the sync folder
     * changes ([app.localgatekeys.android.sync.SafFolderOpener.keepOnly]). Which vault uses which is in that vault.
     */
    var heirFolders: Set<String>
        get() = store.getString(Key.HEIR_FOLDERS)?.split('\n')?.filter { it.isNotEmpty() }?.toSet() ?: emptySet()
        set(v) = store.putString(Key.HEIR_FOLDERS, v.sorted().joinToString("\n"), durable = true)

    /** Consecutive wrong app passwords or recovery phrases (the wrong-try delay); never the password itself. */
    var appPasswordFailures: Int
        get() = (store.getLong(Key.APP_PASSWORD_FAILURES) ?: 0L).toInt()
        set(v) = store.putLong(Key.APP_PASSWORD_FAILURES, v.toLong(), durable = true)

    /** Unix seconds of the last wrong app password. */
    var appPasswordLastFailureAt: Long
        get() = store.getLong(Key.APP_PASSWORD_LAST_FAILURE) ?: 0L
        set(v) = store.putLong(Key.APP_PASSWORD_LAST_FAILURE, v, durable = true)

    /** Monotonic seconds since boot at the last wrong app password (-1: none), and that boot's count. */
    var appPasswordLastFailureElapsed: Long
        get() = store.getLong(Key.APP_PASSWORD_LAST_FAILURE_ELAPSED) ?: -1L
        set(v) = store.putLong(Key.APP_PASSWORD_LAST_FAILURE_ELAPSED, v, durable = true)

    var appPasswordLastFailureBoot: Long
        get() = store.getLong(Key.APP_PASSWORD_LAST_FAILURE_BOOT) ?: -1L
        set(v) = store.putLong(Key.APP_PASSWORD_LAST_FAILURE_BOOT, v, durable = true)

    /**
     * Task 9: the app password's key file as a content URI with a persisted read permission (null: none remembered; ""
     * "Don't remember"). Only the location: the file is never copied. Device-only, like every setting here.
     */
    var unlockKeyFileUri: String?
        get() = store.getString(Key.UNLOCK_KEY_FILE_URI)
        set(v) = if (v == null) store.remove(Key.UNLOCK_KEY_FILE_URI, durable = true) else store.putString(Key.UNLOCK_KEY_FILE_URI, v, durable = true)

    /** The remembered key file's display name (shown on the unlock screen). */
    var unlockKeyFileName: String
        get() = store.getString(Key.UNLOCK_KEY_FILE_NAME) ?: ""
        set(v) = store.putString(Key.UNLOCK_KEY_FILE_NAME, v, durable = true)

    /** Task 9: "Always ask for the key file / YubiKey": no fingerprint shortcut while factors are set. */
    var factorsAlwaysAsk: Boolean
        get() = store.getBoolean(Key.FACTORS_ALWAYS_ASK) ?: false
        set(v) = store.putBoolean(Key.FACTORS_ALWAYS_ASK, v, durable = true)

    /** "Host Wi-Fi sync on this phone" (the Sync screen's Wi-Fi card): off by default. */
    var wifiHostOn: Boolean
        get() = store.getBoolean(Key.WIFI_HOST_ON) ?: false
        set(v) = store.putBoolean(Key.WIFI_HOST_ON, v, durable = true)

    /** The port the Wi-Fi host last listened on (tried first on every start); null: none saved, or not a valid port. */
    var wifiHostPort: Int?
        get() = store.getLong(Key.WIFI_HOST_PORT)?.takeIf { it in 1..65535 }?.toInt()
        set(v) {
            if (v == null || v !in 1..65535) store.remove(Key.WIFI_HOST_PORT) else store.putLong(Key.WIFI_HOST_PORT, v.toLong())
        }

    /**
     * Part of "Erase this phone's vault": removes every preference (durably) except [erasePending], which the lock
     * model sets before the erase and clears only when it succeeded, and [deviceErasedNotice] (shown after the erase).
     */
    fun eraseAllExceptPending() {
        for (k in Key.all) if (k !in Key.keptByErase) store.remove(k, durable = true)
    }
}
