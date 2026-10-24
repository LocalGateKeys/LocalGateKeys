package app.localgatekeys.android.settings

import android.content.Context
import android.content.SharedPreferences

/** How long the app may stay in the background before it locks. */
enum class AutoLockDelay(val seconds: Long, val label: String) {
    IMMEDIATELY(0, "Immediately"),
    ONE_MINUTE(60, "After 1 minute"),
    FIVE_MINUTES(300, "After 5 minutes"),
    FIFTEEN_MINUTES(900, "After 15 minutes"),
    ONE_HOUR(3600, "After 1 hour"),
    ;

    companion object {
        fun of(seconds: Long?): AutoLockDelay? = entries.firstOrNull { it.seconds == seconds }
    }
}

/** How long the unlocked app may go without a touch before it locks. Stored as 0 for Never. */
enum class IdleLock(val seconds: Long, val label: String) {
    ONE_MINUTE(60, "1 minute"),
    FIVE_MINUTES(300, "5 minutes"),
    FIFTEEN_MINUTES(900, "15 minutes"),
    THIRTY_MINUTES(1800, "30 minutes"),
    NEVER(0, "Never"),
    ;

    /** Seconds before locking, or null for Never. */
    val limit: Long? get() = if (this == NEVER) null else seconds

    companion object {
        fun of(seconds: Long?): IdleLock? = entries.firstOrNull { it.seconds == seconds }
    }
}

/** When a copied secret leaves the clipboard. There is no "never": copies always expire. */
enum class ClipboardExpiry(val seconds: Long, val label: String) {
    THIRTY_SECONDS(30, "30 seconds"),
    SIXTY_SECONDS(60, "60 seconds"),
    TWO_MINUTES(120, "2 minutes"),
    FIVE_MINUTES(300, "5 minutes"),
    ;

    companion object {
        fun of(seconds: Long?): ClipboardExpiry? = entries.firstOrNull { it.seconds == seconds }
    }
}

enum class Appearance(val raw: String, val label: String) {
    SYSTEM("system", "System"),
    LIGHT("light", "Light"),
    DARK("dark", "Dark"),
    ;

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
        const val COPY_CODE_ON_FILL = "settings.copyCodeOnFill"
        const val APPEARANCE = "settings.appearance"
        const val GENERATOR_OPTIONS = "settings.generatorOptions"
        const val ERASE_PENDING = "settings.erasePending"
        const val INITIALS = "settings.initials"
        const val PLAN_FULL_REVISION = "settings.planFullRevision"
        val all = listOf(
            AUTO_LOCK_DELAY, IDLE_LOCK, CLIPBOARD_EXPIRY, CONCEAL_SECRETS_IN_DETAIL, SHOW_CODES_ROW, COPY_CODE_ON_FILL,
            APPEARANCE, GENERATOR_OPTIONS, ERASE_PENDING, INITIALS, PLAN_FULL_REVISION,
        )
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

    /** The Vault tab's pinned Codes row. */
    var showCodesRow: Boolean
        get() = store.getBoolean(Key.SHOW_CODES_ROW) ?: true
        set(v) = store.putBoolean(Key.SHOW_CODES_ROW, v)

    /** Filling a login also copies its two-factor code. */
    var copyCodeOnFill: Boolean
        get() = store.getBoolean(Key.COPY_CODE_ON_FILL) ?: true
        set(v) = store.putBoolean(Key.COPY_CODE_ON_FILL, v)

    var appearance: Appearance
        get() = Appearance.of(store.getString(Key.APPEARANCE)) ?: Appearance.SYSTEM
        set(v) = store.putString(Key.APPEARANCE, v.raw)

    /** The generator's last-used options (JSON; never a generated value). Null: desktop defaults. */
    var generatorOptions: String?
        get() = store.getString(Key.GENERATOR_OPTIONS)
        set(v) { if (v == null) store.remove(Key.GENERATOR_OPTIONS) else store.putString(Key.GENERATOR_OPTIONS, v) }

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

    /** The avatar letters (Settings, Appearance), at most two; empty shows the person glyph. */
    var initials: String
        get() = store.getString(Key.INITIALS) ?: ""
        set(v) = store.putString(Key.INITIALS, AvatarInitials.from(v) ?: "")

    /**
     * Part of "Erase this phone's vault": removes every preference (durably) except [erasePending], which the lock
     * model sets before the erase and clears only when it succeeded.
     */
    fun eraseAllExceptPending() {
        for (k in Key.all) if (k != Key.ERASE_PENDING) store.remove(k, durable = true)
    }
}
