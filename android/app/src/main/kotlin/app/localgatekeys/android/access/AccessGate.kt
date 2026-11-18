package app.localgatekeys.android.access

import app.localgatekeys.core.access.AccessRules
import app.localgatekeys.core.json.JsonValue
import java.time.LocalDate

/**
 * This phone's reading of a login's access rules (feature pack 2026-11-15, contract section 4): the synced
 * `policy.require_master_password` / `policy.fill` plus `scope.access`, unknown = strictest. Enforcement never depends
 * on the plan.
 */
object AccessGate {
    fun today(): String = LocalDate.now().toString()

    fun effective(record: Map<String, JsonValue>, today: String = today()): AccessRules.Effective =
        AccessRules.effective(record, AccessRules.DeviceClass.PHONE, today)

    /** Whether autofill (the service, the keyboard chips, the credential provider) may offer and fill [record]. */
    fun mayFill(record: Map<String, JsonValue>, today: String = today()): Boolean = effective(record, today).autofill

    /** What a reveal, a copy or a fill of [record] needs on this phone. */
    enum class Need { NOTHING, OWNER, REFUSED }

    /** A reveal: view-only on phones still reveals (with the owner's check); re-authenticate asks every time. */
    fun reveal(e: AccessRules.Effective): Need = if (e.reauth || e.phoneView) Need.OWNER else Need.NOTHING

    /**
     * A copy of one of the item's secrets: refused when view-only on phones; the owner's check when re-authenticate is on
     * or when copy-once was already used in this unlock ([copiedBefore]).
     */
    fun copy(e: AccessRules.Effective, copiedBefore: Boolean): Need = when {
        e.phoneView -> Need.REFUSED
        e.reauth || (e.copyOnce && copiedBefore) -> Need.OWNER
        else -> Need.NOTHING
    }

    /** A fill chosen in the fill sheet or the credential provider: refused unless [mayFill]; the owner's check when [AccessRules.Effective.reauth]. */
    fun fill(e: AccessRules.Effective, unlockedJustNow: Boolean): Need = when {
        !e.autofill -> Need.REFUSED
        e.reauth && !unlockedJustNow -> Need.OWNER
        else -> Need.NOTHING
    }

    /** Opening the editor, which can show the secrets: the owner's check under the same rules as a reveal (scan A-H3). */
    fun edit(e: AccessRules.Effective): Need = if (e.reauth || e.phoneView || e.expired || e.unknownRule) Need.OWNER else Need.NOTHING

    /**
     * Whether a secret of [record] (password, two-factor code) may be shown or copied from a surface outside the item's
     * detail screen: the long-press menu, the Codes row, the codes widget and the quick settings tile. Those surfaces
     * have no owner check and no copy-once ledger, so any rule that asks for one (re-authenticate, copy once, view
     * only on phones, expired, an unknown rule) keeps the secret in the detail screen only.
     */
    fun mayQuickCopy(record: Map<String, JsonValue>, today: String = today()): Boolean {
        val e = effective(record, today)
        return !(e.reauth || e.copyOnce || e.phoneView || e.expired || e.unknownRule)
    }

    /** Seconds the clipboard keeps a copy-once item's first copy (or the person's shorter setting). */
    const val COPY_ONCE_SECONDS = 10L
}

/** The items copied once in this unlock (copy-once rule). Memory only; cleared at lock. */
class CopyOnceLedger {
    private val copied = HashSet<String>()

    @Synchronized
    fun copiedBefore(id: String): Boolean = id in copied

    @Synchronized
    fun note(id: String) {
        copied.add(id)
    }

    @Synchronized
    fun clear() = copied.clear()
}
