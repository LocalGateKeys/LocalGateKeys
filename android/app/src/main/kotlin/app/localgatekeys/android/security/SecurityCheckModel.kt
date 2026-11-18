package app.localgatekeys.android.security

import androidx.annotation.StringRes
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.settings.KeyValueStore
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.objectOrNull
import app.localgatekeys.android.vault.stringOrNull
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.TravelMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** One row of the Security check. [raw] is the stable code used in the dismissed list. */
enum class SecurityCategory(val raw: String, @StringRes val label: Int, @StringRes val explanation: Int) {
    BREACHED("breached", R.string.security_cat_breached, R.string.security_expl_breached),

    REUSED("reused", R.string.security_cat_reused, R.string.security_expl_reused),
    WEAK("weak", R.string.security_cat_weak, R.string.security_expl_weak),
    OLD("old", R.string.security_cat_old, R.string.security_expl_old),
    NO_TWO_FACTOR("noTwoFactor", R.string.security_cat_no_2fa, R.string.security_expl_no_2fa),
    HTTP("http", R.string.security_cat_http, R.string.security_expl_http),
    PASSKEY("passkey", R.string.security_cat_passkey, R.string.security_expl_passkey),
    ;

    /** Reused and weak rows offer "Change password"; the 2FA, not-HTTPS and passkey rows do not (iPhone rule). */
    val offersChangePassword: Boolean get() = this != NO_TWO_FACTOR && this != HTTP && this != PASSKEY
}

/**
 * The Security check's three settings, over the app's [KeyValueStore]. Breach checks are off until the person turns
 * them on and are refused while strict offline mode (on by default) is on. The dismissed list is ids only and never
 * synced. Task 5's Settings rows ("Breach checks") read and write [breachCheckEnabled] and [strictOfflineMode].
 */
class SecurityPrefs(private val store: KeyValueStore) {
    var breachCheckEnabled: Boolean
        get() = store.getBoolean(KEY_BREACH_ENABLED) ?: false
        set(value) = store.putBoolean(KEY_BREACH_ENABLED, value)

    var strictOfflineMode: Boolean
        get() = store.getBoolean(KEY_STRICT_OFFLINE) ?: true
        set(value) = store.putBoolean(KEY_STRICT_OFFLINE, value)

    /**
     * Lookalike "same account" answers (autofill save prompt): opaque pair ids only, newest last, at most
     * [MAX_SAME_ACCOUNT] (the extension's cap). Never a site name.
     */
    var sameAccountPairs: List<String>
        get() = (store.getString(KEY_SAME_ACCOUNT) ?: "").split('\n').filter { it.isNotEmpty() }
        set(value) {
            val clean = value.filter { it.isNotEmpty() && '\n' !in it }.distinct().takeLast(MAX_SAME_ACCOUNT)
            if (clean.isEmpty()) store.remove(KEY_SAME_ACCOUNT) else store.putString(KEY_SAME_ACCOUNT, clean.joinToString("\n"))
        }

    /** `category:id` entries. */
    var dismissed: Set<String>
        get() = (store.getString(KEY_DISMISSED) ?: "").split('\n').filter { it.isNotEmpty() }.toSet()
        set(value) {
            val clean = value.filter { '\n' !in it }.sorted()
            if (clean.isEmpty()) store.remove(KEY_DISMISSED) else store.putString(KEY_DISMISSED, clean.joinToString("\n"))
        }

    /** Erase vault, Start fresh, device removal: back to the defaults (breach checks off, strict offline on). */
    fun wipe(): Boolean {
        for (k in listOf(KEY_BREACH_ENABLED, KEY_STRICT_OFFLINE, KEY_DISMISSED, KEY_SAME_ACCOUNT)) store.remove(k, durable = true)
        return true
    }

    companion object {
        const val KEY_BREACH_ENABLED = "settings.breachCheckEnabled"
        const val KEY_STRICT_OFFLINE = "settings.strictOfflineMode"
        const val KEY_DISMISSED = "settings.securityDismissed"
        const val KEY_SAME_ACCOUNT = "settings.lookalikeSameAccountPairs"
        const val MAX_SAME_ACCOUNT = 500
    }
}

/** What the breach section says. Held as a code, not text, so it follows the display language. */
sealed class BreachStatus {
    object Running : BreachStatus()
    object Cancelled : BreachStatus()
    object NoneFound : BreachStatus()
    class Found(val count: Int) : BreachStatus()
    object SomeFailed : BreachStatus()
    object BlockedOffline : BreachStatus()
    object BlockedDisabled : BreachStatus()


    fun text(t: Txt): String = when (this) {
        Running -> t.s(R.string.security_status_checking)
        Cancelled -> t.s(R.string.security_status_cancelled)
        NoneFound -> t.s(R.string.security_status_none_found)
        is Found -> t.s(R.string.security_status_found, count)
        SomeFailed -> t.s(R.string.security_status_some_failed)
        BlockedOffline -> t.s(R.string.security_blocked_offline)
        BlockedDisabled -> t.s(R.string.security_blocked_disabled)
    }
}

data class SecurityState(
    val health: VaultHealth? = null,
    val items: List<VaultItem> = emptyList(),
    val breached: Set<String> = emptySet(),
    val dismissed: Set<String> = emptySet(),
    val running: Boolean = false,
    val status: BreachStatus? = null,
) {
    val score: Int? get() = health?.score
    val band: HealthBand get() = health?.band ?: HealthBand.NONE

    fun ids(category: SecurityCategory): Set<String> {
        val h = health ?: return emptySet()
        val all = when (category) {
            SecurityCategory.BREACHED -> h.breached
            SecurityCategory.REUSED -> h.reused
            SecurityCategory.WEAK -> h.weak
            SecurityCategory.OLD -> h.old
            SecurityCategory.NO_TWO_FACTOR -> h.noTwoFactor
            SecurityCategory.HTTP -> h.insecure
            SecurityCategory.PASSKEY -> h.passkeyAvailable
        }
        return all.filterTo(HashSet()) { SecurityCheckModel.dismissKey(category, it) !in dismissed }
    }

    fun count(category: SecurityCategory): Int = ids(category).size

    /** The category's logins, most recently updated first, then by id (the search order for an empty query). */
    fun items(category: SecurityCategory): List<VaultItem> {
        val wanted = ids(category)
        return items.filter { it.id in wanted }
            .sortedWith(compareByDescending<VaultItem> { it.updatedAt }.thenComparator { a, b -> Scalars.compare(a.id, b.id) })
    }
}

/**
 * The phone's Security check (iPhone `SecurityCheckModel`): the shared [VaultHealth] over the vault's logins,
 * computed when the screen opens and kept in memory only. Breach checks are off by default and refused while strict
 * offline is on; results are memory only too. "Dismiss for this item" hides an item from one row on this phone
 * (stored as ids only, never synced). There is no Pro gate: the iPhone has none on this screen.
 *
 * [scope] runs the breach check; [strength] is the 0..4 password score (the desktop estimator's port).
 */
class SecurityCheckModel(
    private val store: ItemStore,
    private val prefs: SecurityPrefs,
    private val clock: UnixClock,
    private val scope: CoroutineScope,
    private val strength: (String) -> Int,
    private val transport: BreachTransport = HttpsBreachTransport(),
    private val appVersion: String = "",
    private val pauseMillis: Long = 1_500,
    /** Which sites offer TOTP and passkeys (the bundled `site_features.json`); empty = no 2FA or passkey hints. */
    private val featuresSource: () -> SiteFeatures = { SiteFeatures.EMPTY },
) {
    private val features: SiteFeatures get() = featuresSource()

    /**
     * This phone's travel mode (feature pack section 2.3): hidden items are left out of every check. Set by the
     * activity once the unlock's local data is open.
     */
    @Volatile var travel: () -> TravelMode.Setting = { TravelMode.Setting.OFF }

    /** Every live item id of the last [refresh], hidden ones included (dismissals of hidden items are kept). */
    @Volatile private var liveIds: Set<String> = emptySet()

    private val cache = StrengthCache(strength)
    private val _state = MutableStateFlow(SecurityState(dismissed = prefs.dismissed))
    val state: StateFlow<SecurityState> = _state.asStateFlow()
    private var job: Job? = null

    /** Why a breach check cannot start now, null when it can (strict offline first, then the on/off switch). */
    val breachBlocked: BreachStatus?
        get() = when {
            prefs.strictOfflineMode -> BreachStatus.BlockedOffline
            !prefs.breachCheckEnabled -> BreachStatus.BlockedDisabled
            else -> null
        }

    /** Reads the vault again and recomputes. Blocking: call it off the main thread. */
    fun refresh() {
        val snapshot = try { store.load() } catch (e: Exception) { return }
        val all = VaultItem.items(snapshot)
        val hidden = try {
            TravelMode.hiddenIds(snapshot, travel())
        } catch (e: Exception) {
            emptySet()
        }
        liveIds = all.mapTo(HashSet()) { it.id }
        val items = if (hidden.isEmpty()) all else all.filter { it.id !in hidden }
        _state.update { recompute(it.copy(items = items, dismissed = prefs.dismissed)) }
    }

    private fun recompute(s: SecurityState): SecurityState {
        val logins = healthLogins(s.items)
        val ids = logins.mapTo(HashSet()) { it.id }
        val breached = s.breached.intersect(ids)
        return s.copy(
            breached = breached,
            health = VaultHealth.compute(logins, breached, clock.now, cache, features, passkeyDomains(s.items, features)),
        )
    }

    fun dismiss(category: SecurityCategory, id: String) {
        val live = liveIds.ifEmpty { _state.value.items.mapTo(HashSet()) { it.id } }
        // Only for items still in the vault, so the list never grows without bound.
        val next = (_state.value.dismissed + dismissKey(category, id)).filterTo(HashSet()) { key ->
            live.isEmpty() || key.substringAfterLast(':') in live
        }
        prefs.dismissed = next
        _state.update { it.copy(dismissed = next) }
    }

    fun restoreDismissed() {
        prefs.dismissed = emptySet()
        _state.update { it.copy(dismissed = emptySet()) }
    }

    /**
     * Checks every login's password with HIBP (k-anonymity range queries, identical passwords once), only after the
     * person confirmed. Refused in strict offline mode and with breach checks off.
     */
    fun checkBreaches(): Job? {
        val blocked = breachBlocked
        if (_state.value.running || blocked != null) {
            if (blocked != null) _state.update { it.copy(status = blocked) }
            return null
        }
        val logins = healthLogins(_state.value.items)
        val checker = BreachChecker(
            transport, appVersion,
            strictOffline = { prefs.strictOfflineMode },
            enabled = { prefs.breachCheckEnabled },
            pauseMillis = pauseMillis,
        )
        _state.update { it.copy(running = true, status = BreachStatus.Running) }
        val started = scope.launch {
            val result = checker.scan(logins)
            if (result.cancelled) {
                _state.update { it.copy(running = false, status = BreachStatus.Cancelled) }
                return@launch
            }
            _state.update {
                val found = result.breached.size
                recompute(
                    it.copy(
                        running = false,
                        breached = result.breached,
                        status = when {
                            result.failed.isNotEmpty() -> BreachStatus.SomeFailed
                            found == 0 -> BreachStatus.NoneFound
                            else -> BreachStatus.Found(found)
                        },
                    ),
                )
            }
        }
        job = started
        return started
    }

    fun cancelBreachCheck() { job?.cancel() }

    /** Lock: forget the results. */
    fun clear() {
        job?.cancel()
        cache.removeAll()
        _state.value = SecurityState(dismissed = prefs.dismissed)
    }

    companion object {
        /** A login made from a 2FA QR code holds a placeholder password and is left out (the Mac's rule). */
        const val NEEDS_PASSWORD_TAG = "needs-password"

        /** The logins the checks look at. The placeholder password is never sent to HIBP either. */
        fun healthLogins(items: List<VaultItem>): List<HealthLogin> =
            items.filter { it.isLogin && NEEDS_PASSWORD_TAG !in it.tags }.map { item ->
                HealthLogin(
                    id = item.id,
                    title = item.title,
                    password = item.record["password"].stringOrNull() ?: "",
                    hasTotp = item.record["totp"].objectOrNull()?.get("secret").stringOrNull()?.isNotEmpty() == true,
                    updatedAt = if (item.updatedAt > 0) item.updatedAt else null,
                    urls = UrlMatcher.entryUrls(item.record).map { it.url },
                )
            }

        /** Registrable domains that already have a passkey item (the item's `payload.relying_party_id`). */
        fun passkeyDomains(items: List<VaultItem>, features: SiteFeatures): Set<String> =
            items.filter { it.kind == "passkey" }.mapNotNullTo(HashSet()) { item ->
                item.record["payload"].objectOrNull()?.get("relying_party_id").stringOrNull()
                    ?.takeIf { it.isNotBlank() }?.let { features.registrableDomain(it) }
            }

        fun dismissKey(category: SecurityCategory, id: String): String = "${category.raw}:$id"
    }
}
