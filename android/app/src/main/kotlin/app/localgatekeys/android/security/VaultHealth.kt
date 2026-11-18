package app.localgatekeys.android.security

import androidx.annotation.StringRes
import app.localgatekeys.android.R
import app.localgatekeys.core.records.UrlMatcher
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/** The parts of a login that vault health looks at (iPhone `HealthLogin`). */
class HealthLogin(
    val id: String,
    val title: String,
    val password: String,
    val hasTotp: Boolean,
    /** Unix seconds; null = unknown, never counted as old. */
    val updatedAt: Long?,
    /** Every saved URL (`scope.origin`, `scope.urls[].url`), for the not-HTTPS and site feature checks. */
    val urls: List<String> = emptyList(),
) {
    /** Never shows the password. */
    override fun toString(): String = "HealthLogin(id=$id)"
}

/**
 * Memoises strength scores by SHA-256 of the password, so repeated health computations do not re-run the
 * estimator. Holds digests and scores only (iPhone `StrengthCache`).
 */
class StrengthCache(private val estimate: (String) -> Int) {
    private val scores = ConcurrentHashMap<String, Int>()

    fun score(password: String, digest: String): Int = scores.getOrPut(digest) { estimate(password) }

    /** Forgets every cached score (call on lock). */
    fun removeAll() = scores.clear()
}

/** The word that goes with the score. A resource id, so it follows the display language. */
enum class HealthBand(@StringRes val label: Int) {
    NONE(R.string.security_band_none),
    GOOD(R.string.security_band_good),
    FAIR(R.string.security_band_fair),
    POOR(R.string.security_band_poor),
}

/** Vault-wide health, matching the desktop `vault_health` and overview score (iPhone `VaultHealth`). */
class VaultHealth private constructor(
    val total: Int,
    val weak: Set<String>,
    val reused: Set<String>,
    /** The site supports TOTP and the login has none; empty without site features. */
    val noTwoFactor: Set<String>,
    /** Not part of the score; shown in the Security check only. */
    val old: Set<String>,
    val breached: Set<String>,
    /** Not part of the score: a saved URL is plain http:// on a host that is not loopback. */
    val insecure: Set<String>,
    /** Not part of the score: the site supports passkeys and none is saved for its registrable domain. */
    val passkeyAvailable: Set<String>,
    /** Null when there are no logins. */
    val score: Int?,
    val band: HealthBand,
    /** Logins counted against the score: weak, reused or breached. */
    val attention: Set<String>,
) {
    companion object {
        const val OLD_AFTER_SECONDS: Long = 365L * 86_400L

        fun digest(password: String): String =
            MessageDigest.getInstance("SHA-256").digest(password.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

        fun compute(
            logins: List<HealthLogin>,
            breached: Set<String>,
            now: Long,
            cache: StrengthCache,
            features: SiteFeatures = SiteFeatures.EMPTY,
            passkeyDomains: Set<String> = emptySet(),
        ): VaultHealth {
            val weak = HashSet<String>()
            val noTwoFactor = HashSet<String>()
            val old = HashSet<String>()
            val insecure = HashSet<String>()
            val passkeyAvailable = HashSet<String>()
            val byDigest = HashMap<String, MutableList<String>>()
            val ids = logins.mapTo(HashSet()) { it.id }
            for (login in logins) {
                if (login.password.isEmpty()) {
                    weak.add(login.id)
                } else {
                    val d = digest(login.password)
                    byDigest.getOrPut(d) { ArrayList() }.add(login.id)
                    if (cache.score(login.password, d) <= 1) weak.add(login.id)
                }
                val web = UrlMatcher.webHosts(login.urls)
                if (web.insecure) insecure.add(login.id)
                val domains = if (features.isEmpty) emptySet() else web.hosts.mapNotNullTo(HashSet()) { features.registrableDomain(it) }
                if (!login.hasTotp && domains.any { features.supports(it, "totp") }) noTwoFactor.add(login.id)
                if (domains.any { features.supports(it, "passkey") && it !in passkeyDomains }) passkeyAvailable.add(login.id)
                val updated = login.updatedAt
                if (updated != null && now - updated > OLD_AFTER_SECONDS) old.add(login.id)
            }
            val reused = byDigest.values.filter { it.size > 1 }.flatten().toSet()
            val breachedLogins = breached.intersect(ids)
            val attention = weak + reused + breachedLogins
            val total = logins.size
            // Round half to even, like Swift `.toNearestOrEven` and Python `round`.
            val score: Int? = if (total == 0) null else Math.rint(100.0 * (total - attention.size) / total).toInt()
            val band = when {
                score == null -> HealthBand.NONE
                score >= 80 -> HealthBand.GOOD
                score >= 50 -> HealthBand.FAIR
                else -> HealthBand.POOR
            }
            return VaultHealth(total, weak, reused, noTwoFactor, old, breachedLogins, insecure, passkeyAvailable, score, band, attention)
        }
    }
}
