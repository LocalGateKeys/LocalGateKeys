package app.localgatekeys.android.security

import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.records.UrlMatcher

/**
 * The passkey upgrade prompt on a login's detail screen (feature pack contract 2026-11-15 section 6.3): a `web` login
 * whose registrable domain lists `passkey` in the bundled site features, with no `passkey` item for that domain (the
 * same rule as the Security check's passkey finding). "Not now" is remembered per device in the local data
 * (`passkey_upgrade_dismissed`) and the prompt comes back after [SHOW_AGAIN_SECONDS]. Never touches the password.
 */
object PasskeyUpgrade {
    const val SHOW_AGAIN_SECONDS: Long = 90L * 86_400L

    /** The registrable domain the prompt is about for [login], or null when there is nothing to offer. */
    fun domain(login: VaultItem, items: List<VaultItem>, features: SiteFeatures): String? {
        if (login.kind != "web" || features.isEmpty) return null
        val hosts = UrlMatcher.webHosts(UrlMatcher.entryUrls(login.record).map { it.url }).hosts
        val have = SecurityCheckModel.passkeyDomains(items, features)
        return hosts.mapNotNull { features.registrableDomain(it) }.distinct().sorted()
            .firstOrNull { features.supports(it, "passkey") && it !in have }
    }

    /** Whether a prompt for [domain] shows at [now], given this phone's dismissals (domain -> Unix seconds). */
    fun shows(domain: String, dismissed: Map<String, Long>, now: Long): Boolean {
        val at = dismissed[domain] ?: return true
        return now - at >= SHOW_AGAIN_SECONDS
    }
}
