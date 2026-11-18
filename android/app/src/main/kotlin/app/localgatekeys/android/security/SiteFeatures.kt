package app.localgatekeys.android.security

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.UrlMatcher

/**
 * Which sites offer two-factor codes (TOTP) or passkeys, from the bundled `site_features.json` (desktop
 * `site_features.SiteFeatures`; iPhone `SiteFeatures`). Keys of the data file are registrable domains; [supports]
 * reduces any host the same way before looking it up, so `login.github.com` finds `github.com`.
 */
class SiteFeatures(sites: Map<String, Set<String>> = emptyMap(), private val matcher: UrlMatcher? = null) {
    private val sites: Map<String, Set<String>> = sites.entries.associate { (domain, features) ->
        domain.lowercase() to features.filterTo(HashSet()) { it in FEATURES }
    }

    val isEmpty: Boolean get() = sites.isEmpty()

    /** The registrable domain of [host], null when it does not parse (desktop `base_domain`). */
    fun registrableDomain(host: String): String? = try {
        (matcher ?: UrlMatcher(null)).baseDomain(host.trim().lowercase())
    } catch (_: Exception) {
        null
    }

    fun supports(host: String, feature: String): Boolean {
        val domain = registrableDomain(host) ?: return false
        return sites[domain]?.contains(feature) == true
    }

    companion object {
        val FEATURES = setOf("passkey", "totp")
        val EMPTY = SiteFeatures()

        /** A missing or malformed file gives an empty map (no hints). */
        fun parse(json: ByteArray, matcher: UrlMatcher?): SiteFeatures = try {
            val root = (CanonicalJson.parse(json) as? JsonValue.Obj)?.fields
            val raw = (root?.get("sites") as? JsonValue.Obj)?.fields
            if (raw == null) {
                EMPTY
            } else {
                val sites = HashMap<String, Set<String>>()
                for ((domain, list) in raw) {
                    val items = (list as? JsonValue.Arr)?.items ?: continue
                    sites[domain] = items.mapNotNullTo(HashSet()) { (it as? JsonValue.Str)?.v }
                }
                SiteFeatures(sites, matcher)
            }
        } catch (_: Exception) {
            EMPTY
        }
    }
}
