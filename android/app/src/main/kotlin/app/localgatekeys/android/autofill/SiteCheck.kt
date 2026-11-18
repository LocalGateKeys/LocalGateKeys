package app.localgatekeys.android.autofill

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.core.security.Lookalike
import app.localgatekeys.core.sync.StoreSnapshot
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** What the save prompt says about the site it is saving for (extension "Verified site" states and guard). */
sealed interface SitePrompt {
    data object Verified : SitePrompt

    data object Related : SitePrompt

    data object New : SitePrompt

    /** A lookalike of [savedHost] (null for a mixed-script host): "Go back" first, or "Continue on [host]". */
    data class Guard(val host: String, val savedHost: String?) : SitePrompt

    /** The same name as [savedHost] on another ending: asked once; "Same account" remembers [pair]. */
    data class SameAccount(val host: String, val savedHost: String, val pair: String) : SitePrompt

    /**
     * A login picked by hand from the search list for a page it is not known to belong to: [otherSite] when it is
     * saved for [savedHost] (null: no website) and not for [host]; [schemeKnown] false when the browser did not say
     * whether the page is https. "Go back" first, or "Continue on [host]".
     */
    data class Mismatch(val host: String, val savedHost: String?, val otherSite: Boolean, val schemeKnown: Boolean) : SitePrompt

    /**
     * A login picked by hand for an app ([packageName]) it is not yet paired with (audit A3): nothing ties the app to
     * [savedHost] (null: no website), so "Go back" first, or "Fill in [packageName]" (which pairs it).
     */
    data class UnverifiedApp(val packageName: String, val savedHost: String?) : SitePrompt
}

/**
 * The phishing check of the autofill save prompt, on the phone only: the page origin (from a trusted browser) is
 * classified with the core [Lookalike] against every URL row of the vault's web logins, after unlock.
 */
object SiteCheck {
    private const val PAIR_INFO = "localgatekeys|site-pair|v1"

    /** Every URL row of every live web login (desktop broker `_saved_web_origins`), de-duplicated in order. */
    fun savedOrigins(s: StoreSnapshot): List<String> {
        val out = LinkedHashSet<String>()
        for ((id, w) in s.records) {
            if (s.meta[id]?.deleted == true) continue
            val f = (w as? JsonValue.Obj)?.fields ?: continue
            if (f["ns"] != JsonValue.Str(Namespace.ENTRY.wire)) continue
            val r = (f["record"] as? JsonValue.Obj)?.fields ?: continue
            if (r["kind"] != JsonValue.Str("web")) continue
            for (row in UrlMatcher.entryUrls(r)) out.add(row.url)
        }
        return out.toList()
    }

    private fun host(url: String): String = try {
        UrlMatcher.hostOf(url)
    } catch (e: Exception) {
        url
    }

    /**
     * The prompt for [origin]. [key] (the unlocked vault's local key) makes the "same account" pair id: an HMAC, so the
     * stored answers name no site and differ per vault. [remembered] holds the pair ids answered "Same account".
     */
    fun prompt(lookalike: Lookalike, origin: String, saved: List<String>, key: ByteArray, remembered: Collection<String>): SitePrompt {
        val v = lookalike.shield(origin, saved)
        return when (v.kind) {
            "exact" -> SitePrompt.Verified
            "related" -> SitePrompt.Related
            "lookalike" -> {
                val matched = v.matched
                if (v.reason == "other-suffix" && matched != null) {
                    val pair = pairId(key, origin, matched)
                    if (pair in remembered) SitePrompt.Related else SitePrompt.SameAccount(host(origin), host(matched), pair)
                } else {
                    SitePrompt.Guard(host(origin), matched?.let(::host))
                }
            }
            else -> SitePrompt.New
        }
    }

    /**
     * Before a login picked by hand from the search list fills [origin]: null fills at once (the login's own site by
     * the same match the suggestions use, [matches], on a page known to be https or loopback http); otherwise the
     * question to ask first. A lookalike of one of the login's own sites ([saved]: its URL rows) gets the lookalike
     * question; any other mismatch names both the page and the login's site.
     */
    fun picked(
        lookalike: Lookalike,
        origin: String,
        saved: List<String>,
        matches: Boolean,
        schemeKnown: Boolean,
        key: ByteArray,
        remembered: Collection<String>,
    ): SitePrompt? {
        val verdict = prompt(lookalike, origin, saved, key, remembered)
        if (verdict is SitePrompt.Guard || verdict is SitePrompt.SameAccount) return verdict
        if (matches && schemeKnown) return null
        return SitePrompt.Mismatch(host(origin), saved.firstOrNull()?.let(::host), otherSite = !matches, schemeKnown = schemeKnown)
    }

    /**
     * The check for a login [id] picked by hand for the app [target]: null when the app is already paired with it on
     * this phone (the person confirmed it before), else [SitePrompt.UnverifiedApp] naming the first saved site.
     * Local only: no Digital Asset Links lookup.
     */
    fun pickedApp(target: FillTarget.App, id: String, index: FillIndex, saved: List<String>): SitePrompt? {
        if (index.apps[target.pairKey]?.contains(id) == true) return null
        return SitePrompt.UnverifiedApp(target.packageName, saved.firstOrNull()?.let(::host))
    }

    /** First 32 hex digits of HMAC-SHA256 under a subkey of [key], over `page origin \n saved origin`. */
    fun pairId(key: ByteArray, origin: String, saved: String): String {
        val sub = hmac(key, PAIR_INFO.toByteArray(Charsets.UTF_8))
        return Hex.lower(hmac(sub, "$origin\n$saved".toByteArray(Charsets.UTF_8))).take(32)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
