package app.localgatekeys.android.autofill

import app.localgatekeys.android.passkey.PrivilegedBrowsers
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.records.Origin

/** What a fill or save request is for: a website in a trusted browser, or an app. */
sealed interface FillTarget {
    /** [origin] is canonical (`https://host[:port]`, or plain http on loopback only). */
    data class Web(val origin: String, val browser: String) : FillTarget

    /**
     * [cert] is the hex SHA-256 of the app's current signing certificate ("" when it could not be read). Pairings
     * are keyed by [pairKey], so a different app later installed under the same package name is not offered them.
     */
    data class App(val packageName: String, val cert: String = "") : FillTarget {
        val pairKey: String get() = "$packageName#$cert"
    }

    companion object {
        /**
         * Browsers whose `webDomain` is trusted for autofill (their own address bar). Any other app's web domain is
         * ignored: an app chooses the `webDomain` of its own WebView, so trusting it would let a phishing app ask for
         * any site's login. The browser must also be on the privileged list with one of its listed certificates (a look-alike
         * package signed by someone else is never trusted).
         */
        val BROWSERS: Set<String> = setOf(
            "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "org.chromium.chrome",
            "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.focus",
            "com.microsoft.emmx", "com.brave.browser", "com.brave.browser_beta", "com.sec.android.app.sbrowser",
            "com.sec.android.app.sbrowser.beta", "com.opera.browser", "com.vivaldi.browser",
            "com.duckduckgo.mobile.android",
        )

        /**
         * The target of a request from [packageName] (signed with [certSha256]s) whose form names [webDomain] /
         * [webScheme]. Null = never fill (this app itself, or a browser page that is not https / loopback http).
         */
        fun of(
            packageName: String,
            certSha256: List<ByteArray>,
            webDomain: String?,
            webScheme: String?,
            ownPackage: String,
            privileged: PrivilegedBrowsers,
        ): FillTarget? {
            if (packageName == ownPackage || packageName.startsWith("$ownPackage.")) return null
            val trustedBrowser = packageName in BROWSERS && privileged.trusts(packageName, certSha256)
            if (!trustedBrowser || webDomain.isNullOrBlank()) {
                // A browser's own screens (no page) fill nothing; other apps fill as apps.
                return if (packageName in BROWSERS) null else App(packageName, certSha256.firstOrNull()?.let { Hex.lower(it) } ?: "")
            }
            val scheme = (webScheme ?: "https").lowercase()
            if (scheme != "https" && scheme != "http") return null
            val origin = try {
                Origin.canonicalize("$scheme://${webDomain.trim()}")
            } catch (e: Exception) {
                return null
            }
            return Web(origin, packageName)
        }
    }
}
