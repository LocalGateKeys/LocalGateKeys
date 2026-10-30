package app.localgatekeys.android.passkey

import app.localgatekeys.core.records.Origin
import app.localgatekeys.core.records.PublicSuffixRules
import app.localgatekeys.core.records.UrlMatcher

/**
 * Who is asking, as the provider will sign for it. [clientDataHash] is set only for a privileged browser that
 * built clientDataJSON itself; otherwise the provider builds clientDataJSON with [origin] (and [androidPackage]).
 */
data class VerifiedCaller(
    val origin: String,
    val rpId: String,
    val clientDataHash: ByteArray?,
    val androidPackage: String?,
) {
    override fun equals(other: Any?): Boolean = other is VerifiedCaller && origin == other.origin && rpId == other.rpId &&
        androidPackage == other.androidPackage && (clientDataHash?.contentEquals(other.clientDataHash ?: ByteArray(0)) ?: (other.clientDataHash == null))

    override fun hashCode(): Int = origin.hashCode() * 31 + rpId.hashCode()
}

/**
 * The phishing-safe origin rules (spec section 5, Passkeys):
 * - A browser's origin is trusted only when its package **and** signing certificate are on the bundled
 *   privileged list. The rp id must be that origin's host or a registrable parent of it (never a public suffix);
 *   https only, plain http on loopback only.
 * - Every other app is `android:apk-key-hash:<cert>`: the relying party checks that against its Digital Asset
 *   Links, so a look-alike app's assertion is refused by the site. A clientDataHash such an app supplies is ignored.
 */
class CallerOrigin(private val privileged: PrivilegedBrowsers, private val rules: PublicSuffixRules?) {
    private fun isIp(host: String): Boolean = host.contains(':') || host.all { it.isDigit() || it == '.' }

    /** [rpId] may claim [host] (WebAuthn "registrable domain suffix"). */
    fun rpIdAllowed(rpId: String, host: String?): Boolean {
        val rp = rpId.lowercase()
        if (rp.isEmpty() || rp.any { it == '/' || it == ':' || it == '@' || it == ' ' } || rp.startsWith(".") || rp.endsWith(".")) return false
        if (isIp(rp)) return host == rp
        if (host != null && host == rp) return true
        if (host != null && !host.endsWith(".$rp")) return false
        if (!rp.contains('.')) return false
        val r = rules ?: return false // no suffix list: refuse rather than guess (desktop fails closed too)
        return r.publicSuffix(rp) != rp
    }

    /**
     * [requestOrigin] is the origin the browser passed (null for an app), [requestedRpId] the request's rp id
     * (null = the origin's host). Throws [WebAuthnException] when the call must be refused.
     */
    fun verify(
        packageName: String,
        signingCertsSha256: List<ByteArray>,
        requestOrigin: String?,
        requestedRpId: String?,
        callerClientDataHash: ByteArray?,
    ): VerifiedCaller {
        if (requestOrigin != null && privileged.trusts(packageName, signingCertsSha256)) {
            val origin = try {
                Origin.canonicalize(requestOrigin.trimEnd('/'))
            } catch (e: Exception) {
                throw WebAuthnException(WebAuthnException.Reason.ORIGIN_REFUSED)
            }
            val host = UrlMatcher.hostOf(origin)
            val rpId = (requestedRpId ?: host).lowercase()
            if (!rpIdAllowed(rpId, host)) throw WebAuthnException(WebAuthnException.Reason.RP_ID_REFUSED)
            val hash = callerClientDataHash?.takeIf { it.size == 32 }
            return VerifiedCaller(origin, rpId, hash, null)
        }
        // Not a privileged browser: an app (any origin it claimed is ignored).
        val cert = signingCertsSha256.firstOrNull()?.takeIf { it.size == 32 } ?: throw WebAuthnException(WebAuthnException.Reason.ORIGIN_REFUSED)
        val rpId = requestedRpId?.lowercase() ?: throw WebAuthnException(WebAuthnException.Reason.RP_ID_REFUSED)
        if (!rpIdAllowed(rpId, null)) throw WebAuthnException(WebAuthnException.Reason.RP_ID_REFUSED)
        return VerifiedCaller(ClientData.apkKeyHashOrigin(cert), rpId, null, packageName)
    }
}
