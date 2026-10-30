package app.localgatekeys.android.passkey

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Hex

/**
 * The privileged-browser allowlist (Google's `gpm_passkeys_privileged_apps.json` format, bundled as
 * `assets/privileged_browsers.json`): the browsers whose request origin is trusted, each with the SHA-256 of its
 * signing certificates. A browser is trusted only when its package **and** one of its certificates match.
 */
class PrivilegedBrowsers private constructor(private val certs: Map<String, List<ByteArray>>, val json: String) {
    val packages: Set<String> get() = certs.keys

    fun lists(packageName: String): Boolean = packageName in certs

    fun trusts(packageName: String, signingCertsSha256: List<ByteArray>): Boolean {
        val listed = certs[packageName] ?: return false
        return signingCertsSha256.any { c -> listed.any { java.security.MessageDigest.isEqual(it, c) } }
    }

    override fun toString(): String = "PrivilegedBrowsers(${certs.size} browsers)"

    companion object {
        val EMPTY = PrivilegedBrowsers(emptyMap(), """{"apps":[]}""")

        /** `AA:BB:...` (any case) to bytes; null when not 32 bytes of hex. */
        fun fingerprint(text: String): ByteArray? {
            val hex = text.replace(":", "").trim().lowercase()
            if (hex.length != 64 || hex.any { it !in "0123456789abcdef" }) return null
            return Hex.decode(hex)
        }

        /** Parses the list; entries that are not `type: android` or carry no valid fingerprint are skipped. */
        fun parse(text: String): PrivilegedBrowsers {
            val root = try {
                CanonicalJson.parse(text.toByteArray(Charsets.UTF_8)) as? JsonValue.Obj
            } catch (e: Exception) {
                null
            } ?: return EMPTY
            val out = LinkedHashMap<String, MutableList<ByteArray>>()
            val apps = (root.fields["apps"] as? JsonValue.Arr)?.items ?: return EMPTY
            for (a in apps) {
                val app = (a as? JsonValue.Obj)?.fields ?: continue
                if (app["type"] != JsonValue.Str("android")) continue
                val info = (app["info"] as? JsonValue.Obj)?.fields ?: continue
                val pkg = (info["package_name"] as? JsonValue.Str)?.v?.takeIf { it.isNotEmpty() } ?: continue
                val sigs = (info["signatures"] as? JsonValue.Arr)?.items ?: continue
                for (s in sigs) {
                    val fp = ((s as? JsonValue.Obj)?.fields?.get("cert_fingerprint_sha256") as? JsonValue.Str)?.v ?: continue
                    val bytes = fingerprint(fp) ?: continue
                    out.getOrPut(pkg) { ArrayList() }.add(bytes)
                }
            }
            return PrivilegedBrowsers(out, text)
        }
    }
}
