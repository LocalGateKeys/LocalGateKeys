package app.localgatekeys.android.vault

import android.content.Context
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import java.net.URI

/** A bundled brand logo: its glyph is the drawable [SiteLogoImages] holds for [slug]; [rgb] is 0xRRGGBB. */
data class SiteLogo(val slug: String, val title: String, val rgb: Int) {
    /** A light brand colour gets a dark glyph. */
    val isLight: Boolean
        get() {
            val r = (rgb shr 16) and 0xFF
            val g = (rgb shr 8) and 0xFF
            val b = rgb and 0xFF
            return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.7
        }
}

/**
 * The bundled site logos (desktop `site_logos.json`, converted by `scripts/make_android_logos.py`): a web login whose
 * origin matches a listed domain shows the brand glyph on the brand colour instead of the kind symbol. No website icon is
 * ever downloaded on Android, so these are the only site images.
 */
class SiteLogos private constructor(val logos: Map<String, SiteLogo>, val domains: Map<String, String>) {
    /**
     * The logo for an origin, or null. A host matches a listed domain or any subdomain of it, never a lookalike
     * (google.com.example.net has no logo).
     */
    fun logoFor(origin: String): SiteLogo? {
        val uri = try { URI(origin) } catch (_: Exception) { return null }
        var host = uri.host?.lowercase() ?: return null
        if (host.endsWith(".")) host = host.dropLast(1)
        if (host.isEmpty()) return null
        val labels = host.split('.')
        if (labels.size < 2) return null
        for (i in 0 until labels.size - 1) {
            val domain = labels.subList(i, labels.size).joinToString(".")
            val slug = domains[domain] ?: continue
            logos[slug]?.let { return it }
        }
        return null
    }

    companion object {
        private val empty = SiteLogos(emptyMap(), emptyMap())

        /** Parses the JSON; a missing or broken file gives an empty table (every row keeps its kind symbol). */
        fun load(json: ByteArray?): SiteLogos {
            if (json == null) return empty
            try {
                val root = CanonicalJson.parse(json).objectOrNull() ?: return empty
                val logoObj = root["logos"].objectOrNull() ?: return empty
                val domainObj = root["domains"].objectOrNull() ?: return empty
                val domains = LinkedHashMap<String, String>()
                for ((d, v) in domainObj) domains[d] = (v as? JsonValue.Str)?.v ?: return empty
                val logos = LinkedHashMap<String, SiteLogo>()
                for ((slug, entry) in logoObj) {
                    val e = entry.objectOrNull() ?: return empty
                    val hex = e["hex"].stringOrNull() ?: continue
                    if (hex.length != 7 || !hex.startsWith("#")) continue
                    val rgb = hex.substring(1).toIntOrNull(16) ?: continue
                    logos[slug] = SiteLogo(slug, e["title"].stringOrNull() ?: slug, rgb)
                }
                return SiteLogos(logos, domains)
            } catch (_: Exception) {
                return empty
            }
        }

        @Volatile
        private var shared: SiteLogos? = null

        /** The table in the app assets, read once. */
        fun shared(context: Context): SiteLogos = shared ?: synchronized(this) {
            shared ?: load(
                try { context.applicationContext.assets.open("site_logos.json").use { it.readBytes() } } catch (_: Exception) { null },
            ).also { shared = it }
        }
    }
}

/** The bundled logo for a web login's origin. */
fun VaultItem.siteLogo(table: SiteLogos): SiteLogo? {
    if (kind != "web") return null
    val origin = record["scope"].objectOrNull()?.get("origin").stringOrNull() ?: return null
    return table.logoFor(origin)
}
