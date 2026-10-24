package app.localgatekeys.android.vault

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The bundled site logos: same matching as the desktop (webui/src/lib/siteLogos.test.js). */
class SiteLogosTest {
    private val repoRoot = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"))
    private val assetFile = File(repoRoot, "android/app/src/main/assets/site_logos.json")
    private val table = SiteLogos.load(assetFile.readBytes())

    @Test fun the_bundled_table_loads_and_every_logo_has_its_image() {
        assertTrue("site_logos.json is missing from the app assets", table.logos.size > 100)
        for (logo in table.logos.values) {
            assertNotNull("no drawable for ${logo.slug}", SiteLogoImages.ids[logo.slug])
        }
        assertEquals(table.logos.keys, SiteLogoImages.ids.keys)
        for ((domain, slug) in table.domains) assertNotNull(domain, table.logos[slug])
    }

    @Test fun the_asset_is_the_desktop_table_byte_for_byte() {
        assertTrue(File(repoRoot, "src/localvault/assets/site_logos.json").readBytes().contentEquals(assetFile.readBytes()))
    }

    @Test fun a_domain_and_its_subdomains_match() {
        assertEquals("github", table.logoFor("https://github.com")?.slug)
        assertEquals("google", table.logoFor("https://accounts.google.com")?.slug)
        assertEquals("netflix", table.logoFor("https://www.netflix.com:443/")?.slug)
        assertEquals("gmail", table.logoFor("https://mail.google.com")?.slug) // the most specific domain wins
        assertEquals("github", table.logoFor("https://GitHub.com./login")?.slug)
    }

    @Test fun lookalikes_and_junk_get_no_logo() {
        assertNull(table.logoFor("https://google.com.example.net"))
        assertNull(table.logoFor("https://evilgoogle.com"))
        assertNull(table.logoFor("https://192.168.1.1"))
        assertNull(table.logoFor("https://localhost"))
        assertNull(table.logoFor("not a url"))
        assertNull(table.logoFor(""))
    }

    @Test fun a_broken_file_gives_an_empty_table() {
        assertTrue(SiteLogos.load(null).logos.isEmpty())
        assertTrue(SiteLogos.load("{".toByteArray()).domains.isEmpty())
        assertTrue(SiteLogos.load("[]".toByteArray()).domains.isEmpty())
        val partial = SiteLogos.load(
            """{"logos":{"a":{"hex":"#112233","title":"A"},"b":{"hex":"nope","title":"B"},"c":{"title":"C"}},"domains":{"a.com":"a","b.com":"b","c.com":"zz"}}"""
                .toByteArray(),
        )
        assertEquals(setOf("a"), partial.logos.keys)
        assertEquals(0x112233, partial.logoFor("https://a.com")?.rgb)
        assertNull(partial.logoFor("https://b.com"))
        assertNull(partial.logoFor("https://c.com"))
    }

    @Test fun light_brand_colours_get_a_dark_glyph() {
        assertTrue(SiteLogo("snapchat", "Snapchat", 0xFFFC00).isLight)
        assertFalse(SiteLogo("github", "GitHub", 0x181717).isLight)
    }

    @Test fun only_web_rows_use_a_logo() {
        val web = item("web", "title" to s("GitHub"), "scope" to rec("origin" to s("https://github.com")))
        assertEquals("github", web.siteLogo(table)?.slug)
        assertNull(item("note", "title" to s("github.com")).siteLogo(table))
        assertNull(item("web", "title" to s("x")).siteLogo(table))
    }
}
