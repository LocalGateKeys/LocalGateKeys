package app.localgatekeys.android

import app.localgatekeys.android.settings.SettingsText
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Task 10 (Google Play Payments policy): no string in the app points at buying outside Play: no shop page, price,
 * payment provider or site link except the app's own legal pages.
 */
class StoreComplianceTest {
    private val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))
    private val forbidden = Regex("""buy\.html|pricing|paddle|lemonsqueezy|\$\d|localgatekeys\.app/(?!legal/app/|ios/backup-device)""")

    /**
     * Not links the user sees: the backup format's UUID5 namespace name (a frozen constant, never opened) and the
     * licence claim endpoint (Task 9, called in the background).
     */
    private val allowed = setOf("https://localgatekeys.app/android/backup-device", "https://licenses.localgatekeys.app/play/claim")

    /** The passphrase generator's word list ("paddle" is a word, not the payment provider). */
    private val skipped = setOf("FallbackWordlist.kt")

    private val literal = Regex("\"\"\"[\\s\\S]*?\"\"\"|\"(?:\\\\.|[^\"\\\\\\n])*\"")

    private fun literals(f: File): List<String> = literal.findAll(f.readText()).map { it.value }.toList()

    @Test
    fun app_strings_never_point_outside_the_store() {
        val main = File(repo, "android/app/src/main")
        val files = main.walkTopDown().filter { it.isFile && it.name !in skipped && (it.extension == "kt" || it.extension == "xml") }.toList()
        assertTrue(files.size > 50)
        val hits = files.flatMap { f ->
            val texts = if (f.extension == "kt") literals(f) else listOf(f.readText())
            texts.filter { t -> t.trim('"') !in allowed && forbidden.containsMatchIn(t) }.map { "${f.relativeTo(main)}: $it" }
        }
        assertEquals(emptyList<String>(), hits)
    }

    @Test
    fun legal_links_open_the_app_pages() {
        assertEquals("https://localgatekeys.app/legal/app/privacy.html", SettingsText.PRIVACY_POLICY_URL)
        assertEquals("https://localgatekeys.app/legal/app/eula.html", SettingsText.LICENCE_AGREEMENT_URL)
    }

    @Test
    fun the_scan_catches_shop_links() {
        for (bad in listOf("https://localgatekeys.app/buy.html", "\$4.99", "https://localgatekeys.app/", "paddle.com", "/pricing")) {
            assertTrue(bad, forbidden.containsMatchIn(bad))
        }
        assertTrue(!forbidden.containsMatchIn("https://localgatekeys.app/legal/app/eula.html"))
        assertTrue(!forbidden.containsMatchIn("\$price \${it.v}"))
    }
}
