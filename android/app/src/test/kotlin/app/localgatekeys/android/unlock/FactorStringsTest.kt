package app.localgatekeys.android.unlock

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.EnglishTxt
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** strings_factors.xml: every language has every string, with the same placeholders. */
class FactorStringsTest {
    private val res = File(checkNotNull(System.getProperty("lgk.repoRoot")), "android/app/src/main/res")
    private val locales = listOf("de", "es", "fr", "it", "ja", "ko", "nl", "pl", "pt-rBR", "b+zh+Hans")

    private fun read(dir: String): Map<String, String> {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(File(res, "$dir/strings_factors.xml"))
        val out = LinkedHashMap<String, String>()
        val nodes = doc.getElementsByTagName("string")
        for (i in 0 until nodes.length) {
            val e = nodes.item(i) as org.w3c.dom.Element
            out[e.getAttribute("name")] = e.textContent
        }
        return out
    }

    private fun placeholders(s: String) = Regex("%\\d+\\$[sd]").findAll(s).map { it.value }.sorted().toList()

    @Test fun every_language_has_every_string_with_the_same_placeholders() {
        val en = read("values")
        assertTrue(en.size > 40)
        for (locale in locales) {
            val tr = read("values-$locale")
            assertEquals(locale, en.keys, tr.keys)
            for ((name, text) in en) {
                assertEquals("$locale/$name", placeholders(text), placeholders(tr.getValue(name)))
                assertTrue("$locale/$name is empty", tr.getValue(name).isNotBlank())
            }
            assertNotEquals(locale, en["factors_needs_app_password"], tr["factors_needs_app_password"])
        }
    }

    @Test fun the_windows_wording_is_reused() {
        val t = EnglishTxt()
        assertEquals("Turn on the app password to add a key file or YubiKey", t.s(R.string.factors_needs_app_password))
        assertEquals("Touch your YubiKey again.", t.s(R.string.factors_yubikey_removed))
        assertEquals("Key file / YubiKey removed; add them again.", t.s(R.string.factors_removed_by_phrase))
        assertEquals("YubiKey set (slot 1)", t.s(R.string.factors_yubikey_set, 1))
    }
}
