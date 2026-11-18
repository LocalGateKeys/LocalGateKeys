package app.localgatekeys.android.security

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.i18n.Txt
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** strings_security.xml: every language has every string, with the same placeholders; the status text follows the language. */
class SecurityStringsTest {
    private val res = File(checkNotNull(System.getProperty("lgk.repoRoot")), "android/app/src/main/res")
    private val locales = listOf("de", "es", "it", "ja", "ko", "nl", "pl", "pt-rBR", "b+zh+Hans", "fr")

    private fun read(dir: String): Map<String, String> {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(File(res, "$dir/strings_security.xml"))
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
        assertTrue(en.size > 30)
        for (locale in locales) {
            val tr = read("values-$locale")
            assertEquals(locale, en.keys, tr.keys)
            for ((name, text) in en) {
                assertEquals("$locale/$name", placeholders(text), placeholders(tr.getValue(name)))
                assertTrue("$locale/$name is empty", tr.getValue(name).isNotBlank())
            }
            // Brand and technical names stay; everything else differs from English somewhere.
            assertNotEquals(locale, en["security_cat_breached"], tr["security_cat_breached"])
        }
    }

    @Test fun the_english_strings_are_found_by_the_test_resolver() {
        val t = EnglishTxt()
        assertEquals("Security score 80 out of 100", t.s(R.string.security_score_description, 80))
        assertEquals("Login, 3 items", t.s(R.string.security_row_description, "Login", 3))
    }

    @Test fun the_breach_status_follows_the_display_language() {
        val en = EnglishTxt()
        val de = object : Txt {
            override fun s(id: Int, vararg args: Any) = "DE:" + en.s(id, *args)
            override fun plural(id: Int, count: Int, vararg args: Any) = "DE:" + en.plural(id, count, *args)
        }
        for (status in listOf(BreachStatus.Running, BreachStatus.Cancelled, BreachStatus.NoneFound, BreachStatus.Found(2), BreachStatus.SomeFailed, BreachStatus.BlockedOffline, BreachStatus.BlockedDisabled)) {
            assertEquals("DE:" + status.text(en), status.text(de))
        }
    }
}
