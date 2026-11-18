package app.localgatekeys.android.security

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** strings_breach_shield.xml: every language has every string and plural form set, with the same placeholders. */
class BreachShieldStringsTest {
    private val res = File(checkNotNull(System.getProperty("lgk.repoRoot")), "android/app/src/main/res")
    private val locales = listOf("de", "es", "fr", "it", "ja", "ko", "nl", "pl", "pt-rBR", "b+zh+Hans")

    /** name -> texts (one for a string, every quantity for a plural). */
    private fun read(dir: String): Map<String, List<String>> {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(File(res, "$dir/strings_breach_shield.xml"))
        val out = LinkedHashMap<String, List<String>>()
        val strings = doc.getElementsByTagName("string")
        for (i in 0 until strings.length) {
            val e = strings.item(i) as org.w3c.dom.Element
            out[e.getAttribute("name")] = listOf(e.textContent)
        }
        val plurals = doc.getElementsByTagName("plurals")
        for (i in 0 until plurals.length) {
            val e = plurals.item(i) as org.w3c.dom.Element
            val items = e.getElementsByTagName("item")
            out[e.getAttribute("name")] = (0 until items.length).map { items.item(it).textContent }
        }
        return out
    }

    private fun placeholders(s: String) = Regex("%\\d+\\$[sd]").findAll(s).map { it.value }.toSortedSet().toList()

    @Test fun every_language_has_every_string_with_the_same_placeholders() {
        val en = read("values")
        assertEquals(15, en.size)
        for (locale in locales) {
            val tr = read("values-$locale")
            assertEquals(locale, en.keys, tr.keys)
            for ((name, texts) in en) {
                for (text in tr.getValue(name)) {
                    assertTrue("$locale/$name is empty", text.isNotBlank())
                    assertEquals("$locale/$name", placeholders(texts.last()), placeholders(text))
                    // A literal percent sign must be escaped in a formatted string.
                    assertTrue("$locale/$name", Regex("%(?!\\d+\\$[sd]|%)").find(text.replace("%%", "")) == null)
                }
            }
            for (name in listOf("autofill_guard_title", "autofill_guard_body")) {
                assertNotEquals("$locale/$name", en.getValue(name), tr.getValue(name))
            }
        }
    }

    @Test fun the_phone_texts_never_say_pc() {
        for (dir in listOf("values") + locales.map { "values-$it" }) {
            for ((name, texts) in read(dir)) for (t in texts) assertTrue("$dir/$name says PC", !Regex("\\bPC\\b|\\bpc\\b|电脑|コンピュータ|komputer").containsMatchIn(t))
        }
    }
}
