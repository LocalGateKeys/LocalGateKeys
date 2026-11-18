package app.localgatekeys.android.i18n

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * Sub-plan 07: `strings_collections.xml` is translated in every language the app has (`scripts/i18n_check.py` reads only
 * `strings.xml`): the same names, the same format arguments, no bare apostrophe or quote.
 */
class CollectionStringsTest {
    private val res = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"), "android/app/src/main/res")

    private fun strings(f: File): Map<String, String> {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(f)
        val out = LinkedHashMap<String, String>()
        val nodes = doc.documentElement.getElementsByTagName("string")
        for (i in 0 until nodes.length) {
            val e = nodes.item(i) as Element
            if (e.getAttribute("translatable") == "false") continue
            out[e.getAttribute("name")] = e.textContent
        }
        return out
    }

    private val arg = Regex("""%(\d+)\$[sd]""")

    @Test fun every_language_has_every_collection_string_with_the_same_arguments() = check("strings_collections.xml")

    /** Phone Wi-Fi host mode: the Mac's wording in every language; the phone never says "Mac". */
    @Test fun every_language_has_every_wifi_host_string_with_the_same_arguments() {
        check("strings_wifi_host.xml")
        for (folder in res.listFiles { f -> f.isDirectory && f.name.startsWith("values") && File(f, "strings_wifi_host.xml").isFile }!!) {
            for ((name, text) in strings(File(folder, "strings_wifi_host.xml"))) {
                assertTrue("${folder.name} $name says Mac", !Regex("""\bMac\b""").containsMatchIn(text))
            }
        }
    }

    /** Task 5m: the share sheet's strings, in every language too; the phone never says "iPhone". */
    @Test fun every_language_has_every_collection_share_string_with_the_same_arguments() {
        check("strings_collection_share.xml")
        for (folder in res.listFiles { f -> f.isDirectory && f.name.startsWith("values") && File(f, "strings_collection_share.xml").isFile }!!) {
            for ((name, text) in strings(File(folder, "strings_collection_share.xml"))) {
                assertTrue("${folder.name} $name says iPhone", !text.contains("iPhone"))
            }
        }
    }

    private fun check(fileName: String) {
        val english = strings(File(res, "values/$fileName"))
        val folders = res.listFiles { f -> f.isDirectory && f.name.startsWith("values-") && File(f, "strings.xml").isFile }!!
        assertEquals(10, folders.size)
        for (folder in folders) {
            val file = File(folder, fileName)
            assertTrue("${folder.name} has no $fileName", file.isFile)
            val tr = strings(file)
            assertEquals(folder.name, english.keys, tr.keys)
            for ((name, text) in tr) {
                assertEquals("${folder.name} $name", arg.findAll(english.getValue(name)).map { it.value }.toSet(), arg.findAll(text).map { it.value }.toSet())
                assertTrue("${folder.name} $name: bare apostrophe", !Regex("""(?<!\\)'""").containsMatchIn(text))
                assertTrue("${folder.name} $name: bare quote", !Regex("""(?<!\\)"""").containsMatchIn(text))
                assertTrue("${folder.name} $name: empty", text.isNotBlank())
            }
        }
    }
}
