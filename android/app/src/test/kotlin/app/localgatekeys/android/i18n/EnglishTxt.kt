package app.localgatekeys.android.i18n

import app.localgatekeys.android.R
import java.io.File
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

/**
 * A [Txt] for JVM tests: resolves resource ids to the English text in res/values/strings.xml (strings and plurals,
 * Android format arguments such as %1$s and %1$d, and the escapes \' \" \n). Ids map to names through the R class.
 */
class EnglishTxt(stringsXml: File = defaultFile()) : Txt {
    private val strings = HashMap<String, String>()
    private val plurals = HashMap<String, Map<String, String>>()

    init {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stringsXml)
        val root = doc.documentElement.childNodes
        for (i in 0 until root.length) {
            val e = root.item(i) as? Element ?: continue
            when (e.tagName) {
                "string" -> strings[e.getAttribute("name")] = unescape(e.textContent)
                "plurals" -> {
                    val items = HashMap<String, String>()
                    val kids = e.getElementsByTagName("item")
                    for (k in 0 until kids.length) {
                        val item = kids.item(k) as Element
                        items[item.getAttribute("quantity")] = unescape(item.textContent)
                    }
                    plurals[e.getAttribute("name")] = items
                }
            }
        }
    }

    override fun s(id: Int, vararg args: Any): String =
        String.format(Locale.ENGLISH, strings[nameOf(R.string::class.java, id)] ?: error("no string for id $id"), *args)

    override fun plural(id: Int, count: Int, vararg args: Any): String {
        val items = plurals[nameOf(R.plurals::class.java, id)] ?: error("no plural for id $id")
        // English: "one" for exactly 1, otherwise "other".
        val text = (if (count == 1) items["one"] else null) ?: items["other"] ?: error("plural $id has no 'other'")
        return String.format(Locale.ENGLISH, text, *args)
    }

    private fun nameOf(cls: Class<*>, id: Int): String =
        cls.fields.firstOrNull { it.type == Int::class.javaPrimitiveType && it.getInt(null) == id }?.name ?: error("unknown id $id")

    private fun unescape(raw: String): String {
        val t = raw.trim().let { if (it.length >= 2 && it.startsWith('"') && it.endsWith('"')) it.substring(1, it.length - 1) else it }
        val sb = StringBuilder()
        var i = 0
        while (i < t.length) {
            val c = t[i]
            if (c == '\\' && i + 1 < t.length) {
                when (val n = t[i + 1]) {
                    'n' -> sb.append('\n')
                    't' -> sb.append('\t')
                    else -> sb.append(n)
                }
                i += 2
            } else {
                sb.append(c); i++
            }
        }
        return sb.toString()
    }

    companion object {
        fun defaultFile(): File {
            val root = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))
            return File(root, "android/app/src/main/res/values/strings.xml")
        }
    }
}
